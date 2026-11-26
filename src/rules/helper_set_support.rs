//! Whether every value one set expression yields is one another yields, read
//! from the declarations, the ladders of the schema and the bodies of the
//! set-returning `LANGUAGE sql` helpers the sets call.

use std::{borrow::Cow, cell::RefCell, collections::HashMap, ops::ControlFlow, rc::Rc};

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ExpressionContext, ExpressionScope, IdentifierCase},
    traits::{DatabaseLike, FunctionLike},
    utils::{identifier_resolution::normalize_identifier, scalar_family::scalar_family},
};
use sqlparser::ast::{
    AccessExpr, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, FunctionSecurity,
    Query, Select, SelectItem, SetExpr, SetOperator, SetQuantifier, Statement, TableAlias,
    TableFactor, Value, WildcardAdditionalOptions, visit_expressions, visit_expressions_mut,
};

use crate::{
    deployment::{Deployment, fully_unfolded},
    rules::{
        existence_oracle_support::{identifier, resolves_alike},
        implication_support::{
            filters_nothing, limits_nothing, parameter_ordinal, renamed_column_call, select_members,
        },
        ladder_support::{Ladders, called, listed_arguments, positional_arguments},
        literal_support::literal,
        policy_support::{sets_only_search_path, sql_set_body},
    },
};

/// A helper a call reaches, with the query its body runs for the call.
type HelperBody<'db, DB> = (&'db <DB as DatabaseLike>::Function, Cow<'db, Query>);

/// Reads which sets lie within which, caching what each helper body tells.
pub(crate) struct HelperSets<'a, DB: DatabaseLike> {
    database: &'a DB,
    ladders: Ladders<'a, DB>,
    /// The spelling each set unfolds to, by the set.
    unfoldings: RefCell<HashMap<Expr, Option<Expr>>>,
    /// The sets each set yields every value of, by the set.
    parts: RefCell<HashMap<Expr, Rc<[Expr]>>>,
}

impl<'a, DB: DatabaseLike> HelperSets<'a, DB> {
    pub(crate) fn new(database: &'a DB) -> Self {
        Self {
            database,
            ladders: Ladders::new(database),
            unfoldings: RefCell::default(),
            parts: RefCell::default(),
        }
    }

    /// Whether every value the set expression `narrower` yields is one
    /// `wider` yields, through the sets `deployment` declares within others
    /// once each set is spelled as the helpers it calls unfold it.
    ///
    /// # Errors
    ///
    /// Returns the lookup error reading a set, a helper or its body raised.
    pub(crate) fn is_set_within(
        &self,
        deployment: &Deployment,
        narrower: &Expr,
        wider: &Expr,
    ) -> Result<bool, LookupError> {
        deployment.is_set_within(
            narrower,
            wider,
            |set| self.unfolded(set),
            |narrower, wider| self.within(narrower, wider),
        )
    }

    /// Whether every value the fully unfolded set `narrower` yields is one
    /// `wider` yields as the schema reads them, off a ladder, or as a set
    /// the body of the helper `wider` calls yields every value of, or the
    /// body of a helper such a set calls.
    fn within(&self, narrower: &Expr, wider: &Expr) -> Result<bool, LookupError> {
        if self.ladders.within(narrower, wider)? {
            return Ok(true);
        }
        let parts = self.parts_of(wider)?;
        if parts.is_empty() {
            return Ok(false);
        }
        // `parts_of` hands out one handle per set, so a body met again, as
        // a helper seeding itself is, is skipped by its handle.
        let mut bodies: Vec<Rc<[Expr]>> = vec![parts];
        let mut next = 0;
        while let Some(parts) = bodies.get(next).map(Rc::clone) {
            for part in parts.iter() {
                if part == narrower || self.ladders.within(narrower, part)? {
                    return Ok(true);
                }
                let further = self.parts_of(part)?;
                if !further.is_empty() && !bodies.iter().any(|body| Rc::ptr_eq(body, &further)) {
                    bodies.push(further);
                }
            }
            next += 1;
        }
        Ok(false)
    }

    /// Another spelling of the set `set` yields, read from the helper it
    /// calls, cached by the set.
    fn unfolded(&self, set: &Expr) -> Result<Option<Expr>, LookupError> {
        if let Some(cached) = self.unfoldings.borrow().get(set) {
            return Ok(cached.clone());
        }
        let found = self.read_unfolded(set)?;
        self.unfoldings
            .borrow_mut()
            .insert(set.clone(), found.clone());
        Ok(found)
    }

    /// [`Self::unfolded`] uncached. The one column of a call, written
    /// `(call).column`, is the call. A call passing no argument to a helper
    /// [`Self::helper_body`] reads is the set its body selects, when the body
    /// selects one set expression that yields there what it yields to the
    /// caller. A call passing arguments keeps its spelling, so that a ladder
    /// still compares it with another call of its helper.
    fn read_unfolded(&self, set: &Expr) -> Result<Option<Expr>, LookupError> {
        if let Expr::CompoundFieldAccess { root, access_chain } = set
            && let (Expr::Nested(call), [AccessExpr::Dot(Expr::Identifier(column))]) =
                (root.as_ref(), access_chain.as_slice())
            && let Expr::Function(function_call) = call.as_ref()
        {
            let Some(function) = called(self.database, function_call)? else {
                return Ok(None);
            };
            let mut returned = function.returned_columns(self.database);
            return Ok(match (returned.next(), returned.next()) {
                (Some((name, _)), None)
                    if normalize_identifier(name.name(), name.name_is_quoted())
                        == identifier(column) =>
                {
                    Some(call.as_ref().clone())
                }
                _ => None,
            });
        }
        if !matches!(set, Expr::Function(call) if listed_arguments(call).is_some_and(|arguments| arguments.is_empty()))
        {
            return Ok(None);
        }
        let Some((function, body)) = self.helper_body(set)? else {
            return Ok(None);
        };
        let Some(members) = self.body_members(&body)? else {
            return Ok(None);
        };
        Ok(self
            .admissible(
                &members,
                function.security_mode() == FunctionSecurity::Definer,
            )?
            .then(|| members.into_owned()))
    }

    /// The sets each of whose values the set `set` yields, fully unfolded,
    /// cached by the set.
    fn parts_of(&self, set: &Expr) -> Result<Rc<[Expr]>, LookupError> {
        if let Some(cached) = self.parts.borrow().get(set) {
            return Ok(Rc::clone(cached));
        }
        let found: Rc<[Expr]> = self.read_parts(set)?.into();
        self.parts
            .borrow_mut()
            .insert(set.clone(), Rc::clone(&found));
        Ok(found)
    }

    /// [`Self::parts_of`] uncached, read from a helper [`Self::helper_body`]
    /// reads, from each arm [`yielding_arms`] finds in its body that selects
    /// one set expression yielding there what it yields to the caller.
    fn read_parts(&self, set: &Expr) -> Result<Vec<Expr>, LookupError> {
        let Some((function, body)) = self.helper_body(set)? else {
            return Ok(Vec::new());
        };
        let Some(arms) = yielding_arms(&body) else {
            return Ok(Vec::new());
        };
        let definer = function.security_mode() == FunctionSecurity::Definer;
        let mut parts = Vec::with_capacity(arms.len());
        for arm in arms {
            if let Some(members) = self.arm_members(arm)?
                && self.admissible(&members, definer)?
            {
                parts.push(fully_unfolded(&members, &mut |set| self.unfolded(set))?.into_owned());
            }
        }
        Ok(parts)
    }

    /// The helper the call `set` reaches, with the query its body runs for
    /// the call, when it is a set-returning `LANGUAGE sql` function that sets
    /// no parameter besides the search path, whose body names reach on that
    /// path what they reach on the schema's own, and the call passes a
    /// literal other than `NULL` for each input parameter, which the query
    /// reads in place of every reference to the parameter.
    fn helper_body(&self, set: &Expr) -> Result<Option<HelperBody<'a, DB>>, LookupError> {
        let Expr::Function(call) = set else {
            return Ok(None);
        };
        let Some(function) = called(self.database, call)? else {
            return Ok(None);
        };
        let Some(arguments) = positional_arguments(call, function).filter(|arguments| {
            arguments
                .iter()
                .all(|argument| literal(argument).is_some_and(|value| *value != Value::Null))
        }) else {
            return Ok(None);
        };
        if !sets_only_search_path(function) {
            return Ok(None);
        }
        let Some(body) = sql_set_body(self.database, function)? else {
            return Ok(None);
        };
        if let Some(path) = function.search_path(self.database)?
            && !resolves_alike(self.database, body.as_ref(), &path)?
        {
            return Ok(None);
        }
        if arguments.is_empty() {
            return Ok(Some((function, body)));
        }
        Ok(
            bound_body(self.database, function, body.into_owned(), &arguments)
                .map(|body| (function, Cow::Owned(body))),
        )
    }

    /// The expression yielding the rows of `query`, when it declares no
    /// `WITH`, limits nothing and runs one arm [`Self::arm_members`] reads.
    fn body_members<'q>(&self, query: &'q Query) -> Result<Option<Cow<'q, Expr>>, LookupError> {
        if query.with.is_some() || !limits_nothing(query) {
            return Ok(None);
        }
        self.arm_members(&query.body)
    }

    /// The expression yielding the rows of the arm `arm`, as
    /// [`select_members`] reads a select, or the call a select projects the
    /// one column of through an alias naming that column, when the call
    /// yields one column.
    fn arm_members<'q>(&self, arm: &'q SetExpr) -> Result<Option<Cow<'q, Expr>>, LookupError> {
        match arm {
            SetExpr::Select(select) => {
                if let Some(members) = select_members(select) {
                    return Ok(Some(members));
                }
                let Some(call) = renamed_column_call(select) else {
                    return Ok(None);
                };
                Ok(self
                    .yields_one_column(&call)?
                    .then_some(Cow::Owned(Expr::Function(call))))
            }
            SetExpr::Query(query) => self.body_members(query),
            _ => Ok(None),
        }
    }

    /// Whether `call` reaches one set-returning function whose rows have
    /// one column, a built-in scalar it returns a set of or the one column
    /// it declares.
    fn yields_one_column(&self, call: &Function) -> Result<bool, LookupError> {
        let Some(function) = called(self.database, call)?.filter(|function| function.returns_set())
        else {
            return Ok(false);
        };
        let mut returned = function.returned_columns(self.database);
        Ok(match (returned.next(), returned.next()) {
            (Some(_), None) => true,
            (None, _) => function
                .return_type_name(self.database)
                .as_deref()
                .and_then(|name| name.strip_prefix("SETOF "))
                .is_some_and(|element| scalar_family(element).is_some()),
            _ => false,
        })
    }

    /// Whether `expression`, read in the body of a helper, yields there
    /// what it yields to the caller of the helper. A body that runs as its
    /// owner, as `definer` tells, reads no table in it and calls only
    /// definers and built-ins that read neither the role nor its privileges.
    ///
    /// # Errors
    ///
    /// Returns the lookup error resolving a call raised.
    pub(crate) fn admissible(&self, expression: &Expr, definer: bool) -> Result<bool, LookupError> {
        let mut admissible = true;
        let mut calls: Vec<Function> = Vec::new();
        let _ = visit_expressions(expression, |node| {
            // `ARRAY(SELECT ...)` constructs an array, calling nothing beyond
            // the calls its subquery holds, which the walk visits.
            if let Expr::Function(function) = node
                && !(matches!(function.args, FunctionArguments::Subquery(_))
                    && function.name.to_string().eq_ignore_ascii_case("array"))
            {
                calls.push(function.clone());
            }
            ControlFlow::<()>::Continue(())
        });
        if definer {
            let _ = sqlparser::ast::visit_relations(expression, |_| {
                admissible = false;
                ControlFlow::<()>::Break(())
            });
        }
        for call in &calls {
            if !admissible {
                break;
            }
            let called: Vec<&DB::Function> = self
                .database
                .functions_reached_by(call, IdentifierCase::Folded)?
                .collect();
            admissible = !called.is_empty()
                && called.iter().all(|function| {
                    let builtin = function.target_name().schema() == Some("pg_catalog");
                    if builtin {
                        !(definer && reads_role(&function.stored_name(), call))
                    } else {
                        !definer || function.security_mode() == FunctionSecurity::Definer
                    }
                });
        }
        Ok(admissible)
    }
}

/// `body`, the query `function` runs, with every reference to an input
/// parameter, by name or as `$n`, replaced by the argument `arguments` holds
/// for it, or `None` when the schema cannot resolve the body's relations,
/// settle whether a name references a parameter or a column, or a
/// placeholder names no parameter.
fn bound_body<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
    body: Query,
    arguments: &[&Expr],
) -> Option<Query> {
    let mut statement = Statement::Query(Box::new(body));
    // The argument standing for each name or placeholder that references a
    // parameter, in the order the walks below meet them, since both meet
    // these leaves in the same order.
    let mut references: Vec<Option<&Expr>> = Vec::new();
    let settled = ExpressionContext::for_statement(
        &statement,
        &ExpressionScope::FunctionBody(function),
        database,
        IdentifierCase::AsWritten,
    )
    .is_ok_and(|context| {
        visit_expressions(&statement, |expression| {
            let ordinal = match expression {
                Expr::Value(_) => parameter_ordinal(expression),
                Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
                    match context.reference(expression) {
                        Ok(Some((ColumnDefinition::Parameter { ordinal, .. }, _))) => Some(ordinal),
                        Ok(_) => None,
                        Err(_) => return ControlFlow::Break(()),
                    }
                }
                _ => return ControlFlow::Continue(()),
            };
            match ordinal.map(|ordinal| arguments.get(ordinal)) {
                Some(None) => return ControlFlow::Break(()),
                Some(Some(argument)) => references.push(Some(*argument)),
                None => references.push(None),
            }
            ControlFlow::Continue(())
        })
        .is_continue()
    });
    if settled {
        let mut met = references.into_iter();
        let _ = visit_expressions_mut(&mut statement, |expression| {
            if matches!(
                expression,
                Expr::Value(_) | Expr::Identifier(_) | Expr::CompoundIdentifier(_)
            ) && let Some(argument) = met.next().flatten()
            {
                *expression = argument.clone();
            }
            ControlFlow::<()>::Continue(())
        });
    }
    match statement {
        Statement::Query(body) if settled => Some(*body),
        _ => None,
    }
}

/// The arms whose every row the query `query` returns: the arms seeding the
/// walk [`recursive_seeds`] reads, or the arms the body of a query declaring
/// no `WITH` and limiting nothing joins by `UNION`, or that body alone.
fn yielding_arms(query: &Query) -> Option<Vec<&SetExpr>> {
    if let Some(seeds) = recursive_seeds(query) {
        return Some(seeds);
    }
    let mut arms = Vec::new();
    (query.with.is_none() && limits_nothing(query) && union_arms(&query.body, &mut arms))
        .then_some(arms)
}

/// The arms seeding the walk `query` runs, when it is `WITH RECURSIVE walk
/// AS (<seed arms> UNION <step arms>)` reselecting every column of the walk
/// in order, without filtering or limiting it. PostgreSQL returns every row
/// of the arms left of the last top-level `UNION`, and the arms right of it
/// only add rows.
fn recursive_seeds(query: &Query) -> Option<Vec<&SetExpr>> {
    let with = query.with.as_ref().filter(|with| with.recursive)?;
    let SetExpr::Select(outer) = query.body.as_ref() else {
        return None;
    };
    let walk = with
        .cte_tables
        .iter()
        .find(|walk| reselects(outer, &walk.alias))?;
    if !limits_nothing(query)
        || !filters_nothing(outer)
        || walk.from.is_some()
        || walk.query.with.is_some()
        || !limits_nothing(&walk.query)
    {
        return None;
    }
    let SetExpr::SetOperation {
        op: SetOperator::Union,
        set_quantifier,
        left,
        ..
    } = walk.query.body.as_ref()
    else {
        return None;
    };
    let mut seeds = Vec::new();
    (positional(*set_quantifier) && union_arms(left, &mut seeds)).then_some(seeds)
}

/// Collects into `arms` the arms of `body` that `UNION` joins, or returns
/// false when one joins them by name.
fn union_arms<'q>(body: &'q SetExpr, arms: &mut Vec<&'q SetExpr>) -> bool {
    match body {
        SetExpr::SetOperation {
            op: SetOperator::Union,
            set_quantifier,
            left,
            right,
        } => positional(*set_quantifier) && union_arms(left, arms) && union_arms(right, arms),
        arm => {
            arms.push(arm);
            true
        }
    }
}

/// Whether a set operation under `quantifier` pairs columns by position.
fn positional(quantifier: SetQuantifier) -> bool {
    matches!(
        quantifier,
        SetQuantifier::None | SetQuantifier::All | SetQuantifier::Distinct
    )
}

/// Whether `select` reads the walk `walk` names alone and projects each of
/// its columns once, in order, as `*` or by the names `walk` lists or the
/// alias it reads the walk under renames them to.
fn reselects(select: &Select, walk: &TableAlias) -> bool {
    let [from] = select.from.as_slice() else {
        return false;
    };
    let TableFactor::Table {
        name,
        alias,
        args: None,
        version: None,
        with_ordinality: false,
        sample: None,
        ..
    } = &from.relation
    else {
        return false;
    };
    let walked = identifier(&walk.name);
    let renamed = alias
        .as_ref()
        .map_or(&[][..], |alias| alias.columns.as_slice());
    if !from.joins.is_empty()
        || !matches!(name.0.as_slice(), [part] if part.as_ident().map(identifier).as_ref() == Some(&walked))
        || renamed.len() > walk.columns.len()
    {
        return false;
    }
    let exposed = alias.as_ref().map(|alias| identifier(&alias.name));
    let exposed = exposed.as_ref().unwrap_or(&walked);
    match select.projection.as_slice() {
        [SelectItem::Wildcard(options)] => *options == WildcardAdditionalOptions::default(),
        items => {
            let columns = renamed.iter().chain(&walk.columns[renamed.len()..]);
            !walk.columns.is_empty()
                && items.len() == walk.columns.len()
                && items.iter().zip(columns).all(|(item, column)| {
                    let named = match item {
                        SelectItem::UnnamedExpr(Expr::Identifier(named))
                        | SelectItem::ExprWithAlias {
                            expr: Expr::Identifier(named),
                            ..
                        } => Some(named),
                        SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts))
                        | SelectItem::ExprWithAlias {
                            expr: Expr::CompoundIdentifier(parts),
                            ..
                        } => parts
                            .split_last()
                            .filter(|(_, qualifier)| {
                                matches!(qualifier, [relation] if identifier(relation) == *exposed)
                            })
                            .map(|(named, _)| named),
                        _ => None,
                    };
                    named.is_some_and(|named| identifier(named) == identifier(&column.name))
                })
        }
    }
}

/// Whether the built-in `name`, called as `call`, reads the acting role, its
/// privileges or the search path, which differ inside a definer that sets
/// it.
fn reads_role(name: &str, call: &Function) -> bool {
    name.starts_with("has_")
        || matches!(
            name,
            "pg_has_role"
                | "row_security_active"
                | "current_user"
                | "current_role"
                | "user"
                | "session_user"
                | "current_schema"
                | "current_schemas"
        )
        || (name == "current_setting"
            && !matches!(
                &call.args,
                FunctionArguments::List(list) if matches!(
                    list.args.first(),
                    Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(value))))
                        if matches!(&value.value, Value::SingleQuotedString(setting) if !setting.eq_ignore_ascii_case("search_path"))
                )
            ))
}
