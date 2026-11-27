//! Whether a filter implies the conditions of row-level-security policies,
//! compared as written once the columns each tests go by one name.

use std::{borrow::Cow, convert::Infallible, iter, mem, ops::ControlFlow, ptr, slice};

use sql_traits::{
    errors::LookupError, structs::RowGate, traits::DatabaseLike,
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{
    AccessExpr, BinaryOperator, DataType, Distinct, Expr, Function, FunctionArg, FunctionArgExpr,
    FunctionArgumentList, FunctionArguments, GroupByExpr, Ident, InTarget, JoinConstraint,
    JoinOperator, LimitClause, ObjectName, ObjectNamePart, Query, Select, SelectItem, SetExpr,
    TableAlias, TableFactor, UnaryOperator, Value, Visit, VisitMut, Visitor, VisitorMut,
    WildcardAdditionalOptions, visit_expressions, visit_expressions_mut,
};

use crate::rules::{
    closed_set_support::stored_name,
    ladder_support::{listed_arguments, plain},
    literal_support::{literal, string_value},
    policy_support::{
        conjuncts, disjuncts, is_column_reference, is_tautology, unnested, unwrapped,
    },
    walk_support::walk,
};

/// What a name a filter writes like a column's stands for.
pub(crate) enum Term {
    /// The column of this stored name.
    Column(String),
    /// The input parameter at this position, counted from zero, of the
    /// function whose body holds the filter.
    Parameter(usize),
}

/// The values an input parameter of an enum type may hold.
pub(crate) struct ParameterValues {
    /// Each label of the enum, as a string literal.
    pub(crate) labels: Vec<Expr>,
    /// Whether the parameter may also be `NULL`, as in a function that runs
    /// on `NULL` input.
    pub(crate) null: bool,
}

/// One value of the row a policy condition tests against a set.
pub(crate) enum Operand<'e, T> {
    /// The condition columns this column names.
    Tested(T),
    /// A value that reads no column, met as written.
    Value(&'e Expr),
}

/// How the columns a policy condition tests map onto those a filter tests.
pub(crate) trait Columns {
    /// The condition columns a set membership tests.
    type Tested;

    /// Whether every value the set expression `narrower` yields is one
    /// `wider` yields.
    ///
    /// # Errors
    ///
    /// Returns the lookup error reading what either expression yields raised.
    fn is_set_within(&self, narrower: &Expr, wider: &Expr) -> Result<bool, LookupError>;

    /// The name the filter gives the condition column stored as `column`.
    fn rename(&self, column: Cow<'_, str>) -> Option<String>;

    /// The condition columns `column` names, when it names one the filter can
    /// test.
    fn tested(&self, column: &Expr) -> Option<Self::Tested>;

    /// Whether the filter column `column` is one of `tested`.
    fn tests(&self, column: &Expr, tested: &Self::Tested) -> bool;

    /// The stored table `name` names in a subquery of a condition, `None`
    /// for any other relation, whose columns are unknown.
    fn relation(&self, _name: &ObjectName) -> Option<StoredRelation> {
        None
    }

    /// The value a policy's `call` returns, written so that it reads alike
    /// wherever it stands, `None` for a call kept as written.
    fn inlined(&self, _call: &Function) -> Option<Expr> {
        None
    }

    /// Whether `clause` alone meets every condition.
    ///
    /// # Errors
    ///
    /// Returns the lookup error reading what the clause leaves raised.
    fn settles(&self, _clause: &Expr) -> Result<bool, LookupError> {
        Ok(false)
    }

    /// The values the input parameter at `ordinal` may hold, `None` for one
    /// whose type is no enum.
    fn parameter_values(&self, _ordinal: usize) -> Option<&ParameterValues> {
        None
    }

    /// Whether `data_type` names an enum type, which PostgreSQL compares
    /// only with values of that same enum.
    fn is_enum(&self, _data_type: &DataType) -> bool {
        false
    }

    /// Whether every function `call` may reach returns `NULL` when its
    /// positional argument at `index`, counted from zero, is `NULL`.
    fn returns_null_on_null_argument(&self, _call: &Function, _index: usize) -> bool {
        false
    }

    /// Whether `clause` draws the row it tests from rows that each meet
    /// `condition`, when the row also meets every one of `context`.
    ///
    /// # Errors
    ///
    /// Returns the lookup error reading the rows' source raised.
    fn draws_implied(
        &self,
        _clause: &Expr,
        _condition: &Condition<'_, Self::Tested>,
        _context: &[&Expr],
    ) -> Result<bool, LookupError> {
        Ok(false)
    }
}

/// A policy condition as a filter would state it.
pub(crate) struct Condition<'e, T> {
    /// The condition as the policy writes it.
    pub(crate) original: &'e Expr,
    /// The condition with each column it tests named as the filter names it,
    /// when the filter names every one.
    renamed: Option<Expr>,
    /// `renamed` with every setting read without `missing_ok` read with it,
    /// when it reads one and the condition is never true while that setting
    /// is unset and so `NULL` with `missing_ok`. Where the setting is unset
    /// the condition read without `missing_ok` raises an error, and a filter
    /// implying this form admits no row.
    relaxed: Option<Expr>,
    /// The row the condition tests against a set, value by value, and the
    /// expression yielding the members of the set.
    pub(crate) membership: Option<(Vec<Operand<'e, T>>, Cow<'e, Expr>)>,
    /// The conjuncts of an `AND`, each implied for the whole.
    pub(crate) parts: Vec<Self>,
    /// The arms of an `OR`, one implied for the whole.
    arms: Vec<Self>,
}

impl<'e, T> Condition<'e, T> {
    /// `condition` as a filter naming columns as `columns` does would state
    /// it, split into its conjuncts and arms.
    pub(crate) fn new<C: Columns<Tested = T>>(columns: &C, condition: &'e Expr) -> Self {
        let condition = unnested(condition);
        let split = |operands: Vec<&'e Expr>| {
            if operands.len() > 1 {
                operands
                    .into_iter()
                    .map(|operand| Self::new(columns, operand))
                    .collect()
            } else {
                Vec::new()
            }
        };
        let renamed = renamed(
            condition,
            |column| {
                stored_name(column)
                    .and_then(|name| columns.rename(name))
                    .map(Term::Column)
            },
            |name| columns.relation(name),
            |call| columns.inlined(call),
        )
        .map(|renamed| untyped_labels(renamed, columns));
        Self {
            original: condition,
            relaxed: renamed
                .as_ref()
                .and_then(missing_ok)
                .filter(|_| rejects_unset(condition)),
            renamed,
            membership: membership(condition).and_then(|(row, members)| {
                let operands = row
                    .iter()
                    .map(|operand| {
                        if is_column(operand) {
                            columns.tested(operand).map(Operand::Tested)
                        } else {
                            Some(Operand::Value(operand))
                        }
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some((operands, members))
            }),
            parts: split(conjuncts(condition)),
            arms: split(disjuncts(condition)),
        }
    }
}

/// Whether every row `clause` admits meets `condition`, when the row also
/// meets every one of `context`. That holds when the clause settles it,
/// states it, finds rows only where the condition's subquery finds one,
/// tests the same row against a set within the condition's, or draws its
/// row from rows meeting it, when it implies the condition in every arm or
/// for every value it lists or in one of its conjuncts, or when it implies
/// each conjunct, one arm or the equality with one value `condition` lists.
/// A list is written `x IN (v, ...)` or `x = ANY (ARRAY[v, ...])`.
///
/// # Errors
///
/// Returns the lookup error [`Columns::settles`], [`Columns::draws_implied`]
/// or [`Columns::is_set_within`] raised.
pub(crate) fn clause_implies<C: Columns>(
    columns: &C,
    clause: &Expr,
    condition: &Condition<'_, C::Tested>,
    context: &[&Expr],
) -> Result<bool, LookupError> {
    let clause = unnested(clause);
    if columns.settles(clause)? {
        return Ok(true);
    }
    let set_within = |narrower: &Expr, wider: &Expr| columns.is_set_within(narrower, wider);
    if let Some(stated) = &condition.renamed
        && let Some(written) = renamed(
            clause,
            |column| stored_name(column).map(|name| Term::Column(name.into_owned())),
            |name| columns.relation(name),
            |_| None,
        )
        .map(|written| untyped_labels(written, columns))
        && (written == *stated
            || missing_ok(&written).as_ref().unwrap_or(&written)
                == condition.relaxed.as_ref().unwrap_or(stated)
            || finds_within(&set_within, &written, stated)?)
    {
        return Ok(true);
    }
    if let Some((operands, wider)) = &condition.membership
        && let Some((row, members)) = membership(clause)
        && row.len() == operands.len()
        && row_meets(columns, row, operands, context)
        && is_within(columns, &members, wider)?
    {
        return Ok(true);
    }
    if columns.draws_implied(clause, condition, context)? {
        return Ok(true);
    }
    let arms = disjuncts(clause);
    if arms.len() > 1
        && every(&arms, |arm| {
            clause_implies(columns, arm, condition, context)
        })?
    {
        return Ok(true);
    }
    if let Some((operand, values)) = listed(clause)
        && every(&equalities(operand, values), |arm| {
            clause_implies(columns, arm, condition, context)
        })?
    {
        return Ok(true);
    }
    if !condition.parts.is_empty()
        && every(&condition.parts, |part| {
            clause_implies(columns, clause, part, context)
        })?
    {
        return Ok(true);
    }
    let parts = conjuncts(clause);
    if parts.len() > 1 {
        for (index, part) in parts.iter().enumerate() {
            let mut beside = context.to_vec();
            beside.extend(
                parts
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .flat_map(|(_, other)| conjuncts(other)),
            );
            if clause_implies(columns, part, condition, &beside)? {
                return Ok(true);
            }
        }
    }
    for arm in &condition.arms {
        if clause_implies(columns, clause, arm, context)? {
            return Ok(true);
        }
    }
    if let Some((operand, values)) = listed(condition.original) {
        for equality in equalities(operand, values) {
            let arm = Condition::new(columns, &equality);
            if clause_implies(columns, clause, &arm, context)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The arms of which every row `condition` admits meets one, those of an
/// `OR` or `x = v` for each value of a list `condition` tests `x` against,
/// when it is either.
pub(crate) fn alternatives(condition: &Expr) -> Option<Vec<Expr>> {
    let condition = unnested(condition);
    let arms = disjuncts(condition);
    if arms.len() > 1 {
        return Some(arms.into_iter().cloned().collect());
    }
    listed(condition).map(|(operand, values)| equalities(operand, values))
}

/// `expression` with each string literal cast to an enum type and compared
/// with a column or parameter written as the bare literal. The comparison
/// resolves only where the other operand is of that enum, whose type the
/// bare literal then takes, so both spellings compare alike.
fn untyped_labels<C: Columns>(mut expression: Expr, columns: &C) -> Expr {
    let _ = visit_expressions_mut(&mut expression, |node| {
        if let Expr::BinaryOp {
            left,
            op:
                BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::Lt
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::GtEq,
            right,
        } = node
        {
            for flipped in [false, true] {
                let (reference, operand) = if flipped {
                    (&**right, &mut **left)
                } else {
                    (&**left, &mut **right)
                };
                if !is_column_reference(unnested(reference)) {
                    continue;
                }
                if let Expr::Cast {
                    expr,
                    data_type,
                    format: None,
                    ..
                } = unnested(operand)
                    && let Expr::Value(value) = expr.as_ref()
                    && string_value(&value.value).is_some()
                    && columns.is_enum(data_type)
                {
                    *operand = Expr::Value(value.clone());
                }
            }
        }
        ControlFlow::<Infallible>::Continue(())
    });
    expression
}

/// The operand `expression` tests and the values it lists, when it is
/// `x IN (v, ...)` or `x = ANY (ARRAY[v, ...])`, either of which holds,
/// fails or is `NULL` where the `OR` of `x = v` over the values does.
fn listed(expression: &Expr) -> Option<(&Expr, &[Expr])> {
    match expression {
        Expr::In {
            expr,
            target: InTarget::List(values),
            negated: false,
            ..
        } => Some((expr, values)),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => match unnested(right) {
            Expr::Array(array) => Some((left, &array.elem)),
            _ => None,
        },
        _ => None,
    }
}

/// `operand = value` for each of `values`.
fn equalities(operand: &Expr, values: &[Expr]) -> Vec<Expr> {
    values
        .iter()
        .map(|value| Expr::BinaryOp {
            left: Box::new(operand.clone()),
            op: BinaryOperator::Eq,
            right: Box::new(value.clone()),
        })
        .collect()
}

/// The name and the `missing_ok` argument, when passed, of a call of
/// `current_setting`.
fn setting_read(expression: &Expr) -> Option<(&Expr, Option<&Expr>)> {
    let Expr::Function(call) = expression else {
        return None;
    };
    let names = |part: &ObjectNamePart, expected: &str| {
        part.as_ident().is_some_and(|ident| {
            normalize_identifier(&ident.value, ident.quote_style.is_some()) == expected
        })
    };
    if !call.name.0.split_last().is_some_and(|(function, schema)| {
        names(function, "current_setting")
            && schema.len() <= 1
            && schema.iter().all(|part| names(part, "pg_catalog"))
    }) {
        return None;
    }
    let arguments = listed_arguments(call)?;
    let setting = *arguments.first()?;
    (arguments.len() <= 2).then(|| (setting, arguments.get(1).copied()))
}

/// The name of the setting `expression` reads through `current_setting`
/// without `missing_ok`, raising an error where the setting is unset.
fn erroring_setting(expression: &Expr) -> Option<&Expr> {
    match setting_read(expression)? {
        (setting, None) => Some(setting),
        (setting, Some(Expr::Value(value))) if value.value == Value::Boolean(false) => {
            Some(setting)
        }
        _ => None,
    }
}

/// `expression` with every setting [`erroring_setting`] reads passed
/// `missing_ok` as `true`, when it reads one.
fn missing_ok(expression: &Expr) -> Option<Expr> {
    visit_expressions(expression, |expression| {
        if erroring_setting(expression).is_some() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .is_break()
    .then(|| {
        let mut written = expression.clone();
        let _ = visit_expressions_mut(&mut written, |expression| {
            if erroring_setting(expression).is_some()
                && let Expr::Function(Function {
                    args: FunctionArguments::List(list),
                    ..
                }) = expression
            {
                list.args.truncate(1);
                list.args
                    .push(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(
                        Value::Boolean(true).into(),
                    ))));
            }
            ControlFlow::<()>::Continue(())
        });
        written
    })
}

/// `condition`, tested on a written row, without each conjunct comparing a
/// value the row is written with to that same value, or `None` when no other
/// conjunct remains. `written` holds each value the row is written with, as
/// the condition holds it in parentheses, and whether a write of `NULL`
/// there fails. The comparison holds wherever the write completes once the
/// value cannot be `NULL` there, since such a write fails or the value is a
/// literal other than `NULL` or a setting read erroring where it is unset.
/// Two reads of a setting compare alike once both read it with `missing_ok`.
pub(crate) fn left_to_prove(condition: &Expr, written: &[(&Expr, bool)]) -> Option<Expr> {
    let not_null = |value: &Expr| {
        written.iter().any(|(held, refused)| {
            *held == value
                && (*refused
                    || matches!(unnested(value), Expr::Value(literal) if literal.value != Value::Null)
                    || erroring_setting(unnested(value)).is_some())
        })
    };
    let read_alike = |expression: &Expr| {
        let expression = unnested(expression);
        missing_ok(expression).unwrap_or_else(|| expression.clone())
    };
    let compared_with_itself = |conjunct: &Expr| {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = unnested(conjunct)
        else {
            return false;
        };
        [(left, right), (right, left)]
            .into_iter()
            .any(|(written, other)| match written.as_ref() {
                Expr::Nested(value) => not_null(value) && read_alike(value) == read_alike(other),
                _ => false,
            })
    };
    conjuncts(condition)
        .into_iter()
        .filter(|conjunct| !compared_with_itself(conjunct))
        .cloned()
        .reduce(|left, right| Expr::BinaryOp {
            left: Box::new(left),
            op: BinaryOperator::And,
            right: Box::new(right),
        })
}

/// Whether `condition` is never true while a setting [`erroring_setting`]
/// finds in it is `NULL`, since for each such setting [`rejected`] holds.
fn rejects_unset(condition: &Expr) -> bool {
    visit_expressions(condition, |expression| match erroring_setting(expression) {
        Some(setting) if !rejected(condition, setting) => ControlFlow::Break(()),
        _ => ControlFlow::Continue(()),
    })
    .is_continue()
}

/// Whether a conjunct of `condition` compares the setting `setting` reads
/// with a strict comparison or tests it with `IN`, so that the conjunct is
/// not true while the setting is `NULL`.
fn rejected(condition: &Expr, setting: &Expr) -> bool {
    let reads =
        |operand: &Expr| setting_read(unwrapped(operand)).is_some_and(|(read, _)| read == setting);
    conjuncts(condition)
        .into_iter()
        .any(|conjunct| match unnested(conjunct) {
            Expr::BinaryOp {
                left,
                op:
                    BinaryOperator::Eq
                    | BinaryOperator::NotEq
                    | BinaryOperator::Lt
                    | BinaryOperator::LtEq
                    | BinaryOperator::Gt
                    | BinaryOperator::GtEq,
                right,
            } => reads(left) || reads(right),
            Expr::In {
                expr,
                negated: false,
                ..
            } => reads(expr),
            _ => false,
        })
}

/// Whether `holds` accepts every one of `items`, stopping at the first it
/// refuses or the first error it raises.
fn every<T, E>(items: &[T], mut holds: impl FnMut(&T) -> Result<bool, E>) -> Result<bool, E> {
    for item in items {
        if !holds(item)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `gates` admit every row of `table` that meets each condition
/// `implied` accepts, which holds when every restrictive term of each gate
/// is a tautology or accepted, and one permissive term is or `implied`
/// accepts the `OR` of them all, the rows PostgreSQL admits.
///
/// # Errors
///
/// Returns the lookup error reading a policy or `implied` raised.
pub(crate) fn admits<'g, 'p: 'g, DB: DatabaseLike, C: Columns>(
    database: &DB,
    table: &DB::Table,
    gates: impl IntoIterator<Item = &'g RowGate<'p, DB::Policy>>,
    columns: &C,
    implied: impl Fn(&Condition<'_, C::Tested>) -> Result<bool, LookupError>,
) -> Result<bool, LookupError>
where
    DB::Policy: 'p,
{
    let holds = |condition: &Expr| -> Result<bool, LookupError> {
        Ok(is_tautology(database, table, condition)?
            || implied(&Condition::new(columns, condition))?)
    };
    for gate in gates {
        for term in gate.restrictive() {
            if !holds(term.expression().expression())? {
                return Ok(false);
            }
        }
        let mut admitted = false;
        for term in gate.permissive() {
            if holds(term.expression().expression())? {
                admitted = true;
                break;
            }
        }
        if !admitted
            && let [first, rest @ ..] = gate.permissive()
            && !rest.is_empty()
        {
            let union = rest
                .iter()
                .fold(first.expression().expression().clone(), |left, term| {
                    Expr::BinaryOp {
                        left: Box::new(left),
                        op: BinaryOperator::Or,
                        right: Box::new(term.expression().expression().clone()),
                    }
                });
            admitted = implied(&Condition::new(columns, &union))?;
        }
        if !admitted {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `expression` is a column reference, bare or qualified.
pub(crate) fn is_column(expression: &Expr) -> bool {
    is_column_reference(unwrapped(expression))
}

/// Whether `node` mentions a column, which in a policy can be one of the
/// row's.
fn references_column<V: Visit>(node: &V) -> bool {
    visit_expressions(node, |expression| {
        if is_column(expression) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .is_break()
}

/// Whether `node` mentions a column or reads an input parameter as `$n`,
/// either of which may hold another value where it is read again.
pub(crate) fn reads_column_or_parameter<V: Visit>(node: &V) -> bool {
    visit_expressions(node, |expression| {
        if is_column(expression) || parameter_ordinal(expression).is_some() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .is_break()
}

/// The numbered placeholder `$n` PostgreSQL reads as the input parameter at
/// `ordinal`, counted from zero.
pub(crate) fn parameter(ordinal: usize) -> Expr {
    Expr::Value(Value::Placeholder(format!("${}", ordinal + 1)).into())
}

/// The position, counted from zero, of the input parameter `expression`
/// reads as `$n`.
pub(crate) fn parameter_ordinal(expression: &Expr) -> Option<usize> {
    let Expr::Value(value) = expression else {
        return None;
    };
    let Value::Placeholder(placeholder) = &value.value else {
        return None;
    };
    let digits = placeholder.strip_prefix('$')?;
    digits.parse::<usize>().ok()?.checked_sub(1)
}

/// A stored table a subquery of a condition reads, as [`renamed`] names it.
pub(crate) struct StoredRelation {
    /// The schema-qualified name the table resolves to.
    pub(crate) name: ObjectName,
    /// The stored names of the table's columns.
    pub(crate) columns: Vec<String>,
}

/// `expression` with every column reference of the row it tests named,
/// quoted, by the column `rename` resolves it to, every parameter reference
/// written as `$n`, every call `inline` resolves replaced by the value it
/// returns, every scalar subquery that reads no relation, such as
/// `(SELECT auth.uid())`, replaced by the value it projects, and every
/// comparison with `TRUE` or `FALSE` written as its operand or `NOT` of it,
/// as [`compared_with_boolean`] gives it. A subquery reading stored tables,
/// which `relation` resolves, reads each under its resolved name and the
/// alias `"depth.position"`, names their columns through that alias and the
/// columns of the tested row through `"0"`, so that two spellings of one
/// subquery rename alike and renaming the result again yields it unchanged.
/// `rename` is called on the references resolving to no relation of a
/// subquery. `None` when `rename` resolves a reference to nothing, a
/// reference is ambiguous, or a reference other than a parameter is read
/// inside a subquery that reads anything but stored tables or may name its
/// output where a column is expected.
pub(crate) fn renamed(
    expression: &Expr,
    rename: impl Fn(&Expr) -> Option<Term>,
    relation: impl Fn(&ObjectName) -> Option<StoredRelation>,
    inline: impl Fn(&Function) -> Option<Expr>,
) -> Option<Expr> {
    let mut resolver = Resolver {
        rename,
        relation,
        inline,
        scopes: Vec::new(),
        inlining: None,
        resolved: Vec::new(),
        relations: Vec::new(),
        inlined: Vec::new(),
    };
    if walk(expression, &mut resolver).is_break() {
        return None;
    }
    let mut renamed = expression.clone();
    let ControlFlow::Continue(()) = VisitMut::visit(
        &mut renamed,
        &mut Renamer {
            resolved: resolver.resolved.into_iter(),
            relations: resolver.relations.into_iter(),
            inlined: resolver.inlined.into_iter(),
        },
    );
    Some(renamed)
}

/// A query around a node of a renamed condition.
struct Scope {
    /// The stored tables the query reads, each under the name its references
    /// qualify it by, or `None` when a column read inside does not resolve.
    bound: Option<Vec<Bound>>,
    /// How many of `bound` the walk has met.
    met: usize,
    /// Whether the query is a scalar subquery reading nothing, which renames
    /// to the value it projects.
    inlined: bool,
}

/// A stored table a subquery reads.
struct Bound {
    /// The alias, or the table's own name without its schema, normalized.
    name: String,
    relation: StoredRelation,
    /// The alias the renamed subquery reads the table under.
    alias: Ident,
}

/// The stored tables `query`, nested `depth` queries deep, reads in its
/// `FROM` list, when it reads nothing else, has no `WITH`, names no output
/// column where PostgreSQL also looks for a column, as `ORDER BY`,
/// `GROUP BY` and `DISTINCT ON` do, and reads no table under [`KEPT`].
fn bound(
    query: &Query,
    depth: usize,
    relation: impl Fn(&ObjectName) -> Option<StoredRelation>,
) -> Option<Vec<Bound>> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    if query.with.is_some()
        || query.order_by.is_some()
        || !query.pipe_operators.is_empty()
        || matches!(select.distinct, Some(Distinct::On(_)))
        || !matches!(&select.group_by, GroupByExpr::Expressions(grouped, _) if grouped.is_empty())
        || !select.lateral_views.is_empty()
        || select
            .projection
            .iter()
            .any(|item| matches!(item, SelectItem::QualifiedWildcard(..)))
    {
        return None;
    }
    let mut bound = Vec::new();
    for from in &select.from {
        for factor in iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
        {
            let TableFactor::Table {
                name,
                alias,
                args: None,
                with_hints,
                version: None,
                with_ordinality: false,
                partitions,
                json_path: None,
                sample: None,
                index_directives,
                ..
            } = factor
            else {
                return None;
            };
            if !with_hints.is_empty()
                || !partitions.is_empty()
                || !index_directives.is_empty()
                || alias.as_ref().is_some_and(|alias| {
                    !alias.columns.is_empty()
                        || (alias.name.quote_style == Some('"') && alias.name.value == KEPT)
                })
            {
                return None;
            }
            let named = match alias {
                Some(alias) => &alias.name,
                None => name.0.last()?.as_ident()?,
            };
            bound.push(Bound {
                name: normalize_identifier(&named.value, named.quote_style.is_some()).into_owned(),
                relation: relation(name)?,
                alias: Ident::with_quote('"', format!("{depth}.{}", bound.len())),
            });
        }
    }
    Some(bound)
}

/// Resolves each reference, relation and call of a subquery, in the order
/// [`Renamer`] meets them.
struct Resolver<F, R, I> {
    rename: F,
    relation: R,
    inline: I,
    /// The queries around the walked node, innermost last.
    scopes: Vec<Scope>,
    /// The scalar subquery about to be walked, when it reads nothing and
    /// renames to the value it projects.
    inlining: Option<*const Query>,
    resolved: Vec<Expr>,
    /// The name and alias each table factor renames to, `None` for one left
    /// as written.
    relations: Vec<Option<(ObjectName, Ident)>>,
    /// The value each call returns, `None` for one left as written.
    inlined: Vec<Option<Expr>>,
}

impl<F: Fn(&Expr) -> Option<Term>, R: Fn(&ObjectName) -> Option<StoredRelation>, I>
    Resolver<F, R, I>
{
    /// `reference`, written as `parts`, as the renamed condition writes it,
    /// resolved first against the tables of the innermost query and last
    /// against the tested row.
    fn resolve(&self, reference: &Expr, parts: &[Ident]) -> Option<Expr> {
        if self.scopes.is_empty() {
            return self.outer(reference);
        }
        let normalized = |name: &Ident| {
            normalize_identifier(&name.value, name.quote_style.is_some()).into_owned()
        };
        let (qualifier, column) = match parts {
            [column] => (None, normalized(column)),
            [qualifier, column] => (Some(normalized(qualifier)), normalized(column)),
            _ => return None,
        };
        for scope in self.scopes.iter().rev() {
            let Some(bound) = &scope.bound else {
                return match (self.rename)(reference)? {
                    Term::Parameter(ordinal) => Some(parameter(ordinal)),
                    Term::Column(_) => None,
                };
            };
            let mut found = bound.iter().filter(|bound| match &qualifier {
                Some(qualifier) => bound.name == *qualifier,
                None => bound.relation.columns.contains(&column),
            });
            if let Some(bound) = found.next() {
                return (found.next().is_none() && bound.relation.columns.contains(&column)).then(
                    || {
                        Expr::CompoundIdentifier(vec![
                            bound.alias.clone(),
                            Ident::with_quote('"', column),
                        ])
                    },
                );
            }
        }
        self.outer(reference)
    }

    /// How many queries around the walked node remain once the scalar
    /// subqueries are inlined.
    fn depth(&self) -> usize {
        self.scopes.iter().filter(|scope| !scope.inlined).count()
    }

    /// `reference`, resolving to no relation of a subquery, as `rename`
    /// resolves it, qualified by `"0"` inside a subquery.
    fn outer(&self, reference: &Expr) -> Option<Expr> {
        Some(match (self.rename)(reference)? {
            Term::Column(name) if self.depth() == 0 => {
                Expr::Identifier(Ident::with_quote('"', name))
            }
            Term::Column(name) => Expr::CompoundIdentifier(vec![
                Ident::with_quote('"', "0"),
                Ident::with_quote('"', name),
            ]),
            Term::Parameter(ordinal) => parameter(ordinal),
        })
    }
}

impl<
    F: Fn(&Expr) -> Option<Term>,
    R: Fn(&ObjectName) -> Option<StoredRelation>,
    I: Fn(&Function) -> Option<Expr>,
> Visitor for Resolver<F, R, I>
{
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if let Expr::Subquery(query) = expression
            && unfiltered(query).and_then(sole_item).is_some()
        {
            self.inlining = Some(ptr::from_ref(query.as_ref()));
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        let inlined = self
            .inlining
            .is_some_and(|inlining| ptr::eq(inlining, query));
        let depth = self.depth() + usize::from(!inlined);
        let bound = bound(query, depth, &self.relation);
        self.scopes.push(Scope {
            bound,
            met: 0,
            inlined,
        });
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
        self.scopes.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, _factor: &TableFactor) -> ControlFlow<()> {
        let renamed = self.scopes.last_mut().and_then(|scope| {
            let bound = scope.bound.as_ref()?.get(scope.met)?;
            scope.met += 1;
            Some((bound.relation.name.clone(), bound.alias.clone()))
        });
        self.relations.push(renamed);
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        let parts = match expression {
            Expr::Identifier(column) => slice::from_ref(column),
            Expr::CompoundIdentifier(parts) => parts.as_slice(),
            Expr::Function(call) => {
                self.inlined.push((self.inline)(call));
                return ControlFlow::Continue(());
            }
            _ => return ControlFlow::Continue(()),
        };
        let Some(resolved) = self.resolve(expression, parts) else {
            return ControlFlow::Break(());
        };
        self.resolved.push(resolved);
        ControlFlow::Continue(())
    }
}

/// Writes the resolved references, relations and calls and inlines the
/// scalar subqueries.
struct Renamer<E, T, C> {
    resolved: E,
    relations: T,
    inlined: C,
}

impl<
    E: Iterator<Item = Expr>,
    T: Iterator<Item = Option<(ObjectName, Ident)>>,
    C: Iterator<Item = Option<Expr>>,
> VisitorMut for Renamer<E, T, C>
{
    type Break = Infallible;

    fn pre_visit_table_factor(&mut self, factor: &mut TableFactor) -> ControlFlow<Infallible> {
        if let Some(Some((stored, renamed))) = self.relations.next()
            && let TableFactor::Table { name, alias, .. } = factor
        {
            *name = stored;
            *alias = Some(TableAlias {
                explicit: true,
                name: renamed,
                columns: Vec::new(),
                at: None,
            });
        }
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<Infallible> {
        if let Expr::Subquery(query) = expression
            && unfiltered(query).and_then(sole_item).is_some()
            && let SetExpr::Select(select) = query.body.as_mut()
            && let [SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. }] =
                select.projection.as_mut_slice()
        {
            *expression = mem::replace(value, Expr::Value(Value::Null.into()));
        } else if matches!(expression, Expr::Function(_))
            && let Some(Some(value)) = self.inlined.next()
        {
            *expression = value;
        } else if is_column_reference(expression)
            && let Some(resolved) = self.resolved.next()
        {
            *expression = resolved;
        } else if let Some(compared) = compared_with_boolean(expression) {
            *expression = compared;
        }
        ControlFlow::Continue(())
    }
}

/// The operand `expression` compares with `TRUE` or `FALSE` through `=` or
/// `<>`, or `NOT` of it, whichever agrees with the comparison on every row,
/// `NULL` included.
fn compared_with_boolean(expression: &mut Expr) -> Option<Expr> {
    let Expr::BinaryOp {
        left,
        op: op @ (BinaryOperator::Eq | BinaryOperator::NotEq),
        right,
    } = expression
    else {
        return None;
    };
    let truth = |operand: &Expr| match operand {
        Expr::Value(value) => match value.value {
            Value::Boolean(truth) => Some(truth),
            _ => None,
        },
        _ => None,
    };
    let (operand, truth) = match (truth(left), truth(right)) {
        (_, Some(truth)) => (left, truth),
        (Some(truth), None) => (right, truth),
        (None, None) => return None,
    };
    let kept = (*op == BinaryOperator::Eq) == truth;
    let operand = mem::replace(operand.as_mut(), Expr::Value(Value::Null.into()));
    Some(if kept {
        operand
    } else {
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr: Box::new(operand),
        }
    })
}

/// The `SELECT` of `query` each row of which comes from a row of its `FROM`
/// passing its `WHERE`, with no row when none passes, projecting columns,
/// constants or `*`.
pub(crate) fn witnessed(query: &Query) -> Option<&Select> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let projected = select.projection.iter().all(|item| match item {
        SelectItem::UnnamedExpr(projected)
        | SelectItem::ExprWithAlias {
            expr: projected, ..
        } => matches!(
            projected,
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_)
        ),
        _ => matches!(
            item,
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..)
        ),
    });
    (query.order_by.is_none() && plain(select) && projected).then_some(select)
}

/// The character joining the alias of a renamed reference to its column in
/// [`flattened`], one no PostgreSQL identifier holds.
const SEPARATOR: char = '\0';

/// The alias of a row only the owner of a function finds, which [`bound`]
/// refuses, so that no renamed condition a caller evaluates follows from it.
pub(crate) const KEPT: &str = "0.kept";

/// The most maps of a condition's subquery relations onto a clause's that
/// [`finds_within`] tries.
const MAPS: usize = 256;

/// `renamed`, written by [`renamed`], with each reference one quoted
/// identifier, its alias and column joined by [`SEPARATOR`], a column of
/// the tested row read outside any subquery under the alias `0` as within
/// one, and the operands of each `=` and `<>` between two references in
/// order, so that the conjuncts of two subqueries compare alike and
/// [`clause_implies`] tells their references apart by name.
fn flattened(renamed: &Expr) -> Expr {
    let mut flattened = renamed.clone();
    let _ = visit_expressions_mut(&mut flattened, |expression| {
        match expression {
            Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
                *expression = Expr::Identifier(Ident::with_quote(
                    '"',
                    format!("{}{SEPARATOR}{}", parts[0].value, parts[1].value),
                ));
            }
            Expr::Identifier(column) if !column.value.contains(SEPARATOR) => {
                column.value = format!("0{SEPARATOR}{}", column.value);
            }
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq | BinaryOperator::NotEq,
                right,
            } if matches!(
                (left.as_ref(), right.as_ref()),
                (Expr::Identifier(left), Expr::Identifier(right)) if left.value > right.value
            ) =>
            {
                mem::swap(left, right);
            }
            _ => {}
        }
        ControlFlow::<()>::Continue(())
    });
    flattened
}

/// The rows a non-negated `EXISTS` or `IN` of a [`flattened`] condition
/// looks for, one combination of rows of `relations` meeting `conjuncts`.
struct Sought {
    /// The stored table each relation reads and the alias [`renamed`]
    /// gave it.
    relations: Vec<(ObjectName, String)>,
    conjuncts: Vec<Expr>,
}

/// What `condition`, flattened, looks for, when it holds exactly when a
/// combination of rows of the stored tables its subquery inner-joins meets
/// the `ON` and `WHERE` of the subquery and, for `IN`, yields the tested
/// value. That subquery projects columns or constants, and an `EXISTS`
/// over it may limit it to a positive number of rows, while an `IN` limits
/// nothing. A `NULL` and a false `IN` both reject a row, so the two agree
/// on every row admitted.
fn sought(condition: &Expr) -> Option<Sought> {
    let (query, tested) = match unnested(condition) {
        Expr::Exists {
            subquery,
            negated: false,
        } if keeps_existence(subquery) => (subquery, None),
        Expr::In {
            expr,
            target: InTarget::Subquery(subquery),
            negated: false,
            ..
        } if subquery.limit_clause.is_none() => (subquery, Some(expr)),
        _ => return None,
    };
    let select = witnessed(query).filter(|_| {
        query.with.is_none() && query.fetch.is_none() && query.pipe_operators.is_empty()
    })?;
    let mut relations = Vec::new();
    let mut met: Vec<Expr> = Vec::new();
    for from in &select.from {
        for factor in iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
        {
            let TableFactor::Table {
                name,
                alias: Some(alias),
                args: None,
                ..
            } = factor
            else {
                return None;
            };
            (alias.name.quote_style == Some('"') && is_renamed_alias(&alias.name.value))
                .then_some(())?;
            relations.push((name.clone(), alias.name.value.clone()));
        }
        for join in &from.joins {
            match &join.join_operator {
                JoinOperator::Join(JoinConstraint::On(on))
                | JoinOperator::Inner(JoinConstraint::On(on))
                | JoinOperator::CrossJoin(JoinConstraint::On(on)) => {
                    met.extend(conjuncts(on).into_iter().cloned());
                }
                JoinOperator::Join(JoinConstraint::None)
                | JoinOperator::Inner(JoinConstraint::None)
                | JoinOperator::CrossJoin(JoinConstraint::None) => {}
                _ => return None,
            }
        }
    }
    met.extend(select.selection.iter().flat_map(conjuncts).cloned());
    if let Some(tested) = tested {
        let [
            SelectItem::UnnamedExpr(projected)
            | SelectItem::ExprWithAlias {
                expr: projected, ..
            },
        ] = select.projection.as_slice()
        else {
            return None;
        };
        met.push(flattened(&Expr::BinaryOp {
            left: Box::new(projected.clone()),
            op: BinaryOperator::Eq,
            right: tested.clone(),
        }));
    }
    Some(Sought {
        relations,
        conjuncts: met,
    })
}

/// Whether `alias` is one [`renamed`] gives a stored table it resolved,
/// its depth and position joined by a dot.
fn is_renamed_alias(alias: &str) -> bool {
    alias.split_once('.').is_some_and(|(depth, position)| {
        [depth, position]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// Whether `query` yields a row exactly when it would without its `LIMIT`,
/// as when it has none or one of a positive integer and no offset.
pub(crate) fn keeps_existence(query: &Query) -> bool {
    query.limit_clause.as_ref().is_none_or(|clause| {
        matches!(clause, LimitClause::LimitOffset { limit: Some(limit), offset: None, limit_by }
            if limit_by.is_empty()
                && matches!(unnested(limit), Expr::Value(value)
                    if matches!(&value.value, Value::Number(number, _)
                        if number.parse::<u64>().is_ok_and(|number| number > 0))))
    })
}

/// Whether every value one expression yields is one another yields, as
/// [`Columns::is_set_within`] tells.
type SetWithin<'s> = dyn Fn(&Expr, &Expr) -> Result<bool, LookupError> + 's;

/// Whether the renamed `clause` finds a row only where the renamed
/// `condition` does, both being a non-negated `EXISTS` or `IN` over stored
/// tables. That holds when some map sends each relation of the condition's
/// subquery to one of the clause's on the same stored table, two possibly
/// to one, so that the clause's conjuncts imply each of the condition's
/// read through the map, as conjunctive queries contain each other.
fn finds_within(
    set_within: &SetWithin<'_>,
    clause: &Expr,
    condition: &Expr,
) -> Result<bool, LookupError> {
    let (Some(found), Some(wanted)) = (sought(&flattened(clause)), sought(&flattened(condition)))
    else {
        return Ok(false);
    };
    let candidates: Vec<Vec<&str>> = wanted
        .relations
        .iter()
        .map(|(table, _)| {
            found
                .relations
                .iter()
                .filter(|(other, _)| other == table)
                .map(|(_, alias)| alias.as_str())
                .collect()
        })
        .collect();
    if candidates
        .iter()
        .try_fold(1_usize, |maps, images| maps.checked_mul(images.len()))
        .is_none_or(|maps| maps == 0 || maps > MAPS)
    {
        return Ok(false);
    }
    let flat = Flattened(set_within);
    let mut choice = vec![0; candidates.len()];
    loop {
        let images: Vec<(&str, &str)> = wanted
            .relations
            .iter()
            .zip(&candidates)
            .zip(&choice)
            .map(|(((_, alias), images), &chosen)| (alias.as_str(), images[chosen]))
            .collect();
        if every(&wanted.conjuncts, |conjunct| {
            conjunct_implied(&flat, &found.conjuncts, &relabelled(conjunct, &images))
        })? {
            return Ok(true);
        }
        let Some(position) =
            (0..choice.len()).find(|&position| choice[position] + 1 < candidates[position].len())
        else {
            return Ok(false);
        };
        choice[position] += 1;
        choice[..position].fill(0);
    }
}

/// `conjunct` with each reference through an alias of `images` read
/// through the alias it maps to.
fn relabelled(conjunct: &Expr, images: &[(&str, &str)]) -> Expr {
    let mut relabelled = conjunct.clone();
    let _ = visit_expressions_mut(&mut relabelled, |expression| {
        if let Expr::Identifier(reference) = expression
            && let Some((alias, column)) = reference.value.split_once(SEPARATOR)
            && let Some((_, image)) = images.iter().find(|(from, _)| *from == alias)
        {
            reference.value = format!("{image}{SEPARATOR}{column}");
        }
        ControlFlow::<()>::Continue(())
    });
    relabelled
}

/// Whether the flattened conjuncts `found` imply the flattened `conjunct`,
/// one of them stating it, finding rows only where it does, or implying it
/// together.
fn conjunct_implied(
    flat: &Flattened<'_>,
    found: &[Expr],
    conjunct: &Expr,
) -> Result<bool, LookupError> {
    if found.contains(conjunct) {
        return Ok(true);
    }
    for clause in found {
        if finds_within(flat.0, clause, conjunct)? {
            return Ok(true);
        }
    }
    found
        .iter()
        .cloned()
        .reduce(|left, right| Expr::BinaryOp {
            left: Box::new(left),
            op: BinaryOperator::And,
            right: Box::new(right),
        })
        .map_or(Ok(false), |together| {
            clause_implies(flat, &together, &Condition::new(flat, conjunct), &[])
        })
}

/// The columns of [`flattened`] conditions, each named by its one
/// identifier, testing sets as the [`Columns`] the conditions came from.
struct Flattened<'s>(&'s SetWithin<'s>);

impl Columns for Flattened<'_> {
    type Tested = String;

    fn is_set_within(&self, narrower: &Expr, wider: &Expr) -> Result<bool, LookupError> {
        (self.0)(narrower, wider)
    }

    fn rename(&self, column: Cow<'_, str>) -> Option<String> {
        Some(column.into_owned())
    }

    fn tested(&self, column: &Expr) -> Option<String> {
        stored_name(column).map(Cow::into_owned)
    }

    fn tests(&self, column: &Expr, tested: &String) -> bool {
        stored_name(column).is_some_and(|name| name == *tested)
    }
}

/// Whether `row`, tested against a set by a clause, holds the values each
/// of `operands` asks of a condition's row, a column matching a column the
/// condition tests, a value matching it as written, and a column `context`
/// fixes to a literal matching that literal either way.
fn row_meets<C: Columns>(
    columns: &C,
    row: &[Expr],
    operands: &[Operand<'_, C::Tested>],
    context: &[&Expr],
) -> bool {
    row.iter()
        .zip(operands)
        .all(|(value, operand)| match operand {
            Operand::Tested(tested) => {
                if is_column(value) {
                    columns.tests(value, tested)
                } else {
                    literal(value).is_some_and(|fixed| {
                        pinned(context, |column| columns.tests(column, tested), fixed)
                    })
                }
            }
            Operand::Value(stated) => {
                value == *stated
                    || is_column(value)
                        && columns.tested(value).is_some_and(|tested| {
                            literal(stated).is_some_and(|fixed| {
                                pinned(context, |column| columns.tests(column, &tested), fixed)
                            })
                        })
            }
        })
}

/// Whether a conjunct of `context` fixes a column `tested` accepts to the
/// literal `fixed` with `=`, written on either side.
fn pinned(context: &[&Expr], tested: impl Fn(&Expr) -> bool, fixed: &Value) -> bool {
    context.iter().any(|conjunct| {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = unnested(conjunct)
        else {
            return false;
        };
        [(left, right), (right, left)]
            .into_iter()
            .any(|(column, value)| {
                is_column(column) && tested(column) && literal(value) == Some(fixed)
            })
    })
}

/// Whether every value `narrower` yields is one `wider` yields, whatever
/// value each input parameter it reads holds. A parameter of an enum type
/// takes each label in turn, and a `NULL` one passes only to a call returning
/// `NULL` on `NULL` input, which yields no value. A parameter of any other
/// type proves nothing.
fn is_within<C: Columns>(columns: &C, narrower: &Expr, wider: &Expr) -> Result<bool, LookupError> {
    let mut ordinals = Vec::new();
    let _ = visit_expressions(narrower, |expression| {
        if let Some(ordinal) = parameter_ordinal(expression)
            && !ordinals.contains(&ordinal)
        {
            ordinals.push(ordinal);
        }
        ControlFlow::<()>::Continue(())
    });
    if ordinals.is_empty() {
        return columns.is_set_within(narrower, wider);
    }
    let Some(values) = ordinals
        .iter()
        .map(|&ordinal| columns.parameter_values(ordinal))
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(false);
    };
    if ordinals
        .iter()
        .zip(&values)
        .any(|(&ordinal, values)| values.null && !nothing_on_null(columns, narrower, ordinal))
    {
        return Ok(false);
    }
    let mut choice = vec![0; ordinals.len()];
    loop {
        let mut expanded = narrower.clone();
        let _ = visit_expressions_mut(&mut expanded, |expression| {
            if let Some(ordinal) = parameter_ordinal(expression)
                && let Some(position) = ordinals.iter().position(|&seen| seen == ordinal)
                && let Some(label) = values[position].labels.get(choice[position])
            {
                *expression = label.clone();
            }
            ControlFlow::<()>::Continue(())
        });
        if !columns.is_set_within(&expanded, wider)? {
            return Ok(false);
        }
        let Some(position) = (0..choice.len())
            .find(|&position| choice[position] + 1 < values[position].labels.len())
        else {
            return Ok(true);
        };
        choice[position] += 1;
        choice[..position].fill(0);
    }
}

/// Whether `narrower` yields no value while the input parameter at
/// `ordinal` is `NULL`, as a call does that takes it, through parentheses
/// and casts, as a positional argument it returns `NULL` for.
fn nothing_on_null<C: Columns>(columns: &C, narrower: &Expr, ordinal: usize) -> bool {
    let Expr::Function(
        call @ Function {
            args: FunctionArguments::List(list),
            ..
        },
    ) = unwrapped(narrower)
    else {
        return false;
    };
    list.args.iter().enumerate().any(|(index, argument)| {
        matches!(
            argument,
            FunctionArg::Unnamed(FunctionArgExpr::Expr(argument))
                if parameter_ordinal(unwrapped(argument)) == Some(ordinal)
        ) && columns.returns_null_on_null_argument(call, index)
    })
}

/// The expression yielding the values `value` holds as the operand of `=`,
/// when it reads no column.
fn value_members(value: &Expr) -> Option<Cow<'_, Expr>> {
    match unwrapped(value) {
        Expr::Subquery(query) => query_members(query),
        value => (!references_column(value)).then_some(Cow::Borrowed(value)),
    }
}

/// The expression yielding the rows of `query`, when the query projects it
/// alone, selects every column of one call or one column of one call, and
/// filters and limits nothing.
pub(crate) fn query_members(query: &Query) -> Option<Cow<'_, Expr>> {
    match query.body.as_ref() {
        SetExpr::Select(select) if query.with.is_none() && limits_nothing(query) => {
            select_members(select)
        }
        _ => None,
    }
}

/// The expression yielding the rows of `select`, when it projects it alone,
/// selects every column of one call or one column of one call, and filters
/// nothing.
pub(crate) fn select_members(select: &Select) -> Option<Cow<'_, Expr>> {
    if !filters_nothing(select) {
        return None;
    }
    match sole_item(select) {
        Some(value) => value_members(value),
        None => sole_call(select)
            .or_else(|| sole_column(select))
            .map(Cow::Owned),
    }
}

/// Whether `query` limits none of the rows its body yields.
pub(crate) fn limits_nothing(query: &Query) -> bool {
    query.limit_clause.is_none() && query.fetch.is_none() && query.pipe_operators.is_empty()
}

/// Whether `select` filters and draws on nothing and keeps every distinct
/// row, so it yields every row its `FROM` list does.
pub(crate) fn filters_nothing(select: &Select) -> bool {
    !matches!(select.distinct, Some(Distinct::On(_)))
        && select.top.is_none()
        && select.prewhere.is_none()
        && select.selection.is_none()
        && select.connect_by.is_empty()
        && select.having.is_none()
        && select.qualify.is_none()
}

/// The `SELECT` of `query`, when it declares no `WITH`, limits nothing and
/// filters nothing.
fn unfiltered(query: &Query) -> Option<&Select> {
    match query.body.as_ref() {
        SetExpr::Select(select)
            if query.with.is_none() && limits_nothing(query) && filters_nothing(select) =>
        {
            Some(select)
        }
        _ => None,
    }
}

/// The one expression `select` projects, when it reads nothing, so it
/// yields that value in one row.
fn sole_item(select: &Select) -> Option<&Expr> {
    if let [SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. }] =
        select.projection.as_slice()
        && select.from.is_empty()
    {
        Some(value)
    } else {
        None
    }
}

/// The call `select` selects every column of, written as an expression, when
/// it reads that call alone, without ordinality, so it yields every row of
/// the call.
fn sole_call(select: &Select) -> Option<Expr> {
    let [SelectItem::Wildcard(options)] = select.projection.as_slice() else {
        return None;
    };
    if *options != WildcardAdditionalOptions::default() {
        return None;
    }
    sole_relation_call(select).map(|(call, _)| Expr::Function(call))
}

/// The column of one call `select` projects, written `(call).column`, when
/// it reads that call alone under an alias renaming no column and names the
/// column through the alias, so it yields every value of the column.
fn sole_column(select: &Select) -> Option<Expr> {
    let (call, alias, column) = aliased_column(select)?;
    alias
        .columns
        .is_empty()
        .then(|| column_of(Expr::Function(call), &column))
}

/// The call `select` reads alone under an alias naming one column, when it
/// projects that column through the alias and filters nothing, so it yields
/// every value of the first column of the call.
pub(crate) fn renamed_column_call(select: &Select) -> Option<Function> {
    if !filters_nothing(select) {
        return None;
    }
    let (call, alias, column) = aliased_column(select)?;
    match alias.columns.as_slice() {
        [renamed]
            if normalize_identifier(&renamed.name.value, renamed.name.quote_style.is_some())
                == column =>
        {
            Some(call)
        }
        _ => None,
    }
}

/// The call `select` reads alone, with its alias and the stored name of the
/// column it projects alone through that alias. The call reads no column or
/// parameter, which could stand for another row's value.
fn aliased_column(select: &Select) -> Option<(Function, &TableAlias, String)> {
    let [
        SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts))
        | SelectItem::ExprWithAlias {
            expr: Expr::CompoundIdentifier(parts),
            ..
        },
    ] = select.projection.as_slice()
    else {
        return None;
    };
    let [relation, column] = parts.as_slice() else {
        return None;
    };
    let (call, Some(alias)) = sole_relation_call(select)? else {
        return None;
    };
    if normalize_identifier(&alias.name.value, alias.name.quote_style.is_some())
        != normalize_identifier(&relation.value, relation.quote_style.is_some())
        || reads_column_or_parameter(&call)
    {
        return None;
    }
    Some((
        call,
        alias,
        normalize_identifier(&column.value, column.quote_style.is_some()).into_owned(),
    ))
}

/// The values the column stored as `column` takes among the rows `call`
/// yields, written `(call).column`, the column quoted unless its stored name
/// is folded.
pub(crate) fn column_of(call: Expr, column: &str) -> Expr {
    let field = if normalize_identifier(column, false) == column {
        Ident::new(column)
    } else {
        Ident::with_quote('"', column)
    };
    Expr::CompoundFieldAccess {
        root: Box::new(Expr::Nested(Box::new(call))),
        access_chain: vec![AccessExpr::Dot(Expr::Identifier(field))],
    }
}

/// The call `select` reads alone, without ordinality, with the alias it
/// reads the call under.
fn sole_relation_call(select: &Select) -> Option<(Function, Option<&TableAlias>)> {
    let [from] = select.from.as_slice() else {
        return None;
    };
    if !from.joins.is_empty() {
        return None;
    }
    let (name, args, alias) = match &from.relation {
        TableFactor::Table {
            name,
            args: Some(args),
            with_ordinality: false,
            sample: None,
            alias,
            ..
        } if args.settings.is_none() => (name, &args.args, alias),
        TableFactor::Function {
            name,
            args,
            with_ordinality: false,
            alias,
            ..
        } => (name, args, alias),
        _ => return None,
    };
    let call = Function {
        name: name.clone(),
        uses_odbc_syntax: false,
        parameters: FunctionArguments::None,
        args: FunctionArguments::List(FunctionArgumentList {
            duplicate_treatment: None,
            args: args.clone(),
            clauses: Vec::new(),
        }),
        filter: None,
        null_treatment: None,
        over: None,
        within_group: Vec::new(),
    };
    Some((call, alias.as_ref()))
}

/// The expression yielding the elements of `array` as the operand of
/// `= ANY`, when it reads no column.
fn array_members(array: &Expr) -> Option<Cow<'_, Expr>> {
    let array = unwrapped(array);
    if let Expr::Function(function) = array
        && function.name.to_string().eq_ignore_ascii_case("array")
        && let FunctionArguments::Subquery(query) = &function.args
    {
        return query_members(query);
    }
    (!references_column(array)).then_some(Cow::Borrowed(array))
}

/// The row `condition` tests against a set with `=`, `= ANY` or `IN`, one
/// column or a row value of columns and values reading none, and the
/// expression yielding the members of the set. Column types keep one
/// expression from yielding a value in one spelling and an array in another.
pub(crate) fn membership(condition: &Expr) -> Option<(&[Expr], Cow<'_, Expr>)> {
    match unwrapped(condition) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => [(left, right), (right, left)]
            .into_iter()
            .find_map(|(column, value)| {
                if is_column(column) {
                    Some((slice::from_ref(column.as_ref()), value_members(value)?))
                } else {
                    None
                }
            }),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } if is_column(left) => Some((slice::from_ref(left.as_ref()), array_members(right)?)),
        Expr::In {
            expr,
            target: InTarget::Subquery(query),
            negated: false,
            ..
        } => {
            let row = match unwrapped(expr) {
                Expr::Tuple(values)
                    if values
                        .iter()
                        .all(|value| is_column(value) || !references_column(value)) =>
                {
                    values.as_slice()
                }
                _ if is_column(expr) => slice::from_ref(expr.as_ref()),
                _ => return None,
            };
            Some((row, query_members(query)?))
        }
        _ => None,
    }
}
