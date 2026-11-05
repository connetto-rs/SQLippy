//! Authority tables: tables a policy reads by the caller's credential, whose
//! rows say which scopes the caller holds.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnDefinitionScope, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, PolicyLike, TableLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArguments, InTarget, JoinConstraint, JoinOperator,
    Query, Select, SelectItem, SetExpr, Visit, Visitor,
};

use crate::{
    deployment::Deployment,
    rules::policy_support::{conjuncts, is_column_reference, sql_set_body},
};

/// A column, as its table's position and its stored name.
pub(crate) type TableColumn = (usize, String);

/// The columns of the authority tables the schema's policies read.
pub(crate) struct AuthorityColumns {
    /// Columns compared with the outer row or returned as the compared set.
    pub(crate) scopes: Vec<TableColumn>,
    /// Columns compared with a credential, by a policy or in an authority
    /// read.
    pub(crate) subjects: Vec<TableColumn>,
}

/// Whether the expression is a declared credential, parenthesised, cast or
/// selected alone.
fn is_credential_value(deployment: &Deployment, expression: &Expr) -> bool {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => {
            is_credential_value(deployment, inner)
        }
        Expr::Subquery(query) => matches!(query.body.as_ref(), SetExpr::Select(select)
            if select.from.is_empty()
                && matches!(select.projection.as_slice(), [SelectItem::UnnamedExpr(item)]
                    if is_credential_value(deployment, item))),
        _ => deployment.is_credential(expression),
    }
}

/// The `SELECT`s a query body combines.
fn selects(body: &SetExpr) -> Vec<&Select> {
    match body {
        SetExpr::Select(select) => vec![select],
        SetExpr::Query(query) => selects(&query.body),
        SetExpr::SetOperation { left, right, .. } => {
            let mut found = selects(left);
            found.extend(selects(right));
            found
        }
        _ => Vec::new(),
    }
}

/// The subquery an `ARRAY(...)` call wraps.
fn array_subquery(expression: &Expr) -> Option<&Query> {
    match expression {
        Expr::Function(Function {
            name,
            args: FunctionArguments::Subquery(query),
            ..
        }) if name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .is_some_and(|ident| ident.value.eq_ignore_ascii_case("array")) =>
        {
            Some(query)
        }
        _ => None,
    }
}

/// The subquery whose rows an expression compares with an operand, written
/// `x IN (SELECT ...)` or `x = ANY (ARRAY(SELECT ...))`.
fn compared_set(expression: &Expr) -> Option<&Query> {
    match expression {
        Expr::In {
            target: InTarget::Subquery(query),
            negated: false,
            ..
        } => Some(query),
        Expr::AnyOp {
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => array_subquery(right),
        _ => None,
    }
}

/// Collects the scope columns of the authority tables policies read.
struct Authority<'a, 'db, DB: DatabaseLike> {
    database: &'db DB,
    deployment: &'a Deployment,
    read: Vec<&'db DB::Function>,
    columns: AuthorityColumns,
}

impl<'db, DB: DatabaseLike> Authority<'_, 'db, DB> {
    /// The functions a call may reach.
    fn reached(&self, call: &Function) -> Result<Vec<&'db DB::Function>, LookupError> {
        if matches!(call.args, FunctionArguments::None) {
            return Ok(Vec::new());
        }
        Ok(self
            .database
            .functions_reached_by(call, IdentifierCase::Folded)?
            .collect())
    }

    /// Reads the bodies of the helpers not read yet.
    fn read_helpers(&mut self, helpers: Vec<&'db DB::Function>) -> Result<(), LookupError> {
        for helper in helpers {
            if self.read.iter().any(|read| std::ptr::eq(*read, helper)) {
                continue;
            }
            self.read.push(helper);
            if let Some(body) = sql_set_body(helper) {
                self.query(&body, true)?;
            }
        }
        Ok(())
    }

    /// Reads a policy expression on `table`: its comparisons with a
    /// credential, its sublinks and the helpers it calls.
    fn expression(&mut self, table: &'db DB::Table, expression: &Expr) -> Result<(), LookupError> {
        let mut walk = PolicyWalk {
            table: ColumnScope::for_table(table, self.database, IdentifierCase::Folded),
            authority: self,
            depth: 0,
            fed: Vec::new(),
            helpers: Vec::new(),
        };
        expression
            .visit(&mut walk)
            .break_value()
            .map_or(Ok(()), Err)?;
        let helpers = walk.helpers;
        self.read_helpers(helpers)
    }

    /// Reads every `SELECT` of a query, whose rows feed a compared set when
    /// `fed`.
    fn query(&mut self, query: &Query, fed: bool) -> Result<(), LookupError> {
        let root = ColumnScope::from_query(query, self.database, IdentifierCase::Folded)?;
        let mut walk = QueryWalk {
            authority: &*self,
            root: &root,
            top: std::ptr::from_ref(query),
            top_fed: fed,
            fed: Vec::new(),
            found: AuthorityColumns {
                scopes: Vec::new(),
                subjects: Vec::new(),
            },
            helpers: Vec::new(),
        };
        query.visit(&mut walk).break_value().map_or(Ok(()), Err)?;
        let (found, helpers) = (walk.found, walk.helpers);
        self.columns.scopes.extend(found.scopes);
        self.columns.subjects.extend(found.subjects);
        self.read_helpers(helpers)
    }
}

/// Walks a policy expression, reading each top-level sublink.
struct PolicyWalk<'w, 'a, 'db, DB: DatabaseLike> {
    authority: &'w mut Authority<'a, 'db, DB>,
    table: ColumnScope<'db, 'db, DB>,
    depth: usize,
    fed: Vec<*const Query>,
    helpers: Vec<&'db DB::Function>,
}

impl<DB: DatabaseLike> Visitor for PolicyWalk<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        let fed = self.fed.contains(&std::ptr::from_ref(query));
        self.authority
            .query(query, fed)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if self.depth > 0 {
            return ControlFlow::Continue(());
        }
        self.fed
            .extend(compared_set(expression).map(std::ptr::from_ref));
        let compared = self.credential_comparison(expression);
        let reached = match expression {
            Expr::Function(call) => self.authority.reached(call),
            _ => Ok(Vec::new()),
        };
        compared
            .and(reached)
            .map_or_else(ControlFlow::Break, |helpers| {
                self.helpers.extend(helpers);
                ControlFlow::Continue(())
            })
    }
}

impl<DB: DatabaseLike> PolicyWalk<'_, '_, '_, DB> {
    /// Records a column of the policy's table the expression compares with a
    /// credential.
    fn credential_comparison(&mut self, expression: &Expr) -> Result<(), LookupError> {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = expression
        else {
            return Ok(());
        };
        for (column, other) in [(left, right), (right, left)] {
            if is_credential_value(self.authority.deployment, other)
                && is_column_reference(column)
                && let Some(ColumnDefinition::Base { table, column }) =
                    self.table.resolve_column_definition(column)?
                && let Some(id) = self.authority.database.table_id(table)
            {
                self.authority
                    .columns
                    .subjects
                    .push((id, column.stored_column_name().into_owned()));
            }
        }
        Ok(())
    }
}

/// Walks one query, recording the scope columns of its authority `SELECT`s
/// and the helpers it calls.
struct QueryWalk<'w, 'a, 'db, 'g, 'q, DB: DatabaseLike> {
    authority: &'w Authority<'a, 'db, DB>,
    root: &'g ColumnScope<'q, 'db, DB>,
    top: *const Query,
    top_fed: bool,
    fed: Vec<*const Query>,
    found: AuthorityColumns,
    helpers: Vec<&'db DB::Function>,
}

impl<DB: DatabaseLike> QueryWalk<'_, '_, '_, '_, '_, DB> {
    /// The table position and column a reference resolves to, when it is a
    /// stored column.
    fn base(
        &self,
        scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
        expression: &Expr,
    ) -> Result<Option<(usize, String)>, LookupError> {
        if !is_column_reference(expression) {
            return Ok(None);
        }
        Ok(match scope.resolve_column_definition(expression)? {
            Some(ColumnDefinition::Base { table, column }) => self
                .authority
                .database
                .table_id(table)
                .map(|id| (id, column.stored_column_name().into_owned())),
            _ => None,
        })
    }

    /// Records the scope columns of one `SELECT` that compares a column of
    /// an authority table with a credential.
    fn select(&mut self, select: &Select, fed: bool) -> Result<(), LookupError> {
        let root = self.root;
        root.scope_for_select(select)
            .map_or(Ok(()), |scope| self.scoped_select(&scope, select, fed))
    }

    /// Records the scope columns of `select`, resolved through `scope`.
    fn scoped_select(
        &mut self,
        scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
        select: &Select,
        fed: bool,
    ) -> Result<(), LookupError> {
        let mut filters: Vec<&Expr> = select.selection.iter().flat_map(conjuncts).collect();
        for from in &select.from {
            for join in &from.joins {
                if let JoinOperator::Join(JoinConstraint::On(condition))
                | JoinOperator::Inner(JoinConstraint::On(condition)) = &join.join_operator
                {
                    filters.extend(conjuncts(condition));
                }
            }
        }
        let mut subjects: Vec<TableColumn> = Vec::new();
        let mut pairs = Vec::new();
        for filter in filters {
            if let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = filter
            {
                pairs.push((left.as_ref(), right.as_ref()));
                pairs.push((right.as_ref(), left.as_ref()));
            }
        }
        for (column, other) in &pairs {
            if is_credential_value(self.authority.deployment, other)
                && let Some(subject) = self.base(scope, column)?
            {
                subjects.push(subject);
            }
        }
        for (column, other) in pairs {
            let Some((table, name)) = self.base(scope, column)? else {
                continue;
            };
            let outer = is_column_reference(other)
                && self
                    .base(scope, other)?
                    .is_none_or(|(owner, _)| owner != table);
            if subjects.iter().any(|(subject, _)| *subject == table) && outer {
                self.found.scopes.push((table, name));
            }
        }
        if fed {
            for item in &select.projection {
                if let SelectItem::UnnamedExpr(item) | SelectItem::ExprWithAlias { expr: item, .. } =
                    item
                    && let Some((table, name)) = self.base(scope, item)?
                    && subjects.iter().any(|(subject, _)| *subject == table)
                {
                    self.found.scopes.push((table, name));
                }
            }
        }
        self.found.subjects.extend(subjects);
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for QueryWalk<'_, '_, '_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        let pointer = std::ptr::from_ref(query);
        let fed = (pointer == self.top && self.top_fed) || self.fed.contains(&pointer);
        selects(&query.body)
            .into_iter()
            .try_for_each(|select| self.select(select, fed))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        self.fed
            .extend(compared_set(expression).map(std::ptr::from_ref));
        let Expr::Function(call) = expression else {
            return ControlFlow::Continue(());
        };
        self.authority
            .reached(call)
            .map_or_else(ControlFlow::Break, |helpers| {
                self.helpers.extend(helpers);
                ControlFlow::Continue(())
            })
    }
}

/// The columns of the authority tables the schema's policies read, through
/// their own comparisons, their sublinks and the set-returning
/// `LANGUAGE sql` helpers they call.
pub(crate) fn authority_columns<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
) -> Result<AuthorityColumns, LookupError> {
    let mut authority = Authority {
        database,
        deployment,
        read: Vec::new(),
        columns: AuthorityColumns {
            scopes: Vec::new(),
            subjects: Vec::new(),
        },
    };
    for table in database.tables() {
        for policy in table.policies(database)? {
            for expression in [
                policy.using_expression(database),
                policy.check_expression(database),
            ]
            .into_iter()
            .flatten()
            {
                authority.expression(table, expression)?;
            }
        }
    }
    Ok(authority.columns)
}
