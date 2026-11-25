//! Authority tables: tables a policy reads by the caller's credential, whose
//! rows say which scopes the caller holds.

use std::{collections::BTreeSet, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnDefinitionScope, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, FunctionLike, PolicyLike, TableLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArguments, InTarget, JoinConstraint, JoinOperator,
    Query, Select, SelectItem, SetExpr, TableFactor, TableWithJoins, UnaryOperator, Value, Visitor,
};

use crate::rules::walk_support::walk;
use crate::{
    deployment::Deployment,
    error::PolicyClause,
    rules::policy_support::{
        Command, conjuncts, is_column_reference, sql_query_body, walked_clauses,
    },
};

/// A column, as its table's position and its stored name.
pub(crate) type TableColumn = (usize, String);

/// The columns of the authority tables the schema's policies read, each named
/// once however many comparisons read it.
pub(crate) struct AuthorityColumns {
    /// Columns compared with the outer row or returned as the compared set.
    pub(crate) scopes: BTreeSet<TableColumn>,
    /// Columns compared with a credential, by a policy or in an authority
    /// read.
    pub(crate) subjects: BTreeSet<TableColumn>,
    /// Columns an authority read compares with a literal or tests as a
    /// boolean.
    pub(crate) attributes: BTreeSet<TableColumn>,
}

/// Whether the expression is a declared credential, parenthesised, cast or
/// selected alone.
pub(crate) fn is_credential_value(deployment: &Deployment, expression: &Expr) -> bool {
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

/// Whether the expression is a literal, parenthesised or cast. A `$n`
/// parameter is not one.
pub(crate) fn is_literal(expression: &Expr) -> bool {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => is_literal(inner),
        Expr::Value(value) => !matches!(value.value, Value::Placeholder(_)),
        Expr::TypedString(_) => true,
        _ => false,
    }
}

/// The operands a filter compares with a literal or tests as a boolean,
/// through `AND`, `OR` and `NOT`.
fn tested_operands(filter: &Expr) -> Vec<&Expr> {
    match filter {
        Expr::Nested(inner)
        | Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr: inner,
        } => tested_operands(inner),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And | BinaryOperator::Or,
            right,
        } => {
            let mut operands = tested_operands(left);
            operands.extend(tested_operands(right));
            operands
        }
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
        } => [(left, right), (right, left)]
            .into_iter()
            .filter(|(operand, other)| !is_literal(operand) && is_literal(other))
            .map(|(operand, _)| operand.as_ref())
            .collect(),
        Expr::In {
            expr,
            target: InTarget::List(list),
            ..
        } if list.iter().all(is_literal) => vec![expr.as_ref()],
        Expr::AnyOp { left, right, .. }
            if matches!(right.as_ref(), Expr::Array(array)
            if array.elem.iter().all(is_literal)) =>
        {
            vec![left.as_ref()]
        }
        Expr::IsTrue(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsNotFalse(inner) => vec![inner.as_ref()],
        _ => vec![filter],
    }
}

/// The column operands a filter compares with a literal or tests as a
/// boolean, through `AND`, `OR` and `NOT`.
pub(crate) fn tested_columns(filter: &Expr) -> Vec<&Expr> {
    tested_operands(filter)
        .into_iter()
        .filter(|column| is_column_reference(column))
        .collect()
}

/// The `SELECT`s a query body combines.
pub(crate) fn selects(body: &SetExpr) -> Vec<&Select> {
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
pub(crate) fn compared_set(expression: &Expr) -> Option<&Query> {
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

/// How a caller uses what a query or a helper selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// Compared with a column of the caller's row, so the selected columns
    /// are scopes.
    Fed,
    /// Tested as a boolean or compared with a literal, so the selected
    /// columns are attributes.
    Tested,
    /// Used otherwise.
    Plain,
}

/// The sublinks and calls whose result a walked expression compares with a
/// column or tests.
#[derive(Default)]
struct Uses {
    queries: Vec<(*const Query, Reading)>,
    calls: Vec<(*const Expr, Reading)>,
}

impl Uses {
    /// Records that the caller uses `operand`, a sublink or a call, as
    /// `reading` says.
    fn note(&mut self, operand: &Expr, reading: Reading) {
        match operand {
            Expr::Nested(inner) => self.note(inner, reading),
            Expr::Subquery(query) => self.queries.push((std::ptr::from_ref(query), reading)),
            Expr::Function(_) => self.calls.push((std::ptr::from_ref(operand), reading)),
            _ => {}
        }
    }

    /// Records the operands `filter` tests.
    fn tested(&mut self, filter: &Expr) {
        for operand in tested_operands(filter) {
            self.note(operand, Reading::Tested);
        }
    }

    /// Records the operands `expression` compares with a column.
    fn compared(&mut self, expression: &Expr) {
        if let Some(query) = compared_set(expression) {
            self.queries.push((std::ptr::from_ref(query), Reading::Fed));
        }
        if let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = expression
        {
            for (column, other) in [(left, right), (right, left)] {
                if is_column_reference(column) {
                    self.note(other, Reading::Fed);
                }
            }
        }
    }

    /// Records `root`, an expression its caller uses as `reading` says.
    fn root(&mut self, root: &Expr, reading: Reading) {
        match reading {
            Reading::Tested => self.tested(root),
            Reading::Fed => self.note(root, Reading::Fed),
            Reading::Plain => {}
        }
    }

    /// How the caller uses a sublink.
    fn query(&self, query: &Query) -> Reading {
        let pointer = std::ptr::from_ref(query);
        self.queries
            .iter()
            .find(|(used, _)| *used == pointer)
            .map_or(Reading::Plain, |(_, reading)| *reading)
    }

    /// How the caller uses a call, an [`Expr::Function`].
    fn call(&self, call: &Expr) -> Reading {
        let pointer = std::ptr::from_ref(call);
        self.calls
            .iter()
            .find(|(used, _)| *used == pointer)
            .map_or(Reading::Plain, |(_, reading)| *reading)
    }
}

/// Collects the scope columns of the authority tables policies read.
struct Authority<'a, 'db, DB: DatabaseLike> {
    database: &'db DB,
    deployment: &'a Deployment,
    read: Vec<(&'db DB::Function, Reading)>,
    columns: AuthorityColumns,
}

impl<'db, DB: DatabaseLike> Authority<'_, 'db, DB> {
    /// The functions a call may reach, with how the caller uses each: the
    /// rows of a set-returning one feed a compared set, and the value of a
    /// scalar one is used as `uses` records.
    fn reached(
        &self,
        uses: &Uses,
        expression: &Expr,
    ) -> Result<Vec<(&'db DB::Function, Reading)>, LookupError> {
        let Expr::Function(call) = expression else {
            return Ok(Vec::new());
        };
        if matches!(call.args, FunctionArguments::None) {
            return Ok(Vec::new());
        }
        Ok(self
            .database
            .functions_reached_by(call, IdentifierCase::Folded)?
            .map(|helper| {
                let reading = if helper.returns_set() {
                    Reading::Fed
                } else {
                    uses.call(expression)
                };
                (helper, reading)
            })
            .collect())
    }

    /// Reads the bodies of the helpers not read yet for the same use, a
    /// query or a `RETURN` expression.
    fn read_helpers(
        &mut self,
        helpers: Vec<(&'db DB::Function, Reading)>,
    ) -> Result<(), LookupError> {
        for (helper, reading) in helpers {
            if self
                .read
                .iter()
                .any(|(read, as_read)| std::ptr::eq(*read, helper) && *as_read == reading)
            {
                continue;
            }
            self.read.push((helper, reading));
            if let Some(body) = sql_query_body(self.database, helper)? {
                self.query(&body, reading)?;
            } else if let Some(body) = helper.body_expression(self.database)? {
                self.expression(None, &body, reading)?;
            }
        }
        Ok(())
    }

    /// Reads a policy expression on `table`, or a helper's `RETURN`
    /// expression on no table, which its caller uses as `reading` says: its
    /// comparisons with a credential, its sublinks and the helpers it calls.
    fn expression(
        &mut self,
        table: Option<&'db DB::Table>,
        expression: &Expr,
        reading: Reading,
    ) -> Result<(), LookupError> {
        let mut uses = Uses::default();
        uses.root(expression, reading);
        let mut policy = PolicyWalk {
            table: table
                .map(|table| ColumnScope::for_table(table, self.database, IdentifierCase::Folded)),
            authority: self,
            depth: 0,
            uses,
            helpers: Vec::new(),
        };
        walk(expression, &mut policy)
            .break_value()
            .map_or(Ok(()), Err)?;
        let helpers = policy.helpers;
        self.read_helpers(helpers)
    }

    /// Reads every `SELECT` of a query, whose caller uses what it selects as
    /// `reading` says.
    fn query(&mut self, query: &Query, reading: Reading) -> Result<(), LookupError> {
        let root = ColumnScope::from_query(query, self.database, IdentifierCase::Folded)?;
        let mut reads = QueryWalk {
            authority: &*self,
            root: &root,
            top: std::ptr::from_ref(query),
            top_reading: reading,
            uses: Uses::default(),
            found: AuthorityColumns {
                scopes: BTreeSet::new(),
                subjects: BTreeSet::new(),
                attributes: BTreeSet::new(),
            },
            helpers: Vec::new(),
        };
        walk(query, &mut reads).break_value().map_or(Ok(()), Err)?;
        let (found, helpers) = (reads.found, reads.helpers);
        self.columns.scopes.extend(found.scopes);
        self.columns.subjects.extend(found.subjects);
        self.columns.attributes.extend(found.attributes);
        self.read_helpers(helpers)
    }
}

/// Walks a policy expression, or a helper's `RETURN` expression, reading each
/// top-level sublink.
struct PolicyWalk<'w, 'a, 'db, DB: DatabaseLike> {
    authority: &'w mut Authority<'a, 'db, DB>,
    table: Option<ColumnScope<'db, 'db, DB>>,
    depth: usize,
    uses: Uses,
    helpers: Vec<(&'db DB::Function, Reading)>,
}

impl<DB: DatabaseLike> Visitor for PolicyWalk<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        let reading = self.uses.query(query);
        self.authority
            .query(query, reading)
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
        self.uses.compared(expression);
        let compared = self.credential_comparison(expression);
        let reached = self.authority.reached(&self.uses, expression);
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
        let Some(table) = &self.table else {
            return Ok(());
        };
        let compared = credential_compared(
            self.authority.database,
            self.authority.deployment,
            table,
            expression,
        )?;
        self.authority.columns.subjects.extend(compared);
        Ok(())
    }
}

/// The stored columns `scope` resolves that the expression compares with a
/// declared credential by `=`.
pub(crate) fn credential_compared<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    scope: &ColumnScope<'_, '_, DB>,
    expression: &Expr,
) -> Result<Vec<TableColumn>, LookupError> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expression
    else {
        return Ok(Vec::new());
    };
    let mut compared = Vec::new();
    for (column, other) in [(left, right), (right, left)] {
        if is_credential_value(deployment, other)
            && is_column_reference(column)
            && let Some(ColumnDefinition::Base { table, column, .. }) =
                scope.resolve_column_definition(column)?
            && let Some(id) = database.table_id(table)
        {
            compared.push((id, column.stored_column_name().into_owned()));
        }
    }
    Ok(compared)
}

/// Walks one query, recording the scope columns of its authority `SELECT`s
/// and the helpers it calls.
struct QueryWalk<'w, 'a, 'db, 'g, 'q, DB: DatabaseLike> {
    authority: &'w Authority<'a, 'db, DB>,
    root: &'g ColumnScope<'q, 'db, DB>,
    top: *const Query,
    top_reading: Reading,
    uses: Uses,
    found: AuthorityColumns,
    helpers: Vec<(&'db DB::Function, Reading)>,
}

/// The conjuncts of a `SELECT`'s `WHERE` and of the `ON` of its inner joins.
pub(crate) fn filters(select: &Select) -> Vec<&Expr> {
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
    filters
}

/// The expressions a `SELECT` returns.
fn projected(select: &Select) -> impl Iterator<Item = &Expr> {
    select.projection.iter().filter_map(|item| match item {
        SelectItem::UnnamedExpr(item) | SelectItem::ExprWithAlias { expr: item, .. } => Some(item),
        _ => None,
    })
}

/// Whether `factor` is a relation `joined` reads, inside nested joins too.
fn reads_factor(joined: &TableWithJoins, factor: &TableFactor) -> bool {
    std::iter::once(&joined.relation)
        .chain(joined.joins.iter().map(|join| &join.relation))
        .any(|relation| {
            std::ptr::eq(relation, factor)
                || matches!(relation, TableFactor::NestedJoin { table_with_joins, .. }
                    if reads_factor(table_with_joins, factor))
        })
}

/// Whether `reference` binds to a relation of `select`'s own `FROM`, so it
/// reads neither the outer row nor a parameter.
fn reads_own<DB: DatabaseLike>(
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    select: &Select,
    reference: &Expr,
) -> Result<bool, LookupError> {
    Ok(scope
        .resolve_column_binding(reference)?
        .and_then(|(_, binding)| binding.entry())
        .is_some_and(|entry| {
            select
                .from
                .iter()
                .any(|joined| reads_factor(joined, entry.factor()))
        }))
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
            Some(ColumnDefinition::Base { table, column, .. }) => self
                .authority
                .database
                .table_id(table)
                .map(|id| (id, column.stored_column_name().into_owned())),
            _ => None,
        })
    }

    /// Records the operands one `SELECT` tests, and the scope and attribute
    /// columns it reads when it compares a column of an authority table with
    /// a credential, its caller using what it selects as `reading` says.
    fn select(&mut self, select: &Select, reading: Reading) -> Result<(), LookupError> {
        let filters = filters(select);
        for filter in &filters {
            self.uses.tested(filter);
        }
        if reading == Reading::Tested {
            for item in projected(select) {
                self.uses.tested(item);
            }
        }
        let root = self.root;
        root.scope_for_select(select).map_or(Ok(()), |scope| {
            self.scoped_select(&scope, select, &filters, reading)
        })
    }

    /// Records the scope and attribute columns of `select`, resolved through
    /// `scope`.
    fn scoped_select(
        &mut self,
        scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
        select: &Select,
        filters: &[&Expr],
        reading: Reading,
    ) -> Result<(), LookupError> {
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
            if subjects.iter().any(|(subject, _)| *subject == table)
                && is_column_reference(other)
                && !reads_own(scope, select, other)?
            {
                self.found.scopes.insert((table, name));
            }
        }
        let tested: Vec<&Expr> = match reading {
            Reading::Fed => {
                for item in projected(select) {
                    if let Some((table, name)) = self.base(scope, item)?
                        && subjects.iter().any(|(subject, _)| *subject == table)
                    {
                        self.found.scopes.insert((table, name));
                    }
                }
                filters.to_vec()
            }
            Reading::Tested => filters.iter().copied().chain(projected(select)).collect(),
            Reading::Plain => filters.to_vec(),
        };
        for filter in tested {
            for column in tested_columns(filter) {
                if let Some((table, name)) = self.base(scope, column)?
                    && subjects.iter().any(|(subject, _)| *subject == table)
                {
                    self.found.attributes.insert((table, name));
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
        let reading = if std::ptr::from_ref(query) == self.top {
            self.top_reading
        } else {
            self.uses.query(query)
        };
        selects(&query.body)
            .into_iter()
            .try_for_each(|select| self.select(select, reading))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        self.uses.compared(expression);
        self.authority
            .reached(&self.uses, expression)
            .map_or_else(ControlFlow::Break, |helpers| {
                self.helpers.extend(helpers);
                ControlFlow::Continue(())
            })
    }
}

/// The columns of the authority tables the schema's policies read, through
/// their own comparisons, their sublinks and the `LANGUAGE sql` helpers they
/// call.
pub(crate) fn authority_columns<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
) -> Result<AuthorityColumns, LookupError> {
    clause_columns(database, deployment, |_, _| true)
}

/// The columns of the authority tables read by the `USING` clauses of the
/// policies applying to `SELECT`, the clauses that decide which rows a caller
/// sees.
pub(crate) fn read_authority_columns<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
) -> Result<AuthorityColumns, LookupError> {
    clause_columns(database, deployment, |policy: &DB::Policy, clause| {
        clause == PolicyClause::Using && Command::Select.covered_by(policy.command())
    })
}

/// The columns of the authority tables read by the policy clauses `walked`
/// keeps.
fn clause_columns<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    walked: impl Fn(&DB::Policy, PolicyClause) -> bool,
) -> Result<AuthorityColumns, LookupError> {
    let mut authority = Authority {
        database,
        deployment,
        read: Vec::new(),
        columns: AuthorityColumns {
            scopes: BTreeSet::new(),
            subjects: BTreeSet::new(),
            attributes: BTreeSet::new(),
        },
    };
    for table in database.tables() {
        for policy in table.policies(database)? {
            for (clause, expression) in walked_clauses(database, policy)? {
                if let Some(expression) = expression
                    && walked(policy, clause)
                {
                    authority.expression(Some(table), expression, Reading::Tested)?;
                }
            }
        }
    }
    Ok(authority.columns)
}
