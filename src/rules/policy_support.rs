//! Facts about row-level security policies shared by the policy rules.

use std::{borrow::Cow, collections::BTreeSet, mem, ops::ControlFlow, ptr};

use sql_traits::{
    errors::LookupError,
    structs::{
        ActingRole, ColumnDefinition, ColumnDefinitionScope, ColumnScope, ExpressionTruth,
        FunctionKind, IdentifierCase, Outcomes, PolicyExpression, Raising, RowGate, WrittenCall,
    },
    traits::{DatabaseLike, FunctionLike, PolicyLike, RoleLike, RoleMembershipLike, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::{
    ast::{
        BinaryOperator, CreatePolicyCommand, Expr, FunctionArguments, FunctionSecurity, ObjectName,
        Owner, Query, Select, Statement, TableFactor, Visit, Visitor,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::rules::{
    cte_support::{WithScopes, stored_table},
    walk_support::walk,
};
use crate::{deployment::Deployment, error::PolicyClause};

/// Statement command whose policies PostgreSQL applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Select,
    Insert,
    Update,
    Delete,
}

impl Command {
    pub(crate) const ALL: [Self; 4] = [Self::Select, Self::Insert, Self::Update, Self::Delete];

    /// Returns whether a policy declared `FOR command` applies to `self`.
    pub(crate) fn covered_by(self, command: CreatePolicyCommand) -> bool {
        matches!(
            (command, self),
            (CreatePolicyCommand::All, _)
                | (CreatePolicyCommand::Select, Self::Select)
                | (CreatePolicyCommand::Insert, Self::Insert)
                | (CreatePolicyCommand::Update, Self::Update)
                | (CreatePolicyCommand::Delete, Self::Delete)
        )
    }
}

/// Stage of a command at which a policy expression is evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Existing rows are filtered.
    Filter,
    /// New rows are checked.
    Check,
}

/// One expression PostgreSQL evaluates for a policy and a command.
pub(crate) struct Applied<'db> {
    pub(crate) stage: Stage,
    pub(crate) clause: PolicyClause,
    pub(crate) expression: &'db Expr,
}

/// Expressions of `policy` PostgreSQL evaluates for `command`, following
/// "Policies Applied by Command Type" in the `CREATE POLICY` documentation.
pub(crate) fn applied<'db, DB: DatabaseLike>(
    database: &'db DB,
    policy: &'db DB::Policy,
    command: Command,
) -> Result<Vec<Applied<'db>>, LookupError> {
    let using = policy.using_expression(database)?;
    let check = policy.check_expression(database)?;
    let filter = using.map(|expression| Applied {
        stage: Stage::Filter,
        clause: PolicyClause::Using,
        expression,
    });
    let new_rows = match check {
        Some(expression) => Some(Applied {
            stage: Stage::Check,
            clause: PolicyClause::WithCheck,
            expression,
        }),
        None => using.map(|expression| Applied {
            stage: Stage::Check,
            clause: PolicyClause::Using,
            expression,
        }),
    };
    match command {
        Command::Select | Command::Delete => Ok(filter.into_iter().collect()),
        Command::Insert => Ok(new_rows.into_iter().collect()),
        Command::Update => Ok(filter.into_iter().chain(new_rows).collect()),
    }
}

/// The `USING` and `WITH CHECK` clauses of `policy`, each for a walk of the
/// relations, subqueries and calls it holds, stored when every literal of it
/// could be read and written when one could not.
pub(crate) fn walked_clauses<'db, DB: DatabaseLike>(
    database: &'db DB,
    policy: &'db DB::Policy,
) -> Result<[(PolicyClause, Option<&'db Expr>); 2], LookupError> {
    Ok([
        (
            PolicyClause::Using,
            policy
                .using_clause(database)?
                .as_ref()
                .map(PolicyExpression::expression),
        ),
        (
            PolicyClause::WithCheck,
            policy
                .check_clause(database)?
                .as_ref()
                .map(PolicyExpression::expression),
        ),
    ])
}

/// Normalized name of a policy role.
pub(crate) fn owner_name(owner: &Owner) -> String {
    match owner {
        Owner::Ident(ident) => {
            normalize_identifier(&ident.value, ident.quote_style.is_some()).into_owned()
        }
        Owner::CurrentRole => "CURRENT_ROLE".to_owned(),
        Owner::CurrentUser => "CURRENT_USER".to_owned(),
        Owner::SessionUser => "SESSION_USER".to_owned(),
    }
}

/// Normalized roles a policy applies to, or `None` for `PUBLIC`.
pub(crate) fn policy_roles<DB: DatabaseLike>(
    database: &DB,
    policy: &DB::Policy,
) -> Option<Vec<String>> {
    (!policy.applies_to_public()).then(|| policy.roles(database).map(owner_name).collect())
}

/// Roles whose privileges `role` holds, itself included, following the
/// memberships granted with the `INHERIT` option.
pub(crate) fn held_roles<DB: DatabaseLike>(database: &DB, role: &DB::Role) -> BTreeSet<String> {
    let mut held = BTreeSet::from([role.stored_name().into_owned()]);
    let mut frontier = vec![role];
    while let Some(member) = frontier.pop() {
        for membership in member.memberships(database) {
            if membership.inherit_option()
                && held.insert(membership.stored_role_name().into_owned())
                && let Some(parent) = membership.role(database)
            {
                frontier.push(parent);
            }
        }
    }
    held
}

/// Roles whose privileges the named role holds, or the name alone when the
/// schema does not declare it.
pub(crate) fn held_by_name<DB: DatabaseLike>(database: &DB, role: &str) -> BTreeSet<String> {
    database.role(role).map_or_else(
        || BTreeSet::from([role.to_owned()]),
        |role| held_roles(database, role),
    )
}

/// The roles each anonymous caller holds: one set per declared anonymous
/// role, with the roles it inherits, and an empty set for a caller holding
/// only `PUBLIC`.
pub(crate) fn anonymous_callers<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
) -> Vec<BTreeSet<String>> {
    deployment
        .anonymous_roles()
        .map(|role| held_by_name(database, role))
        .chain([BTreeSet::new()])
        .collect()
}

/// The client roles of `deployment` the schema declares, its app roles then
/// its anonymous roles, each with the name a message gives it, followed by
/// `PUBLIC` as `None`.
pub(crate) fn client_roles<'db, DB: DatabaseLike>(
    database: &'db DB,
    deployment: &Deployment,
) -> Vec<(String, Option<&'db DB::Role>)> {
    let mut roles: Vec<(String, Option<&DB::Role>)> = deployment
        .app_roles()
        .chain(deployment.anonymous_roles())
        .filter_map(|name| {
            database
                .role(name)
                .map(|role| (format!("'{name}'"), Some(role)))
        })
        .collect();
    roles.push(("PUBLIC".to_owned(), None));
    roles
}

/// The acting role for a declared role, or `PUBLIC` for `None`.
pub(crate) fn acting<R>(role: Option<&R>) -> ActingRole<'_, R> {
    role.map_or(ActingRole::Public, ActingRole::Declared)
}

/// Removes casts and parentheses from an expression.
pub(crate) fn unwrapped(mut expression: &Expr) -> &Expr {
    loop {
        match expression {
            Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => expression = inner,
            _ => return expression,
        }
    }
}

/// Whether `policy` applies to a caller holding the roles `held`.
pub(crate) fn applies_to<DB: DatabaseLike>(
    database: &DB,
    policy: &DB::Policy,
    held: &BTreeSet<String>,
) -> bool {
    policy_roles(database, policy).is_none_or(|roles| roles.iter().any(|role| held.contains(role)))
}

/// Returns whether a policy for `deciding` roles applies to every role of
/// `policy`, either role list being `None` for `PUBLIC`.
pub(crate) fn covers<DB: DatabaseLike>(
    database: &DB,
    deciding: Option<&[String]>,
    policy: Option<&[String]>,
) -> bool {
    match (deciding, policy) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(deciding), Some(policy)) => policy.iter().all(|role| {
            held_by_name(database, role)
                .iter()
                .any(|held| deciding.contains(held))
        }),
    }
}

/// The statement of a body of statements, when it is one.
fn single_statement(mut statements: Vec<Statement>) -> Option<Statement> {
    match (statements.pop(), statements.is_empty()) {
        (Some(statement), true) => Some(statement),
        _ => None,
    }
}

/// Whether `function` sets no configuration parameter besides
/// `search_path`.
pub(crate) fn sets_only_search_path<F: FunctionLike>(function: &F) -> bool {
    function.configuration_parameters().iter().all(|parameter| {
        parameter
            .name
            .to_string()
            .eq_ignore_ascii_case("search_path")
    })
}

/// The statements a `LANGUAGE sql` function runs in order, written as a
/// string or as a `BEGIN ATOMIC` block, when its body parses.
pub(crate) fn sql_statements_body<'f, F: FunctionLike>(
    database: &F::DB,
    function: &'f F,
) -> Result<Option<Cow<'f, [Statement]>>, LookupError> {
    if function
        .stored_language()
        .is_some_and(|language| language != "sql")
    {
        return Ok(None);
    }
    if let Some(body) = function.body() {
        return Ok(Parser::parse_sql(&PostgreSqlDialect {}, body)
            .ok()
            .map(Cow::Owned));
    }
    function.atomic_statements(database)
}

/// The statement a `LANGUAGE sql` function runs, when its body is one
/// statement written as a string or as a `BEGIN ATOMIC` block.
pub(crate) fn sql_statement_body<'f, F: FunctionLike>(
    database: &F::DB,
    function: &'f F,
) -> Result<Option<Cow<'f, Statement>>, LookupError> {
    Ok(match sql_statements_body(database, function)? {
        Some(Cow::Borrowed([statement])) => Some(Cow::Borrowed(statement)),
        Some(Cow::Owned(statements)) => single_statement(statements).map(Cow::Owned),
        _ => None,
    })
}

/// The query a `LANGUAGE sql` function runs, when its body is one query
/// written as a string or as a `BEGIN ATOMIC` block.
pub(crate) fn sql_query_body<'f, F: FunctionLike>(
    database: &F::DB,
    function: &'f F,
) -> Result<Option<Cow<'f, Query>>, LookupError> {
    Ok(match sql_statement_body(database, function)? {
        Some(Cow::Borrowed(Statement::Query(query))) => Some(Cow::Borrowed(query.as_ref())),
        Some(Cow::Owned(Statement::Query(query))) => Some(Cow::Owned(*query)),
        _ => None,
    })
}

/// The query a set-returning `LANGUAGE sql` function runs, when its body is
/// one query.
pub(crate) fn sql_set_body<'f, F: FunctionLike>(
    database: &F::DB,
    function: &'f F,
) -> Result<Option<Cow<'f, Query>>, LookupError> {
    if !function.returns_set() {
        return Ok(None);
    }
    sql_query_body(database, function)
}

/// Whether the expression holds a sublink or a call with arguments.
pub(crate) fn holds_sublink_or_call(expression: &Expr) -> bool {
    struct Found;
    impl Visitor for Found {
        type Break = ();
        fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
            ControlFlow::Break(())
        }
        fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            match expression {
                Expr::Function(call) if !matches!(call.args, FunctionArguments::None) => {
                    ControlFlow::Break(())
                }
                _ => ControlFlow::Continue(()),
            }
        }
    }
    walk(expression, &mut Found).is_break()
}

/// Finds column references to the policy's table, or to one of its columns,
/// outside sublinks or anywhere in a sublink, its `WITH` items and nested
/// sublinks included, that the sublink's own relations do not resolve.
struct RowReferences<'db, DB: DatabaseLike> {
    database: &'db DB,
    table: ColumnScope<'db, 'db, DB>,
    column: Option<&'db DB::Column>,
    depth: usize,
    until_first: bool,
    outside: bool,
    correlated: Vec<String>,
}

impl<DB: DatabaseLike> RowReferences<'_, DB> {
    fn reads_table(&self, expression: &Expr) -> Result<bool, LookupError> {
        Ok(self
            .table
            .resolve_column_definition(expression)?
            .is_some_and(|definition| {
                self.column.is_none_or(|wanted| {
                    matches!(definition, ColumnDefinition::Base { column, .. } if column == wanted)
                })
            }))
    }

    /// Lets `mark` record a row reference, then stops after the first one when
    /// only its existence matters.
    fn record(
        &mut self,
        reads: Result<bool, LookupError>,
        mark: impl FnOnce(&mut Self),
    ) -> ControlFlow<Option<LookupError>> {
        match reads {
            Ok(false) => ControlFlow::Continue(()),
            Ok(true) => {
                mark(self);
                if self.until_first {
                    ControlFlow::Break(None)
                } else {
                    ControlFlow::Continue(())
                }
            }
            Err(error) => ControlFlow::Break(Some(error)),
        }
    }
}

/// References anywhere in one sublink, each resolved in the `SELECT` holding
/// it, so a `WITH` item or a nested sublink reading the checked row counts.
struct SublinkReferences<'outer, 'db, 'query, 'scope, DB: DatabaseLike> {
    outer: &'outer RowReferences<'db, DB>,
    local: &'scope ColumnScope<'query, 'db, DB>,
    /// One entry per query and per `SELECT` the walk stands in, innermost
    /// last, `None` for a query's own clauses or a `SELECT` without a scope.
    scopes: Vec<Option<ColumnDefinitionScope<'scope, 'query, 'db, DB>>>,
}

impl<DB: DatabaseLike> Visitor for SublinkReferences<'_, '_, '_, '_, DB> {
    type Break = Result<(), LookupError>;

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.scopes.push(None);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.scopes.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        self.scopes.push(self.local.scope_for_select(select));
        ControlFlow::Continue(())
    }

    fn post_visit_select(&mut self, _select: &Select) -> ControlFlow<Self::Break> {
        self.scopes.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if !is_column_reference(expression) {
            return ControlFlow::Continue(());
        }
        let local = match self.scopes.as_slice() {
            [.., Some(select)] => select.resolve_column_definition(expression),
            [None] => self.local.resolve_column_definition(expression),
            _ => return ControlFlow::Continue(()),
        };
        decide(local.and_then(|local| match local {
            Some(_) => Ok(false),
            None => self.outer.reads_table(expression),
        }))
    }
}

/// Stops the traversal on a row reference or a lookup failure.
fn decide(reads_row: Result<bool, LookupError>) -> ControlFlow<Result<(), LookupError>> {
    match reads_row {
        Ok(false) => ControlFlow::Continue(()),
        Ok(true) => ControlFlow::Break(Ok(())),
        Err(error) => ControlFlow::Break(Err(error)),
    }
}

impl<DB: DatabaseLike> Visitor for RowReferences<'_, DB> {
    /// A lookup failure, or `None` after the first row reference.
    type Break = Option<LookupError>;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        let reads = match ColumnScope::from_query(query, self.database, IdentifierCase::Folded) {
            Ok(local) => match walk(
                query,
                &mut SublinkReferences {
                    outer: self,
                    local: &local,
                    scopes: Vec::new(),
                },
            ) {
                ControlFlow::Continue(()) => Ok(false),
                ControlFlow::Break(outcome) => outcome.map(|()| true),
            },
            Err(error) => Err(error),
        };
        self.record(reads, |references| {
            references.correlated.push(query.to_string());
        })
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if self.depth != 0 || !is_column_reference(expression) {
            return ControlFlow::Continue(());
        }
        let reads = self.reads_table(expression);
        self.record(reads, |references| references.outside = true)
    }
}

/// Whether a call that reaches the functions `reached` may run an aggregate:
/// one of them is an aggregate, or it reaches no known function.
///
/// # Errors
///
/// Returns the first lookup failure of a function's kind.
pub(crate) fn may_aggregate<'db, DB: DatabaseLike>(
    database: &DB,
    reached: impl IntoIterator<Item = &'db DB::Function>,
) -> Result<bool, LookupError>
where
    DB::Function: 'db,
{
    let mut known = false;
    for function in reached {
        known = true;
        if function.kind(database)? == FunctionKind::Aggregate {
            return Ok(true);
        }
    }
    Ok(!known)
}

/// Strips the parentheses around an expression.
pub(crate) fn unnested(mut expression: &Expr) -> &Expr {
    while let Expr::Nested(inner) = expression {
        expression = inner;
    }
    expression
}

/// The operands of the `AND` chain of an expression.
pub(crate) fn conjuncts(expression: &Expr) -> Vec<&Expr> {
    chain(expression, &BinaryOperator::And)
}

/// The operands of the `OR` chain of an expression.
pub(crate) fn disjuncts(expression: &Expr) -> Vec<&Expr> {
    chain(expression, &BinaryOperator::Or)
}

/// The operands of the `operator` chain of an expression, through
/// parentheses.
fn chain<'e>(expression: &'e Expr, operator: &BinaryOperator) -> Vec<&'e Expr> {
    match expression {
        Expr::Nested(inner) => chain(inner, operator),
        Expr::BinaryOp { left, op, right } if op == operator => {
            let mut operands = chain(left, operator);
            operands.extend(chain(right, operator));
            operands
        }
        _ => vec![expression],
    }
}

pub(crate) fn is_column_reference(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
    )
}

/// Whether the expression reads the current or session role, `user` being
/// PostgreSQL's spelling of `current_user`.
pub(crate) fn is_role_read(expression: &Expr) -> bool {
    is_call_to(
        expression,
        &["current_user", "current_role", "session_user", "user"],
        true,
    )
}

/// Whether the expression calls one of `names`, written without parentheses
/// when `bare`.
fn is_call_to(expression: &Expr, names: &[&str], bare: bool) -> bool {
    let Expr::Function(function) = expression else {
        return false;
    };
    matches!(function.args, FunctionArguments::None) == bare
        && function
            .name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .is_some_and(|ident| {
                names
                    .iter()
                    .any(|name| ident.value.eq_ignore_ascii_case(name))
            })
}

/// Finds a term identifying the caller.
struct CallerTerm<'a>(&'a Deployment);

impl Visitor for CallerTerm<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if self.0.is_credential(expression)
            || is_role_read(expression)
            || is_call_to(expression, &["current_setting"], false)
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Whether the node holds a term identifying the caller: a declared
/// credential, a `current_setting` call or a read of the current role.
pub(crate) fn holds_caller<V: Visit>(deployment: &Deployment, node: &V) -> bool {
    walk(node, &mut CallerTerm(deployment)).is_break()
}

/// Whether a policy operand on `table` is derived from the caller alone,
/// holding a caller term and no reference to the row being checked.
pub(crate) fn derives_from_caller<DB: DatabaseLike, V: Visit>(
    database: &DB,
    table: &DB::Table,
    deployment: &Deployment,
    node: &V,
) -> Result<bool, LookupError> {
    Ok(holds_caller(deployment, node) && !reads_row(database, table, None, node)?)
}

/// Row references of a policy expression on `table`, to `column` alone when
/// given.
fn row_references<'db, DB: DatabaseLike, V: Visit>(
    database: &'db DB,
    table: &'db DB::Table,
    column: Option<&'db DB::Column>,
    node: &V,
    until_first: bool,
) -> Result<RowReferences<'db, DB>, LookupError> {
    let mut references = RowReferences {
        database,
        table: ColumnScope::for_table(table, database, IdentifierCase::Folded),
        column,
        depth: 0,
        until_first,
        outside: false,
        correlated: Vec::new(),
    };
    match walk(node, &mut references) {
        ControlFlow::Break(Some(error)) => Err(error),
        ControlFlow::Continue(()) | ControlFlow::Break(None) => Ok(references),
    }
}

/// Returns whether a policy expression on `table` depends on the row it is
/// evaluated for, or on its `column` alone when given.
pub(crate) fn reads_row<'db, DB: DatabaseLike, V: Visit>(
    database: &'db DB,
    table: &'db DB::Table,
    column: Option<&'db DB::Column>,
    node: &V,
) -> Result<bool, LookupError> {
    let references = row_references(database, table, column, node, true)?;
    Ok(references.outside || !references.correlated.is_empty())
}

/// Returns every sublink of a policy expression on `table` whose top-level
/// query references the row being checked, rendered as SQL.
pub(crate) fn correlated_subqueries<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    expression: &Expr,
) -> Result<Vec<String>, LookupError> {
    Ok(row_references(database, table, None, expression, false)?.correlated)
}

/// Returns whether PostgreSQL can prove the expression true for every row.
pub(crate) fn is_tautology<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    expression: &Expr,
) -> Result<bool, LookupError> {
    Ok(admits_every_row(table.expression_truth(
        database,
        expression,
        IdentifierCase::AsWritten,
    )?))
}

/// Returns whether PostgreSQL can prove the expression never true for any
/// row.
pub(crate) fn is_contradiction<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    expression: &Expr,
) -> Result<bool, LookupError> {
    Ok(admits_no_row(table.expression_truth(
        database,
        expression,
        IdentifierCase::AsWritten,
    )?))
}

/// Whether a policy clause of this truth admits every row, being true
/// without raising.
pub(crate) fn admits_every_row(truth: ExpressionTruth) -> bool {
    truth.outcomes == Outcomes::TRUE && truth.raising == Raising::Never
}

/// Whether a policy clause of this truth admits no row, being never true.
pub(crate) fn admits_no_row(truth: ExpressionTruth) -> bool {
    !truth.outcomes.truth
}

/// Whether `role`, `PUBLIC` for `None`, may select every column of `table`.
pub(crate) fn selects_every_column<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    role: Option<&DB::Role>,
) -> Result<bool, LookupError> {
    let held = table.privileges(acting(role), database)?;
    for column in table.columns(database)? {
        if !held.select.on_column(column) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `caller` may evaluate every term of `gates`, executing every
/// function the terms call and selecting every column of every table they
/// read, and so for every function running as its caller they call in
/// turn. PostgreSQL raises a permission error otherwise, which admits no
/// row. A policy names a relation as the schema's search path resolves it.
pub(crate) fn evaluates_every_term<DB: DatabaseLike>(
    database: &DB,
    caller: Option<&DB::Role>,
    gates: &[RowGate<'_, DB::Policy>],
) -> Result<bool, LookupError> {
    let mut evaluating = Evaluating::new(database, caller, None);
    for term in gates
        .iter()
        .flat_map(|gate| gate.permissive().iter().chain(gate.restrictive()))
    {
        if !evaluating.evaluates(term.expression().expression())? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The walk for whether a role may evaluate a policy term.
struct Evaluating<'p, 'a, DB: DatabaseLike> {
    database: &'a DB,
    /// The role evaluating the term, `None` standing for `PUBLIC`.
    caller: Option<&'a DB::Role>,
    /// The search path the names of the walked term resolve on.
    path: Option<&'p [(Cow<'p, str>, bool)]>,
    /// The `WITH` items of the queries the walk stands in.
    items: WithScopes,
    /// The functions running as the caller whose bodies are walked.
    reading: Vec<*const DB::Function>,
}

impl<'p, 'a, DB: DatabaseLike> Evaluating<'p, 'a, DB> {
    /// The walk over a term whose names resolve on `path`.
    fn new(
        database: &'a DB,
        caller: Option<&'a DB::Role>,
        path: Option<&'p [(Cow<'p, str>, bool)]>,
    ) -> Self {
        Self {
            database,
            caller,
            path,
            items: WithScopes::default(),
            reading: Vec::new(),
        }
    }

    /// Whether the caller may evaluate `node`.
    fn evaluates<N: Visit + ?Sized>(&mut self, node: &N) -> Result<bool, LookupError> {
        match walk(node, self) {
            ControlFlow::Continue(()) => Ok(true),
            ControlFlow::Break(found) => found.map_or(Ok(false), Err),
        }
    }

    /// Whether the caller may execute every function `call` may reach, and
    /// evaluate the `LANGUAGE sql` body of one running as its caller.
    fn executes<'c>(&mut self, call: impl Into<WrittenCall<'c>>) -> Result<bool, LookupError> {
        let database = self.database;
        for function in database.functions_reached_by(call, IdentifierCase::Folded)? {
            let executes = match self.caller {
                Some(role) => function.can_execute(role, database)?,
                None => function.is_executable_by_public(database)?,
            };
            if !executes {
                return Ok(false);
            }
            let address = ptr::from_ref(function);
            if function.security_mode() == FunctionSecurity::Definer
                || self.reading.contains(&address)
            {
                continue;
            }
            let Some(query) = sql_query_body(database, function)? else {
                continue;
            };
            let path = function.search_path(database)?;
            let mut within = Evaluating::new(database, self.caller, path.as_deref());
            within.reading = mem::take(&mut self.reading);
            within.reading.push(address);
            let evaluates = within.evaluates(query.as_ref());
            self.reading = within.reading;
            if !evaluates? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether the caller may select every column of the stored table
    /// `name` names, when no `WITH` item of the walked queries does.
    fn selects(&self, name: &ObjectName) -> Result<bool, LookupError> {
        if self.items.binding(name).is_some() {
            return Ok(true);
        }
        match stored_table(self.database, name, self.path)? {
            Some(table) => selects_every_column(self.database, table, self.caller),
            None => Ok(true),
        }
    }

    /// The walk's step for whether the caller may evaluate a call or read.
    fn verdict(outcome: Result<bool, LookupError>) -> ControlFlow<Option<LookupError>> {
        match outcome {
            Ok(true) => ControlFlow::Continue(()),
            Ok(false) => ControlFlow::Break(None),
            Err(error) => ControlFlow::Break(Some(error)),
        }
    }
}

impl<DB: DatabaseLike> Visitor for Evaluating<'_, '_, DB> {
    type Break = Option<LookupError>;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.items.enter(query);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.items.leave(query);
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        match expression {
            Expr::Function(call) => Self::verdict(self.executes(call)),
            _ => ControlFlow::Continue(()),
        }
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table {
            name, args: None, ..
        } = factor
        {
            return Self::verdict(self.selects(name));
        }
        WrittenCall::relation(factor).map_or(ControlFlow::Continue(()), |call| {
            Self::verdict(self.executes(call))
        })
    }
}
