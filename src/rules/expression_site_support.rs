//! Views, materialized views, policies, check constraints, SQL and PL/pgSQL
//! function bodies and statements, walked for one kind of expression and
//! reported by the rules finding it.

use sql_traits::{
    errors::LookupError,
    traits::{CheckConstraintLike, DatabaseLike, FunctionLike, PolicyLike, TableLike, ViewLike},
};
use sqlparser::{
    ast::{Expr, Query, Statement, Value, Visit},
    dialect::PostgreSqlDialect,
    parser::Parser,
};
use sqlparser_plpgsql::{
    embedded::{
        Block, BoundCursor, DeclarationKind, Dynamic, Fetch, FetchCount, FetchDirection,
        FetchPosition, Indirection, LoopControl, Node, Open, ReturnQuery,
    },
    embedded_sql,
};

use crate::{
    error::{Interruption, PolicySite},
    rules::policy_support::walked_clauses,
    traits::{Reporter, reporter::signature},
};

/// Whether `expression`, under casts and parentheses, is the `NULL` literal.
pub(crate) fn is_null_literal(mut expression: &Expr) -> bool {
    loop {
        match expression {
            Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => expression = inner,
            Expr::Value(literal) => return matches!(literal.value, Value::Null),
            _ => return false,
        }
    }
}

/// What one rule finds in expressions, and how it explains a finding.
pub(crate) trait ExpressionFinder {
    /// The findings of `node`, each as its description, which continues a
    /// sentence after "uses", and its expression rendered as SQL.
    ///
    /// # Errors
    ///
    /// Returns the lookup error resolving a name of `node` raised.
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError>;

    /// The findings of `node` in the body of `function`, for a finder whose
    /// answer depends on the settings the function runs under.
    ///
    /// # Errors
    ///
    /// Returns the lookup error resolving a name of `node` raised.
    fn find_in_body<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        _function: &DB::Function,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        self.find(database, node)
    }

    /// The findings of the check constraint `expression`, for a finder that
    /// reads a check differently from the other sites.
    ///
    /// # Errors
    ///
    /// Returns the lookup error resolving a name of `expression` raised.
    fn find_in_check<DB: DatabaseLike>(
        &self,
        database: &DB,
        expression: &Expr,
    ) -> Result<Vec<(String, String)>, LookupError> {
        self.find(database, expression)
    }

    /// Why a finding is a problem, continuing its sentence.
    fn problem(&self) -> &'static str;

    /// The corrected shape.
    fn resolution(&self) -> &'static str;
}

/// Reports the findings of views, materialized views, policies, table check
/// constraints and SQL and PL/pgSQL function bodies.
pub(crate) fn check_schema<DB: DatabaseLike>(
    finder: &impl ExpressionFinder,
    database: &DB,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    let problem = finder.problem();
    let resolution = finder.resolution();
    for view in database.views() {
        for (found, _) in finder.find(database, view.definition())? {
            reporter.view(
                view,
                format!("View '{}' uses {found}, {problem}.", view.view_name()),
                resolution.to_owned(),
            )?;
        }
    }
    for view in database.materialized_views() {
        for (found, _) in finder.find(database, view.definition())? {
            reporter.materialized_view(
                view,
                format!(
                    "Materialized view '{}' uses {found}, {problem}.",
                    view.view_name()
                ),
                resolution.to_owned(),
            )?;
        }
    }
    for table in database.tables() {
        for policy in table.policies(database)? {
            for (clause, expression) in walked_clauses(database, policy)? {
                for (found, _) in expression.map_or(Ok(Vec::new()), |expression| {
                    finder.find(database, expression)
                })? {
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: found.clone(),
                        }],
                        format!(
                            "Policy '{}' on '{}' uses {found} in its {clause} clause, {problem}.",
                            policy.name(),
                            table.table_name()
                        ),
                        resolution.to_owned(),
                    )?;
                }
            }
        }
        for check in table.check_constraints(database)? {
            for (found, _) in finder.find_in_check(database, check.expression(database))? {
                reporter.table(
                    table,
                    format!(
                        "Check `{}` on '{}' uses {found}, {problem}.",
                        check.expression(database),
                        table.table_name()
                    ),
                    resolution.to_owned(),
                )?;
            }
        }
    }
    let functions = database
        .functions()
        .filter(|function| function.target_name().schema() != Some("pg_catalog"));
    for function in functions {
        let mut found = Vec::new();
        for statement in body_statements(function) {
            found.extend(finder.find_in_body(database, function, &statement)?);
        }
        if let Ok(Some(body)) = function.body_expression(database) {
            found.extend(finder.find_in_body(database, function, body.as_ref())?);
        }
        for (found, _) in found {
            reporter.function(
                function,
                format!(
                    "Function '{}' uses {found}, {problem}.",
                    signature(function, database)
                ),
                resolution.to_owned(),
            )?;
        }
    }
    Ok(())
}

/// Reports the findings of a statement.
pub(crate) fn check_statement<DB: DatabaseLike>(
    finder: &impl ExpressionFinder,
    database: &DB,
    statement: &Statement,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    for (found, expression) in finder.find(database, statement)? {
        reporter.statement(
            statement,
            expression,
            format!("The statement uses {found}, {}.", finder.problem()),
            finder.resolution().to_owned(),
        )?;
    }
    Ok(())
}

/// The statements a SQL or PL/pgSQL function body runs, none for a body that
/// does not parse or is written in another language.
pub(crate) fn body_statements<F: FunctionLike>(function: &F) -> Vec<Statement> {
    parsed_body_statements(function).unwrap_or_default()
}

/// The statements a SQL or PL/pgSQL function body runs, or `None` for a body
/// that is absent, does not parse or is written in another language.
pub(crate) fn parsed_body_statements<F: FunctionLike>(function: &F) -> Option<Vec<Statement>> {
    let body = function.body()?;
    match function.stored_language().as_deref() {
        None | Some("sql") => Parser::parse_sql(&PostgreSqlDialect {}, body).ok(),
        Some("plpgsql") => embedded_sql(body).ok().map(|block| {
            let mut statements = Vec::new();
            block_statements(block, &mut statements);
            statements
        }),
        Some(_) => None,
    }
}

/// Appends every statement a PL/pgSQL block runs, its declaration defaults,
/// conditions, loop controls and run-time command strings included.
fn block_statements(block: Block, statements: &mut Vec<Statement>) {
    for declaration in block.declarations {
        if let DeclarationKind::Variable(variable) = declaration.kind {
            statements.extend(variable.default.map(Statement::Query));
        }
    }
    nodes_statements(block.statements, statements);
    for handler in block.handlers {
        nodes_statements(handler.statements, statements);
    }
}

/// Appends the command and `USING` arguments of a dynamic execution.
fn dynamic_statements(dynamic: Dynamic, statements: &mut Vec<Statement>) {
    statements.push(Statement::Query(dynamic.command));
    statements.extend(
        dynamic
            .arguments
            .into_iter()
            .map(|argument| Statement::Query(Box::new(argument))),
    );
}

/// Appends every statement the PL/pgSQL `nodes` run.
fn nodes_statements(nodes: Vec<Node>, statements: &mut Vec<Statement>) {
    for node in nodes {
        match node {
            Node::Statement {
                statement: query, ..
            }
            | Node::Open(Open::Query { query, .. })
            | Node::Perform { query }
            | Node::ReturnQuery(ReturnQuery::Query(query)) => statements.push(*query),
            Node::Dynamic { dynamic, .. }
            | Node::Open(Open::Dynamic { dynamic, .. })
            | Node::ReturnQuery(ReturnQuery::Dynamic(dynamic)) => {
                dynamic_statements(dynamic, statements);
            }
            Node::Assignment(assignment) => {
                for indirection in assignment.target.indirection {
                    match indirection {
                        Indirection::Field(_) => {}
                        Indirection::Index(index) => statements.push(Statement::Query(index)),
                        Indirection::Slice { lower, upper } => {
                            statements.extend(lower.into_iter().chain(upper).map(Statement::Query));
                        }
                    }
                }
                statements.push(Statement::Query(assignment.value));
            }
            Node::Open(Open::Bound(cursor)) => bound_cursor_statements(cursor, statements),
            Node::Fetch(Fetch { direction, .. }) | Node::Move { direction, .. } => {
                statements.extend(direction_query(direction).map(Statement::Query));
            }
            Node::Diagnostics(_)
            | Node::Close { .. }
            | Node::Commit { .. }
            | Node::Rollback { .. } => {}
            Node::Exit(exit) => statements.extend(exit.condition.map(Statement::Query)),
            Node::Return { value } | Node::ReturnNext { value } => {
                statements.extend(value.map(Statement::Query));
            }
            Node::Raise(raise) => statements.extend(
                raise
                    .arguments
                    .into_iter()
                    .chain(raise.options.into_iter().map(|option| option.value))
                    .map(|argument| Statement::Query(Box::new(argument))),
            ),
            Node::Assert(assert) => {
                statements.push(Statement::Query(assert.condition));
                statements.extend(assert.message.map(Statement::Query));
            }
            Node::Block(block) => block_statements(block, statements),
            Node::If(conditional) => {
                for branch in conditional.branches {
                    statements.push(Statement::Query(branch.condition));
                    nodes_statements(branch.statements, statements);
                }
                nodes_statements(conditional.otherwise, statements);
            }
            Node::Case(case) => {
                statements.extend(case.subject.map(Statement::Query));
                for branch in case.branches {
                    statements.push(Statement::Query(branch.condition));
                    nodes_statements(branch.statements, statements);
                }
                nodes_statements(case.otherwise, statements);
            }
            Node::Loop(repeated) => {
                match repeated.control {
                    LoopControl::Unconditional => {}
                    LoopControl::While(query) | LoopControl::Array { array: query, .. } => {
                        statements.push(Statement::Query(query));
                    }
                    LoopControl::Query { query, .. } => statements.push(*query),
                    LoopControl::Range {
                        lower, upper, step, ..
                    } => {
                        statements.extend([Statement::Query(lower), Statement::Query(upper)]);
                        statements.extend(step.map(Statement::Query));
                    }
                    LoopControl::Cursor { cursor, .. } => {
                        bound_cursor_statements(cursor, statements);
                    }
                    LoopControl::Dynamic { dynamic, .. } => dynamic_statements(dynamic, statements),
                }
                nodes_statements(repeated.statements, statements);
            }
        }
    }
}

/// Appends the arguments of a bound cursor and the query it opens.
fn bound_cursor_statements(cursor: BoundCursor, statements: &mut Vec<Statement>) {
    statements.extend(
        cursor
            .arguments
            .into_iter()
            .map(|argument| Statement::Query(Box::new(argument))),
    );
    statements.push(*cursor.query);
}

/// The `SELECT` that evaluates the count, position or offset of a `FETCH` or
/// `MOVE`, when one is written.
fn direction_query(direction: FetchDirection) -> Option<Box<Query>> {
    match direction {
        FetchDirection::Forward(FetchCount::Rows(query))
        | FetchDirection::Backward(FetchCount::Rows(query))
        | FetchDirection::Absolute(FetchPosition::Row(query))
        | FetchDirection::Relative(query) => Some(query),
        FetchDirection::Forward(FetchCount::One | FetchCount::All)
        | FetchDirection::Backward(FetchCount::One | FetchCount::All)
        | FetchDirection::Absolute(FetchPosition::First | FetchPosition::Last) => None,
    }
}
