//! Views, materialized views, policies, check constraints, SQL function
//! bodies and statements, walked for one kind of expression and reported by
//! the rules finding it.

use sql_traits::{
    errors::LookupError,
    traits::{CheckConstraintLike, DatabaseLike, FunctionLike, PolicyLike, TableLike, ViewLike},
};
use sqlparser::{
    ast::{Expr, Statement, Value, Visit},
    dialect::PostgreSqlDialect,
    parser::Parser,
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

    /// Why a finding is a problem, continuing its sentence.
    fn problem(&self) -> &'static str;

    /// The corrected shape.
    fn resolution(&self) -> &'static str;
}

/// Reports the findings of views, materialized views, policies, table check
/// constraints and SQL function bodies.
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
            for (found, _) in finder.find(database, check.expression(database))? {
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
    let functions = database.functions().filter(|function| {
        function.target_name().schema() != Some("pg_catalog")
            && function
                .stored_language()
                .is_none_or(|language| language == "sql")
    });
    for function in functions {
        let body = function
            .body()
            .and_then(|body| Parser::parse_sql(&PostgreSqlDialect {}, body).ok())
            .unwrap_or_default();
        let mut found = finder.find(database, &body)?;
        if let Ok(Some(body)) = function.body_expression(database) {
            found.extend(finder.find(database, body.as_ref())?);
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
