//! Views, materialized views, policies, table check constraints and SQL and
//! PL/pgSQL function bodies, each walked with the bindings and types
//! PostgreSQL gives its expressions, and reported by the rules that judge an
//! expression by what its operands are.

use sql_traits::{
    errors::LookupError,
    structs::{ExpressionContext, ExpressionScope, IdentifierCase},
    traits::{CheckConstraintLike, DatabaseLike, FunctionLike, PolicyLike, TableLike, ViewLike},
};
use sqlparser::ast::Visit;

use crate::{
    error::{Interruption, PolicySite},
    rules::{expression_site_support::body_statements, policy_support::walked_clauses},
    traits::{Reporter, reporter::signature},
};

/// One finding of a [`TypedFinder`].
pub(crate) struct TypedFinding {
    /// What the site uses, continuing a sentence after "uses".
    pub(crate) found: String,
    /// The corrected shape.
    pub(crate) resolution: String,
}

/// What one rule finds in expressions whose operands it reads through their
/// bindings and types.
pub(crate) trait TypedFinder {
    /// Whether the rule reads table check constraints.
    fn reads_checks(&self) -> bool;

    /// The findings of `node`, whose expressions `context` binds and types.
    /// `clause` holds when `node` is a policy clause, whose top-level
    /// conjuncts filter rows.
    ///
    /// # Errors
    ///
    /// Returns the lookup error resolving a name of `node` raised.
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        context: &ExpressionContext<'_, '_, DB>,
        node: &V,
        clause: bool,
    ) -> Result<Vec<TypedFinding>, LookupError>;

    /// Why a finding is a problem, continuing its sentence.
    fn problem(&self) -> &'static str;
}

/// Reports the findings of views, materialized views, policies, table check
/// constraints when the finder reads them, and SQL and PL/pgSQL function
/// bodies.
pub(crate) fn check_typed_sites<DB: DatabaseLike>(
    finder: &impl TypedFinder,
    database: &DB,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    let problem = finder.problem();
    for view in database.views() {
        let context = ExpressionContext::new(view.definition(), database, IdentifierCase::Folded)?;
        for finding in finder.find(database, &context, view.definition(), false)? {
            reporter.view(
                view,
                format!(
                    "View '{}' uses {}, {problem}.",
                    view.view_name(),
                    finding.found
                ),
                finding.resolution,
            )?;
        }
    }
    for view in database.materialized_views() {
        let context = ExpressionContext::new(view.definition(), database, IdentifierCase::Folded)?;
        for finding in finder.find(database, &context, view.definition(), false)? {
            reporter.materialized_view(
                view,
                format!(
                    "Materialized view '{}' uses {}, {problem}.",
                    view.view_name(),
                    finding.found
                ),
                finding.resolution,
            )?;
        }
    }
    for table in database.tables() {
        let scope = ExpressionScope::Table(table);
        for policy in table.policies(database)? {
            for (clause, expression) in walked_clauses(database, policy)? {
                let Some(expression) = expression else {
                    continue;
                };
                let context = ExpressionContext::for_expression(
                    expression,
                    &scope,
                    database,
                    IdentifierCase::Folded,
                )?;
                for finding in finder.find(database, &context, expression, true)? {
                    let message = format!(
                        "Policy '{}' on '{}' uses {} in its {clause} clause, {problem}.",
                        policy.name(),
                        table.table_name(),
                        finding.found
                    );
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: finding.found,
                        }],
                        message,
                        finding.resolution,
                    )?;
                }
            }
        }
        if !finder.reads_checks() {
            continue;
        }
        for check in table.check_constraints(database)? {
            let expression = check.expression(database);
            let context = ExpressionContext::for_expression(
                expression,
                &scope,
                database,
                IdentifierCase::Folded,
            )?;
            for finding in finder.find(database, &context, expression, false)? {
                reporter.table(
                    table,
                    format!(
                        "Check `{expression}` on '{}' uses {}, {problem}.",
                        table.table_name(),
                        finding.found
                    ),
                    finding.resolution,
                )?;
            }
        }
    }
    check_function_bodies(finder, database, reporter)
}

/// Reports the findings of SQL and PL/pgSQL function bodies.
fn check_function_bodies<DB: DatabaseLike>(
    finder: &impl TypedFinder,
    database: &DB,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    let problem = finder.problem();
    let functions = database.functions().filter(|function| {
        !matches!(
            function.target_name().schema(),
            Some("pg_catalog" | "information_schema")
        )
    });
    for function in functions {
        let scope = ExpressionScope::FunctionBody(function);
        let mut findings = Vec::new();
        for statement in &body_statements(function) {
            let context = ExpressionContext::for_statement(
                statement,
                &scope,
                database,
                IdentifierCase::Folded,
            )?;
            findings.extend(finder.find(database, &context, statement, false)?);
        }
        if let Some(statements) = function.atomic_statements(database)? {
            for statement in statements.iter() {
                let context = ExpressionContext::for_statement(
                    statement,
                    &scope,
                    database,
                    IdentifierCase::Folded,
                )?;
                findings.extend(finder.find(database, &context, statement, false)?);
            }
        }
        if let Some(body) = function.body_expression(database)? {
            let context =
                ExpressionContext::for_expression(&body, &scope, database, IdentifierCase::Folded)?;
            findings.extend(finder.find(database, &context, body.as_ref(), false)?);
        }
        for finding in findings {
            reporter.function(
                function,
                format!(
                    "Function '{}' uses {}, {problem}.",
                    signature(function, database),
                    finding.found
                ),
                finding.resolution,
            )?;
        }
    }
    Ok(())
}
