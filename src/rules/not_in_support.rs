//! `NOT IN` over a subquery, found in views, policies, SQL function bodies
//! and statements, shared by the rules reporting it.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, FunctionLike, PolicyLike, TableLike, ViewLike},
};
use sqlparser::{
    ast::{Expr, InTarget, Query, SelectItem, SetExpr, Statement, Visit, Visitor},
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::rules::walk_support::walk;
use crate::{
    error::{Interruption, PolicySite},
    rules::policy_support::{conjuncts, walked_clauses},
    traits::{Reporter, reporter::signature},
};

/// One `NOT IN` over a subquery.
pub(crate) struct NotIn {
    /// The `NOT IN` expression rendered as SQL.
    pub(crate) expression: String,
    /// The nullable column the subquery returns, as `table.column`.
    pub(crate) nullable: Option<String>,
}

/// The nullable column a `NOT IN` subquery returns, unless its `WHERE`
/// excludes `NULL`.
fn nullable_output<DB: DatabaseLike>(
    database: &DB,
    query: &Query,
) -> Result<Option<String>, LookupError> {
    // Expression evaluator: the output counts as possibly `NULL` only when it
    // is a nullable column that no `WHERE` conjunct tests with `IS NOT NULL`.
    // The evaluator decides whether any output expression can be `NULL`, so
    // computed outputs such as `a_id + 1` and filters such as `a_id > 0` are
    // judged too.
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Ok(None);
    };
    let [SelectItem::UnnamedExpr(output) | SelectItem::ExprWithAlias { expr: output, .. }] =
        select.projection.as_slice()
    else {
        return Ok(None);
    };
    let scope = ColumnScope::from_query(query, database, IdentifierCase::Folded)?;
    let Some(ColumnDefinition::Base { table, column, .. }) =
        scope.resolve_column_definition(output)?
    else {
        return Ok(None);
    };
    let excluded = select.selection.iter().flat_map(conjuncts).any(|filter| {
        matches!(filter, Expr::IsNotNull(tested) if tested.to_string() == output.to_string())
    });
    Ok((!excluded && column.is_nullable(database)?)
        .then(|| format!("{}.{}", table.table_name(), column.column_name())))
}

/// Collects the `NOT IN` subqueries of a node.
struct NotIns<'db, DB: DatabaseLike> {
    database: &'db DB,
    found: Vec<NotIn>,
}

impl<DB: DatabaseLike> Visitor for NotIns<'_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        let Expr::In {
            target: InTarget::Subquery(query),
            negated: true,
            ..
        } = expression
        else {
            return ControlFlow::Continue(());
        };
        nullable_output(self.database, query).map_or_else(ControlFlow::Break, |nullable| {
            self.found.push(NotIn {
                expression: expression.to_string(),
                nullable,
            });
            ControlFlow::Continue(())
        })
    }
}

/// The `NOT IN` subqueries a node holds.
fn not_ins<DB: DatabaseLike, V: Visit + ?Sized>(
    database: &DB,
    node: &V,
) -> Result<Vec<NotIn>, LookupError> {
    let mut found = NotIns {
        database,
        found: Vec::new(),
    };
    walk(node, &mut found).break_value().map_or(Ok(()), Err)?;
    Ok(found.found)
}

/// How one rule describes the `NOT IN` subqueries it reports.
pub(crate) struct NotInCheck {
    /// Describes a `NOT IN` the rule reports, or skips it.
    pub(crate) describe: fn(&NotIn) -> Option<String>,
    /// Why the described `NOT IN` is a problem, continuing its sentence.
    pub(crate) problem: &'static str,
    /// The corrected shape.
    pub(crate) resolution: &'static str,
}

impl NotInCheck {
    /// Descriptions of the reported `NOT IN` subqueries a node holds, with
    /// their expressions.
    fn found<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        Ok(not_ins(database, node)?
            .into_iter()
            .filter_map(|not_in| {
                (self.describe)(&not_in).map(|described| (described, not_in.expression))
            })
            .collect())
    }

    /// Reports the `NOT IN` subqueries of views, materialized views,
    /// policies and SQL function bodies.
    pub(crate) fn check_schema<DB: DatabaseLike>(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        let Self {
            problem,
            resolution,
            ..
        } = self;
        for view in database.views() {
            for (found, _) in self.found(database, view.definition())? {
                reporter.view(
                    view,
                    format!("View '{}' uses {found}, {problem}.", view.view_name()),
                    (*resolution).to_owned(),
                )?;
            }
        }
        for view in database.materialized_views() {
            for (found, _) in self.found(database, view.definition())? {
                reporter.materialized_view(
                    view,
                    format!(
                        "Materialized view '{}' uses {found}, {problem}.",
                        view.view_name()
                    ),
                    (*resolution).to_owned(),
                )?;
            }
        }
        for table in database.tables() {
            for policy in table.policies(database)? {
                for (clause, expression) in walked_clauses(database, policy)? {
                    for (found, _) in expression.map_or(Ok(Vec::new()), |expression| {
                        self.found(database, expression)
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
                            (*resolution).to_owned(),
                        )?;
                    }
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
            let mut found = self.found(database, &body)?;
            if let Ok(Some(body)) = function.body_expression(database) {
                found.extend(self.found(database, body.as_ref())?);
            }
            for (found, _) in found {
                reporter.function(
                    function,
                    format!(
                        "Function '{}' uses {found}, {problem}.",
                        signature(function, database)
                    ),
                    (*resolution).to_owned(),
                )?;
            }
        }
        Ok(())
    }

    /// Reports the `NOT IN` subqueries of a statement.
    pub(crate) fn check_statement<DB: DatabaseLike>(
        &self,
        database: &DB,
        statement: &Statement,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        for (found, expression) in self.found(database, statement)? {
            reporter.statement(
                statement,
                expression,
                format!("The statement uses {found}, {}.", self.problem),
                self.resolution.to_owned(),
            )?;
        }
        Ok(())
    }
}
