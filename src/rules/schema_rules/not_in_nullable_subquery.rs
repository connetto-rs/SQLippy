//! Submodule providing the `NotInNullableSubquery` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, FunctionLike, PolicyLike, TableLike, ViewLike},
};
use sqlparser::{
    ast::{Expr, InTarget, Query, SelectItem, SetExpr, Visit, Visitor},
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::policy_support::conjuncts,
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

/// The nullable column a `NOT IN` subquery returns, unless its `WHERE`
/// excludes `NULL`.
fn nullable_output<DB: DatabaseLike>(
    database: &DB,
    query: &Query,
) -> Result<Option<String>, LookupError> {
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

/// Collects the `NOT IN` subqueries over a nullable column.
struct NotIns<'db, DB: DatabaseLike> {
    database: &'db DB,
    found: Vec<String>,
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
        nullable_output(self.database, query).map_or_else(ControlFlow::Break, |column| {
            self.found
                .extend(column.map(|column| format!("`{expression}` over nullable '{column}'")));
            ControlFlow::Continue(())
        })
    }
}

/// The `NOT IN` subqueries over a nullable column a node holds.
fn not_ins<DB: DatabaseLike, V: Visit + ?Sized>(
    database: &DB,
    node: &V,
) -> Result<Vec<String>, LookupError> {
    let mut found = NotIns {
        database,
        found: Vec::new(),
    };
    node.visit(&mut found).break_value().map_or(Ok(()), Err)?;
    Ok(found.found)
}

const PROBLEM: &str = "which returns no row once the subquery yields a NULL";

const RESOLUTION: &str =
    "Use NOT EXISTS, declare the column NOT NULL, or filter it with IS NOT NULL in the subquery.";

/// Struct defining a rule that reports `NOT IN` over a subquery whose column
/// is nullable.
///
/// `x NOT IN (SELECT c ...)` is never true once any `c` is `NULL`, so it
/// silently returns no row. The rule reads views, materialized views,
/// policies and SQL function bodies, and accepts a subquery whose `WHERE`
/// requires the column `IS NOT NULL`.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NotInNullableSubquery::default().into();
/// let schema = "CREATE TABLE a (id INT); CREATE TABLE b (a_id INT);";
/// let nullable = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&nullable).is_err());
/// let exists = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS SELECT id FROM a WHERE NOT EXISTS (SELECT 1 FROM b WHERE b.a_id = a.id);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&exists).is_ok());
/// ```
pub struct NotInNullableSubquery<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NotInNullableSubquery<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NotInNullableSubquery<DB>> for GenericConstrainer<DB> {
    fn from(rule: NotInNullableSubquery<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for NotInNullableSubquery<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NotInNullableSubquery",
            group: LintGroup::Suspicious,
            rationale: "NOT IN is never true once the subquery yields a NULL, so a nullable column makes it silently return no row.",
            source: Some("https://wiki.postgresql.org/wiki/Don%27t_Do_This"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for NotInNullableSubquery<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for view in database.views() {
            for found in not_ins(database, view.definition())? {
                reporter.view(
                    view,
                    format!("View '{}' uses {found}, {PROBLEM}.", view.view_name()),
                    RESOLUTION.to_owned(),
                )?;
            }
        }
        for view in database.materialized_views() {
            for found in not_ins(database, view.definition())? {
                reporter.materialized_view(
                    view,
                    format!(
                        "Materialized view '{}' uses {found}, {PROBLEM}.",
                        view.view_name()
                    ),
                    RESOLUTION.to_owned(),
                )?;
            }
        }
        for table in database.tables() {
            for policy in table.policies(database)? {
                for (clause, expression) in [
                    (PolicyClause::Using, policy.using_expression(database)),
                    (PolicyClause::WithCheck, policy.check_expression(database)),
                ] {
                    for found in expression
                        .map_or(Ok(Vec::new()), |expression| not_ins(database, expression))?
                    {
                        reporter.policies(
                            vec![PolicySite {
                                table: Box::new(table.clone()),
                                policy: Box::new(policy.clone()),
                                clause,
                                expression: found.clone(),
                            }],
                            format!(
                                "Policy '{}' on '{}' uses {found} in its {clause} clause, {PROBLEM}.",
                                policy.name(),
                                table.table_name()
                            ),
                            RESOLUTION.to_owned(),
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
            let mut found = not_ins(database, &body)?;
            if let Ok(Some(body)) = function.body_expression(database) {
                found.extend(not_ins(database, body.as_ref())?);
            }
            for found in found {
                reporter.function(
                    function,
                    format!(
                        "Function '{}' uses {found}, {PROBLEM}.",
                        signature(function, database)
                    ),
                    RESOLUTION.to_owned(),
                )?;
            }
        }
        Ok(())
    }
}
