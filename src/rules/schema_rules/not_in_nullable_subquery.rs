//! Submodule providing the `NotInNullableSubquery` rule.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::Statement;

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    rules::not_in_support::NotInCheck,
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

const CHECK: NotInCheck = NotInCheck {
    describe: |not_in| {
        not_in
            .nullable
            .as_ref()
            .map(|column| format!("`{}` over nullable '{column}'", not_in.expression))
    },
    problem: "which returns no row once the subquery yields a NULL",
    resolution: "Use NOT EXISTS, declare the column NOT NULL, or filter it with IS NOT NULL in the subquery.",
};

/// Struct defining a rule that reports `NOT IN` over a subquery whose column
/// is nullable.
///
/// `x NOT IN (SELECT c ...)` is never true once any `c` is `NULL`, so it
/// silently returns no row. The rule reads views, materialized views,
/// policies, SQL function bodies and, as a query rule, statements, and
/// accepts a subquery whose `WHERE` requires the column `IS NOT NULL`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
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
        constrainer.register_query_rule(Box::new(NotInNullableSubquery::default()));
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
            basis: Basis::Declared,
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
        CHECK.check_schema(database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for NotInNullableSubquery<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        CHECK.check_statement(database, statement, reporter)
    }
}
