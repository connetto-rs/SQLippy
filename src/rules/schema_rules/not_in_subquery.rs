//! Submodule providing the `NotInSubquery` rule.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::Statement;

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::not_in_support::NotInCheck,
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

const CHECK: NotInCheck = NotInCheck {
    describe: |not_in| {
        not_in
            .nullable
            .is_none()
            .then(|| format!("`{}`", not_in.expression))
    },
    problem: "which PostgreSQL never plans as an anti-join, so it runs the subquery as a subplan that is re-scanned per outer row once it outgrows work_mem",
    resolution: "Use NOT EXISTS, which PostgreSQL plans as an anti-join.",
};

/// Struct defining a rule that reports `NOT IN` over a subquery that
/// [`NotInNullableSubquery`](crate::rules::NotInNullableSubquery) leaves
/// alone.
///
/// PostgreSQL never turns `x NOT IN (SELECT c ...)` into an anti-join, even
/// when `c` is `NOT NULL`. Measured on PostgreSQL 17.11 and 18.6 with
/// `work_mem` at 64kB, it took 146 ms for 600 rows where `NOT EXISTS` took
/// 0.25 ms. The rule reads views, materialized views, policies, SQL function
/// bodies and, as a query rule, statements.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NotInSubquery::default().into();
/// let schema = "CREATE TABLE a (id INT); CREATE TABLE b (a_id INT NOT NULL);";
/// let not_in = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&not_in).is_err());
/// let exists = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS SELECT id FROM a WHERE NOT EXISTS (SELECT 1 FROM b WHERE b.a_id = a.id);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&exists).is_ok());
/// ```
pub struct NotInSubquery<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NotInSubquery<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NotInSubquery<DB>> for GenericConstrainer<DB> {
    fn from(rule: NotInSubquery<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(NotInSubquery::default()));
        constrainer
    }
}

impl<DB> Rule for NotInSubquery<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NotInSubquery",
            group: LintGroup::Perf,
            rationale: "PostgreSQL never plans NOT IN over a subquery as an anti-join, so once the subquery outgrows work_mem it is re-scanned for every outer row.",
            source: Some("https://wiki.postgresql.org/wiki/Don%27t_Do_This"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for NotInSubquery<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        CHECK.check_schema(database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for NotInSubquery<DB> {
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
