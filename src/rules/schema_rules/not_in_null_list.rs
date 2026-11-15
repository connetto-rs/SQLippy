//! Submodule providing the `NotInNullList` rule.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::Statement;

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::{check_schema, check_statement},
        not_in_support::{NotInCheck, NotInOperand},
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

const CHECK: NotInCheck = NotInCheck {
    describe: |not_in| {
        matches!(not_in.operand, NotInOperand::NullList).then(|| format!("`{}`", not_in.expression))
    },
    problem: "which is never true once the list holds a NULL, so a filter keeps no row and a check rejects none",
    resolution: "Drop the NULL from the list, and test for NULL apart with IS NULL where it is meant.",
};

/// Struct defining a rule that reports `NOT IN` over a list, or `<> ALL`
/// over an array literal, holding a `NULL`.
///
/// `x NOT IN (1, NULL)` is `NULL` for every `x` other than `1` and false for
/// `1`, so it is never true. The `NULL` may stand under casts or
/// parentheses. The rule reads views, materialized views, policies, table
/// check constraints, SQL function bodies and, as a query rule, statements.
/// `NOT IN` over a subquery is left to
/// [`NotInNullableSubquery`](crate::rules::NotInNullableSubquery).
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NotInNullList::default().into();
/// let null = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (id INT, x INT); CREATE VIEW v AS SELECT id FROM t WHERE x NOT IN (1, NULL);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&null).is_err());
/// let values = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (id INT, x INT); CREATE VIEW v AS SELECT id FROM t WHERE x NOT IN (1, 2);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&values).is_ok());
/// ```
pub struct NotInNullList<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NotInNullList<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NotInNullList<DB>> for GenericConstrainer<DB> {
    fn from(rule: NotInNullList<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(NotInNullList::default()));
        constrainer
    }
}

impl<DB> Rule for NotInNullList<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NotInNullList),
            group: LintGroup::Correctness,
            rationale: "NOT IN over a list holding a NULL is never true, so a filter written with it keeps no row and a check written with it rejects none.",
            source: Some("https://www.postgresql.org/docs/current/functions-comparisons.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE t (id INT, x INT);\n\
SELECT id FROM t WHERE x NOT IN (1, NULL);",
                good: "CREATE TABLE t (id INT, x INT);\n\
SELECT id FROM t WHERE x NOT IN (1, 2);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for NotInNullList<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&CHECK, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for NotInNullList<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&CHECK, database, statement, reporter)
    }
}
