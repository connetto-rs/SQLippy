//! Submodule providing the `EmptyPartialIndex` rule.

use sql_traits::{
    structs::{IdentifierCase, Outcomes},
    traits::{DatabaseLike, IndexLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a partial index whose predicate no row
/// of its table can satisfy.
///
/// PostgreSQL stores in a partial index only the rows its `WHERE` predicate
/// is true for. When the column types, `NOT NULL`, the domain checks and the
/// validated `CHECK` constraints of the table leave the predicate false or
/// `NULL` on every row, the index stays empty, serves no query and is still
/// maintained on every write. A table whose checks admit no row at all is
/// left to `unsatisfiable_check`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = EmptyPartialIndex::default().into();
/// let empty = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));
///      CREATE INDEX refunds ON payments (id) WHERE amount < 0;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&empty).is_err());
/// let large = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));
///      CREATE INDEX large ON payments (id) WHERE amount > 1000;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&large).is_ok());
/// ```
pub struct EmptyPartialIndex<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for EmptyPartialIndex<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<EmptyPartialIndex<DB>> for GenericConstrainer<DB> {
    fn from(rule: EmptyPartialIndex<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for EmptyPartialIndex<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(EmptyPartialIndex),
            group: LintGroup::Correctness,
            rationale: "A partial index whose predicate no row of its table satisfies stays empty, serves no query, and is still maintained on every write.",
            source: Some("https://www.postgresql.org/docs/current/indexes-partial.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));\nCREATE INDEX refunds ON payments (id) WHERE amount < 0;",
                good: "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));\nCREATE INDEX large ON payments (id) WHERE amount > 1000;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for EmptyPartialIndex<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for index in table.indices(database)? {
            let Some(predicate) = index.predicate() else {
                continue;
            };
            let truth = table.expression_truth(database, predicate, IdentifierCase::AsWritten)?;
            // No outcome without an error means the table's checks admit no
            // row, and an error on every row is a failing write, which no
            // index makes empty.
            if truth.outcomes.truth || truth.outcomes == Outcomes::NONE {
                continue;
            }
            let name = table.table_name();
            let index_name = index.name().unwrap_or("the partial index");
            reporter.index(
                index,
                format!(
                    "Index '{index_name}' on '{name}' holds only the rows where `{predicate}`, which the column types and constraints of '{name}' never let be true, so the index stays empty and serves no query while every write still maintains it."
                ),
                "Drop the index, or rewrite its predicate to select the rows it was meant to hold."
                    .to_owned(),
            )?;
        }
        Ok(())
    }
}
