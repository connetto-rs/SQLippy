//! Submodule providing the `NeedlessIndexPredicate` rule.

use sql_traits::{
    structs::{IdentifierCase, Outcomes},
    traits::{DatabaseLike, IndexLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a partial index whose predicate every
/// row of its table satisfies.
///
/// When the column types, `NOT NULL`, the domain checks and the validated
/// `CHECK` constraints of the table make the `WHERE` predicate of an index
/// true on every row, without raising, the predicate leaves out no row. The
/// index then holds what a full index holds, yet the planner uses it only for
/// queries whose own conditions imply the predicate, so a query that does not
/// restate it scans without the index.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NeedlessIndexPredicate::default().into();
/// let needless = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL CHECK (amount > 0));
///      CREATE INDEX paid ON payments (id) WHERE amount > 0;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&needless).is_err());
/// let large = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL CHECK (amount > 0));
///      CREATE INDEX large ON payments (id) WHERE amount > 1000;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&large).is_ok());
/// ```
pub struct NeedlessIndexPredicate<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NeedlessIndexPredicate<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NeedlessIndexPredicate<DB>> for GenericConstrainer<DB> {
    fn from(rule: NeedlessIndexPredicate<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for NeedlessIndexPredicate<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NeedlessIndexPredicate),
            group: LintGroup::Perf,
            rationale: "A partial index whose predicate every row satisfies holds what a full index holds, yet serves only the queries that restate its predicate.",
            source: Some("https://www.postgresql.org/docs/current/indexes-partial.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL CHECK (amount > 0));\nCREATE INDEX paid ON payments (id) WHERE amount > 0;",
                good: "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL CHECK (amount > 0));\nCREATE INDEX paid ON payments (id);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for NeedlessIndexPredicate<DB> {
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
            if truth.outcomes != Outcomes::TRUE || truth.may_raise {
                continue;
            }
            let name = table.table_name();
            let index_name = index.name().unwrap_or("the partial index");
            reporter.index(
                index,
                format!(
                    "Index '{index_name}' on '{name}' holds only the rows where `{predicate}`, which the column types and constraints of '{name}' make true on every row, so the predicate leaves out nothing while the planner uses the index only for queries that restate it."
                ),
                "Recreate the index without its WHERE clause.".to_owned(),
            )?;
        }
        Ok(())
    }
}
