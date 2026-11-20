//! Submodule providing the `FractionalCount` rule.

use sql_traits::{
    traits::{ColumnLike, DataTypeLike, DatabaseLike},
    utils::scalar_family::ScalarFamily,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        name_support::{NameHint, names_count},
        type_support::underlying_type,
    },
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// A column named for a count of things and stored as a fraction.
const HINT: NameHint = NameHint {
    families: &[ScalarFamily::Float, ScalarFamily::Decimal],
    names: names_count,
    holds: "a count of things",
    flaw: "which stores fractional counts such as `2.5`",
    resolution: "Declare it `integer` or `bigint`. An integer column rounds a fractional input such as `2.5` to `3` rather than refusing it, so the writes that produce fractions need fixing too.",
};

rule_definition!(
    /// Struct defining a rule that reports a column whose name ends with a
    /// count term, such as `item_count` or `quantity`, and whose type is
    /// floating point or `numeric`.
    ///
    /// The name's last words are matched against the deployment's
    /// vocabularies, English unless it selects others, and a name holding an
    /// average word such as `avg_count` is skipped. The type is read through
    /// arrays and domains, and PostgreSQL `numeric` with scale 0 is skipped because it rounds to whole numbers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = FractionalCount::default().into();
    /// let float = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (item_count REAL);").unwrap();
    /// assert!(constrainer.validate_schema(&float).is_err());
    /// let integer = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (item_count INTEGER);").unwrap();
    /// assert!(constrainer.validate_schema(&integer).is_ok());
    /// ```
    FractionalCount,
    register_column_rule,
    LintGroup::Pedantic,
    "A count of things is a whole number, while a floating-point or numeric column can hold fractional counts such as 2.5.",
    Some("https://www.postgresql.org/docs/current/datatype-numeric.html#DATATYPE-INT"),
    RuleExample {
        bad: "CREATE TABLE t (item_count REAL);",
        good: "CREATE TABLE t (item_count INTEGER);",
    },
    Basis::Names
);

impl<DB: DatabaseLike> ColumnRule for FractionalCount<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if Engine::of(database) == Engine::PostgreSql
            && underlying_type(database, column.data_type(database)).numeric_scale(database)
                == Some(0)
        {
            return Ok(());
        }
        let hint = match Engine::of(database) {
            Engine::PostgreSql => HINT,
            Engine::Sqlite => NameHint {
                resolution: "Use `INTEGER` with `CHECK (typeof(col) IN ('integer', 'null'))`, replacing `col` with this column name, since SQLite otherwise stores `2.5` as `REAL` even in an `INTEGER` column.",
                ..HINT
            },
        };
        hint.check(database, column, reporter)
    }
}
