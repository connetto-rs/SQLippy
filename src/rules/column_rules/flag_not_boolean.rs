//! Submodule providing the `FlagNotBoolean` rule.

use sql_traits::{traits::DatabaseLike, utils::scalar_family::ScalarFamily};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::name_support::{NameHint, names_flag},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// A flag-named column stored as a number or text.
pub(super) const HINT: NameHint = NameHint {
    families: &[ScalarFamily::Int, ScalarFamily::String],
    names: names_flag,
    holds: "a yes or no state",
    flaw: "which also stores values that are neither",
    resolution: "Declare it `boolean`, which refuses a third value, or an enum when the column holds more than two states on purpose.",
};

rule_definition!(
    /// Struct defining a rule that reports a column whose name opens with a
    /// yes or no word, such as `is_active`, and whose type is an integer or
    /// text.
    ///
    /// The first word of the name is matched against the deployment's
    /// vocabularies, English unless it selects others, and the type is read
    /// through arrays and domains.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = FlagNotBoolean::default().into();
    /// let number = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (is_active SMALLINT);").unwrap();
    /// assert!(constrainer.validate_schema(&number).is_err());
    /// let flag = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (is_active BOOLEAN);").unwrap();
    /// assert!(constrainer.validate_schema(&flag).is_ok());
    /// ```
    FlagNotBoolean,
    register_column_rule,
    LintGroup::Pedantic,
    "An integer or text column stores any number of values, so a yes or no state kept in one can hold 2, -1 or 'maybe', which a boolean column refuses.",
    Some("https://www.postgresql.org/docs/current/datatype-boolean.html"),
    RuleExample {
        bad: "CREATE TABLE t (is_active SMALLINT);",
        good: "CREATE TABLE t (is_active BOOLEAN);",
    },
    Basis::Names
);

impl<DB: DatabaseLike> ColumnRule for FlagNotBoolean<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        HINT.check(database, column, reporter)
    }
}
