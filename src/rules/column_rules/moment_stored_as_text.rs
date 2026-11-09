//! Submodule providing the `MomentStoredAsText` rule.

use sql_traits::{traits::DatabaseLike, utils::scalar_family::ScalarFamily};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::name_support::{NameHint, names_moment},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// A column named for a moment or a day and stored as text.
pub(super) const HINT: NameHint = NameHint {
    families: &[ScalarFamily::String],
    names: names_moment,
    holds: "a moment or a day",
    flaw: "which accepts impossible dates such as `2026-02-30` and orders `2026-1-9` after `2026-01-10`",
    resolution: "Declare it `timestamptz` for a moment or `date` for a day, which refuse impossible values and order by time.",
};

rule_definition!(
    /// Struct defining a rule that reports a column whose name ends with a
    /// moment word, such as `created_at` or `start_date`, and whose type is
    /// text.
    ///
    /// The last word of the name is matched against the deployment's
    /// vocabularies, English unless it selects others, and the type is read
    /// through arrays and domains. [`PastTimeColumnRule`](crate::rules::PastTimeColumnRule)
    /// leaves the columns this rule reports to it.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = MomentStoredAsText::default().into();
    /// let text = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (start_date TEXT);").unwrap();
    /// assert!(constrainer.validate_schema(&text).is_err());
    /// let date = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (start_date DATE);").unwrap();
    /// assert!(constrainer.validate_schema(&date).is_ok());
    /// ```
    MomentStoredAsText,
    register_column_rule,
    LintGroup::Pedantic,
    "Text compares a date by its characters, so impossible dates are stored, `2026-1-9` sorts after `2026-01-10`, and range filters and time arithmetic need a cast on every read.",
    Some("https://www.postgresql.org/docs/current/datatype-datetime.html")
);

impl<DB: DatabaseLike> ColumnRule for MomentStoredAsText<DB> {
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
