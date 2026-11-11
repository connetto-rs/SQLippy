//! Submodule providing the `UuidStoredAsText` rule.

use sql_traits::{traits::DatabaseLike, utils::scalar_family::ScalarFamily};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    rules::name_support::{NameHint, names_uuid},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// A uuid-named column stored as text.
const HINT: NameHint = NameHint {
    families: &[ScalarFamily::String],
    names: names_uuid,
    holds: "a uuid",
    flaw: "which keeps two spellings of one uuid apart and accepts text that is no uuid",
    resolution: "Declare it `uuid`, which reads every spelling of a uuid as one value, refuses malformed ones and stores each in 16 bytes.",
};

rule_definition!(
    /// Struct defining a rule that reports a column whose name ends with a
    /// uuid word, such as `owner_uuid`, and whose type is text.
    ///
    /// The last word of the name is matched against the deployment's
    /// vocabularies, English unless it selects others, and the type is read
    /// through arrays and domains.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UuidStoredAsText::default().into();
    /// let text = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (owner_uuid TEXT);").unwrap();
    /// assert!(constrainer.validate_schema(&text).is_err());
    /// let uuid = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (owner_uuid UUID);").unwrap();
    /// assert!(constrainer.validate_schema(&uuid).is_ok());
    /// ```
    UuidStoredAsText,
    register_column_rule,
    LintGroup::Pedantic,
    "Text compares a uuid by its spelling, so upper-case and lower-case forms of one uuid are two values, malformed text is accepted, and each value takes 40 bytes against the 16 of a uuid column.",
    Some("https://www.postgresql.org/docs/current/datatype-uuid.html"),
    Basis::Names
);

impl<DB: DatabaseLike> ColumnRule for UuidStoredAsText<DB> {
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
