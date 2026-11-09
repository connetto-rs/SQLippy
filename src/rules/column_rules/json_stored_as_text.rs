//! Submodule providing the `JsonStoredAsText` rule.

use sql_traits::{traits::DatabaseLike, utils::scalar_family::ScalarFamily};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::name_support::{NameHint, names_json},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// A column named for a JSON document and stored as text.
const HINT: NameHint = NameHint {
    families: &[ScalarFamily::String],
    names: names_json,
    holds: "a JSON document",
    flaw: "which accepts malformed JSON such as `{\"a\": 1`",
    resolution: "Declare it `jsonb`, which refuses malformed documents and reads keys and paths without a cast.",
};

rule_definition!(
    /// Struct defining a rule that reports a column whose name ends with a
    /// JSON term, such as `payload_json`, and whose type is text.
    ///
    /// The name's last words are matched against the deployment's
    /// vocabularies, English unless it selects others, and the type is read
    /// through arrays and domains. A `json` column is reported by
    /// [`JsonType`](crate::rules::JsonType) instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = JsonStoredAsText::default().into();
    /// let text = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (payload_json TEXT);").unwrap();
    /// assert!(constrainer.validate_schema(&text).is_err());
    /// let jsonb = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (payload_json JSONB);").unwrap();
    /// assert!(constrainer.validate_schema(&jsonb).is_ok());
    /// ```
    JsonStoredAsText,
    register_column_rule,
    LintGroup::Pedantic,
    "Text stores any string, so a malformed document is accepted and every read of a key or path needs a cast to json.",
    Some("https://www.postgresql.org/docs/current/datatype-json.html")
);

impl<DB: DatabaseLike> ColumnRule for JsonStoredAsText<DB> {
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
