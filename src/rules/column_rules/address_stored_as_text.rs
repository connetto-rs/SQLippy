//! Submodule providing the `AddressStoredAsText` rule.

use sql_traits::{traits::DatabaseLike, utils::scalar_family::ScalarFamily};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::name_support::{NameHint, names_address},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// A column named for an IP address or network and stored as text.
const HINT: NameHint = NameHint {
    families: &[ScalarFamily::String],
    names: names_address,
    holds: "an IP address or network",
    flaw: "which accepts `999.1.1.1` and orders `10.0.0.10` before `10.0.0.9`",
    resolution: "Declare it `inet` for an address or `cidr` for a network, which refuse impossible values, order numerically and answer containment with `<<`.",
};

rule_definition!(
    /// Struct defining a rule that reports a column whose name ends with an
    /// address term, such as `client_ip` or `server_ip_address`, and whose
    /// type is text.
    ///
    /// The name's last words are matched against the deployment's
    /// vocabularies, English unless it selects others, and the type is read
    /// through arrays and domains.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = AddressStoredAsText::default().into();
    /// let text = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (client_ip TEXT);").unwrap();
    /// assert!(constrainer.validate_schema(&text).is_err());
    /// let inet = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (client_ip INET);").unwrap();
    /// assert!(constrainer.validate_schema(&inet).is_ok());
    /// ```
    AddressStoredAsText,
    register_column_rule,
    LintGroup::Pedantic,
    "Text compares an address by its characters, so `999.1.1.1` is stored, `10.0.0.10` sorts before `10.0.0.9`, and asking whether an address lies in a network needs a cast on every read.",
    Some("https://www.postgresql.org/docs/current/datatype-net-types.html")
);

impl<DB: DatabaseLike> ColumnRule for AddressStoredAsText<DB> {
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
