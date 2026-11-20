//! Submodule providing the rule reporting an extension created without
//! `VERSION`.

use sql_traits::traits::{DatabaseLike, ExtensionLike};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

rule_definition!(
    /// Struct defining a rule that reports a `CREATE EXTENSION` without
    /// `VERSION`.
    ///
    /// The rule does not run on SQLite, which has no extensions. A live
    /// catalog knows the version each extension holds, so the rule reports
    /// only schemas parsed from SQL.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ExtensionWithoutVersion::default().into();
    /// let unpinned =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE EXTENSION IF NOT EXISTS pgcrypto;").unwrap();
    /// assert!(constrainer.validate_schema(&unpinned).is_err());
    /// let pinned = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE EXTENSION IF NOT EXISTS pgcrypto VERSION '1.3';",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&pinned).is_ok());
    /// ```
    ExtensionWithoutVersion,
    register_schema_rule,
    LintGroup::Pedantic,
    "Without `VERSION`, `CREATE EXTENSION` installs the default version of the server's packages, so the same script builds different functions and types on servers with different packages.",
    Some("https://www.postgresql.org/docs/current/sql-createextension.html"),
    RuleExample {
        bad: "CREATE EXTENSION IF NOT EXISTS pgcrypto;",
        good: "CREATE EXTENSION IF NOT EXISTS pgcrypto VERSION '1.3';",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> SchemaRule for ExtensionWithoutVersion<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for extension in database.extensions() {
            if extension.version().is_some() {
                continue;
            }
            let name = extension.name();
            reporter.extension(
                extension,
                format!("Extension '{name}' is created without `VERSION`, so each server installs the default version of its own packages."),
                format!("Name the version the schema is tested against, as in `CREATE EXTENSION {name} VERSION '<version>'`."),
            )?;
        }
        Ok(())
    }
}
