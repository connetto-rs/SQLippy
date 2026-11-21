//! Binary replication checks for deployment-selected tables.

use sql_traits::traits::{BinarySend, ColumnLike, DataTypeLike, DatabaseLike, TableLike};

use crate::{
    deployment::Declaration,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::grant_support::is_binary_replicated,
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

rule_definition!(
    /// Reports a selected column whose binary send function reaches a type without one.
    ///
    /// The rule does not run on SQLite, which has no PostgreSQL binary send protocol.
    ///
    /// [`Deployment::with_binary_replication_table`](crate::deployment::Deployment::with_binary_replication_table) or [`Deployment::with_binary_replication_all_tables`](crate::deployment::Deployment::with_binary_replication_all_tables) selects the tables to check, and the rule is inactive until one of them does.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE grants (items aclitem[]);",
    /// ).unwrap();
    /// let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    /// constrainer.set_deployment(
    ///     Deployment::default().with_binary_replication_table("public", "grants"),
    /// );
    /// assert!(constrainer.diagnostics(&database).iter().any(|error| {
    ///     matches!(error, Error::Violation(v) if v.rule().name == "binary_send_failure" && v.level() == Level::Deny)
    /// }));
    /// ```
    BinarySendFailure,
    register_column_rule,
    LintGroup::Restriction,
    "A container's binary send function fails when a nested type has no send function, stopping the replication stream at that record.",
    Some("https://www.postgresql.org/docs/current/protocol-logicalrep-message-formats.html"),
    RuleExample {
        bad: "CREATE TABLE events (id INT PRIMARY KEY, grants ACLITEM[]);",
        good: "CREATE TABLE events (id INT PRIMARY KEY, grants TEXT[]);",
    },
    Basis::Declared,
    &[Engine::PostgreSql],
    &[Declaration::BinaryReplicationTables]
);

impl<DB: DatabaseLike> ColumnRule for BinarySendFailure<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &DB,
        column: &DB::Column,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        if !is_binary_replicated(database, reporter.deployment(), column.table(database))? {
            return Ok(());
        }
        let declared = column.data_type(database);
        if let BinarySend::Fails(failing) = declared.binary_send(database) {
            reporter.column(
                column,
                format!(
                    "Column `{}.{}` of type `{}` fails binary replication because nested type `{}` has no binary send function.",
                    column.table(database).table_name(),
                    column.column_name(),
                    declared.name(database),
                    failing.name(database),
                ),
                "Use sendable nested types or stream this table without `binary on`.".to_owned(),
            )?;
        }
        Ok(())
    }
}

rule_definition!(
    /// Reports a selected column whose binary sendability cannot be determined.
    ///
    /// The rule does not run on SQLite, which has no PostgreSQL binary send protocol.
    ///
    /// [`DefaultConstrainer`](crate::traits::DefaultConstrainer) runs this warning alongside [`BinarySendFailure`], and both are inactive until the deployment selects binary-replicated tables.
    UnknownBinarySend,
    register_column_rule,
    LintGroup::Restriction,
    "An unknown send function leaves the safety of binary replication unverified.",
    Some("https://www.postgresql.org/docs/current/protocol-logicalrep-message-formats.html"),
    RuleExample {
        bad: "CREATE EXTENSION postgis;\nCREATE TABLE events (id INT PRIMARY KEY, area BOX2D);",
        good: "CREATE TABLE events (id INT PRIMARY KEY, area BOX);",
    },
    Basis::Declared,
    &[Engine::PostgreSql],
    &[Declaration::BinaryReplicationTables]
);

impl<DB: DatabaseLike> ColumnRule for UnknownBinarySend<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &DB,
        column: &DB::Column,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        if !is_binary_replicated(database, reporter.deployment(), column.table(database))? {
            return Ok(());
        }
        let declared = column.data_type(database);
        if let BinarySend::Unknown(unknown) = declared.binary_send(database) {
            reporter.column(
                column,
                format!(
                    "Column `{}.{}` of type `{}` has unknown binary send support for type `{}`.",
                    column.table(database).table_name(),
                    column.column_name(),
                    declared.name(database),
                    unknown.name(database),
                ),
                "Check the live PostgreSQL catalog before enabling `binary on` for this table."
                    .to_owned(),
            )?;
        }
        Ok(())
    }
}
