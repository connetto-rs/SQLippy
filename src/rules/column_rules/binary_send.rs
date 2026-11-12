//! Binary replication checks for deployment-selected tables.

use sql_traits::traits::{BinarySend, ColumnLike, DataTypeLike, DatabaseLike, TableLike};

use crate::{
    deployment::Deployment,
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::grant_support::schema_of,
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// Returns whether the deployment selects this column's table for binary replication.
fn selected<DB: DatabaseLike>(database: &DB, column: &DB::Column, deployment: &Deployment) -> bool {
    let table = column.table(database);
    deployment.is_binary_replicated(
        &schema_of(database, table.stored_table_schema()),
        &table.stored_table_name(),
    )
}

rule_definition!(
    /// Reports a selected column whose binary send function reaches a type without one.
    ///
    /// [`Deployment::with_binary_replication_table`] or [`Deployment::with_binary_replication_all_tables`] selects the tables to check.
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
    }
);

impl<DB: DatabaseLike> ColumnRule for BinarySendFailure<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &DB,
        column: &DB::Column,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        if !selected(database, column, reporter.deployment()) {
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
    /// [`DefaultConstrainer`](crate::traits::DefaultConstrainer) enables this warning alongside [`BinarySendFailure`] when the deployment selects binary-replicated tables.
    UnknownBinarySend,
    register_column_rule,
    LintGroup::Restriction,
    "An unknown send function leaves the safety of binary replication unverified.",
    Some("https://www.postgresql.org/docs/current/protocol-logicalrep-message-formats.html"),
    RuleExample {
        bad: "CREATE EXTENSION postgis;\nCREATE TABLE events (id INT PRIMARY KEY, area BOX2D);",
        good: "CREATE TABLE events (id INT PRIMARY KEY, area BOX);",
    }
);

impl<DB: DatabaseLike> ColumnRule for UnknownBinarySend<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &DB,
        column: &DB::Column,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        if !selected(database, column, reporter.deployment()) {
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
