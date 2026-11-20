//! Submodule providing the `BooleanStateWithoutTime` rule.

use sql_traits::{
    traits::{ColumnLike, DataTypeLike, DatabaseLike, TableLike},
    utils::scalar_family::ScalarFamily,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        name_support::{lifecycle_event, names_moment},
        type_support::underlying_type,
    },
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

rule_definition!(
    /// Struct defining a rule that reports a `boolean` column named for a
    /// one-way event that happens to a row, such as `revoked`, `archived` or
    /// `is_deleted`.
    ///
    /// The name, alone or after a flag prefix such as `is`, is matched
    /// against the lifecycle terms of the deployment's vocabularies, English
    /// unless it selects others, and the type is read through arrays and
    /// domains. Present-state names such as `active` or `enabled` name a
    /// toggle with no event and are not reported. A table that also holds a
    /// moment column named for the same event, such as `revoked_at`, already
    /// keeps the time and is not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = BooleanStateWithoutTime::default().into();
    /// let flag = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE tokens (id INT PRIMARY KEY, revoked BOOLEAN NOT NULL DEFAULT false);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&flag).is_err());
    /// let moment = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE tokens (id INT PRIMARY KEY, revoked_at TIMESTAMPTZ);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&moment).is_ok());
    /// ```
    BooleanStateWithoutTime,
    register_column_rule,
    LintGroup::Pedantic,
    "A boolean records that a one-way event happened and loses when, which retention by age, audits and investigations need.",
    Some("https://www.postgresql.org/docs/current/datatype-datetime.html"),
    RuleExample {
        bad: "CREATE TABLE tokens (id INT PRIMARY KEY, revoked BOOLEAN NOT NULL DEFAULT false);",
        good: "CREATE TABLE tokens (id INT PRIMARY KEY, revoked_at TIMESTAMPTZ);",
    },
    Basis::Names
);

impl<DB: DatabaseLike> ColumnRule for BooleanStateWithoutTime<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let vocabularies = reporter.deployment().vocabularies();
        let Some(event) = lifecycle_event(vocabularies, column.column_name()) else {
            return Ok(());
        };
        if underlying_type(database, column.data_type(database)).scalar_family(database)
            != Some(ScalarFamily::Bool)
        {
            return Ok(());
        }
        let table = column.table(database);
        for other in table.columns(database)? {
            let name = other.column_name();
            if name.len() > event.len()
                && name.as_bytes()[event.len()] == b'_'
                && name[..event.len()].eq_ignore_ascii_case(event)
                && names_moment(vocabularies, name)
            {
                return Ok(());
            }
        }
        reporter.column(
            column,
            format!(
                "Column '{}.{}' records whether the row was {event} as a boolean, so when it happened is lost.",
                table.table_name(),
                column.column_name()
            ),
            match Engine::of(database) {
                Engine::PostgreSql => format!(
                    "Store the moment instead, as a nullable `timestamptz` such as `{event}_at` that stays NULL until the event happens."
                ),
                Engine::Sqlite => format!(
                    "Store the moment as canonical UTC `TEXT` such as `{event}_at`, leaving it NULL until the event happens and validating its date and time spelling on write."
                ),
            },
        )?;
        Ok(())
    }
}
