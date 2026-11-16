//! Submodule providing the `SuperkeyPrimaryKey` rule.

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::key_support::equality_keys,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

rule_definition!(
    /// Struct defining a rule that reports a primary key strictly containing
    /// another unique key of the same table.
    ///
    /// The contained key already tells the rows apart, and its columns are
    /// non-`NULL` because the primary key holds them, so the wider primary key
    /// adds no identity and invites wider references. A unique key with a
    /// predicate or over expressions is not compared.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = SuperkeyPrimaryKey::default().into();
    /// let superkey = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE entries (id INT UNIQUE, kind TEXT, PRIMARY KEY (id, kind));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&superkey).is_err());
    /// let key = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE entries (id INT PRIMARY KEY, kind TEXT NOT NULL);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&key).is_ok());
    /// ```
    SuperkeyPrimaryKey,
    register_table_rule,
    LintGroup::Pedantic,
    "A primary key containing another unique key of its table adds no row identity, and every reference to it must carry the extra columns.",
    Some(
        "https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-PRIMARY-KEYS"
    ),
    RuleExample {
        bad: "CREATE TABLE entries (id integer UNIQUE NOT NULL, kind text NOT NULL, PRIMARY KEY (id, kind));",
        good: "CREATE TABLE entries (id integer PRIMARY KEY, kind text NOT NULL);",
    }
);

impl<DB: DatabaseLike> TableRule for SuperkeyPrimaryKey<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let primary_key: Vec<&DB::Column> = table.primary_key_columns(database)?.collect();
        let mut contained: Vec<Vec<&DB::Column>> = Vec::new();
        for key in equality_keys(database, table)? {
            if key.len() < primary_key.len()
                && key.iter().all(|column| primary_key.contains(column))
                && !contained.iter().any(|found| {
                    found.len() == key.len() && key.iter().all(|column| found.contains(column))
                })
            {
                contained.push(key);
            }
        }
        if contained.is_empty() {
            return Ok(());
        }
        let list = |columns: &[&DB::Column]| {
            columns
                .iter()
                .copied()
                .map(ColumnLike::column_name)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let keys = contained
            .iter()
            .map(|key| format!("({})", list(key)))
            .collect::<Vec<_>>()
            .join(" and ");
        let name = table.table_name();
        reporter.table(
            table,
            format!(
                "Primary key ({}) of '{name}' contains the unique key {keys}, so its other columns add no row identity.",
                list(&primary_key)
            ),
            format!(
                "Make {} the primary key of '{name}', after moving any foreign key that references the wider key.",
                contained
                    .iter()
                    .min_by_key(|key| key.len())
                    .map_or_else(String::new, |key| format!("({})", list(key)))
            ),
        )?;
        Ok(())
    }
}
