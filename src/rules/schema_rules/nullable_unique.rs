//! Submodule providing the `NullableUniqueColumn` rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, IndexLike, TableIndexLike, TableLike},
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        external_key_support::external_host_columns,
        key_support::{Key, nullable_host_columns, unique_keys},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Whether `column` is the one nullable column of a foreign key of its
/// table, local or among the host columns of its `external` keys, so a
/// `NULL` there means the row references nothing.
fn is_optional_reference<DB: DatabaseLike>(
    database: &DB,
    external: &[Vec<&DB::Column>],
    column: &DB::Column,
) -> Result<bool, LookupError> {
    for foreign_key in column.foreign_keys(database)? {
        if nullable_host_columns(database, foreign_key)?.len() == 1 {
            return Ok(true);
        }
    }
    for columns in external.iter().filter(|columns| columns.contains(&column)) {
        let mut nullable = 0;
        for host in columns {
            nullable += usize::from(host.is_nullable(database)?);
        }
        if nullable == 1 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The nullable columns of a unique index that treats nulls as distinct,
/// other than optional references, none when its columns span one of the
/// table's `keys` and so already tell its rows apart.
fn nullable_columns<DB: DatabaseLike, I: TableIndexLike<DB = DB>>(
    database: &DB,
    external: &[Vec<&DB::Column>],
    keys: &[Key<'_, DB>],
    index: &I,
) -> Result<Vec<String>, LookupError> {
    if !index.nulls_distinct() {
        return Ok(Vec::new());
    }
    let columns: Vec<&DB::Column> = index.columns(database)?.collect();
    if keys
        .iter()
        .any(|key| key.iter().all(|column| columns.contains(column)))
    {
        return Ok(Vec::new());
    }
    let mut nullable = Vec::new();
    for column in columns {
        if column.is_nullable(database)? && !is_optional_reference(database, external, column)? {
            nullable.push(format!("'{}'", column.column_name()));
        }
    }
    Ok(nullable)
}

schema_rule!(
    /// Struct defining a rule that reports a unique constraint or unique
    /// index over a nullable column without `NULLS NOT DISTINCT`.
    ///
    /// An optional reference, the one nullable column of a foreign key such
    /// as `invitation_id` under `FOREIGN KEY (tenant_id, invitation_id)` with
    /// `tenant_id` `NOT NULL`, is exempt, since distinct `NULL`s there let
    /// many rows reference nothing. A foreign key the deployment declares
    /// with [`Deployment::with_external_foreign_key`](crate::deployment::Deployment::with_external_foreign_key)
    /// exempts its column the same way. A constraint spanning a unique key
    /// that already tells rows apart is exempt too, such as
    /// `UNIQUE (id, parent_id)` beside `id` `PRIMARY KEY` as the target of a
    /// foreign key into `(id, parent_id)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = NullableUniqueColumn::default().into();
    /// let distinct = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (email TEXT UNIQUE);").unwrap();
    /// assert!(constrainer.validate_schema(&distinct).is_err());
    /// let not_distinct = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE t (email TEXT UNIQUE NULLS NOT DISTINCT);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&not_distinct).is_ok());
    /// ```
    NullableUniqueColumn,
    LintGroup::Pedantic,
    "A unique constraint treats every NULL as distinct by default, so rows that hold NULL in a constrained column can repeat everything else.",
    Some("https://www.postgresql.org/docs/current/ddl-constraints.html"),
    RuleExample {
        bad: "CREATE TABLE users (email TEXT UNIQUE);",
        good: "CREATE TABLE users (email TEXT UNIQUE NULLS NOT DISTINCT);",
    }
);

impl<DB: DatabaseLike> SchemaRule for NullableUniqueColumn<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        for table in database.tables() {
            let external = external_host_columns(database, deployment, table)?;
            let keys = unique_keys(database, table)?;
            let mut found: Vec<(Option<&str>, Vec<String>)> = Vec::new();
            for index in table.unique_indices(database)? {
                found.push((
                    index.name(),
                    nullable_columns(database, &external, &keys, index)?,
                ));
            }
            for index in table.indices(database)?.filter(|index| index.is_unique()) {
                found.push((
                    index.name(),
                    nullable_columns(database, &external, &keys, index)?,
                ));
            }
            let name = table.table_name();
            for (index, columns) in found.into_iter().filter(|(_, columns)| !columns.is_empty()) {
                let columns = columns.join(", ");
                let index = index.map_or_else(
                    || format!("unique ({columns})"),
                    |index| format!("'{index}'"),
                );
                reporter.table(
                    table,
                    format!("Unique constraint {index} on '{name}' covers nullable {columns} and treats NULLs as distinct, so rows with a NULL there can repeat the rest."),
                    match Engine::of(database) {
                        Engine::PostgreSql => "Add NULLS NOT DISTINCT, or declare the columns NOT NULL, unless repeated NULLs are intended.",
                        Engine::Sqlite => "Declare the columns NOT NULL, unless repeated NULLs are intended.",
                    }.to_owned(),
                )?;
            }
        }
        Ok(())
    }
}
