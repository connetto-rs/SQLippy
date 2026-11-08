//! Submodule providing the `NullableUniqueColumn` rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, IndexLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// The nullable columns of a unique index that treats nulls as distinct.
fn nullable_columns<DB: DatabaseLike, I: IndexLike<DB = DB>>(
    database: &DB,
    index: &I,
) -> Result<Vec<String>, LookupError> {
    if !index.nulls_distinct() {
        return Ok(Vec::new());
    }
    let mut nullable = Vec::new();
    for column in index.columns(database)? {
        if column.is_nullable(database)? {
            nullable.push(format!("'{}'", column.column_name()));
        }
    }
    Ok(nullable)
}

schema_rule!(
    /// Struct defining a rule that reports a unique constraint or unique
    /// index over a nullable column without `NULLS NOT DISTINCT`.
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
    Some("https://www.postgresql.org/docs/current/ddl-constraints.html")
);

impl<DB: DatabaseLike> SchemaRule for NullableUniqueColumn<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for table in database.tables() {
            let mut found: Vec<(Option<&str>, Vec<String>)> = Vec::new();
            for index in table.unique_indices(database)? {
                found.push((index.name(), nullable_columns(database, index)?));
            }
            for index in table.indices(database)?.filter(|index| index.is_unique()) {
                found.push((index.name(), nullable_columns(database, index)?));
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
                    "Add NULLS NOT DISTINCT, or declare the columns NOT NULL, unless repeated NULLs are intended.".to_owned(),
                )?;
            }
        }
        Ok(())
    }
}
