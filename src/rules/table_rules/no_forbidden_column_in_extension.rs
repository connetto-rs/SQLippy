//! Submodule providing the `NoForbiddenColumnInExtension` constraint, which
//! enforces that if a table extends other tables, it cannot have a column with
//! a forbidden name (by default "extension", but configurable).

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that if a table extends other
/// tables, it cannot have a column with a forbidden name (by default
/// "extension", but configurable).
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `NoForbiddenColumnInExtension` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NoForbiddenColumnInExtension::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     extension TEXT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     data TEXT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// // Tables that don't extend other tables can have columns with the forbidden name
/// let valid_non_extension_schema =
///     ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (id INT PRIMARY KEY, extension TEXT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_non_extension_schema).is_ok());
///
/// // Custom forbidden name
/// let custom_constrainer: GenericConstrainer<ParserDB> =
///     NoForbiddenColumnInExtension::new("custom_forbidden").into();
///
/// let invalid_custom_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     custom_forbidden TEXT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(custom_constrainer.validate_schema(&invalid_custom_schema).is_err());
/// ```
pub struct NoForbiddenColumnInExtension<DB> {
    forbidden_name: String,
    _phantom: std::marker::PhantomData<DB>,
}

impl<DB> NoForbiddenColumnInExtension<DB> {
    /// Creates a new `NoForbiddenColumnInExtension` constraint with a custom
    /// forbidden column name.
    ///
    /// # Arguments
    ///
    /// * `forbidden_name` - The name of the column that should not appear in
    ///   extension tables.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    ///
    /// let constraint: NoForbiddenColumnInExtension<ParserDB> =
    ///     NoForbiddenColumnInExtension::new("my_forbidden_column");
    /// ```
    pub fn new(forbidden_name: impl Into<String>) -> Self {
        Self {
            forbidden_name: forbidden_name.into(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<DB> Default for NoForbiddenColumnInExtension<DB> {
    fn default() -> Self {
        Self::new("extension")
    }
}

impl<DB: DatabaseLike + 'static> From<NoForbiddenColumnInExtension<DB>> for GenericConstrainer<DB> {
    fn from(constraint: NoForbiddenColumnInExtension<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for NoForbiddenColumnInExtension<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NoForbiddenColumnInExtension",
            group: LintGroup::Suspicious,
            rationale: "The extension model keeps the configured column name for its own use, so a column with that name on an extending table collides with it.",
            source: None,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for NoForbiddenColumnInExtension<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        // Check if the table extends other tables
        if !table.is_extension(database)? {
            // If the table doesn't extend any other table, the constraint doesn't apply
            return Ok(());
        }

        // Check if any column has the forbidden name (case-insensitive comparison)
        let forbidden_name_lower = self.forbidden_name.to_lowercase();
        for column in table.columns(database)? {
            if column.column_name().to_lowercase() == forbidden_name_lower {
                let table_name = table.table_name();
                let column_name = column.column_name();
                let extended_table_names = table
                    .extended_tables(database)?
                    .map(TableLike::table_name)
                    .collect::<Vec<_>>();
                reporter.column(
                    column,
                    format!(
                        "Table '{table_name}' extends {} ({}) but defines the forbidden column '{column_name}'.",
                        if extended_table_names.len() == 1 { "the table" } else { "the tables" },
                        extended_table_names.join(", ")
                    ),
                    format!(
                        "Rename or remove the column '{column_name}' from table '{table_name}'."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
