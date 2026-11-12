//! Submodule providing the `UniqueColumnNamesInExtensionGraph` constraint,
//! which enforces that column names are unique within an extension graph.

use std::collections::HashSet;

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that column names are unique
/// within an extension graph (i.e., a table which extends other tables cannot
/// have a column whose name also appears in other tables it extends).
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `UniqueColumnNamesInExtensionGraph` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> =
///     UniqueColumnNamesInExtensionGraph::default().into();
///
/// // Invalid: child_table has 'name' column, which also exists in parent_table
/// let invalid_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     name TEXT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Valid: child_table has unique column names
/// let valid_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     description TEXT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// // Valid: non-extension tables can have any column names
/// let valid_non_extension = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE table1 (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE table2 (id INT PRIMARY KEY, name TEXT);
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_non_extension).is_ok());
///
/// // Valid: primary key column (id) can be shared in extension
/// let valid_shared_pk = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     value INT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_shared_pk).is_ok());
///
/// // Invalid: transitive extension - grandchild cannot have column from grandparent
/// let invalid_transitive = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE grandparent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE parent_table (
///     id INT PRIMARY KEY,
///     age INT,
///     FOREIGN KEY (id) REFERENCES grandparent_table(id)
/// );
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     name TEXT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_transitive).is_err());
/// ```
pub struct UniqueColumnNamesInExtensionGraph<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UniqueColumnNamesInExtensionGraph<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UniqueColumnNamesInExtensionGraph<DB>>
    for GenericConstrainer<DB>
{
    fn from(constraint: UniqueColumnNamesInExtensionGraph<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for UniqueColumnNamesInExtensionGraph<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "UniqueColumnNamesInExtensionGraph",
            group: LintGroup::Suspicious,
            rationale: "A column name repeated across an extension hierarchy makes the merged row ambiguous.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE records (id INT PRIMARY KEY, name TEXT);\n\
CREATE TABLE notes (id INT PRIMARY KEY REFERENCES records (id), name TEXT);",
                good: "CREATE TABLE records (id INT PRIMARY KEY, name TEXT);\n\
CREATE TABLE notes (id INT PRIMARY KEY REFERENCES records (id), description TEXT);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> UniqueColumnNamesInExtensionGraph<DB> {
    /// Helper method to find duplicate column names in the extension graph
    fn find_duplicate_columns(
        database: &DB,
        table: &<DB as DatabaseLike>::Table,
    ) -> Result<Vec<String>, LookupError> {
        let mut duplicates = Vec::new();
        let extended_tables = table
            .extended_tables(database)?
            .collect::<Vec<&<DB as DatabaseLike>::Table>>();

        if extended_tables.is_empty() {
            return Ok(duplicates);
        }

        let mut extended_column_names: HashSet<String> = HashSet::new();
        let mut tables_to_check = extended_tables;
        let mut checked_tables: HashSet<String> = HashSet::new();

        while let Some(extended_table) = tables_to_check.pop() {
            let table_name = extended_table.table_name().to_string();
            if checked_tables.contains(&table_name) {
                continue;
            }
            checked_tables.insert(table_name);
            for column in extended_table.columns(database)? {
                extended_column_names.insert(column.column_name().to_string());
            }

            for parent in extended_table.extended_tables(database)? {
                tables_to_check.push(parent);
            }
        }

        for column in table.columns(database)? {
            let column_name = column.column_name();
            if table
                .primary_key_columns(database)?
                .any(|pk_col| pk_col.column_name() == column_name)
            {
                continue;
            }
            if extended_column_names.contains(column_name) {
                duplicates.push(column_name.to_string());
            }
        }

        Ok(duplicates)
    }
}

impl<DB: DatabaseLike> TableRule for UniqueColumnNamesInExtensionGraph<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        // Check if any column in the current table conflicts with extended tables
        let duplicates = Self::find_duplicate_columns(database, table)?;
        if duplicates.is_empty() {
            return Ok(());
        }

        let table_name = table.table_name();
        for column in table.columns(database)? {
            let column_name = column.column_name();
            if duplicates.iter().any(|name| name == column_name) {
                reporter.column(
                    column,
                    format!(
                        "Column '{column_name}' of table '{table_name}' conflicts with a column of the same name in the tables it extends."
                    ),
                    format!(
                        "Rename the column '{column_name}' in table '{table_name}' so its name is unique across the extension hierarchy."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
