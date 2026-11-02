//! Submodule providing the `CompatibleForeignKey` constraint, which enforces
//! that foreign key columns are compatible with the referenced columns, i.e.
//! have the same data type and are part of the same extension hierarchy.

use std::borrow::Borrow;

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DataTypeLike, DatabaseLike, ForeignKeyLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that foreign key columns are
/// compatible with the referenced columns, i.e. have the same data type and
/// are part of the same extension hierarchy.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `CompatibleForeignKey` constraint.
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = CompatibleForeignKey::default().into();
///
/// let invalid_data_type = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE mytable (id INT PRIMARY KEY);
/// CREATE TABLE othertable (id SMALLINT, CONSTRAINT fk FOREIGN KEY (id) REFERENCES mytable (id));
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_data_type).is_err());
///
/// let both_generated = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent (id SERIAL PRIMARY KEY);
/// CREATE TABLE child (id SERIAL PRIMARY KEY, FOREIGN KEY (id) REFERENCES parent (id));
/// ",
/// )
/// .unwrap();
/// let error = constrainer.validate_schema(&both_generated).unwrap_err();
/// assert!(matches!(
///     error,
///     Error::Violation(violation)
///         if violation
///             .message()
///             .contains("`child.id` and referenced column `parent.id` both generate their own values")
/// ));
///
/// // `d.x` references `a`, while the unique `b.code` references nothing
/// let host_in_other_hierarchy = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE a (id INT PRIMARY KEY);
/// CREATE TABLE b (id INT PRIMARY KEY, code INT UNIQUE);
/// CREATE TABLE d (id INT PRIMARY KEY, x INT REFERENCES a (id), FOREIGN KEY (x) REFERENCES b (code));
/// ",
/// )
/// .unwrap();
/// let error = constrainer.validate_schema(&host_in_other_hierarchy).unwrap_err();
/// assert!(matches!(
///     error,
///     Error::Violation(violation)
///         if violation
///             .message()
///             .contains("`d.x` references [a], while `b.code` references [none]")
/// ));
///
/// // `d.b_a_id` references nothing, while the unique `b.a_id` references `a`
/// let referenced_in_other_hierarchy = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE a (id INT PRIMARY KEY);
/// CREATE TABLE b (id INT PRIMARY KEY, a_id INT UNIQUE REFERENCES a (id));
/// CREATE TABLE d (id INT PRIMARY KEY, b_a_id INT REFERENCES b (a_id));
/// ",
/// )
/// .unwrap();
/// let error = constrainer.validate_schema(&referenced_in_other_hierarchy).unwrap_err();
/// assert!(matches!(
///     error,
///     Error::Violation(violation)
///         if violation
///             .message()
///             .contains("`d.b_a_id` references [none], while `b.a_id` references [a]")
/// ));
///
/// let extension_dag = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE root (id SERIAL PRIMARY KEY);
/// CREATE TABLE left_root (id INT PRIMARY KEY REFERENCES root (id));
/// CREATE TABLE right_root (id INT PRIMARY KEY REFERENCES root (id));
/// CREATE TABLE left_child (id INT PRIMARY KEY REFERENCES left_root (id));
/// CREATE TABLE right_child (id INT PRIMARY KEY REFERENCES right_root (id));
/// CREATE TABLE mytable (
///     id INT PRIMARY KEY,
///     other_id INT,
///     FOREIGN KEY (other_id) REFERENCES left_child (id),
///     FOREIGN KEY (other_id) REFERENCES right_child (id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&extension_dag).is_ok());
///
/// let valid_schema2 = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE root (id INT PRIMARY KEY);
/// CREATE TABLE child (id INT PRIMARY KEY REFERENCES root (id));
/// CREATE TABLE mytable (id INT PRIMARY KEY, other_id INT REFERENCES child (id));
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema2).is_ok());
/// ```
pub struct CompatibleForeignKey<C>(std::marker::PhantomData<C>);

impl<C> Default for CompatibleForeignKey<C> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<CompatibleForeignKey<DB>> for GenericConstrainer<DB> {
    fn from(constraint: CompatibleForeignKey<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(constraint));
        constrainer
    }
}

impl<C> Rule for CompatibleForeignKey<C> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "CompatibleForeignKey",
            group: LintGroup::Suspicious,
            rationale: "A foreign key whose columns differ in type from the referenced columns, or that links tables outside one extension hierarchy, usually points at the wrong column.",
            source: None,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> CompatibleForeignKey<DB> {
    fn get_incompatibility_details(
        database: &DB,
        host_table: &<DB as DatabaseLike>::Table,
        referenced_table: &<DB as DatabaseLike>::Table,
        host_column: &<DB as DatabaseLike>::Column,
        referenced_column: &<DB as DatabaseLike>::Column,
    ) -> Result<(String, String), LookupError> {
        if host_column.is_generated(database) && referenced_column.is_generated(database) {
            Ok((
                format!(
                    "Foreign key column `{}.{}` and referenced column `{}.{}` both generate their own values, so they match the referenced row only by coincidence.",
                    host_table.table_name(),
                    host_column.column_name(),
                    referenced_table.table_name(),
                    referenced_column.column_name(),
                ),
                format!(
                    "Remove the generative property from `{}.{}` (drop SERIAL, AUTO_INCREMENT or the identity, keeping INT/BIGINT) or redesign the foreign key relationship.",
                    host_table.table_name(),
                    host_column.column_name(),
                ),
            ))
        } else if host_column.data_type(database).normalized_name(database)
            != referenced_column
                .data_type(database)
                .normalized_name(database)
        {
            Ok((
                format!(
                    "Foreign key column `{}.{}` has data type '{}', which differs from referenced column `{}.{}` with data type '{}'.",
                    host_table.table_name(),
                    host_column.column_name(),
                    host_column.data_type(database).normalized_name(database),
                    referenced_table.table_name(),
                    referenced_column.column_name(),
                    referenced_column
                        .data_type(database)
                        .normalized_name(database),
                ),
                format!(
                    "Change the data type of `{}.{}` to '{}' to match the referenced column.",
                    host_table.table_name(),
                    host_column.column_name(),
                    referenced_column
                        .data_type(database)
                        .normalized_name(database),
                ),
            ))
        } else {
            // The columns reference incompatible table hierarchies
            let host_referenced_tables =
                host_table.referenced_tables_via_column(database, host_column.borrow())?;
            let other_referenced_tables = referenced_table
                .referenced_tables_via_column(database, referenced_column.borrow())?;

            let describe = |tables: &[&<DB as DatabaseLike>::Table]| {
                if tables.is_empty() {
                    "none".to_owned()
                } else {
                    tables
                        .iter()
                        .copied()
                        .map(TableLike::table_name)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            };
            let host_refs = describe(&host_referenced_tables);
            let other_refs = describe(&other_referenced_tables);

            Ok((
                format!(
                    "Foreign key column `{}.{}` and referenced column `{}.{}` belong to unrelated extension hierarchies, since `{}.{}` references [{}], while `{}.{}` references [{}].",
                    host_table.table_name(),
                    host_column.column_name(),
                    referenced_table.table_name(),
                    referenced_column.column_name(),
                    host_table.table_name(),
                    host_column.column_name(),
                    host_refs,
                    referenced_table.table_name(),
                    referenced_column.column_name(),
                    other_refs,
                ),
                format!(
                    "Ensure that `{}.{}` and `{}.{}` are part of the same table extension hierarchy, or reconsider the foreign key relationship.",
                    host_table.table_name(),
                    host_column.column_name(),
                    referenced_table.table_name(),
                    referenced_column.column_name(),
                ),
            ))
        }
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for CompatibleForeignKey<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let host_table = foreign_key.host_table(database);
        let referenced_table = foreign_key.referenced_table(database)?;
        for (host_column, referenced_column) in foreign_key
            .host_columns(database)?
            .zip(foreign_key.referenced_columns(database)?)
        {
            if !host_column.is_compatible_with(database, referenced_column)? {
                // Determine the specific reason for incompatibility
                let (message, resolution) = Self::get_incompatibility_details(
                    database,
                    host_table,
                    referenced_table,
                    host_column,
                    referenced_column,
                )?;
                reporter.foreign_key(foreign_key, message, resolution)?;
            }
        }

        Ok(())
    }
}
