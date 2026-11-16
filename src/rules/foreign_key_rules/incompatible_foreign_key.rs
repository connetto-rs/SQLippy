//! Submodule providing the `IncompatibleForeignKey` constraint, which enforces
//! that foreign key columns are compatible with the referenced columns, i.e.
//! have the same data type, and that the references of each column name one
//! extension hierarchy.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DataTypeLike, DatabaseLike, ForeignKeyLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that foreign key columns are
/// compatible with the referenced columns, i.e. have the same data type, and
/// that the foreign keys of each column reference one extension hierarchy.
///
/// A column takes the extension hierarchy of every column it references,
/// through keys of any width, so a column of a composite key is the entity its
/// referenced column is. A column whose keys reference unrelated hierarchies is
/// reported once, on the first of those keys.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `incompatible_foreign_key` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = IncompatibleForeignKey::default().into();
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
/// // `d.x` must be an `a` and a `b`, which the unique `b.code` identifies
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
///             .contains("`d.x` references unrelated extension hierarchies, [a] through `a (id)` and [b] through `b (code)`")
/// ));
///
/// // The unique `b.a_id` references `a`, so its values are rows of `a` and `b`
/// let unique_key_in_hierarchy = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE a (id INT PRIMARY KEY);
/// CREATE TABLE b (id INT PRIMARY KEY, a_id INT UNIQUE REFERENCES a (id));
/// CREATE TABLE d (id INT PRIMARY KEY, b_a_id INT REFERENCES b (a_id));
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&unique_key_in_hierarchy).is_ok());
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
pub struct IncompatibleForeignKey<C>(std::marker::PhantomData<C>);

impl<C> Default for IncompatibleForeignKey<C> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<IncompatibleForeignKey<DB>> for GenericConstrainer<DB> {
    fn from(constraint: IncompatibleForeignKey<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(constraint));
        constrainer
    }
}

impl<C> Rule for IncompatibleForeignKey<C> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(IncompatibleForeignKey),
            group: LintGroup::Suspicious,
            rationale: "A foreign key whose columns differ in type from the referenced columns, or whose column another foreign key ties to an unrelated entity, usually points at the wrong column.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (parent_id SMALLINT REFERENCES parents (id));",
                good: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (parent_id INT REFERENCES parents (id));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> IncompatibleForeignKey<DB> {
    /// Message and resolution for a host column whose type or generated values
    /// rule out the column it references, or `None` when the pair is
    /// compatible.
    fn pair_incompatibility(
        database: &DB,
        host_table: &<DB as DatabaseLike>::Table,
        referenced_table: &<DB as DatabaseLike>::Table,
        host_column: &<DB as DatabaseLike>::Column,
        referenced_column: &<DB as DatabaseLike>::Column,
    ) -> Option<(String, String)> {
        if host_column.is_compatible_with(database, referenced_column) {
            None
        } else if host_column.is_generated(database) && referenced_column.is_generated(database) {
            Some((
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
        } else {
            Some((
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
        }
    }

    /// Message and resolution for a host column whose foreign keys reference
    /// unrelated extension hierarchies, given each conflicting key with the
    /// hierarchy it contributes.
    fn hierarchy_conflict(
        database: &DB,
        host_table: &<DB as DatabaseLike>::Table,
        host_column: &<DB as DatabaseLike>::Column,
        conflicts: &[(
            &<DB as DatabaseLike>::ForeignKey,
            Vec<&<DB as DatabaseLike>::Table>,
        )],
    ) -> Result<(String, String), LookupError> {
        let mut references = Vec::with_capacity(conflicts.len());
        for (foreign_key, hierarchy) in conflicts {
            let referenced_columns = foreign_key
                .referenced_columns(database)?
                .map(ColumnLike::column_name)
                .collect::<Vec<_>>()
                .join(", ");
            let hierarchy = hierarchy
                .iter()
                .copied()
                .map(TableLike::table_name)
                .collect::<Vec<_>>()
                .join(", ");
            references.push(format!(
                "[{hierarchy}] through `{} ({referenced_columns})`",
                foreign_key.referenced_table(database)?.table_name(),
            ));
        }
        let last = references.pop().unwrap_or_default();
        Ok((
            format!(
                "Foreign key column `{}.{}` references unrelated extension hierarchies, {} and {last}, so every value would have to be a row of unrelated tables.",
                host_table.table_name(),
                host_column.column_name(),
                references.join(", "),
            ),
            format!(
                "Keep only the foreign keys of `{}.{}` whose referenced columns share an extension hierarchy, or reconsider which column each key references.",
                host_table.table_name(),
                host_column.column_name(),
            ),
        ))
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for IncompatibleForeignKey<DB> {
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
            if let Some((message, resolution)) = Self::pair_incompatibility(
                database,
                host_table,
                referenced_table,
                host_column,
                referenced_column,
            ) {
                reporter.foreign_key(foreign_key, message, resolution)?;
            }
            // The conflict belongs to the column, so only its first
            // conflicting key reports it.
            let conflicts = host_column.conflicting_references(database)?;
            if conflicts
                .first()
                .is_some_and(|(first, _)| *first == foreign_key)
            {
                let (message, resolution) =
                    Self::hierarchy_conflict(database, host_table, host_column, &conflicts)?;
                reporter.foreign_key(foreign_key, message, resolution)?;
            }
        }

        Ok(())
    }
}
