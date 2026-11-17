//! Submodule providing the `ReferenceWithoutIdSuffix` constraint, which
//! enforces that foreign key host columns that reference primary key columns
//! (directly or indirectly) must have names ending with "id".

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that foreign key host columns
/// that reference primary key columns (directly or indirectly) must have names
/// ending with "id".
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `reference_without_id_suffix` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ReferenceWithoutIdSuffix::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent (id INT PRIMARY KEY);
/// CREATE TABLE child (parent_key INT, FOREIGN KEY (parent_key) REFERENCES parent (id));
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema_direct = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent (id INT PRIMARY KEY);
/// CREATE TABLE child (parent_id INT, FOREIGN KEY (parent_id) REFERENCES parent (id));
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema_direct).is_ok());
///
/// let valid_schema_indirect = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE grandparent (id INT PRIMARY KEY);
/// CREATE TABLE parent (gp_id INT UNIQUE, FOREIGN KEY (gp_id) REFERENCES grandparent (id));
/// CREATE TABLE child (parent_id INT, FOREIGN KEY (parent_id) REFERENCES parent (gp_id));
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema_indirect).is_ok());
///
/// let valid_schema_non_pk = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent (id INT PRIMARY KEY, code TEXT UNIQUE);
/// CREATE TABLE child (parent_code TEXT, FOREIGN KEY (parent_code) REFERENCES parent (code));
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema_non_pk).is_ok());
///
/// // `parent.owner_id` references a primary key, but `child` references `parent.code`
/// let valid_schema_other_fk = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE owner (id INT PRIMARY KEY);
/// CREATE TABLE parent (id INT PRIMARY KEY, code INT UNIQUE, owner_id INT REFERENCES owner (id));
/// CREATE TABLE child (parent_code INT, FOREIGN KEY (parent_code) REFERENCES parent (code));
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema_other_fk).is_ok());
/// ```
pub struct ReferenceWithoutIdSuffix<C>(std::marker::PhantomData<C>);

impl<C> Default for ReferenceWithoutIdSuffix<C> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ReferenceWithoutIdSuffix<DB>> for GenericConstrainer<DB> {
    fn from(constraint: ReferenceWithoutIdSuffix<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(constraint));
        constrainer
    }
}

impl<C> Rule for ReferenceWithoutIdSuffix<C> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(ReferenceWithoutIdSuffix),
            group: LintGroup::Style,
            rationale: "Ending every column that references a primary key in `_id` shows at a glance which columns are references.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (parent_key INT REFERENCES parents (id));",
                good: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (parent_id INT REFERENCES parents (id));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ReferenceWithoutIdSuffix<DB> {
    /// Returns the primary key column that `column` is mapped to by one of the
    /// foreign keys of its table.
    fn primary_key_column_through_foreign_key<'db>(
        database: &'db DB,
        column: &'db DB::Column,
    ) -> Result<Option<&'db DB::Column>, LookupError> {
        for foreign_key in column.table(database).foreign_keys(database)? {
            let Some(referenced_column) =
                foreign_key.referenced_column_for_host_column(database, column)?
            else {
                continue;
            };
            let referenced_table = foreign_key.referenced_table(database)?;
            if referenced_table.is_primary_key_column(database, referenced_column)? {
                return Ok(Some(referenced_column));
            }
        }
        Ok(None)
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for ReferenceWithoutIdSuffix<DB> {
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
            if host_column.column_name().ends_with("id") {
                continue;
            }
            let reference =
                if referenced_table.is_primary_key_column(database, referenced_column)? {
                    format!(
                        "primary key column '{}.{}'",
                        referenced_table.table_name(),
                        referenced_column.column_name()
                    )
                } else if let Some(primary_key_column) =
                    Self::primary_key_column_through_foreign_key(database, referenced_column)?
                {
                    format!(
                        "'{}.{}', which references primary key column '{}.{}',",
                        referenced_table.table_name(),
                        referenced_column.column_name(),
                        primary_key_column.table(database).table_name(),
                        primary_key_column.column_name()
                    )
                } else {
                    continue;
                };
            reporter.foreign_key(
                foreign_key,
                format!(
                    "Foreign key host column '{}.{}' references {reference} but does not end with 'id'.",
                    host_table.table_name(),
                    host_column.column_name(),
                ),
                format!(
                    "Rename column '{}.{}' to '{}_id'.",
                    host_table.table_name(),
                    host_column.column_name(),
                    host_column.column_name()
                ),
            )?;
        }

        Ok(())
    }
}
