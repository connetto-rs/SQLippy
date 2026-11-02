//! Submodule providing the `ExtensionForeignKeyOnDeleteCascade` constraint,
//! which enforces that extension foreign keys must have `ON DELETE CASCADE`
//! specified.

use sql_traits::traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike};
use sqlparser::ast::ReferentialAction;

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that extension foreign keys
/// must have `ON DELETE CASCADE` specified.
///
/// An extension foreign key is a foreign key where:
/// - The host columns are the primary key of the host table
/// - The referenced columns are the primary key of the referenced table
/// - The foreign key is not self-referential
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `ExtensionForeignKeyOnDeleteCascade` constraint.
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> =
///     ExtensionForeignKeyOnDeleteCascade::default().into();
///
/// // Extension FK without ON DELETE CASCADE - should fail
/// let invalid_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY);
/// CREATE TABLE extension_table (
///     id INT PRIMARY KEY,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // A named extension FK is reported by its name and keeps it in the fix
/// let invalid_named = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY);
/// CREATE TABLE extension_table (
///     id INT PRIMARY KEY,
///     CONSTRAINT extension_parent FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// let Err(Error::Violation(violation)) = constrainer.validate_schema(&invalid_named) else {
///     panic!("the named extension foreign key must be reported");
/// };
/// assert_eq!(violation.object(), "extension_table.extension_parent");
/// assert!(violation.resolution().contains("CONSTRAINT extension_parent FOREIGN KEY (id)"));
///
/// // Extension FK with ON DELETE CASCADE - should pass
/// let valid_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY);
/// CREATE TABLE extension_table (
///     id INT PRIMARY KEY,
///     FOREIGN KEY (id) REFERENCES parent_table(id) ON DELETE CASCADE
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// // Non-extension FK without ON DELETE CASCADE - should pass (not an extension FK)
/// let valid_schema2 = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY);
/// CREATE TABLE reference_table (
///     id INT PRIMARY KEY,
///     parent_id INT,
///     FOREIGN KEY (parent_id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema2).is_ok());
/// ```
pub struct ExtensionForeignKeyOnDeleteCascade<C>(std::marker::PhantomData<C>);

impl<C> Default for ExtensionForeignKeyOnDeleteCascade<C> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ExtensionForeignKeyOnDeleteCascade<DB>>
    for GenericConstrainer<DB>
{
    fn from(constraint: ExtensionForeignKeyOnDeleteCascade<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(constraint));
        constrainer
    }
}

impl<C> Rule for ExtensionForeignKeyOnDeleteCascade<C> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "ExtensionForeignKeyOnDeleteCascade",
            group: LintGroup::Suspicious,
            rationale: "PostgreSQL's default `NO ACTION` refuses to delete a parent row while extension rows reference it, so extension rows have to follow their parent with `ON DELETE CASCADE`.",
            source: Some(
                "https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-FK",
            ),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for ExtensionForeignKeyOnDeleteCascade<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        // Only check extension foreign keys
        if foreign_key.is_extension_foreign_key(database)?
            && foreign_key.on_delete(database) != ReferentialAction::Cascade
        {
            let host = foreign_key.host_table(database).table_name();
            let referenced = foreign_key.referenced_table(database)?.table_name();
            let host_columns = foreign_key
                .host_columns(database)?
                .map(ColumnLike::column_name)
                .collect::<Vec<_>>()
                .join(", ");
            let referenced_columns = foreign_key
                .referenced_columns(database)?
                .map(ColumnLike::column_name)
                .collect::<Vec<_>>()
                .join(", ");
            let constraint = foreign_key
                .foreign_key_name()
                .map_or_else(String::new, |name| format!("CONSTRAINT {name} "));
            reporter.foreign_key(
                foreign_key,
                format!(
                    "Extension foreign key from {host} ({host_columns}) to {referenced} ({referenced_columns}) has no ON DELETE CASCADE."
                ),
                format!(
                    "Declare it as `{constraint}FOREIGN KEY ({host_columns}) REFERENCES {referenced} ({referenced_columns}) ON DELETE CASCADE`."
                ),
            )?;
        }
        Ok(())
    }
}
