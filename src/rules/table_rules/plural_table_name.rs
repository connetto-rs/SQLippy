//! Submodule providing the `PluralTableName` constraint, which enforces that
//! the last segment of table names is plural.

use inflection_rs::inflection::pluralize;
use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that the last segment of table
/// names is plural.
///
/// For table names with underscores (e.g., `user_accounts`), only the last
/// segment after the final underscore is checked for plurality.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `PluralTableName` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = PluralTableName::default().into();
///
/// // Invalid singular table names
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE user (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let invalid_schema2 = ParserDB::parse::<GenericDialect>("CREATE TABLE user_account (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema2).is_err());
///
/// // Valid plural table names
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE users (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// let valid_schema2 = ParserDB::parse::<GenericDialect>("CREATE TABLE user_accounts (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema2).is_ok());
///
/// // Edge cases with Latin plurals
/// let valid_spectra = ParserDB::parse::<GenericDialect>("CREATE TABLE spectra (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_spectra).is_ok());
///
/// let invalid_spectrum = ParserDB::parse::<GenericDialect>("CREATE TABLE spectrum (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_spectrum).is_err());
///
/// let valid_matrices = ParserDB::parse::<GenericDialect>("CREATE TABLE matrices (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_matrices).is_ok());
///
/// let invalid_matrix = ParserDB::parse::<GenericDialect>("CREATE TABLE matrix (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_matrix).is_err());
///
/// let valid_taxa = ParserDB::parse::<GenericDialect>("CREATE TABLE taxa (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_taxa).is_ok());
///
/// let invalid_taxon = ParserDB::parse::<GenericDialect>("CREATE TABLE taxon (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_taxon).is_err());
/// ```
pub struct PluralTableName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PluralTableName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PluralTableName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: PluralTableName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for PluralTableName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "PluralTableName",
            group: LintGroup::Style,
            rationale: "One naming convention keeps queries predictable, and this crate names a table after the collection of rows it holds.",
            source: None,
            basis: Basis::Names,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for PluralTableName<DB> {
    type Database = DB;

    fn check_table(
        &self,
        _database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table_name = table.table_name();
        let last_segment = table_name.split('_').next_back().unwrap_or(table_name);

        // Check if the last segment is plural by verifying that pluralizing it doesn't
        // change it
        let pluralized = pluralize(last_segment);

        if pluralized != last_segment {
            let expected_name = if table_name.contains('_') {
                let prefix = &table_name[..table_name.rfind('_').unwrap()];
                format!("{prefix}_{pluralized}")
            } else {
                pluralized
            };

            reporter.table(
                table,
                format!(
                    "The last segment '{last_segment}' of table '{table_name}' is singular, not plural."
                ),
                format!("Rename the table to '{expected_name}'."),
            )?;
        }
        Ok(())
    }
}
