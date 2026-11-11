//! Submodule providing the `SnakeCaseTableName` constraint, which enforces that
//! table names follow `snake_case` style.

use heck::ToSnakeCase;
use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that table names follow
/// `snake_case` style.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `SnakeCaseTableName` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = SnakeCaseTableName::default().into();
///
/// // Invalid: PascalCase
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE MyTable (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Invalid: double underscore
/// let invalid_schema2 = ParserDB::parse::<GenericDialect>("CREATE TABLE my__table (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema2).is_err());
///
/// // Invalid: camelCase
/// let invalid_schema3 = ParserDB::parse::<GenericDialect>("CREATE TABLE myTable (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema3).is_err());
///
/// // Valid: proper snake_case
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE my_table (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// let valid_schema2 = ParserDB::parse::<GenericDialect>("CREATE TABLE users (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema2).is_ok());
///
/// let valid_schema3 = ParserDB::parse::<GenericDialect>("CREATE TABLE user_accounts (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema3).is_ok());
/// ```
pub struct SnakeCaseTableName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for SnakeCaseTableName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<SnakeCaseTableName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: SnakeCaseTableName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for SnakeCaseTableName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "SnakeCaseTableName",
            group: LintGroup::Style,
            rationale: "Snake case keeps multi-word names readable after PostgreSQL folds unquoted identifiers to lower case.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS",
            ),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for SnakeCaseTableName<DB> {
    type Database = DB;

    fn check_table(
        &self,
        _database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table_name = table.table_name();
        let expected_name = table_name.to_snake_case();

        if expected_name != table_name {
            let issue = if table_name.contains("__") {
                "contains double underscores"
            } else if table_name.chars().any(|c| c.is_ascii_uppercase()) {
                "contains uppercase letters"
            } else {
                "does not follow snake_case convention"
            };
            reporter.table(
                table,
                format!("Table '{table_name}' {issue}."),
                format!("Rename the table to '{expected_name}'."),
            )?;
        }
        Ok(())
    }
}
