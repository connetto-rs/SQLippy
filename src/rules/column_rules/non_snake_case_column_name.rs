//! Submodule providing the `NonSnakeCaseColumnName` constraint, which enforces
//! that column names follow `snake_case` style.

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};
use heck::ToSnakeCase;

/// Struct defining a constraint that enforces that column names follow
/// `snake_case` style.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `non_snake_case_column_name` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NonSnakeCaseColumnName::default().into();
///
/// // Invalid: PascalCase
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (MyColumn INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Valid: proper snake_case
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (my_column INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// // Invalid: double underscore and camelCase
/// for name in ["my__column", "myColumn"] {
///     let schema = ParserDB::parse::<GenericDialect>(&format!("CREATE TABLE mytable ({name} INT);")).unwrap();
///     assert!(constrainer.validate_schema(&schema).is_err(), "{name}");
/// }
///
/// // Valid: single words and multi-word snake_case
/// for name in ["id", "first_name"] {
///     let schema = ParserDB::parse::<GenericDialect>(&format!("CREATE TABLE mytable ({name} INT);")).unwrap();
///     assert!(constrainer.validate_schema(&schema).is_ok(), "{name}");
/// }
/// ```
pub struct NonSnakeCaseColumnName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NonSnakeCaseColumnName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NonSnakeCaseColumnName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: NonSnakeCaseColumnName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for NonSnakeCaseColumnName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NonSnakeCaseColumnName),
            group: LintGroup::Style,
            rationale: "Snake case keeps multi-word names readable after PostgreSQL folds unquoted identifiers to lower case.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE t (\"myColumn\" INT);",
                good: "CREATE TABLE t (my_column INT);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for NonSnakeCaseColumnName<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let column_name = column.column_name();
        let snake_cased = column_name.to_snake_case();
        if snake_cased == column_name {
            return Ok(());
        }

        let table_name = column.table(database).table_name();
        let expected_name = snake_cased;
        let issue = if column_name.contains("__") {
            "contains double underscores"
        } else if column_name.chars().any(|c| c.is_ascii_uppercase()) {
            "contains uppercase letters"
        } else {
            "does not follow snake_case convention"
        };
        reporter.column(
            column,
            format!("Column '{column_name}' in table '{table_name}' violates snake_case naming convention and {issue}."),
            format!(
                "Rename '{column_name}' to '{expected_name}' in table '{table_name}', using lowercase letters and single underscores."
            ),
        )?;
        Ok(())
    }
}
