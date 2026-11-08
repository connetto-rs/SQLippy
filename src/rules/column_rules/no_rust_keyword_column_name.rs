//! Submodule providing the `NoRustKeywordColumnName` constraint, which enforces
//! that column names are not Rust keywords.

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::rust_keywords::is_rust_keyword,
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that column names are not Rust
/// keywords.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `NoRustKeywordColumnName` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NoRustKeywordColumnName::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (struct INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (my_struct INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct NoRustKeywordColumnName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NoRustKeywordColumnName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NoRustKeywordColumnName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: NoRustKeywordColumnName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for NoRustKeywordColumnName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NoRustKeywordColumnName",
            group: LintGroup::Restriction,
            rationale: "Code generated from the schema cannot name a Rust item after a keyword without a raw identifier.",
            source: Some("https://doc.rust-lang.org/reference/keywords.html"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for NoRustKeywordColumnName<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let column_name = column.column_name();
        if !is_rust_keyword(column_name) {
            return Ok(());
        }

        let table_name = column.table(database).table_name();
        reporter.column(
            column,
            format!("Column name '{column_name}' in table '{table_name}' is a Rust keyword"),
            format!("Rename the column '{column_name}' to something that is not a Rust keyword"),
        )?;
        Ok(())
    }
}
