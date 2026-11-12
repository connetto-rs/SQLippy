//! Submodule providing the `RustKeywordColumnName` constraint, which enforces
//! that column names are not Rust keywords.

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::rust_keywords::is_rust_keyword,
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that column names are not Rust
/// keywords.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `rust_keyword_column_name` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = RustKeywordColumnName::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (struct INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (my_struct INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct RustKeywordColumnName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RustKeywordColumnName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RustKeywordColumnName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: RustKeywordColumnName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for RustKeywordColumnName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RustKeywordColumnName),
            group: LintGroup::Restriction,
            rationale: "Code generated from the schema cannot name a Rust item after a keyword without a raw identifier.",
            source: Some("https://doc.rust-lang.org/reference/keywords.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE t (struct INT);",
                good: "CREATE TABLE t (my_struct INT);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for RustKeywordColumnName<DB> {
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
