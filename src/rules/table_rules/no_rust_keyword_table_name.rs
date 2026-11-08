//! Submodule providing the `NoRustKeywordTableName` constraint, which enforces
//! that table names are not Rust keywords.

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::rust_keywords::is_rust_keyword,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that table names are not Rust
/// keywords.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `NoRustKeywordTableName` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NoRustKeywordTableName::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE struct (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE my_struct (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct NoRustKeywordTableName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NoRustKeywordTableName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NoRustKeywordTableName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: NoRustKeywordTableName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for NoRustKeywordTableName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NoRustKeywordTableName",
            group: LintGroup::Restriction,
            rationale: "Code generated from the schema cannot name a Rust item after a keyword without a raw identifier.",
            source: Some("https://doc.rust-lang.org/reference/keywords.html"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for NoRustKeywordTableName<DB> {
    type Database = DB;

    fn check_table(
        &self,
        _database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table_name = table.table_name();
        if is_rust_keyword(table_name) {
            reporter.table(
                table,
                format!("Table name '{table_name}' is a Rust keyword."),
                format!("Rename the table '{table_name}' to a name that is not a Rust keyword."),
            )?;
        }
        Ok(())
    }
}
