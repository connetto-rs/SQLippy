//! Submodule providing the `RustKeywordTableName` constraint, which enforces
//! that table names are not Rust keywords.

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::rust_keywords::is_rust_keyword,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that table names are not Rust
/// keywords.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `rust_keyword_table_name` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = RustKeywordTableName::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE struct (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE my_struct (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct RustKeywordTableName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RustKeywordTableName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RustKeywordTableName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: RustKeywordTableName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for RustKeywordTableName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RustKeywordTableName),
            group: LintGroup::Restriction,
            rationale: "Code generated from the schema cannot name a Rust item after a keyword without a raw identifier.",
            source: Some("https://doc.rust-lang.org/reference/keywords.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE struct (id INT);",
                good: "CREATE TABLE structs (id INT);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for RustKeywordTableName<DB> {
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
