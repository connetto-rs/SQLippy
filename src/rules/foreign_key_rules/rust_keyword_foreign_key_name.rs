//! Submodule providing the `RustKeywordForeignKeyName` constraint, which
//! enforces that foreign key names are not Rust keywords.

use sql_traits::traits::{DatabaseLike, ForeignKeyLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::rust_keywords::is_rust_keyword,
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that foreign key names are not
/// Rust keywords.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `rust_keyword_foreign_key_name` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = RustKeywordForeignKeyName::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE other_table (id INT PRIMARY KEY); CREATE TABLE mytable (id INT, CONSTRAINT struct FOREIGN KEY (id) REFERENCES other_table (id));").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE other_table (id INT PRIMARY KEY); CREATE TABLE mytable (id INT, CONSTRAINT my_struct FOREIGN KEY (id) REFERENCES other_table (id));").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct RustKeywordForeignKeyName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RustKeywordForeignKeyName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RustKeywordForeignKeyName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: RustKeywordForeignKeyName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for RustKeywordForeignKeyName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RustKeywordForeignKeyName),
            group: LintGroup::Restriction,
            rationale: "Code generated from the schema cannot name a Rust item after a keyword without a raw identifier.",
            source: Some("https://doc.rust-lang.org/reference/keywords.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (parent_id INT, CONSTRAINT struct FOREIGN KEY (parent_id) REFERENCES parents (id));",
                good: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (parent_id INT, CONSTRAINT parent_fk FOREIGN KEY (parent_id) REFERENCES parents (id));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for RustKeywordForeignKeyName<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        _database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if let Some(name) = foreign_key.foreign_key_name()
            && is_rust_keyword(name)
        {
            reporter.foreign_key(
                foreign_key,
                format!("Foreign key name '{name}' is a Rust keyword."),
                format!("Rename the foreign key '{name}' to a name that is not a Rust keyword."),
            )?;
        }
        Ok(())
    }
}
