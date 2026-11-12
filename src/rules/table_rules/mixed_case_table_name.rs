//! Submodule providing the `MixedCaseTableName` constraint, which enforces that
//! table names are lowercase.

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that table names are lowercase.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `mixed_case_table_name` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = MixedCaseTableName::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE MyTable (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct MixedCaseTableName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for MixedCaseTableName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<MixedCaseTableName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: MixedCaseTableName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for MixedCaseTableName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(MixedCaseTableName),
            group: LintGroup::Style,
            rationale: "PostgreSQL folds unquoted identifiers to lower case, so a mixed-case name has to be quoted in every query.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE \"Notes\" (id INT);",
                good: "CREATE TABLE notes (id INT);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for MixedCaseTableName<DB> {
    type Database = DB;

    fn check_table(
        &self,
        _database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table_name = table.table_name();
        if table_name
            .chars()
            .any(|c| c.is_alphabetic() && !c.is_lowercase())
        {
            reporter.table(
                table,
                format!("Table '{table_name}' is not lowercase."),
                format!("Rename the table to '{}'.", table_name.to_lowercase()),
            )?;
        }
        Ok(())
    }
}
