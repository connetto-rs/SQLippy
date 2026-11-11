//! Submodule providing the `LowercaseColumnName` constraint, which enforces
//! that column names are lowercase.

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that column names are lowercase.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `LowercaseColumnName` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = LowercaseColumnName::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (Id INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (id INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct LowercaseColumnName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for LowercaseColumnName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<LowercaseColumnName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: LowercaseColumnName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for LowercaseColumnName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "LowercaseColumnName",
            group: LintGroup::Style,
            rationale: "PostgreSQL folds unquoted identifiers to lower case, so a mixed-case name has to be quoted in every query.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS",
            ),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for LowercaseColumnName<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if column
            .column_name()
            .chars()
            .all(|c| !c.is_alphabetic() || c.is_lowercase())
        {
            return Ok(());
        }

        let table_name = column.table(database).table_name();
        let column_name = column.column_name();
        reporter.column(
            column,
            format!("Column '{column_name}' in table '{table_name}' is not lowercase"),
            format!("Rename column '{column_name}' in table '{table_name}' to be all lowercase"),
        )?;
        Ok(())
    }
}
