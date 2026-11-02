//! Submodule providing the `NonEmptyTextualColumnRule` rule.

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};
use sql_traits::traits::{CheckConstraintLike, ColumnLike, DataTypeLike, DatabaseLike, TableLike};

/// Struct defining a rule that requires every textual column to have a check
/// constraint verifying it is not empty.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NonEmptyTextualColumnRule::default().into();
///
/// // Invalid: textual column without a not-empty check
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE users (name TEXT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Valid: textual column with a not-empty check
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE users (name TEXT CHECK (name <> ''));").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct NonEmptyTextualColumnRule<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NonEmptyTextualColumnRule<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NonEmptyTextualColumnRule<DB>> for GenericConstrainer<DB> {
    fn from(constraint: NonEmptyTextualColumnRule<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for NonEmptyTextualColumnRule<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NonEmptyTextualColumnRule",
            group: LintGroup::Pedantic,
            rationale: "An empty string beside NULL gives a column two spellings of a missing value.",
            source: None,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for NonEmptyTextualColumnRule<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !column.data_type(database).is_textual(database) {
            return Ok(());
        }

        let mut has_not_empty_check = false;
        for cc in column.check_constraints(database)? {
            if cc.is_not_empty_text_constraint(database)? {
                has_not_empty_check = true;
                break;
            }
        }
        if has_not_empty_check {
            return Ok(());
        }

        let table_name = column.table(database).table_name();
        let column_name = column.column_name();
        reporter.column(
            column,
            format!(
                "Textual column '{table_name}.{column_name}' has no check rejecting the empty string."
            ),
            format!(
                "Add a check constraint verifying the column is not empty (e.g. `CHECK ({column_name} <> '')`)."
            ),
        )?;
        Ok(())
    }
}
