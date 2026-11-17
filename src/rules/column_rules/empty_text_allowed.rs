//! Submodule providing the `EmptyTextAllowed` rule.

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::key_support::holds_through_references,
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};
use sql_traits::{
    errors::LookupError,
    traits::{CheckConstraintLike, ColumnLike, DataTypeLike, DatabaseLike, TableLike},
};

/// Whether a check constraint of `column` rejects the empty string.
fn rejects_empty<DB: DatabaseLike>(
    database: &DB,
    column: &DB::Column,
) -> Result<bool, LookupError> {
    for check in column.check_constraints(database)? {
        if check.is_not_empty_text_constraint(database)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Struct defining a rule that requires every textual column to have a check
/// constraint verifying it is not empty, its own or that of a column a
/// foreign key forces its values to equal.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = EmptyTextAllowed::default().into();
///
/// // Invalid: textual column without a not-empty check
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE users (name TEXT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Valid: textual column with a not-empty check
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE users (name TEXT CHECK (name <> ''));").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// // Valid: a reference to a non-empty key
/// let referencing = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE statuses (id TEXT PRIMARY KEY CHECK (id <> ''));
///      CREATE TABLE runs (id INT PRIMARY KEY, status_id TEXT NOT NULL REFERENCES statuses (id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&referencing).is_ok());
/// ```
pub struct EmptyTextAllowed<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for EmptyTextAllowed<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<EmptyTextAllowed<DB>> for GenericConstrainer<DB> {
    fn from(constraint: EmptyTextAllowed<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for EmptyTextAllowed<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(EmptyTextAllowed),
            group: LintGroup::Pedantic,
            rationale: "An empty string beside NULL gives a column two spellings of a missing value.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE users (name TEXT);",
                good: "CREATE TABLE users (name TEXT CHECK (name <> ''));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for EmptyTextAllowed<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !column.data_type(database).is_textual(database)
            || holds_through_references(database, column, |source| rejects_empty(database, source))?
        {
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
