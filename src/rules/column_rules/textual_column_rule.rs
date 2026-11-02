//! Submodule providing the `TextualColumnRule` rule.

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};
use sql_traits::traits::{CheckConstraintLike, ColumnLike, DataTypeLike, DatabaseLike, TableLike};

/// Struct defining a rule that requires every textual column to have an upper
/// length bound, either an enforced declared length or a length check.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = TextualColumnRule::default().into();
///
/// // Invalid: textual column without any upper bound
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE users (name TEXT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Valid: an indexed column passes with any bound
/// let indexed_bounded = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE users (id INT PRIMARY KEY, name TEXT CHECK (LENGTH(name) <= 100000));
///      CREATE INDEX users_name ON users (name);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&indexed_bounded).is_ok());
///
/// // Valid: a bound without a non-empty check
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE users (name TEXT CHECK (LENGTH(name) <= 255));").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// // Valid: a declared length the engine enforces
/// let declared = ParserDB::parse::<GenericDialect>("CREATE TABLE users (name VARCHAR(100));").unwrap();
/// assert!(constrainer.validate_schema(&declared).is_ok());
/// ```
pub struct TextualColumnRule<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for TextualColumnRule<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<TextualColumnRule<DB>> for GenericConstrainer<DB> {
    fn from(constraint: TextualColumnRule<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for TextualColumnRule<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "TextualColumnRule",
            group: LintGroup::Suspicious,
            rationale: "Without an upper bound one value of a client-writable text column can reach about 1 GB, and a bound in the database is a limit no client can skip.",
            source: Some("https://www.postgresql.org/docs/current/datatype-character.html"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for TextualColumnRule<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !column.data_type(database).is_textual(database)
            || column
                .data_type(database)
                .max_character_length(database)
                .is_some()
        {
            return Ok(());
        }
        for check in column.check_constraints(database)? {
            if check.is_upper_bounded_text_constraint(database)?.is_some() {
                return Ok(());
            }
        }

        let table_name = column.table(database).table_name();
        let column_name = column.column_name();
        reporter.column(
            column,
            format!("Textual column '{table_name}.{column_name}' has no upper length bound."),
            format!(
                "Declare an enforced length such as `VARCHAR(n)`, or add `CHECK (LENGTH({column_name}) <= n)`, with n fitting the data and large if the domain needs it."
            ),
        )?;
        Ok(())
    }
}
