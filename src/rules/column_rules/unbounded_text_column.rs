//! Submodule providing the `UnboundedTextColumn` rule.

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{json_support::holds_json_document, key_support::holds_through_references},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};
use sql_traits::{
    errors::LookupError,
    traits::{CheckConstraintLike, ColumnLike, DataTypeLike, DatabaseLike, TableLike},
};

/// Whether `column` declares an enforced length or an enforced check bounds
/// its length.
fn is_bounded<DB: DatabaseLike>(database: &DB, column: &DB::Column) -> Result<bool, LookupError> {
    if column
        .data_type(database)
        .max_character_length(database)
        .is_some()
    {
        return Ok(true);
    }
    for check in column
        .check_constraints(database)?
        .filter(|check| check.is_enforced())
    {
        if check.is_upper_bounded_text_constraint(database)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Struct defining a rule that requires every textual column to have an upper
/// length bound, either a declared length the engine enforces or a length
/// check, its own or that of a column a foreign key forces its values to
/// equal.
///
/// SQLite enforces no declared length, so there only a check bounds a
/// column.
///
/// A textual column a check holds to a JSON document, with `json_valid` or
/// `IS JSON`, stores what a `json` or `jsonb` column would, and passes as
/// those do.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UnboundedTextColumn::default().into();
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
///
/// // Valid: a reference to a bounded key
/// let referencing = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE statuses (id TEXT PRIMARY KEY CHECK (LENGTH(id) <= 63));
///      CREATE TABLE runs (id INT PRIMARY KEY, status_id TEXT NOT NULL REFERENCES statuses (id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&referencing).is_ok());
///
/// // Valid: a JSON document, as SQLite stores one
/// let document = ParserDB::parse::<GenericDialect>("CREATE TABLE events (payload TEXT CHECK (json_valid(payload)));").unwrap();
/// assert!(constrainer.validate_schema(&document).is_ok());
/// ```
pub struct UnboundedTextColumn<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnboundedTextColumn<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnboundedTextColumn<DB>> for GenericConstrainer<DB> {
    fn from(constraint: UnboundedTextColumn<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for UnboundedTextColumn<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UnboundedTextColumn),
            group: LintGroup::Suspicious,
            rationale: "Without an upper bound one value of a client-writable text column can reach about 1 GB, and a bound in the database is a limit no client can skip.",
            source: Some("https://www.postgresql.org/docs/current/datatype-character.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE users (name TEXT);",
                good: "CREATE TABLE users (name TEXT CHECK (LENGTH(name) <= 255));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for UnboundedTextColumn<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !column.data_type(database).is_textual(database)
            || holds_through_references(database, column, |source| {
                Ok(is_bounded(database, source)? || holds_json_document(database, source)?)
            })?
        {
            return Ok(());
        }

        let table_name = column.table(database).table_name();
        let column_name = column.column_name();
        let check = format!("`CHECK (LENGTH({column_name}) <= n)`");
        let bound = match Engine::of(database) {
            Engine::PostgreSql => {
                format!("Declare an enforced length such as `VARCHAR(n)`, or add {check}")
            }
            Engine::Sqlite => format!("Add {check}"),
        };
        reporter.column(
            column,
            format!("Textual column '{table_name}.{column_name}' has no upper length bound."),
            format!("{bound}, with n fitting the data and large if the domain needs it."),
        )?;
        Ok(())
    }
}
