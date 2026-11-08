//! Submodule providing the `PastTimeColumnRule` rule.

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};
use sql_traits::traits::{CheckConstraintLike, ColumnLike, DatabaseLike, TableLike};

/// Struct defining a rule that enforces that time-related columns must have a
/// check constraint ensuring they are in the past.
///
/// This rule checks if a column name ends with `_at` (e.g., `created_at`,
/// `updated_at`).
/// If so, it requires a check constraint involving `NOW()` or
/// `CURRENT_TIMESTAMP` and a less-than operator.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = PastTimeColumnRule::default().into();
///
/// // Invalid: created_at without constraint
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE users (created_at TIMESTAMP);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Valid: created_at with constraint
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE users (created_at TIMESTAMP CHECK (created_at <= NOW()));").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct PastTimeColumnRule<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PastTimeColumnRule<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PastTimeColumnRule<DB>> for GenericConstrainer<DB> {
    fn from(rule: PastTimeColumnRule<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for PastTimeColumnRule<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "PastTimeColumnRule",
            group: LintGroup::Pedantic,
            rationale: "A timestamp recording when something happened cannot lie in the future.",
            source: None,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for PastTimeColumnRule<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let column_name = column.column_name();

        // Identify time-related columns by suffix "_at".
        if !column_name.ends_with("_at") {
            return Ok(());
        }

        // Exclude common future or interval boundary columns.
        let future_or_ambiguous = [
            "expires_at",
            "due_at",
            "starts_at",
            "ends_at",
            "scheduled_at",
        ];
        if future_or_ambiguous.contains(&column_name) {
            return Ok(());
        }

        let has_past_check = column.check_constraints(database)?.any(|cc| {
            let expr = cc.expression(database).to_string().to_lowercase();

            // Check for "now()" or "current_timestamp".
            let mentions_now = expr.contains("now()") || expr.contains("current_timestamp");

            // Check for less than operator.
            let has_lt = expr.contains('<');

            mentions_now && has_lt
        });
        if has_past_check {
            return Ok(());
        }

        let table_name = column.table(database).table_name();
        reporter.column(
            column,
            format!(
                "Time-related column '{table_name}.{column_name}' has no check keeping it in the past."
            ),
            format!(
                "Add `CHECK ({column_name} <= NOW())`. PostgreSQL assumes check conditions are immutable, so a row can fail this check on restore when the restoring server's clock is behind."
            ),
        )?;
        Ok(())
    }
}
