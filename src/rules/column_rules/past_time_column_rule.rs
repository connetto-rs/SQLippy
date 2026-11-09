//! Submodule providing the `PastTimeColumnRule` rule.

use std::time::Duration;

use sql_traits::{
    traits::{CheckConstraintLike, ColumnLike, DatabaseLike, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{BinaryOperator, Expr, Ident};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::clock_support::{bound_clock, upper_bound},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports a time-related column with no check
/// keeping it in the past.
///
/// A column whose name ends with `_at` is time-related, apart from names of
/// future instants such as `expires_at`. A check keeps it in the past when a
/// top-level `AND` conjunct bounds the plain column from above by the
/// current time, optionally plus a constant tolerance. The resolution adds
/// the tolerance the deployment declares with
/// [`Deployment::with_clock_tolerance`](crate::deployment::Deployment::with_clock_tolerance).
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

/// The PostgreSQL interval text measuring `tolerance` whole, in minutes,
/// seconds, milliseconds or microseconds, or `None` for no tolerance.
fn interval_text(tolerance: Duration) -> Option<String> {
    let micros = tolerance.as_micros();
    let (count, unit) = match micros {
        0 => return None,
        _ if micros.is_multiple_of(60_000_000) => (micros / 60_000_000, "minute"),
        _ if micros.is_multiple_of(1_000_000) => (micros / 1_000_000, "second"),
        _ if micros.is_multiple_of(1_000) => (micros / 1_000, "millisecond"),
        _ => (micros, "microsecond"),
    };
    let plural = if count == 1 { "" } else { "s" };
    Some(format!("{count} {unit}{plural}"))
}

/// Whether the expression is a reference to the column with this stored
/// name.
fn names_column(expression: &Expr, column: &str) -> bool {
    let is_column =
        |ident: &Ident| normalize_identifier(&ident.value, ident.quote_style.is_some()) == column;
    match expression {
        Expr::Nested(inner) => names_column(inner, column),
        Expr::Identifier(ident) => is_column(ident),
        Expr::CompoundIdentifier(parts) => parts.last().is_some_and(is_column),
        _ => false,
    }
}

/// Whether a top-level `AND` conjunct of the check bounds the column from
/// above by the current time.
fn keeps_in_past(expression: &Expr, column: &str) -> bool {
    match expression {
        Expr::Nested(inner) => keeps_in_past(inner, column),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => keeps_in_past(left, column) || keeps_in_past(right, column),
        _ => upper_bound(expression).is_some_and(|(value, bound)| {
            names_column(value, column) && bound_clock(bound).is_some()
        }),
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

        if column
            .check_constraints(database)?
            .any(|check| keeps_in_past(check.expression(database), column_name))
        {
            return Ok(());
        }

        let table_name = column.table(database).table_name();
        let resolution = match reporter
            .deployment()
            .clock_tolerance()
            .and_then(interval_text)
        {
            Some(tolerance) => format!(
                "Add `CHECK ({column_name} <= now() + interval '{tolerance}')`, the deployment's clock tolerance. A row stamped by a clock running more than {tolerance} ahead of the database's is refused until the database's clock catches up."
            ),
            None => format!(
                "Add `CHECK ({column_name} <= now())`, adding the tolerance declared with `Deployment::with_clock_tolerance` when the clocks stamping rows can run ahead. A row stamped by a clock running ahead of the database's is refused until the database's clock catches up."
            ),
        };
        reporter.column(
            column,
            format!(
                "Time-related column '{table_name}.{column_name}' has no check keeping it in the past."
            ),
            resolution,
        )?;
        Ok(())
    }
}
