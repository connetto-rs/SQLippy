//! Submodule providing the `TimeDependentCheck` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    traits::{CheckConstraintLike, DatabaseLike, FunctionLike, TableLike},
};
use sqlparser::ast::{BinaryOperator, Expr, FunctionArguments, FunctionBehavior, Visit, Visitor};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::policy_support::is_column_reference,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Functions reading the current time.
const CLOCKS: [&str; 9] = [
    "now",
    "current_timestamp",
    "current_date",
    "current_time",
    "localtimestamp",
    "localtime",
    "transaction_timestamp",
    "statement_timestamp",
    "clock_timestamp",
];

/// Whether the expression calls a function reading the current time.
fn is_clock(expression: &Expr) -> bool {
    matches!(expression, Expr::Function(call) if call
        .name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .is_some_and(|ident| CLOCKS.iter().any(|clock| ident.value.eq_ignore_ascii_case(clock))))
}

/// Whether the expression reads no column and calls nothing.
fn is_constant(expression: &Expr) -> bool {
    struct Found;
    impl Visitor for Found {
        type Break = ();
        fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            if is_column_reference(expression) || matches!(expression, Expr::Function(_)) {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        }
    }
    expression.visit(&mut Found).is_continue()
}

/// The clock call an upper bound by the current time reads, with an
/// optional constant tolerance added or subtracted and casts around it.
fn bound_clock(expression: &Expr) -> Option<&Expr> {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => bound_clock(inner),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Plus | BinaryOperator::Minus,
            right,
        } if is_constant(right) => bound_clock(left),
        _ => is_clock(expression).then_some(expression),
    }
}

/// Finds the calls of a check whose result can change over time, apart from
/// clocks bounding a value from above.
struct Changing<'a, 'db, DB: DatabaseLike> {
    database: &'db DB,
    check: &'a DB::CheckConstraint,
    exempt: Vec<*const Expr>,
    found: Vec<String>,
}

impl<DB: DatabaseLike> Changing<'_, '_, DB> {
    /// Whether a call can return another result later for the same
    /// arguments.
    fn changes(&self, expression: &Expr) -> Result<bool, LookupError> {
        let Expr::Function(call) = expression else {
            return Ok(false);
        };
        if is_clock(expression) {
            return Ok(true);
        }
        if matches!(call.args, FunctionArguments::None) {
            return Ok(false);
        }
        Ok(self
            .check
            .functions_reached_by(call, self.database)?
            .any(|function| function.volatility() != FunctionBehavior::Immutable))
    }
}

impl<DB: DatabaseLike> Visitor for Changing<'_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if let Expr::BinaryOp { left, op, right } = expression {
            let upper = match op {
                BinaryOperator::Lt | BinaryOperator::LtEq => Some(right),
                BinaryOperator::Gt | BinaryOperator::GtEq => Some(left),
                _ => None,
            };
            self.exempt.extend(
                upper
                    .and_then(|upper| bound_clock(upper))
                    .map(std::ptr::from_ref),
            );
        }
        if self.exempt.contains(&std::ptr::from_ref(expression)) {
            return ControlFlow::Continue(());
        }
        self.changes(expression)
            .map_or_else(ControlFlow::Break, |changes| {
                if changes {
                    self.found.push(expression.to_string());
                }
                ControlFlow::Continue(())
            })
    }
}

/// Struct defining a rule that reports a `CHECK` whose result can turn from
/// true to false as time passes.
///
/// The rule reports a call to a function reading the current time, to a
/// `VOLATILE` built-in such as `random()`, or to a user function that is not
/// `IMMUTABLE`. A clock bounding a value from above, optionally with a
/// constant tolerance, is exempt: once such a check holds it holds forever.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = TimeDependentCheck::default().into();
/// let future = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (expires TIMESTAMPTZ CHECK (expires > now()));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&future).is_err());
/// let past = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (created TIMESTAMPTZ CHECK (created <= now() + interval '5 minutes'));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&past).is_ok());
/// ```
pub struct TimeDependentCheck<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for TimeDependentCheck<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<TimeDependentCheck<DB>> for GenericConstrainer<DB> {
    fn from(rule: TimeDependentCheck<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for TimeDependentCheck<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "TimeDependentCheck",
            group: LintGroup::Suspicious,
            rationale: "PostgreSQL assumes a CHECK is immutable and tests it only when a row is written, so a check that turns false as time passes leaves stored rows that fail it, and a dump of them fails to restore.",
            source: Some("https://www.postgresql.org/docs/current/ddl-constraints.html"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for TimeDependentCheck<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for check in table.check_constraints(database)? {
            let mut changing = Changing {
                database,
                check,
                exempt: Vec::new(),
                found: Vec::new(),
            };
            check
                .expression(database)
                .visit(&mut changing)
                .break_value()
                .map_or(Ok(()), Err)?;
            if changing.found.is_empty() {
                continue;
            }
            reporter.table(
                table,
                format!(
                    "A check on '{}' calls {}, so a row it accepts can fail it later.",
                    table.table_name(),
                    changing.found.join(", ")
                ),
                "Keep the check to immutable expressions, bounding values by the current time only from above, and enforce the rest in a trigger or in the writes.".to_owned(),
            )?;
        }
        Ok(())
    }
}
