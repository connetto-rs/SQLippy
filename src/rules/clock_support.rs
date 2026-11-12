//! Calls reading the current time and the upper bounds they set.

use std::ops::ControlFlow;

use sqlparser::ast::{BinaryOperator, Expr, Visitor};

use crate::rules::policy_support::is_column_reference;
use crate::rules::walk_support::walk;

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
pub(crate) fn is_clock(expression: &Expr) -> bool {
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
    walk(expression, &mut Found).is_continue()
}

/// The clock call an upper bound by the current time reads, with an
/// optional constant tolerance added or subtracted and casts around it.
pub(crate) fn bound_clock(expression: &Expr) -> Option<&Expr> {
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

/// The value and its upper bound when the comparison bounds a value from
/// above, as `value < bound`, `value <= bound` or the mirrored `>` and `>=`.
pub(crate) fn upper_bound(expression: &Expr) -> Option<(&Expr, &Expr)> {
    let Expr::BinaryOp { left, op, right } = expression else {
        return None;
    };
    match op {
        BinaryOperator::Lt | BinaryOperator::LtEq => Some((left, right)),
        BinaryOperator::Gt | BinaryOperator::GtEq => Some((right, left)),
        _ => None,
    }
}
