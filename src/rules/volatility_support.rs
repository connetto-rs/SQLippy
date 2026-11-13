//! Finds the terms of an expression that PostgreSQL may evaluate to another
//! value on each call.

use std::ops::ControlFlow;

use sql_traits::{
    traits::{DatabaseLike, FunctionLike, OperatorLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{BinaryOperator, Expr, FunctionBehavior, Visitor};

use crate::rules::walk_support::walk;

/// Whether an operator written `name` may run a `VOLATILE` function, `custom`
/// when it is written `OPERATOR(...)`, which then also holds when it names no
/// known operator.
fn operator_is_volatile<DB: DatabaseLike>(database: &DB, name: &str, custom: bool) -> bool {
    let Some(operators) = database.operators() else {
        return custom;
    };
    let mut matched = false;
    for operator in operators.filter(|operator| operator.target_name().name() == name) {
        matched = true;
        if operator
            .implementation(database)
            .is_none_or(|function| function.volatility() == FunctionBehavior::Volatile)
        {
            return true;
        }
    }
    custom && !matched
}

/// Whether the binary operator `op` may run a `VOLATILE` function.
fn binary_operator_is_volatile<DB: DatabaseLike>(database: &DB, op: &BinaryOperator) -> bool {
    match op {
        BinaryOperator::PGCustomBinaryOperator(parts) => parts
            .last()
            .is_none_or(|name| operator_is_volatile(database, name, true)),
        _ => operator_is_volatile(database, &op.to_string(), false),
    }
}

/// Whether `expression` itself, apart from its operands and arguments, may
/// run a `VOLATILE` function: a call whose name reaches a `VOLATILE` overload
/// or no known function, or an operator, quantified by `ANY` or `ALL` or
/// not, whose name reaches one with a `VOLATILE` or unknown implementation,
/// `OPERATOR(...)` naming no known operator included.
fn is_volatile_term<DB: DatabaseLike>(database: &DB, expression: &Expr) -> bool {
    match expression {
        Expr::Function(call) => call
            .name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .is_none_or(|name| {
                let name = normalize_identifier(&name.value, name.quote_style.is_some());
                let mut reached = database.functions_named(&name).peekable();
                reached.peek().is_none()
                    || reached.any(|function| function.volatility() == FunctionBehavior::Volatile)
            }),
        Expr::BinaryOp { op, .. }
        | Expr::AnyOp { compare_op: op, .. }
        | Expr::AllOp { compare_op: op, .. } => binary_operator_is_volatile(database, op),
        Expr::UnaryOp { op, .. } => operator_is_volatile(database, &op.to_string(), false),
        _ => false,
    }
}

/// Finds a term [`is_volatile_term`] reports.
struct VolatileTerm<'a, DB>(&'a DB);

impl<DB: DatabaseLike> Visitor for VolatileTerm<'_, DB> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if is_volatile_term(self.0, expression) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Whether evaluating `expression` may run a `VOLATILE` function, directly
/// or through an operator, a call or operator the schema does not declare
/// included.
pub(crate) fn runs_volatile<DB: DatabaseLike>(database: &DB, expression: &Expr) -> bool {
    walk(expression, &mut VolatileTerm(database)).is_break()
}
