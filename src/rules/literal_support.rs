//! Literals written in expressions, read through the parentheses and casts
//! around them.

use std::borrow::Cow;

use sqlparser::ast::{Expr, UnaryOperator, Value};

/// The text of a string literal, in any quoting PostgreSQL accepts.
pub(crate) fn string_value(value: &Value) -> Option<&str> {
    match value {
        Value::SingleQuotedString(text)
        | Value::EscapedStringLiteral(text)
        | Value::UnicodeStringLiteral(text)
        | Value::NationalStringLiteral(text) => Some(text),
        Value::DollarQuotedString(quoted) => Some(&quoted.value),
        _ => None,
    }
}

/// The literal `expression` is under parentheses and casts, `NULL`
/// included.
pub(crate) fn literal(mut expression: &Expr) -> Option<&Value> {
    loop {
        match expression {
            Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => expression = inner,
            Expr::Value(literal) => return Some(&literal.value),
            Expr::TypedString(typed) => return Some(&typed.value.value),
            _ => return None,
        }
    }
}

/// The text of the string literal `expression` is under parentheses and
/// casts.
pub(crate) fn text_literal(expression: &Expr) -> Option<&str> {
    literal(expression).and_then(string_value)
}

/// The number `expression` writes under parentheses, casts and signs, as
/// written with its sign, such as `32` or `-2.5`.
pub(crate) fn number_literal(mut expression: &Expr) -> Option<Cow<'_, str>> {
    let mut negative = false;
    loop {
        match expression {
            Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => expression = inner,
            Expr::UnaryOp {
                op: UnaryOperator::Minus,
                expr,
            } => {
                negative = !negative;
                expression = expr;
            }
            Expr::UnaryOp {
                op: UnaryOperator::Plus,
                expr,
            } => expression = expr,
            Expr::Value(literal) => {
                let Value::Number(digits, _) = &literal.value else {
                    return None;
                };
                return Some(if negative {
                    Cow::Owned(format!("-{digits}"))
                } else {
                    Cow::Borrowed(digits)
                });
            }
            _ => return None,
        }
    }
}
