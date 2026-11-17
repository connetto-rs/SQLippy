//! Predicates and expressions that cannot be true, or turn null, while a
//! bound column is null.

use sql_traits::errors::LookupError;
use sqlparser::ast::{CastKind, Expr, InTarget, UnaryOperator};

use crate::rules::credential_support::is_strict_operator;

/// Whether a predicate cannot be true while the column `bound` accepts is
/// null.
pub(crate) fn rejects_null(
    filter: &Expr,
    bound: &impl Fn(&Expr) -> Result<bool, LookupError>,
) -> Result<bool, LookupError> {
    Ok(match filter {
        Expr::IsNotNull(inner) => null_when(inner, bound)?,
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => {
            let mut inner = expr.as_ref();
            while let Expr::Nested(nested) = inner {
                inner = nested;
            }
            match inner {
                Expr::IsNull(inner) => null_when(inner, bound)?,
                _ => null_when(inner, bound)?,
            }
        }
        _ => null_when(filter, bound)?,
    })
}

/// Whether a strict expression becomes null when the column `bound` accepts
/// is null.
pub(crate) fn null_when(
    expression: &Expr,
    bound: &impl Fn(&Expr) -> Result<bool, LookupError>,
) -> Result<bool, LookupError> {
    Ok(match expression {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => bound(expression)?,
        Expr::Nested(inner)
        | Expr::Cast {
            kind: CastKind::Cast | CastKind::DoubleColon,
            expr: inner,
            ..
        }
        | Expr::UnaryOp {
            op: UnaryOperator::Plus | UnaryOperator::Minus | UnaryOperator::Not,
            expr: inner,
        } => null_when(inner, bound)?,
        Expr::BinaryOp { left, op, right } if is_strict_operator(op) => {
            null_when(left, bound)? || null_when(right, bound)?
        }
        Expr::Like { expr, pattern, .. }
        | Expr::ILike { expr, pattern, .. }
        | Expr::SimilarTo { expr, pattern, .. } => {
            null_when(expr, bound)? || null_when(pattern, bound)?
        }
        Expr::Between { expr, .. }
        | Expr::In {
            expr,
            target: InTarget::List(_),
            ..
        } => null_when(expr, bound)?,
        Expr::AnyOp {
            left,
            compare_op,
            right,
            ..
        } if is_strict_operator(compare_op) => null_when(left, bound)? || null_when(right, bound)?,
        _ => false,
    })
}
