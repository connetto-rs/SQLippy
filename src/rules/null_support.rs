//! Predicates and expressions that cannot be true, or turn null, while a
//! bound column is null.

use sql_traits::{
    errors::LookupError,
    structs::{ExpressionContext, OperatorResolution},
    traits::{DatabaseLike, FunctionLike, OperatorLike},
};
use sqlparser::ast::{BinaryOperator, CastKind, Expr, InTarget, UnaryOperator};

/// Whether a predicate cannot be true while the column `bound` accepts is
/// null, reading operators as `types` types them.
pub(crate) fn rejects_null<DB: DatabaseLike>(
    filter: &Expr,
    bound: &impl Fn(&Expr) -> Result<bool, LookupError>,
    database: &DB,
    types: &ExpressionContext<'_, '_, DB>,
) -> Result<bool, LookupError> {
    Ok(match filter {
        Expr::IsNotNull(inner) => null_when(inner, bound, database, types)?,
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => {
            let mut inner = expr.as_ref();
            while let Expr::Nested(nested) = inner {
                inner = nested;
            }
            match inner {
                Expr::IsNull(inner) => null_when(inner, bound, database, types)?,
                _ => null_when(inner, bound, database, types)?,
            }
        }
        _ => null_when(filter, bound, database, types)?,
    })
}

/// Whether a strict expression becomes null when the column `bound` accepts
/// is null, reading operators as `types` types them.
pub(crate) fn null_when<DB: DatabaseLike>(
    expression: &Expr,
    bound: &impl Fn(&Expr) -> Result<bool, LookupError>,
    database: &DB,
    types: &ExpressionContext<'_, '_, DB>,
) -> Result<bool, LookupError> {
    let null = |inner: &Expr| null_when(inner, bound, database, types);
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
        } => null(inner)?,
        Expr::BinaryOp {
            left,
            op: operator,
            right,
        }
        | Expr::AnyOp {
            left,
            compare_op: operator,
            right,
            ..
        } => {
            let (left_strict, right_strict) = strictness(database, types, expression, operator)?;
            (left_strict && null(left)?) || (right_strict && null(right)?)
        }
        Expr::Like { expr, pattern, .. }
        | Expr::ILike { expr, pattern, .. }
        | Expr::SimilarTo { expr, pattern, .. } => null(expr)? || null(pattern)?,
        Expr::Between { expr, .. }
        | Expr::In {
            expr,
            target: InTarget::List(_),
            ..
        } => null(expr)?,
        _ => false,
    })
}

/// Whether `expression`, applying `operator`, is `NULL` for a `NULL` left
/// operand and for a `NULL` right one, as the function implementing the
/// operator PostgreSQL selects declares. Where `types` cannot tell the
/// selection, each overload of a comparison or an arithmetic operator is
/// strict, unlike those of `||`, which appends to an array whatever the
/// other operand holds.
pub(crate) fn strictness<DB: DatabaseLike>(
    database: &DB,
    types: &ExpressionContext<'_, '_, DB>,
    expression: &Expr,
    operator: &BinaryOperator,
) -> Result<(bool, bool), LookupError> {
    if let Some(applications) = types.operators(expression)?
        && let [application] = applications.as_slice()
        && let OperatorResolution::Selected(selected) = application.resolution()
        && let Some(function) = selected.operator().implementation(database)
    {
        return Ok((
            function.returns_null_on_null_argument(database, 0),
            function.returns_null_on_null_argument(database, 1),
        ));
    }
    let strict = is_strict_operator(operator);
    Ok((strict, strict))
}

/// Operators whose every overload yields `NULL` when an operand is `NULL`.
fn is_strict_operator(operator: &BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Lt
            | BinaryOperator::LtEq
            | BinaryOperator::Gt
            | BinaryOperator::GtEq
            | BinaryOperator::Plus
            | BinaryOperator::Minus
            | BinaryOperator::Multiply
            | BinaryOperator::Divide
            | BinaryOperator::Modulo
            | BinaryOperator::PGRegexMatch
            | BinaryOperator::PGRegexIMatch
            | BinaryOperator::PGRegexNotMatch
            | BinaryOperator::PGRegexNotIMatch
            | BinaryOperator::Arrow
            | BinaryOperator::LongArrow
    )
}
