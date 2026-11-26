//! Predicates and expressions that cannot be true, or turn null, while a
//! bound column is null, and stored columns whose rows may hold null.

use sql_traits::{
    errors::LookupError,
    structs::{Assumption, CallResolution, ExpressionContext, IdentifierCase, OperatorResolution},
    traits::{
        CheckConstraintLike, ColumnLike, DatabaseLike, FunctionLike, OperatorLike, TableLike,
    },
};
use sqlparser::ast::{BinaryOperator, CastKind, Expr, Ident, InTarget, UnaryOperator};

/// Whether a row of the table of `column` may hold `NULL` in it, which its
/// declaration allows and the table's enforced and validated checks do not
/// rule out, as `CHECK (c IS NOT NULL)` does, or `CHECK (c IS NOT NULL OR
/// kind = 'z')` with `kind` held to other values.
///
/// # Errors
///
/// Returns the lookup error reading the column or the checks of its table
/// raised.
pub(crate) fn may_hold_null<DB: DatabaseLike>(
    database: &DB,
    column: &DB::Column,
) -> Result<bool, LookupError> {
    if !column.is_nullable(database)? {
        return Ok(false);
    }
    let mut checked = false;
    for check in column.check_constraints(database)? {
        checked |= check.is_enforced() && check.is_validated(database)?;
    }
    if !checked {
        return Ok(true);
    }
    let table = column.table(database);
    let mut checks = Vec::new();
    for check in table.check_constraints(database)? {
        if check.is_enforced() && check.is_validated(database)? {
            checks.push(Assumption::Check(check));
        }
    }
    let null = Expr::IsNull(Box::new(Expr::Identifier(Ident::with_quote(
        '"',
        column.stored_column_name().as_ref(),
    ))));
    Ok(table
        .truth_under(database, &null, IdentifierCase::AsWritten, &checks)?
        .outcomes
        .truth)
}

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
        Expr::Nested(inner) => rejects_null(inner, bound, database, types)?,
        // A `NULL` left operand makes the comparison `NULL`, or `false` over
        // no element, and neither is true.
        Expr::AnyOp {
            left, compare_op, ..
        } => {
            (strictness(database, types, filter, compare_op)?.0
                && null_when(left, bound, database, types)?)
                || null_when(filter, bound, database, types)?
        }
        // A `NULL` left operand makes `IN` over a query `NULL`, or `false`
        // over no row, and neither is true.
        Expr::In {
            expr,
            target: InTarget::Subquery(_),
            negated: false,
            ..
        } => null_when(expr, bound, database, types)?,
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
        } => {
            let (left_strict, right_strict) = strictness(database, types, expression, operator)?;
            (left_strict && null(left)?) || (right_strict && null(right)?)
        }
        Expr::AnyOp {
            left,
            compare_op: operator,
            right,
            ..
        } => {
            let (left_strict, right_strict) = strictness(database, types, expression, operator)?;
            let has_elements =
                matches!(right.as_ref(), Expr::Array(array) if !array.elem.is_empty());
            (left_strict && has_elements && null(left)?) || (right_strict && null(right)?)
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
        Expr::Function(_) => find_null_passing_argument(database, types, expression, |argument| {
            Ok(null(argument)?.then_some(()))
        })?
        .is_some(),
        _ => false,
    })
}

/// The first of `judge`'s answers for the arguments of the call `expression`
/// that pass a parameter whose `NULL` makes the function PostgreSQL selects
/// return `NULL`, none where `types` cannot tell the selection.
pub(crate) fn find_null_passing_argument<'node, DB: DatabaseLike, T>(
    database: &DB,
    types: &ExpressionContext<'_, '_, DB>,
    expression: &'node Expr,
    mut judge: impl FnMut(&'node Expr) -> Result<Option<T>, LookupError>,
) -> Result<Option<T>, LookupError> {
    let Some(application) = types.call(expression)? else {
        return Ok(None);
    };
    let CallResolution::Selected(selected) = application.resolution() else {
        return Ok(None);
    };
    for (&argument, passed) in application.arguments().iter().zip(selected.arguments()) {
        if selected
            .function()
            .returns_null_on_null_argument(database, passed.parameter())
            && let Some(answer) = judge(argument)?
        {
            return Ok(Some(answer));
        }
    }
    Ok(None)
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

/// Operators whose every overload yields a value when both operands hold one.
pub(crate) fn yields_value_for_values(operator: &BinaryOperator) -> bool {
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
            | BinaryOperator::StringConcat
            | BinaryOperator::And
            | BinaryOperator::Or
    )
}

/// Operators reading a key, an element or a path of their left operand,
/// which yield `NULL` where the operand lacks it.
pub(crate) fn extracts_part(operator: &BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::Arrow
            | BinaryOperator::LongArrow
            | BinaryOperator::HashArrow
            | BinaryOperator::HashLongArrow
    )
}
