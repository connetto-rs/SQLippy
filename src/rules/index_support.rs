//! Which comparisons an index can serve and which columns lead an index,
//! shared by the rules that ask whether PostgreSQL can find rows without
//! reading a whole table.

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, IndexLike, TableLike},
};
use sqlparser::ast::{BinaryOperator, Expr, InTarget, Query};

use crate::rules::policy_support::is_column_reference;

/// Calls `visit` with each column side and other side a comparison an index
/// can serve may have.
pub(crate) fn comparison_sides(
    expression: &Expr,
    mut visit: impl FnMut(&Expr, Side<'_>) -> Result<(), LookupError>,
) -> Result<(), LookupError> {
    match expression {
        Expr::BinaryOp {
            left,
            op:
                BinaryOperator::Eq
                | BinaryOperator::Lt
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::GtEq,
            right,
        } => {
            visit(left, Side::Expr(right))?;
            visit(right, Side::Expr(left))
        }
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => visit(left, Side::Expr(right)),
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated: false,
            ..
        } => visit(expr, Side::List(list)),
        Expr::In {
            expr,
            target: InTarget::Subquery(subquery),
            negated: false,
            ..
        } => visit(expr, Side::Query(subquery)),
        _ => Ok(()),
    }
}

/// The side of a comparison facing the column.
#[derive(Clone, Copy)]
pub(crate) enum Side<'e> {
    Expr(&'e Expr),
    List(&'e Vec<Expr>),
    Query(&'e Query),
}

/// The first element of an index, unwrapped from parentheses.
pub(crate) fn leading(expression: &Expr) -> &Expr {
    match expression {
        Expr::Nested(inner) => leading(inner),
        Expr::Tuple(elements) => elements.first().map_or(expression, leading),
        _ => expression,
    }
}

/// Whether an index without a predicate leads with `column`.
fn leads<DB: DatabaseLike, I: IndexLike<DB = DB>>(
    database: &DB,
    index: &I,
    column: &DB::Column,
) -> Result<bool, LookupError> {
    Ok(index.predicate().is_none()
        && is_column_reference(leading(index.expression(database)?))
        && index.columns(database)?.next() == Some(column))
}

/// Whether an index without a predicate, a unique constraint or the primary
/// key of `table` leads with `column`.
pub(crate) fn indexed<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    column: &DB::Column,
) -> Result<bool, LookupError> {
    for index in table.indices(database)? {
        if leads(database, index, column)? {
            return Ok(true);
        }
    }
    for index in table.unique_indices(database)? {
        if leads(database, index, column)? {
            return Ok(true);
        }
    }
    Ok(false)
}
