//! Text columns a check holds to a JSON document, the text a `json` or
//! `jsonb` column would store.

use sql_traits::{
    errors::LookupError,
    traits::{CheckConstraintLike, ColumnLike, DatabaseLike},
};
use sqlparser::ast::{BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments};

use crate::rules::{closed_set_support::names_column, function_reach_support::calls};

/// Whether `expression` is false for every value of the column whose stored
/// name is `column` that is neither `NULL` nor a JSON document. It holds for
/// `json_valid(column)`, `column IS JSON` and `column IS NULL`, for an `AND`
/// with one operand where it holds, and for an `OR` whose operands all hold.
fn rejects_non_json(expression: &Expr, column: &str) -> bool {
    match expression {
        Expr::Nested(inner) => rejects_non_json(inner, column),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => rejects_non_json(left, column) || rejects_non_json(right, column),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => rejects_non_json(left, column) && rejects_non_json(right, column),
        Expr::IsJson {
            expr,
            negated: false,
            ..
        }
        | Expr::IsNull(expr) => names_column(expr, column),
        Expr::Function(function) if calls(function, "json_valid") => matches!(
            &function.args,
            FunctionArguments::List(list) if matches!(
                list.args.first(),
                Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(document)))
                    if names_column(document, column)
            )
        ),
        _ => false,
    }
}

/// Whether an enforced check of `column` holds it to a JSON document, so the
/// column stores what a `json` or `jsonb` column would and never the empty
/// string.
pub(crate) fn holds_json_document<DB: DatabaseLike>(
    database: &DB,
    column: &DB::Column,
) -> Result<bool, LookupError> {
    let stored = column.stored_column_name();
    for check in column
        .check_constraints(database)?
        .filter(|check| check.is_enforced())
    {
        if rejects_non_json(check.expression(database), &stored) {
            return Ok(true);
        }
    }
    Ok(false)
}
