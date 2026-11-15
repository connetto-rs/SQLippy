//! Text columns a check constraint restricts to a list of string literals,
//! shared by the rules that read such a column as a closed set.

use sql_traits::{
    errors::LookupError,
    traits::{CheckConstraintLike, ColumnLike, DataTypeLike, DatabaseLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{BinaryOperator, Expr, Ident, InTarget};

use crate::rules::{
    literal_support::text_literal, policy_support::conjuncts, type_support::underlying_type,
};

/// Whether `expression`, under parentheses, names the column whose stored
/// name is `column`, bare or qualified.
pub(crate) fn names_column(mut expression: &Expr, column: &str) -> bool {
    while let Expr::Nested(inner) = expression {
        expression = inner;
    }
    let stored =
        |name: &Ident| normalize_identifier(&name.value, name.quote_style.is_some()) == column;
    match expression {
        Expr::Identifier(name) => stored(name),
        Expr::CompoundIdentifier(parts) => parts.last().is_some_and(stored),
        _ => false,
    }
}

/// Whether `expression`, under parentheses and casts, names the column whose
/// stored name is `column`, as PostgreSQL prints a `varchar` column compared
/// with text.
pub(crate) fn names_cast_column(mut expression: &Expr, column: &str) -> bool {
    while let Expr::Nested(inner) | Expr::Cast { expr: inner, .. } = expression {
        expression = inner;
    }
    names_column(expression, column)
}

/// The text of every element of `list`, or `None` when one is not a string
/// literal.
fn texts(list: &[Expr]) -> Option<Vec<&str>> {
    list.iter().map(text_literal).collect()
}

/// The elements of `ARRAY[...]` under parentheses and casts.
fn array_elements(mut expression: &Expr) -> Option<&[Expr]> {
    loop {
        match expression {
            Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => expression = inner,
            Expr::Array(array) => return Some(&array.elem),
            _ => return None,
        }
    }
}

/// The literals `expression` admits for the column whose stored name is
/// `column`, written `column IN ('a', ...)`, `column = ANY (ARRAY['a', ...])`
/// or an `OR` of `column = 'a'` equalities in either operand order.
fn listed<'e>(expression: &'e Expr, column: &str) -> Option<Vec<&'e str>> {
    match expression {
        Expr::Nested(inner) => listed(inner, column),
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated: false,
            ..
        } if names_cast_column(expr, column) => texts(list),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } if names_cast_column(left, column) => texts(array_elements(right)?),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            if names_cast_column(left, column) {
                text_literal(right).map(|text| vec![text])
            } else if names_cast_column(right, column) {
                text_literal(left).map(|text| vec![text])
            } else {
                None
            }
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => {
            let mut labels = listed(left, column)?;
            labels.extend(listed(right, column)?);
            Some(labels)
        }
        _ => None,
    }
}

/// The distinct labels a check of the textual `column` restricts it to, in
/// the order first written, when one top-level conjunct of a check lists at
/// least two.
///
/// # Errors
///
/// Returns the lookup error reading the column's checks raised.
pub(crate) fn closed_set<'db, DB: DatabaseLike>(
    database: &'db DB,
    column: &'db DB::Column,
) -> Result<Option<Vec<&'db str>>, LookupError> {
    if !underlying_type(database, column.data_type(database)).is_textual(database) {
        return Ok(None);
    }
    let stored = column.stored_column_name();
    for check in column.check_constraints(database)? {
        for conjunct in conjuncts(check.expression(database)) {
            let Some(listed) = listed(conjunct, &stored) else {
                continue;
            };
            let mut labels: Vec<&str> = Vec::with_capacity(listed.len());
            for label in listed {
                if !labels.contains(&label) {
                    labels.push(label);
                }
            }
            if labels.len() >= 2 {
                return Ok(Some(labels));
            }
        }
    }
    Ok(None)
}
