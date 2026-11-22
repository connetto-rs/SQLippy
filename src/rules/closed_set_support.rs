//! Columns a check constraint restricts to literals, shared by the rules that
//! read such a column as a closed set or as pinned to one value.

use std::borrow::Cow;

use sql_traits::{
    errors::LookupError,
    traits::{
        CheckConstraintLike, ColumnCollation, ColumnLike, DataTypeLike, DatabaseLike,
        EnumerationKind,
    },
    utils::{identifier_resolution::normalize_identifier, scalar_family::ScalarFamily},
};
use sqlparser::ast::{BinaryOperator, DataType, Expr, InTarget};

use crate::rules::{
    literal_support::{string_value, text_literal},
    policy_support::{conjuncts, unwrapped},
    type_support::underlying_type,
};

/// The rows a rule relies on a check to have checked.
#[derive(Clone, Copy)]
pub(crate) enum CheckedRows {
    /// The rows written from now on, which every enforced check checks.
    Written,
    /// Every stored row, which only a validated check has checked, since a
    /// `NOT VALID` check skips the rows that predate it.
    Stored,
}

impl CheckedRows {
    /// Whether `check` has checked these rows.
    ///
    /// # Errors
    ///
    /// Returns the lookup error reading whether `check` is validated raised.
    pub(crate) fn checked_by<DB: DatabaseLike>(
        self,
        database: &DB,
        check: &DB::CheckConstraint,
    ) -> Result<bool, LookupError> {
        match self {
            Self::Written => Ok(check.is_enforced()),
            Self::Stored => check.is_validated(database),
        }
    }
}

/// The stored name of the column `expression` names under parentheses, bare
/// or qualified.
pub(crate) fn stored_name(mut expression: &Expr) -> Option<Cow<'_, str>> {
    while let Expr::Nested(inner) = expression {
        expression = inner;
    }
    let name = match expression {
        Expr::Identifier(name) => name,
        Expr::CompoundIdentifier(parts) => parts.last()?,
        _ => return None,
    };
    Some(normalize_identifier(
        &name.value,
        name.quote_style.is_some(),
    ))
}

/// Whether `expression`, under parentheses, names the column whose stored
/// name is `column`, bare or qualified.
pub(crate) fn names_column(expression: &Expr, column: &str) -> bool {
    stored_name(expression).is_some_and(|name| name == column)
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

/// The distinct labels a check of the textual `column` that has checked
/// `rows` restricts it to, in the order first written, when one top-level
/// conjunct of such a check lists at least two.
///
/// # Errors
///
/// Returns the lookup error reading the column's checks raised.
pub(crate) fn closed_set<'db, DB: DatabaseLike>(
    database: &'db DB,
    column: &'db DB::Column,
    rows: CheckedRows,
) -> Result<Option<Vec<&'db str>>, LookupError> {
    if !underlying_type(database, column.data_type(database)).is_textual(database) {
        return Ok(None);
    }
    let stored = column.stored_column_name();
    for check in column.check_constraints(database)? {
        if !rows.checked_by(database, check)? {
            continue;
        }
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

/// The literals an enforced check of `column` restricts it to, whatever its
/// type, when one top-level conjunct of such a check lists them.
///
/// # Errors
///
/// Returns the lookup error reading the column's checks raised.
pub(crate) fn checked_literals<'db, DB: DatabaseLike>(
    database: &'db DB,
    column: &'db DB::Column,
) -> Result<Option<Vec<&'db str>>, LookupError> {
    let stored = column.stored_column_name();
    for check in column
        .check_constraints(database)?
        .filter(|check| check.is_enforced())
    {
        if let Some(listed) = conjuncts(check.expression(database))
            .into_iter()
            .find_map(|conjunct| listed(conjunct, &stored))
        {
            return Ok(Some(listed));
        }
    }
    Ok(None)
}

/// What `=` compares the values of a column by, when two values it holds
/// equal are the same value.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Identity {
    /// A builtin type of this family.
    Family(ScalarFamily),
    /// The enum type of this name.
    Enumeration(String),
}

/// What `=` compares the values of `column` by, or `None` when two equal
/// values of it may differ.
pub(crate) fn identity<DB: DatabaseLike>(
    column: &DB::Column,
    database: &DB,
) -> Result<Option<Identity>, LookupError> {
    let declared = column.data_type(database);
    let data_type = declared.base_type(database).unwrap_or(declared);
    Ok(if data_type.array_element(database).is_some() {
        None
    } else if let Some(enumeration) = data_type.enumeration(database) {
        (enumeration.kind() == EnumerationKind::Enum)
            .then(|| Identity::Enumeration(data_type.name(database).into_owned()))
    } else {
        match data_type.scalar_family(database) {
            Some(
                family @ (ScalarFamily::Bool
                | ScalarFamily::Int
                | ScalarFamily::Uuid
                | ScalarFamily::Date
                | ScalarFamily::Timestamp
                | ScalarFamily::TimestampTz),
            ) => Some(Identity::Family(family)),
            Some(ScalarFamily::String)
                if declared.domain(database).is_none()
                    && !data_type.normalized_name(database).starts_with("CHAR")
                    && matches!(
                        column.collation(database)?,
                        ColumnCollation::DatabaseDefault
                    ) =>
            {
                Some(Identity::Family(ScalarFamily::String))
            }
            _ => None,
        }
    })
}

/// The values every row of its table holds `column` to, the expression it is
/// generated as or the values [`checked_values`] reads.
pub(crate) fn held_values<'a, DB: DatabaseLike>(
    database: &'a DB,
    column: &'a DB::Column,
) -> Result<Option<Vec<&'a Expr>>, LookupError> {
    if let Some(expression) = column.generation_expression() {
        return Ok(Some(vec![expression]));
    }
    checked_values(database, column)
}

/// The values a `NOT NULL` column is held to by a top-level conjunct of a
/// validated check, `=` one value or `IN` a list of values, those of the
/// first such check.
pub(crate) fn checked_values<'a, DB: DatabaseLike>(
    database: &'a DB,
    column: &'a DB::Column,
) -> Result<Option<Vec<&'a Expr>>, LookupError> {
    if column.is_nullable(database)? {
        return Ok(None);
    }
    let stored = column.stored_column_name();
    for check in column.check_constraints(database)? {
        if !check.is_validated(database)? {
            continue;
        }
        if let Some((_, values)) = conjuncts(check.expression(database))
            .into_iter()
            .filter_map(fixed_by)
            .find(|(name, _)| *name == stored)
        {
            return Ok(Some(values));
        }
    }
    Ok(None)
}

/// A column with the texts its row may hold in it.
pub(crate) type Fixed<'a, DB> = (&'a <DB as DatabaseLike>::Column, Vec<String>);

/// `column` with the texts of `values`, when it is an enum or a text column
/// `=` compares by identity and each value a string literal it holds as
/// written.
pub(crate) fn pin<'a, DB: DatabaseLike>(
    database: &DB,
    column: &'a DB::Column,
    values: &[&Expr],
) -> Result<Option<Fixed<'a, DB>>, LookupError> {
    let enumeration = match identity(column, database)? {
        Some(Identity::Enumeration(_)) => true,
        Some(Identity::Family(ScalarFamily::String)) => false,
        _ => return Ok(None),
    };
    Ok(values
        .iter()
        .map(|value| kept_literal(value, enumeration).map(str::to_owned))
        .collect::<Option<Vec<String>>>()
        .map(|values| (column, values)))
}

/// The string literal `expression` writes under parentheses and casts that
/// keep its text: to `text`, to `varchar` of no length, and, for an enum
/// column, to a type of no modifiers, which `=` accepts only as the enum.
pub(crate) fn kept_literal(mut expression: &Expr, enumeration: bool) -> Option<&str> {
    loop {
        match expression {
            Expr::Nested(inner) => expression = inner,
            Expr::Cast {
                expr, data_type, ..
            } if matches!(
                data_type,
                DataType::Text | DataType::Varchar(None) | DataType::CharacterVarying(None)
            ) || (enumeration
                && matches!(data_type, DataType::Custom(_, modifiers) if modifiers.is_empty())) =>
            {
                expression = expr;
            }
            Expr::Value(value) => return string_value(&value.value),
            _ => return None,
        }
    }
}

/// The column `condition` fixes with `=` or `IN` to values reading no
/// column, with the values.
pub(crate) fn fixed_by(condition: &Expr) -> Option<(Cow<'_, str>, Vec<&Expr>)> {
    match unwrapped(condition) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => [(left, right), (right, left)]
            .into_iter()
            .find_map(|(column, value)| Some((stored_name(column)?, vec![value.as_ref()]))),
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated: false,
            ..
        } => Some((stored_name(expr)?, list.iter().collect())),
        _ => None,
    }
}
