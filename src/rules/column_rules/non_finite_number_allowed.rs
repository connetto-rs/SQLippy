//! Submodule providing the `NonFiniteNumberAllowed` rule.

use std::cmp::Ordering;

use sql_traits::{
    errors::LookupError,
    traits::{CheckConstraintLike, ColumnLike, DataTypeLike, DatabaseLike, DomainLike, TableLike},
    utils::scalar_family::ScalarFamily,
};
use sqlparser::ast::{BinaryOperator, Expr, InTarget, UnaryOperator, Value};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::names_column,
        key_support::holds_through_references,
        literal_support::{literal, string_value},
    },
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// Where a value sits in the order PostgreSQL's floating-point and `numeric`
/// types share: `'-Infinity'` below every number and `'Infinity'` above, with
/// `'NaN'` above everything and equal to itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    NegativeInfinity,
    Number,
    Infinity,
    NaN,
}

impl Rank {
    /// The rank of the value with the opposite sign.
    const fn negated(self) -> Self {
        match self {
            Self::NegativeInfinity => Self::Infinity,
            Self::Infinity => Self::NegativeInfinity,
            Self::Number | Self::NaN => self,
        }
    }
}

/// A value PostgreSQL stores in a floating-point or `numeric` column that is
/// no number, in the order messages name them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NonFinite {
    NaN,
    Infinity,
    NegativeInfinity,
}

impl NonFinite {
    const ALL: [Self; 3] = [Self::NaN, Self::Infinity, Self::NegativeInfinity];

    const fn rank(self) -> Rank {
        match self {
            Self::NaN => Rank::NaN,
            Self::Infinity => Rank::Infinity,
            Self::NegativeInfinity => Rank::NegativeInfinity,
        }
    }

    const fn literal(self) -> &'static str {
        match self {
            Self::NaN => "'NaN'",
            Self::Infinity => "'Infinity'",
            Self::NegativeInfinity => "'-Infinity'",
        }
    }
}

/// The rank of the value a string literal spells as PostgreSQL's
/// floating-point and `numeric` input read it.
fn spelled_rank(text: &str) -> Option<Rank> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("nan") {
        return Some(Rank::NaN);
    }
    let (negative, magnitude) = match text.strip_prefix('-') {
        Some(magnitude) => (true, magnitude),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if magnitude.eq_ignore_ascii_case("infinity") || magnitude.eq_ignore_ascii_case("inf") {
        return Some(if negative {
            Rank::NegativeInfinity
        } else {
            Rank::Infinity
        });
    }
    text.parse::<f64>()
        .is_ok_and(f64::is_finite)
        .then_some(Rank::Number)
}

/// The rank of the constant `expression` writes under parentheses, casts and
/// signs, such as `0.0`, `(0)::double precision` or `'-Infinity'::real`.
fn constant(expression: &Expr) -> Option<Rank> {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => constant(inner),
        Expr::UnaryOp {
            op: UnaryOperator::Plus,
            expr,
        } => constant(expr),
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => constant(expr).map(Rank::negated),
        _ => match literal(expression)? {
            Value::Number(..) => Some(Rank::Number),
            value => string_value(value).and_then(spelled_rank),
        },
    }
}

/// The test `operator` puts to the ordering of its operands, `None` for an
/// operator that compares nothing.
fn ordering_test(operator: &BinaryOperator) -> Option<fn(Ordering) -> bool> {
    Some(match operator {
        BinaryOperator::Eq => Ordering::is_eq,
        BinaryOperator::NotEq => Ordering::is_ne,
        BinaryOperator::Lt => Ordering::is_lt,
        BinaryOperator::LtEq => Ordering::is_le,
        BinaryOperator::Gt => Ordering::is_gt,
        BinaryOperator::GtEq => Ordering::is_ge,
        _ => return None,
    })
}

/// Whether the ordering of `left` and `right` passes `test`, `None` when the
/// ranks cannot tell, as between two numbers.
fn compare(left: Rank, test: fn(Ordering) -> bool, right: Rank) -> Option<bool> {
    (left != Rank::Number || right != Rank::Number).then(|| test(left.cmp(&right)))
}

/// `true` when every answer is, `false` when one is, `None` otherwise.
fn all(answers: impl IntoIterator<Item = Option<bool>>) -> Option<bool> {
    let mut decided = Some(true);
    for answer in answers {
        match answer {
            Some(false) => return Some(false),
            Some(true) => {}
            None => decided = None,
        }
    }
    decided
}

/// `true` when one answer is, `false` when every answer is, `None`
/// otherwise.
fn any(answers: impl IntoIterator<Item = Option<bool>>) -> Option<bool> {
    all(answers.into_iter().map(|answer| answer.map(|holds| !holds))).map(|none| !none)
}

/// The elements of `ARRAY[...]` under parentheses and casts.
fn array_elements(expression: &Expr) -> Option<&[Expr]> {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => array_elements(inner),
        Expr::Array(array) => Some(&array.elem),
        _ => None,
    }
}

/// Whether `expression` holds when the column whose stored name is `column`
/// holds `value`, `None` when that depends on anything else, such as another
/// column, a call or a `NULL`.
fn holds(expression: &Expr, column: &str, value: Rank) -> Option<bool> {
    let operand = |side: &Expr| {
        if names_column(side, column) {
            Some(value)
        } else {
            constant(side)
        }
    };
    let compared = |left: &Expr, operator: &BinaryOperator, right: &Expr| {
        let test = ordering_test(operator)?;
        compare(operand(left)?, test, operand(right)?)
    };
    match expression {
        Expr::Nested(inner) => holds(inner, column, value),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => all([holds(left, column, value), holds(right, column, value)]),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => any([holds(left, column, value), holds(right, column, value)]),
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => holds(expr, column, value).map(|holds| !holds),
        Expr::BinaryOp { left, op, right } => compared(left, op, right),
        Expr::IsNotDistinctFrom(left, right) => compared(left, &BinaryOperator::Eq, right),
        Expr::IsDistinctFrom(left, right) => compared(left, &BinaryOperator::NotEq, right),
        Expr::IsNotNull(inner) if names_column(inner, column) => Some(true),
        Expr::IsNull(inner) if names_column(inner, column) => Some(false),
        Expr::Between {
            expr,
            negated,
            low,
            high,
        } => all([
            compared(low, &BinaryOperator::LtEq, expr),
            compared(expr, &BinaryOperator::LtEq, high),
        ])
        .map(|within| within != *negated),
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated,
            ..
        } => any(list
            .iter()
            .map(|item| compared(expr, &BinaryOperator::Eq, item)))
        .map(|listed| listed != *negated),
        Expr::AnyOp {
            left,
            compare_op,
            right,
            ..
        } => any(array_elements(right)?
            .iter()
            .map(|element| compared(left, compare_op, element))),
        Expr::AllOp {
            left,
            compare_op,
            right,
        } => all(array_elements(right)?
            .iter()
            .map(|element| compared(left, compare_op, element))),
        _ => None,
    }
}

/// The type `column` stores its values as, through domains, with the check
/// expressions of those domains, or `None` for an array.
fn stored_type<'db, DB: DatabaseLike>(
    database: &'db DB,
    column: &'db DB::Column,
) -> Option<(&'db DB::DataType, Vec<&'db Expr>)> {
    let mut data_type = column.data_type(database);
    let mut checks = Vec::new();
    loop {
        if data_type.array_element(database).is_some() {
            return None;
        }
        let Some(domain) = data_type.domain(database) else {
            return Some((data_type, checks));
        };
        checks.extend(domain.check_expressions());
        data_type = domain.data_type(database);
    }
}

/// The non-finite values `column` admits, as its type stores them and no
/// check of the column or of a domain it goes through refuses them.
fn admitted<DB: DatabaseLike>(
    database: &DB,
    column: &DB::Column,
) -> Result<Vec<NonFinite>, LookupError> {
    let Some((data_type, domain_checks)) = stored_type(database, column) else {
        return Ok(Vec::new());
    };
    let stored: &[NonFinite] = match data_type.scalar_family(database) {
        Some(ScalarFamily::Decimal)
            if data_type
                .normalized_name(database)
                .eq_ignore_ascii_case("money") =>
        {
            &[]
        }
        Some(ScalarFamily::Decimal) if data_type.numeric_precision(database).is_some() => {
            &[NonFinite::NaN]
        }
        Some(ScalarFamily::Float | ScalarFamily::Decimal) => &NonFinite::ALL,
        _ => &[],
    };
    let table_checks: Vec<&Expr> = column
        .check_constraints(database)?
        .map(|check| check.expression(database))
        .collect();
    let name = column.stored_column_name();
    let refuses = |value: NonFinite| {
        table_checks
            .iter()
            .any(|check| holds(check, &name, value.rank()) == Some(false))
            || domain_checks
                .iter()
                .any(|check| holds(check, "value", value.rank()) == Some(false))
    };
    Ok(stored
        .iter()
        .copied()
        .filter(|&value| !refuses(value))
        .collect())
}

/// The literals of `values` joined as a sentence names them.
fn listed(values: &[NonFinite]) -> String {
    let literals: Vec<&str> = values.iter().map(|value| value.literal()).collect();
    match literals.split_last() {
        Some((last, init)) if !init.is_empty() => format!("{} and {last}", init.join(", ")),
        _ => literals.concat(),
    }
}

rule_definition!(
    /// Struct defining a rule that reports a `real`, `double precision` or
    /// `numeric` column whose checks admit `'NaN'`, `'Infinity'` or
    /// `'-Infinity'`.
    ///
    /// PostgreSQL sorts `'NaN'` above every number, `'Infinity'` included,
    /// so `CHECK (volume_l > 0.0)` admits both `'NaN'` and `'Infinity'`.
    /// Within a check, `col < x` with `x` a finite literal or `'Infinity'`
    /// refuses `'NaN'` and `'Infinity'`, and `col > x` with `x` a finite
    /// literal or `'-Infinity'` refuses `'-Infinity'`. Comparisons, `BETWEEN`,
    /// `IN` lists and `ANY` or `ALL` over an array of literals are read
    /// through `AND`, `OR` and `NOT`, and a check whose answer depends on
    /// anything else refuses nothing. `numeric` with a declared precision
    /// refuses the infinities itself. The type is read through domains,
    /// whose `CHECK (VALUE ...)` count as the column's own, a column a
    /// foreign key forces to equal another takes that column's checks, and
    /// arrays are skipped. A nullable column is judged on its non-null
    /// values.
    ///
    /// The rule does not run on SQLite, which stores `NaN` as `NULL` and
    /// reads `'Infinity'` as text.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = NonFiniteNumberAllowed::default().into();
    /// let positive = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE containers (volume_l DOUBLE PRECISION CHECK (volume_l > 0.0));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&positive).is_err());
    /// let finite = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE containers (volume_l DOUBLE PRECISION
    ///          CHECK (volume_l > 0.0 AND volume_l < 'Infinity'::double precision));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&finite).is_ok());
    /// ```
    NonFiniteNumberAllowed,
    register_column_rule,
    LintGroup::Pedantic,
    "PostgreSQL stores 'NaN' and the infinities in floating-point and numeric columns and sorts 'NaN' above every number, so a check bounding a column only from below admits them, while a client such as Rust compares NaN false with everything and refuses what PostgreSQL stored.",
    Some("https://www.postgresql.org/docs/current/datatype-numeric.html#DATATYPE-FLOAT"),
    RuleExample {
        bad: "CREATE TABLE containers (id INT PRIMARY KEY, volume_l DOUBLE PRECISION NOT NULL CHECK (volume_l > 0.0));",
        good: "CREATE TABLE containers (id INT PRIMARY KEY, volume_l DOUBLE PRECISION NOT NULL CHECK (volume_l > 0.0 AND volume_l < 'Infinity'::double precision));",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> ColumnRule for NonFiniteNumberAllowed<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut values = Vec::new();
        for value in admitted(database, column)? {
            let refused_through_references = holds_through_references(database, column, |held| {
                Ok(!admitted(database, held)?.contains(&value))
            })?;
            if !refused_through_references {
                values.push(value);
            }
        }
        if values.is_empty() {
            return Ok(());
        }

        let table_name = column.table(database).table_name();
        let column_name = column.column_name();
        let type_name = stored_type(database, column)
            .map_or_default(|(data_type, _)| bound_type_name(database, data_type));
        let lower = values
            .contains(&NonFinite::NegativeInfinity)
            .then(|| format!("{column_name} > '-Infinity'::{type_name}"));
        let upper = values
            .iter()
            .any(|&value| value != NonFinite::NegativeInfinity)
            .then(|| format!("{column_name} < 'Infinity'::{type_name}"));
        let bound = [lower, upper]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" AND ");
        reporter.column(
            column,
            format!(
                "Column '{table_name}.{column_name}' admits {}.",
                listed(&values)
            ),
            format!(
                "Bound the column with finite literals, or add `CHECK ({bound})`. PostgreSQL has no `isfinite()` for these types, and `'NaN'` sorts above `'Infinity'`, so `< 'Infinity'` refuses both."
            ),
        )?;
        Ok(())
    }
}

/// The type a bound on a column storing `data_type` casts its literal to.
fn bound_type_name<DB: DatabaseLike>(database: &DB, data_type: &DB::DataType) -> &'static str {
    match data_type.scalar_family(database) {
        Some(ScalarFamily::Float)
            if data_type
                .normalized_name(database)
                .eq_ignore_ascii_case("real") =>
        {
            "real"
        }
        Some(ScalarFamily::Float) => "double precision",
        _ => "numeric",
    }
}
