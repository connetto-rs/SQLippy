//! Submodule providing the query rules that read the types of the values a
//! statement compares and computes.

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnDefinitionScope},
    traits::{ColumnLike, DataTypeLike, DatabaseLike},
};
use sqlparser::ast::{
    BinaryOperator, DataType, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments,
    Statement, TimezoneInfo, Value, ValueWithSpan,
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::statement_support::{Finding, check_select_expressions, report},
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// The type family of a value, as far as the rules tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Integer,
    Timestamp,
    TimestampTz,
    Time,
    Date,
    Other,
}

impl Kind {
    /// The family of a type named the way PostgreSQL normalizes it.
    fn named(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "int" | "integer" | "int4" | "smallint" | "int2" | "bigint" | "int8" => Self::Integer,
            "timestamp" | "timestamp without time zone" => Self::Timestamp,
            "timestamptz" | "timestamp with time zone" => Self::TimestampTz,
            "time" | "time without time zone" | "timetz" | "time with time zone" => Self::Time,
            "date" => Self::Date,
            _ => Self::Other,
        }
    }

    /// The family of a type as written in a cast.
    fn written(data_type: &DataType) -> Self {
        match data_type {
            DataType::Int(_)
            | DataType::Integer(_)
            | DataType::SmallInt(_)
            | DataType::BigInt(_)
            | DataType::Int2(_)
            | DataType::Int4(_)
            | DataType::Int8(_) => Self::Integer,
            DataType::Timestamp(_, TimezoneInfo::WithTimeZone | TimezoneInfo::Tz) => {
                Self::TimestampTz
            }
            DataType::Timestamp(..) => Self::Timestamp,
            DataType::Time(..) => Self::Time,
            DataType::Date => Self::Date,
            _ => Self::Other,
        }
    }

    /// The family a clock function returns.
    fn clock(function: &Function) -> Self {
        match called(function).as_deref() {
            Some(
                "now"
                | "current_timestamp"
                | "transaction_timestamp"
                | "statement_timestamp"
                | "clock_timestamp",
            ) => Self::TimestampTz,
            Some("localtimestamp") => Self::Timestamp,
            _ => Self::Other,
        }
    }
}

/// The lowercase name a call names, without its schema.
fn called(function: &Function) -> Option<String> {
    function
        .name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .map(|ident| ident.value.to_ascii_lowercase())
}

/// The family of `expression`, resolved in `scope`.
fn kind<DB: DatabaseLike>(
    database: &DB,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    expression: &Expr,
) -> Result<Kind, LookupError> {
    // Expression evaluator: the family comes from columns, derived-table
    // outputs, casts, integer literals and the clock functions. The
    // evaluator types every expression, such as `a + b` or
    // `coalesce(at, now())`, and the literals Q11 and Q13 compare with.
    Ok(match expression {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            match scope.resolve_column_definition(expression)? {
                Some(ColumnDefinition::Base { column, .. }) => {
                    Kind::named(&column.data_type(database).normalized_name(database))
                }
                Some(ColumnDefinition::Expression {
                    expression,
                    scope: defining,
                }) => kind(database, &defining, expression)?,
                _ => Kind::Other,
            }
        }
        Expr::Nested(inner) => kind(database, scope, inner)?,
        Expr::Cast { data_type, .. } => Kind::written(data_type),
        Expr::Value(ValueWithSpan {
            value: Value::Number(number, _),
            ..
        }) if !number.contains(['.', 'e', 'E']) => Kind::Integer,
        Expr::Function(function) => Kind::clock(function),
        _ => Kind::Other,
    })
}

/// The second argument of a call that passes exactly two positional ones.
fn second_of_two(function: &Function) -> Option<&Expr> {
    if let FunctionArguments::List(list) = &function.args
        && let [
            FunctionArg::Unnamed(FunctionArgExpr::Expr(_)),
            FunctionArg::Unnamed(FunctionArgExpr::Expr(second)),
        ] = list.args.as_slice()
    {
        return Some(second);
    }
    None
}

/// Reports every finding `find` returns for the expressions of `statement`.
fn report_findings<DB: DatabaseLike>(
    database: &DB,
    statement: &Statement,
    reporter: &mut Reporter<'_, DB>,
    resolution: &str,
    mut find: impl FnMut(
        &ColumnDefinitionScope<'_, '_, '_, DB>,
        &Expr,
    ) -> Result<Option<String>, LookupError>,
) -> Result<(), Interruption> {
    report(statement, reporter, |found| {
        check_select_expressions(database, statement, |scope, expression| {
            found.extend(find(scope, expression)?.map(|message| Finding {
                object: expression.to_string(),
                message,
                resolution: resolution.to_owned(),
            }));
            Ok(())
        })
    })
}

query_rule!(
    /// Struct defining a rule that reports `BETWEEN` or `NOT BETWEEN` on a
    /// `timestamp`, `timestamptz` or `time` value.
    ///
    /// `BETWEEN` includes both ends. Measured on PostgreSQL 17.11 and 18.6
    /// with events at Jan 1 10:00, Jan 1 23:59:59.5, Jan 2 00:00 and Jan 2
    /// 12:00, two adjacent day ranges counted 3 and 2 events for 4, and an
    /// upper bound of `23:59:59` missed the event at 23:59:59.5. `BETWEEN`
    /// on dates and integers is exact and not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = TimestampBetween::default().into();
    /// let database =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (at TIMESTAMPTZ, day DATE);").unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT 1 FROM t WHERE at BETWEEN $1 AND $2").is_err());
    /// assert!(check("SELECT 1 FROM t WHERE day BETWEEN $1 AND $2").is_ok());
    /// ```
    TimestampBetween,
    LintGroup::Suspicious,
    "BETWEEN includes both ends, so on continuous time values adjacent ranges overlap at their boundary and a closing time such as 23:59:59 misses fractional seconds.",
    Some("https://wiki.postgresql.org/wiki/Don%27t_Do_This")
);

impl<DB: DatabaseLike> QueryRule for TimestampBetween<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report_findings(
            database,
            statement,
            reporter,
            "Write a half-open range, value >= start AND value < next_start.",
            |scope, expression| {
                let Expr::Between { expr, .. } = expression else {
                    return Ok(None);
                };
                let name = match kind(database, scope, expr)? {
                    Kind::Timestamp => "timestamp without time zone",
                    Kind::TimestampTz => "timestamp with time zone",
                    Kind::Time => "time",
                    _ => return Ok(None),
                };
                Ok(Some(format!(
                    "`{expression}` uses BETWEEN on a {name} value, which includes both ends."
                )))
            },
        )
    }
}

query_rule!(
    /// Struct defining a rule that reports a time result that depends on the
    /// session's `TimeZone` setting.
    ///
    /// The rule reports a `timestamptz` cast to `date` or `time`, the
    /// two-argument `date_trunc` over a `timestamptz`, and a comparison of a
    /// `timestamp` with a `timestamptz`, such as `timestamp_col < now()`.
    /// Measured on PostgreSQL 17.11 and 18.6, an event at `2026-01-01
    /// 23:30+00` gave Jan 1 and 23:30 under UTC and Jan 2 and 08:30 under
    /// Tokyo for `::date`, `::time` and `date_trunc('day', …)`, and
    /// `TIMESTAMP '2026-01-02 05:00' < TIMESTAMPTZ '2026-01-02 00:00+00'`
    /// flipped between the two zones. `AT TIME ZONE` and the three-argument
    /// `date_trunc` gave the same answer under both and are not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = SessionTimeZoneDependence::default().into();
    /// let database =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (at TIMESTAMPTZ);").unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT at::date FROM t").is_err());
    /// assert!(check("SELECT (at AT TIME ZONE 'UTC')::date FROM t").is_ok());
    /// ```
    SessionTimeZoneDependence,
    LintGroup::Suspicious,
    "PostgreSQL converts between timestamp with and without time zone in the session's TimeZone, so the result changes with that setting.",
    Some("https://www.postgresql.org/docs/current/datatype-datetime.html")
);

impl<DB: DatabaseLike> QueryRule for SessionTimeZoneDependence<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report_findings(
            database,
            statement,
            reporter,
            "Name the zone with AT TIME ZONE or the three-argument date_trunc, or compare values of the same type.",
            |scope, expression| {
                Ok(match expression {
                    Expr::Cast {
                        expr, data_type, ..
                    } => {
                        let target = match Kind::written(data_type) {
                            Kind::Date => "date",
                            Kind::Time => "time",
                            _ => return Ok(None),
                        };
                        (kind(database, scope, expr)? == Kind::TimestampTz).then(|| {
                            format!(
                                "`{expression}` turns a timestamp with time zone into a {target} in the session's TimeZone."
                            )
                        })
                    }
                    Expr::Function(function)
                        if called(function).as_deref() == Some("date_trunc")
                            && let Some(truncated) = second_of_two(function)
                            && kind(database, scope, truncated)? == Kind::TimestampTz =>
                    {
                        Some(format!(
                            "`{expression}` truncates a timestamp with time zone in the session's TimeZone."
                        ))
                    }
                    // Expression evaluator: a timestamp with time zone
                    // compared with a literal that names no zone waits on
                    // the evaluator, which types the literal.
                    Expr::BinaryOp { left, op, right }
                        if matches!(
                            op,
                            BinaryOperator::Lt
                                | BinaryOperator::LtEq
                                | BinaryOperator::Gt
                                | BinaryOperator::GtEq
                                | BinaryOperator::Eq
                                | BinaryOperator::NotEq
                        ) && matches!(
                            (kind(database, scope, left)?, kind(database, scope, right)?),
                            (Kind::Timestamp, Kind::TimestampTz)
                                | (Kind::TimestampTz, Kind::Timestamp)
                        ) =>
                    {
                        Some(format!(
                            "`{expression}` compares a timestamp without time zone with a timestamp with time zone, which PostgreSQL converts in the session's TimeZone."
                        ))
                    }
                    _ => None,
                })
            },
        )
    }
}

query_rule!(
    /// Struct defining a rule that reports integer division scaled
    /// afterwards, such as `score / total * 100`.
    ///
    /// Integer division truncates toward zero before the multiplication.
    /// Measured on PostgreSQL 17.11 and 18.6, `score / total * 100` gave only
    /// 0 and 100 where `score * 100 / total` gave 0, 50 and 100. Bare integer
    /// division such as `id / 1000` is not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = TruncatingIntegerDivision::default().into();
    /// let database =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (score INT, total INT);").unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT score / total * 100 FROM t").is_err());
    /// assert!(check("SELECT score * 100 / total FROM t").is_ok());
    /// ```
    TruncatingIntegerDivision,
    LintGroup::Suspicious,
    "Integer division truncates toward zero, so scaling the quotient afterwards keeps only whole multiples.",
    Some("https://www.postgresql.org/docs/current/functions-math.html")
);

impl<DB: DatabaseLike> QueryRule for TruncatingIntegerDivision<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report_findings(
            database,
            statement,
            reporter,
            "Multiply before dividing, or cast one operand to numeric.",
            |scope, expression| {
                // Expression evaluator: an integer quotient compared with a
                // fractional value, such as `score / total > 0.4`, waits on
                // the evaluator, which types the compared value.
                let Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Multiply,
                    ..
                } = expression
                else {
                    return Ok(None);
                };
                let mut quotient = left.as_ref();
                while let Expr::Nested(inner) = quotient {
                    quotient = inner;
                }
                let Expr::BinaryOp {
                    left: dividend,
                    op: BinaryOperator::Divide,
                    right: divisor,
                } = quotient
                else {
                    return Ok(None);
                };
                Ok((kind(database, scope, dividend)? == Kind::Integer
                    && kind(database, scope, divisor)? == Kind::Integer)
                    .then(|| {
                        format!("`{expression}` divides integers before scaling, so the quotient is truncated first.")
                    }))
            },
        )
    }
}
