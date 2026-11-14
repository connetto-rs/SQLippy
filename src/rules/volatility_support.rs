//! Finds the terms of an expression that PostgreSQL may evaluate to another
//! value on each call.

use std::ops::ControlFlow;

use sql_traits::{
    structs::TargetName,
    traits::{CastLike, CastMethod, DatabaseLike, FunctionLike, OperatorLike},
    utils::{identifier_resolution::normalize_identifier, normalize_postgres_type},
};
use sqlparser::ast::{
    ArrayElemTypeDef, BinaryOperator, DataType, Expr, FunctionBehavior, InTarget, Visitor,
};

use crate::rules::walk_support::walk;

/// Whether an operator written `name` may run a `VOLATILE` function, `custom`
/// when it is written `OPERATOR(...)`, which then also holds when it names no
/// known operator.
fn operator_is_volatile<DB: DatabaseLike>(database: &DB, name: &str, custom: bool) -> bool {
    let Some(operators) = database.operators() else {
        return custom;
    };
    let mut matched = false;
    for operator in operators.filter(|operator| operator.target_name().name() == name) {
        matched = true;
        if operator
            .implementation(database)
            .is_none_or(|function| function.volatility() == FunctionBehavior::Volatile)
        {
            return true;
        }
    }
    custom && !matched
}

/// Whether the binary operator `op` may run a `VOLATILE` function.
fn binary_operator_is_volatile<DB: DatabaseLike>(database: &DB, op: &BinaryOperator) -> bool {
    match op {
        BinaryOperator::PGCustomBinaryOperator(parts) => parts
            .last()
            .is_none_or(|name| operator_is_volatile(database, name, true)),
        _ => operator_is_volatile(database, &op.to_string(), false),
    }
}

/// The operators PostgreSQL runs for a comparison it spells with keywords,
/// such as `~~` for `LIKE`, `>=` and `<=` for `BETWEEN` and `=` for `IN`,
/// `IS DISTINCT FROM` and a `CASE` with an operand.
fn keyword_operators(expression: &Expr) -> &'static [&'static str] {
    match expression {
        Expr::Like { negated: false, .. } => &["~~"],
        Expr::Like { negated: true, .. } => &["!~~"],
        Expr::ILike { negated: false, .. } => &["~~*"],
        Expr::ILike { negated: true, .. } => &["!~~*"],
        Expr::SimilarTo { negated: false, .. } => &["~"],
        Expr::SimilarTo { negated: true, .. } => &["!~"],
        Expr::In {
            target: InTarget::List(_),
            negated: true,
            ..
        } => &["<>"],
        Expr::In { .. }
        | Expr::IsDistinctFrom(..)
        | Expr::IsNotDistinctFrom(..)
        | Expr::Case {
            operand: Some(_), ..
        } => &["="],
        Expr::Between { negated: false, .. } => &[">=", "<="],
        Expr::Between { negated: true, .. } => &["<", ">"],
        _ => &[],
    }
}

/// The element type of `data_type` with every array level removed, and
/// whether there was one. PostgreSQL ignores array dimensions, so every
/// level names one array type.
fn element_type(data_type: &DataType) -> (&DataType, bool) {
    match data_type {
        DataType::Array(
            ArrayElemTypeDef::AngleBracket(element)
            | ArrayElemTypeDef::SquareBracket(element, _)
            | ArrayElemTypeDef::Parenthesis(element)
            | ArrayElemTypeDef::ParenthesisNotNull(element)
            | ArrayElemTypeDef::Qualified(element, _),
        ) => (element_type(element).0, true),
        _ => (data_type, false),
    }
}

/// A cast's target spelled the way a written type normalizes: the stored
/// name without its schema, and an array type, as the database's type facts
/// know it, as its element followed by `[]`.
fn target_spelling<DB: DatabaseLike>(database: &DB, target: TargetName<'_>) -> String {
    let scalar = TargetName::new(target.name(), target.name_is_quoted()).to_string();
    database
        .type_facts(target)
        .and_then(|facts| {
            facts.array_element().map(|element| {
                format!(
                    "{}[]",
                    TargetName::new(element.name(), element.name_is_quoted())
                )
            })
        })
        .unwrap_or(scalar)
}

/// Whether an explicit cast to `data_type` may run a `VOLATILE` function: a
/// cast to a type of that name, from any source and in any schema, that runs
/// a `VOLATILE` function or one the database does not hold. A cast to an
/// array type runs a cast to the array type itself when there is one, and
/// otherwise the element type's cast on each element, so both count.
fn cast_is_volatile<DB: DatabaseLike>(database: &DB, data_type: &DataType) -> bool {
    let Some(casts) = database.casts() else {
        return false;
    };
    let (element, array) = element_type(data_type);
    let element = match element {
        DataType::Custom(name, _) => name.0.last().map_or_else(String::new, ToString::to_string),
        element => element.to_string(),
    };
    let whole = array.then(|| normalize_postgres_type(&format!("{element}[]")).into_owned());
    let element = normalize_postgres_type(&element);
    casts
        .filter(|cast| {
            let spelling = target_spelling(database, cast.target_type(database));
            let target = normalize_postgres_type(&spelling);
            target == element || whole.as_deref() == Some(&*target)
        })
        .any(|cast| {
            cast.method() == CastMethod::Function
                && cast
                    .function(database)
                    .is_none_or(|function| function.volatility() == FunctionBehavior::Volatile)
        })
}

/// Whether `expression` itself, apart from its operands and arguments, may
/// run a `VOLATILE` function: a call whose name reaches a `VOLATILE` overload
/// or no known function, an operator, quantified by `ANY` or `ALL`, spelled
/// with keywords or neither, whose name reaches one with a `VOLATILE` or
/// unknown implementation, `OPERATOR(...)` naming no known operator
/// included, or an explicit cast [`cast_is_volatile`] reports.
fn is_volatile_term<DB: DatabaseLike>(database: &DB, expression: &Expr) -> bool {
    match expression {
        Expr::Function(call) => call
            .name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .is_none_or(|name| {
                let name = normalize_identifier(&name.value, name.quote_style.is_some());
                let mut reached = database.functions_named(&name).peekable();
                reached.peek().is_none()
                    || reached.any(|function| function.volatility() == FunctionBehavior::Volatile)
            }),
        Expr::BinaryOp { op, .. }
        | Expr::AnyOp { compare_op: op, .. }
        | Expr::AllOp { compare_op: op, .. } => binary_operator_is_volatile(database, op),
        Expr::UnaryOp { op, .. } => operator_is_volatile(database, &op.to_string(), false),
        Expr::Cast { data_type, .. } => cast_is_volatile(database, data_type),
        _ => keyword_operators(expression)
            .iter()
            .any(|name| operator_is_volatile(database, name, false)),
    }
}

/// Finds a term [`is_volatile_term`] reports.
struct VolatileTerm<'a, DB>(&'a DB);

impl<DB: DatabaseLike> Visitor for VolatileTerm<'_, DB> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if is_volatile_term(self.0, expression) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Whether evaluating `expression` may run a `VOLATILE` function, directly
/// or through an operator or an explicit cast, a call or operator the
/// schema does not declare included.
pub(crate) fn runs_volatile<DB: DatabaseLike>(database: &DB, expression: &Expr) -> bool {
    walk(expression, &mut VolatileTerm(database)).is_break()
}

#[cfg(test)]
mod tests {
    use sql_traits::prelude::*;
    use sqlparser::{
        dialect::{PostgreSqlDialect, SQLiteDialect},
        parser::Parser,
    };

    use super::runs_volatile;

    /// Whether `expression`, written for PostgreSQL, may run a `VOLATILE`
    /// function in `database`.
    fn volatile(database: &ParserDB, expression: &str) -> bool {
        let expression = Parser::new(&PostgreSqlDialect {})
            .try_with_sql(expression)
            .and_then(|mut parser| parser.parse_expr())
            .expect("expression parses");
        runs_volatile(database, &expression)
    }

    fn postgres(schema: &str) -> ParserDB {
        ParserDB::parse::<PostgreSqlDialect>(schema).expect("schema parses")
    }

    #[test]
    fn keyword_and_prefix_operators_reach_declared_volatile_implementations() {
        let moods = postgres(
            "CREATE TYPE mood AS ENUM ('a', 'b');
             CREATE FUNCTION toss(a mood, b TEXT) RETURNS BOOL LANGUAGE sql VOLATILE
                 AS 'SELECT random() < 0.5';
             CREATE FUNCTION toss_pair(a mood, b mood) RETURNS BOOL LANGUAGE sql VOLATILE
                 AS 'SELECT random() < 0.5';
             CREATE FUNCTION toss_one(a mood) RETURNS BOOL LANGUAGE sql VOLATILE
                 AS 'SELECT random() < 0.5';
             CREATE OPERATOR ~~ (LEFTARG = mood, RIGHTARG = TEXT, FUNCTION = toss);
             CREATE OPERATOR !~~ (LEFTARG = mood, RIGHTARG = TEXT, FUNCTION = toss);
             CREATE OPERATOR ~~* (LEFTARG = mood, RIGHTARG = TEXT, FUNCTION = toss);
             CREATE OPERATOR !~~* (LEFTARG = mood, RIGHTARG = TEXT, FUNCTION = toss);
             CREATE OPERATOR ~ (LEFTARG = mood, RIGHTARG = TEXT, FUNCTION = toss);
             CREATE OPERATOR !~ (LEFTARG = mood, RIGHTARG = TEXT, FUNCTION = toss);
             CREATE OPERATOR = (LEFTARG = mood, RIGHTARG = mood, FUNCTION = toss_pair);
             CREATE OPERATOR <> (LEFTARG = mood, RIGHTARG = mood, FUNCTION = toss_pair);
             CREATE OPERATOR >= (LEFTARG = mood, RIGHTARG = mood, FUNCTION = toss_pair);
             CREATE OPERATOR <= (LEFTARG = mood, RIGHTARG = mood, FUNCTION = toss_pair);
             CREATE OPERATOR < (LEFTARG = mood, RIGHTARG = mood, FUNCTION = toss_pair);
             CREATE OPERATOR > (LEFTARG = mood, RIGHTARG = mood, FUNCTION = toss_pair);
             CREATE OPERATOR - (RIGHTARG = mood, FUNCTION = toss_one);",
        );
        for expression in [
            "'a'::mood LIKE 'a'",
            "'a'::mood NOT LIKE 'a'",
            "'a'::mood ILIKE 'a'",
            "'a'::mood NOT ILIKE 'a'",
            "'a'::mood SIMILAR TO 'a'",
            "'a'::mood NOT SIMILAR TO 'a'",
            "'a'::mood IN ('a'::mood)",
            "'a'::mood NOT IN ('a'::mood)",
            "'a'::mood BETWEEN 'a'::mood AND 'a'::mood",
            "'a'::mood NOT BETWEEN 'a'::mood AND 'a'::mood",
            "'a'::mood IS DISTINCT FROM 'a'::mood",
            "'a'::mood IS NOT DISTINCT FROM 'a'::mood",
            "CASE 'a'::mood WHEN 'a'::mood THEN true ELSE false END",
            "- 'a'::mood",
        ] {
            assert!(volatile(&moods, expression), "{expression}");
        }
        let plain = postgres("");
        for expression in [
            "'a' LIKE 'a'",
            "'a' SIMILAR TO 'a'",
            "1 IN (1, 2)",
            "1 NOT IN (1, 2)",
            "1 BETWEEN 0 AND 2",
            "1 IS DISTINCT FROM 2",
            "CASE 1 WHEN 1 THEN true ELSE false END",
            "-1 = -1",
        ] {
            assert!(!volatile(&plain, expression), "{expression}");
        }
    }

    #[test]
    fn a_cast_to_a_user_type_or_its_arrays_reaches_its_volatile_function() {
        let app = |name| TargetName::new(name, false).with_schema("app", false);
        let int = || TargetName::new("int4", false).with_schema("pg_catalog", false);
        let database = ParseOptions::default()
            .with_postgres_catalog(PostgresCatalog::default().with_cast(
                PostgresCatalogCast::through_function(
                    int(),
                    app("coin"),
                    CastContext::Explicit,
                    app("flip"),
                    [int()],
                ),
            ))
            .parse::<PostgreSqlDialect>(
                "CREATE SCHEMA app;
                 CREATE TYPE app.coin AS (v INT);
                 CREATE FUNCTION app.flip(INT) RETURNS app.coin LANGUAGE sql VOLATILE
                     AS 'SELECT ROW((random() < 0.5)::INT)::app.coin';",
            )
            .expect("schema parses");
        for expression in [
            "1::app.coin = '(1)'::app.coin",
            "((ARRAY[1]::app.coin[])[1]).v = 1",
            "((ARRAY[ARRAY[1]]::app.coin[][])[1][1]).v = 1",
            "((CAST(ARRAY[1] AS app.coin ARRAY))[1]).v = 1",
        ] {
            assert!(volatile(&database, expression), "{expression}");
        }
        for expression in ["1::BIGINT = 1", "(ARRAY[1]::BIGINT[])[1] = 1"] {
            assert!(!volatile(&database, expression), "{expression}");
        }
    }

    #[test]
    fn a_cast_to_an_array_type_itself_reaches_its_volatile_function() {
        let app = |name| TargetName::new(name, false).with_schema("app", false);
        let database = ParseOptions::default()
            .with_postgres_catalog(PostgresCatalog::default().with_cast(
                PostgresCatalogCast::through_function(
                    app("coin"),
                    TargetName::new("_bool", false).with_schema("pg_catalog", false),
                    CastContext::Explicit,
                    app("toss_all"),
                    [app("coin")],
                ),
            ))
            .parse::<PostgreSqlDialect>(
                "CREATE SCHEMA app;
                 CREATE TYPE app.coin AS (v INT);
                 CREATE FUNCTION app.toss_all(app.coin) RETURNS BOOL[] LANGUAGE sql VOLATILE
                     AS 'SELECT ARRAY[random() < 0.5]';",
            )
            .expect("schema parses");
        for expression in [
            "('(1)'::app.coin::BOOL[])[1]",
            "(CAST('(1)'::app.coin AS BOOLEAN ARRAY))[1]",
        ] {
            assert!(volatile(&database, expression), "{expression}");
        }
        assert!(!volatile(&database, "'t'::BOOL"));
    }

    #[test]
    fn a_scalar_type_named_with_a_leading_underscore_is_no_array() {
        let app = |name| TargetName::new(name, false).with_schema("app", false);
        let int = || TargetName::new("int4", false).with_schema("pg_catalog", false);
        let database = ParseOptions::default()
            .with_postgres_catalog(PostgresCatalog::default().with_cast(
                PostgresCatalogCast::through_function(
                    int(),
                    app("_coin"),
                    CastContext::Explicit,
                    app("flip"),
                    [int()],
                ),
            ))
            .parse::<PostgreSqlDialect>(
                "CREATE SCHEMA app;
                 CREATE TYPE app._coin AS (v INT);
                 CREATE FUNCTION app.flip(INT) RETURNS app._coin LANGUAGE sql VOLATILE
                     AS 'SELECT ROW((random() < 0.5)::INT)::app._coin';",
            )
            .expect("schema parses");
        assert!(volatile(&database, "(1::app._coin).v = 1"));
        assert!(!volatile(&database, "(ARRAY[1]::BIGINT[])[1] = 1"));
    }

    #[test]
    fn without_a_catalog_only_an_unknown_custom_operator_counts() {
        let database = ParserDB::parse::<SQLiteDialect>("").expect("schema parses");
        assert!(volatile(&database, "1 OPERATOR(app.<?>) 1"));
        for expression in ["1 = 1", "CAST(1 AS INTEGER) = 1"] {
            assert!(!volatile(&database, expression), "{expression}");
        }
    }
}
