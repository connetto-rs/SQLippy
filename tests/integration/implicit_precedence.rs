//! Explicit grouping of mixed operators.

use crate::{common::parse, rule_findings::statement};
use sqlippy::prelude::*;
use sqlparser::dialect::SQLiteDialect;

const SCHEMA: &str = "CREATE TABLE t (a INT, b INT, c INT, x INT, y INT, ts TIMESTAMP);";

/// Returns the messages for a query or a view expression.
fn messages(expression: &str, view: bool) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = ImplicitPrecedence::default().into();
    let query = format!("SELECT a FROM t WHERE {expression}");
    let diagnostics = if view {
        let sql = format!("{SCHEMA} CREATE VIEW v AS {query}");
        let database = if matches!(
            expression,
            "a + b NOT LIKE 'x'" | "a + b ILIKE 'x'" | "a + b SIMILAR TO 'x'"
        ) {
            ParserDB::parse::<SQLiteDialect>(&sql)
                .expect("SQLite arithmetic pattern operands parse")
        } else {
            parse(&sql)
        };
        constrainer.diagnostics(&database)
    } else {
        constrainer.statement_diagnostics(&parse(SCHEMA), &statement(&query))
    };
    diagnostics
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

/// Mixed operators require grouping in queries and views.
#[test]
fn mixed_operators_are_reported_in_queries_and_views() {
    for expression in [
        "a AND b OR c",
        "a OR b AND c",
        "NOT a = b",
        "'a' || 1 + 2",
        "a::TEXT || b::TEXT = c::TEXT",
        "x::JSONB ->> 'k' = y::TEXT",
        "x::JSONB ->> 'k' + 1",
        "a & b + c",
        "a & b | c",
        "a = b = TRUE",
        "a < b = TRUE",
        "a IS NULL = TRUE",
        "-a ^ b",
        "ts AT TIME ZONE 'UTC' = x::TIMESTAMP",
        "a + b || c::TEXT",
        "a BETWEEN b & c AND x",
        "a::TEXT || b::TEXT IN (c::TEXT)",
        "a::TEXT || b::TEXT LIKE 'x'",
    ] {
        for view in [false, true] {
            assert!(
                !messages(expression, view).is_empty(),
                "{expression}, view={view}"
            );
        }
    }
}

/// Exempt operator layers and syntactic delimiters need no grouping.
#[test]
fn exempt_layers_and_delimiters_are_accepted() {
    for expression in [
        "a AND b AND c",
        "a::TEXT || b::TEXT || c::TEXT",
        "a + b - c",
        "a * b / c",
        "a + b * c",
        "a * b + c",
        "-a + +b",
        "a * -b",
        "-a = +b",
        "a + b > c * x",
        "a = b AND b < c",
        "a IS NULL OR b IS NOT NULL",
        "NOT a AND b",
        "a OR NOT b",
        "(a AND b) OR c",
        "NOT (a = b)",
        "(a::TEXT || b::TEXT) = c::TEXT",
        "(x::JSONB ->> 'k')::INT + 1",
        "a & (b + c)",
        "(-a) ^ b",
        "x::JSONB -> 'a' ->> 'b'",
        "x::JSONB #> '{a}' #>> '{b}'",
        "x::JSONB -> 'a' #>> '{b}'",
        "a + b IS NULL",
        "a + b IS NOT TRUE",
        "a + b IS FALSE",
        "a + b IS NOT FALSE",
        "a + b IS UNKNOWN",
        "a + b IS NOT UNKNOWN",
        "a + b IS TRUE",
        "a + b IS NOT NULL",
        "a + b IS DISTINCT FROM c",
        "a + b IS NOT DISTINCT FROM c",
        "a + b NOT BETWEEN c - x AND y * 2",
        "a::TEXT NOT IN (c::TEXT || x::TEXT)",
        "a + b NOT IN (c & x, y & 1)",
        "a + b NOT LIKE 'x'",
        "a + b ILIKE 'x'",
        "a + b SIMILAR TO 'x'",
        "a + b = ANY(ARRAY[c])",
        "a + b > ALL(ARRAY[c])",
        "LENGTH(a::TEXT || b::TEXT) + x",
        "CASE WHEN a = b THEN c | x ELSE y END + 1",
        "ARRAY[a | b, c & x]",
        "(SELECT a | b FROM t) + 1",
        "a::INT + b",
        "CAST(a AS INT) + b",
        "a::TEXT COLLATE \"C\" || b::TEXT",
    ] {
        for view in [false, true] {
            assert!(
                messages(expression, view).is_empty(),
                "{expression}, view={view}"
            );
        }
    }
}

/// The suggested grouping preserves the parsed expression.
#[test]
fn finding_names_both_operators_and_explicit_grouping() {
    let found = messages("a AND b OR c", false);
    assert_eq!(found.len(), 1);
    for fragment in ["`a AND b OR c`", "`AND`", "`OR`", "`(a AND b) OR c`"] {
        assert!(found[0].contains(fragment), "{found:?}");
    }
}

/// SQLite schemas use the grouping produced by their parser.
#[test]
fn sqlite_schema_reports_mixed_operators() {
    let constrainer: GenericConstrainer<ParserDB> = ImplicitPrecedence::default().into();
    let database = ParserDB::parse::<SQLiteDialect>(
        "CREATE TABLE t (a INT); CREATE VIEW v AS SELECT 'a' || 1 + 2 FROM t;",
    )
    .unwrap();
    assert_eq!(constrainer.diagnostics(&database).len(), 1);
}

/// Schema expression sites share the same rule.
#[test]
fn schema_expression_sites_require_grouping() {
    let constrainer: GenericConstrainer<ParserDB> = ImplicitPrecedence::default().into();
    let database = parse(&format!(
        "{SCHEMA}
        CREATE MATERIALIZED VIEW mv AS SELECT a & b + c FROM t;
        CREATE POLICY p ON t USING (a AND b OR c);
        ALTER TABLE t ADD CONSTRAINT checked CHECK (a AND b OR c);
        CREATE FUNCTION f() RETURNS INT LANGUAGE sql AS $$ SELECT a & b + c FROM t $$;
        CREATE FUNCTION g(a INT, b INT, c INT) RETURNS INT LANGUAGE plpgsql AS $$
        BEGIN RETURN a & b + c; END $$;"
    ));
    assert_eq!(constrainer.diagnostics(&database).len(), 5);
}

/// SQLite pattern operators share the comparison exemptions.
#[test]
fn sqlite_pattern_operators_follow_comparison_layers() {
    let constrainer: GenericConstrainer<ParserDB> = ImplicitPrecedence::default().into();
    let database = ParserDB::parse::<SQLiteDialect>(SCHEMA).unwrap();
    for comparison in ["GLOB", "MATCH", "REGEXP", "NOT REGEXP"] {
        for (expression, expected) in [
            (format!("a + b {comparison} 'x'"), 0),
            (format!("a {comparison} 'x' AND b = c"), 0),
            (format!("a || b {comparison} 'x'"), 1),
        ] {
            let query = format!("SELECT a FROM t WHERE {expression}");
            let statements =
                sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, &query).unwrap();
            assert_eq!(
                constrainer
                    .statement_diagnostics(&database, &statements[0])
                    .len(),
                expected,
                "{expression}"
            );
            let view =
                ParserDB::parse::<SQLiteDialect>(&format!("{SCHEMA} CREATE VIEW v AS {query}"))
                    .unwrap();
            assert_eq!(
                constrainer.diagnostics(&view).len(),
                expected,
                "{expression}"
            );
        }
    }
}
