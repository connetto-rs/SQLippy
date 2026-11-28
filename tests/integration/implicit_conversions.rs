//! Operands and arguments PostgreSQL converts implicitly, or compares across
//! two types of one family, judged as Rust judges mixed types.

use crate::{common::parse, rule_findings::statement};
use sqlippy::prelude::*;
use sqlparser::dialect::SQLiteDialect;

const SCHEMA: &str = "CREATE DOMAIN email AS TEXT;
CREATE TABLE t (
    id INT4, big INT8, small INT2, amount NUMERIC, ratio FLOAT8,
    label TEXT, code VARCHAR(10), padded CHAR(4), mail email,
    day DATE, at TIMESTAMP, atz TIMESTAMPTZ, data JSONB, flag BOOLEAN, ident UUID
);
CREATE FUNCTION widened(n BIGINT) RETURNS BIGINT LANGUAGE sql IMMUTABLE RETURN n;";

const PROBLEM: &str = "so its meaning rests on an implicit conversion the SQL does not show";

fn constrainer() -> GenericConstrainer<ParserDB> {
    ImplicitConversion::default().into()
}

/// Messages of the findings in the schema `sql` declares after `SCHEMA`.
fn schema_messages(sql: &str) -> Vec<String> {
    messages(constrainer().diagnostics(&parse(&format!("{SCHEMA} {sql}"))))
}

/// Messages of the findings in the statement `sql`.
fn statement_messages(sql: &str) -> Vec<String> {
    messages(constrainer().statement_diagnostics(&parse(SCHEMA), &statement(sql)))
}

fn messages(diagnostics: Vec<Error<ParserDB>>) -> Vec<String> {
    diagnostics
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn mixed_operands_are_reported() {
    for (expression, found) in [
        (
            "id = big",
            "`id = big`, whose operands are `int4` and `int8`",
        ),
        (
            "small < id",
            "`small < id`, whose operands are `int2` and `int4`",
        ),
        (
            "day < at",
            "`day < at`, whose operands are `date` and `timestamp`",
        ),
        (
            "at < atz",
            "`at < atz`, whose operands are `timestamp` and `timestamptz`",
        ),
        (
            "id + ratio > ratio",
            "`id + ratio`, which converts `id` from `int4` to `float8`",
        ),
        (
            "amount * 2 > amount",
            "`amount * 2`, which converts `2` from `int4` to `numeric`",
        ),
        (
            "amount > 0",
            "`amount > 0`, which converts `0` from `int4` to `numeric`",
        ),
        (
            "padded = label",
            "`padded = label`, which converts `padded` from `bpchar` to `text`",
        ),
        (
            "label || id = 'x'",
            "`label || id`, which converts `id` from `int4` to `text`",
        ),
        (
            "'a' || 1 = label",
            "`'a' || 1`, which converts `1` from `int4` to `text`",
        ),
        (
            "atz > '2026-01-01'",
            "`atz > '2026-01-01'`, which reads the string `'2026-01-01'` as `timestamptz`",
        ),
        (
            "data @> '{\"a\": 1}'",
            "`data @> '{\"a\": 1}'`, which reads the string `'{\"a\": 1}'` as `jsonb`",
        ),
        (
            "round(id, 2) > amount",
            "`round(id, 2)`, which converts `id` from `int4` to `numeric`",
        ),
        (
            "widened(id) > 0",
            "`widened(id)`, which converts `id` from `int4` to `int8`",
        ),
        (
            "id IN (big, 2)",
            "`id IN (big, 2)`, whose operands are `int4` and `int8`",
        ),
        (
            "id BETWEEN 1 AND big",
            "`id BETWEEN 1 AND big`, whose operands are `int4` and `int8`",
        ),
    ] {
        let sql = format!("SELECT 1 FROM t WHERE {expression}");
        assert_eq!(
            statement_messages(&sql),
            [format!("The statement uses {found}, {PROBLEM}.")],
            "{sql}"
        );
    }
}

#[test]
fn same_typed_operands_and_adapting_literals_pass() {
    for expression in [
        "big > 5",
        "small = 5",
        "-5 < big",
        "amount * 2.0 > amount",
        "ratio * 2.5 > ratio",
        "label = 'x'",
        "code = label",
        "code || 'x' = label",
        "mail = label",
        "length(mail) > 3",
        "mail = 'a@b.c'",
        "atz > TIMESTAMPTZ '2026-01-01 00:00+00'",
        "atz > now()",
        "atz - INTERVAL '1 day' < atz",
        "day + 1 > day",
        "data ->> 'a' = label",
        "data -> 0 IS NOT NULL",
        "id = $1",
        "flag = true",
        "round(amount, 2) > amount",
        "id::NUMERIC * amount > amount",
        "ident = 'x'::UUID",
        "label IS NULL",
        "amount = NULL",
    ] {
        let sql = format!("SELECT 1 FROM t WHERE {expression}");
        assert_eq!(statement_messages(&sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn conversions_are_reported_wherever_the_schema_writes_them() {
    assert_eq!(
        schema_messages(
            "CREATE VIEW v AS SELECT id FROM t WHERE id = big;
             CREATE POLICY p ON t USING (id + ratio > ratio);
             ALTER TABLE t ADD CONSTRAINT bounded CHECK (amount * 2 > amount);
             CREATE FUNCTION f(n INT4) RETURNS SETOF INT4 LANGUAGE sql
               AS $$ SELECT id FROM t WHERE big = n $$;"
        ),
        [
            format!("View 'v' uses `id = big`, whose operands are `int4` and `int8`, {PROBLEM}."),
            format!(
                "Policy 'p' on 't' uses `id + ratio`, which converts `id` from `int4` to `float8` in its USING clause, {PROBLEM}."
            ),
            format!(
                "Check `amount * 2 > amount` on 't' uses `amount * 2`, which converts `2` from `int4` to `numeric`, {PROBLEM}."
            ),
            format!(
                "Function 'f(INT4)' uses `big = n`, whose operands are `int8` and `int4`, {PROBLEM}."
            ),
        ]
    );
}

#[test]
fn a_sqlite_schema_is_not_judged() {
    let database = ParserDB::parse::<SQLiteDialect>(
        "CREATE TABLE t (id INTEGER, label TEXT);
         CREATE VIEW v AS SELECT id FROM t WHERE id = label;",
    )
    .unwrap();
    assert!(constrainer().diagnostics(&database).is_empty());
}
