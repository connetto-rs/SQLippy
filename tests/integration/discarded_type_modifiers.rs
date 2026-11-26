//! Type modifiers on a function's declared types, which PostgreSQL discards.
//! Measured on PostgreSQL 18, where `OUT id VARCHAR(3)` assigned `'abcd'`
//! returns `abcd`, `OUT a NUMERIC(5,2)` assigned `1.23456` returns `1.23456`,
//! `RETURNS varchar(2)` and `RETURNS TABLE (x varchar(2))` return longer
//! strings, an `interval day` argument keeps its hours, and
//! `pg_get_function_arguments` answers `OUT id character varying`.

use crate::common::parse;
use sqlippy::prelude::*;

fn messages(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = DiscardedTypeModifier::default().into();
    constrainer
        .diagnostics(&parse(sql))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn an_out_parameter_with_a_length_is_reported() {
    assert_eq!(
        messages(
            "CREATE FUNCTION acting_installation(OUT namespace_id UUID, OUT id VARCHAR(3)) RETURNS RECORD
             LANGUAGE plpgsql STABLE AS $$ BEGIN id := 'abcd'; END $$;"
        ),
        ["Function 'acting_installation()' declares OUT parameter `id` as `VARCHAR(3)`, and PostgreSQL discards the type modifier of a function's argument and result types, so nothing enforces it."]
    );
}

#[test]
fn every_declared_position_is_reported() {
    assert_eq!(
        messages(
            "CREATE FUNCTION f(NUMERIC(5,2), INOUT b TIMESTAMP(0)) RETURNS NUMERIC(5,2) LANGUAGE sql AS 'SELECT 1';
             CREATE FUNCTION g() RETURNS TABLE (x VARCHAR(2), y TEXT) LANGUAGE sql AS 'SELECT ''a'', ''b''';
             CREATE FUNCTION h() RETURNS SETOF CHAR(2) LANGUAGE sql AS 'SELECT ''a''';"
        ),
        [
            "Function 'f(NUMERIC, TIMESTAMP)' declares parameter 1 as `NUMERIC(5,2)`, and PostgreSQL discards the type modifier of a function's argument and result types, so nothing enforces it.",
            "Function 'f(NUMERIC, TIMESTAMP)' declares INOUT parameter `b` as `TIMESTAMP(0) WITHOUT TIME ZONE`, and PostgreSQL discards the type modifier of a function's argument and result types, so nothing enforces it.",
            "Function 'f(NUMERIC, TIMESTAMP)' declares its return type as `NUMERIC(5,2)`, and PostgreSQL discards the type modifier of a function's argument and result types, so nothing enforces it.",
            "Function 'g()' declares returned column `x` as `VARCHAR(2)`, and PostgreSQL discards the type modifier of a function's argument and result types, so nothing enforces it.",
            "Function 'h()' declares its return type as `CHAR(2)`, and PostgreSQL discards the type modifier of a function's argument and result types, so nothing enforces it.",
        ]
    );
}

#[test]
fn bare_char_declares_the_length_postgresql_discards() {
    assert_eq!(
        messages("CREATE FUNCTION f(a CHAR) RETURNS TEXT LANGUAGE sql AS 'SELECT a';").len(),
        1
    );
}

#[test]
fn unmodified_types_and_domains_pass() {
    for sql in [
        "CREATE FUNCTION f(OUT id VARCHAR, OUT note TEXT, OUT amount NUMERIC) RETURNS RECORD LANGUAGE sql AS 'SELECT ''a'', ''b'', 1';",
        "CREATE FUNCTION f(a TIMESTAMP WITH TIME ZONE, b INTERVAL, c VARCHAR[]) RETURNS SETOF TEXT LANGUAGE sql AS 'SELECT ''a''';",
        "CREATE FUNCTION f() RETURNS TABLE (x VARCHAR, y UUID) LANGUAGE sql AS 'SELECT ''a'', gen_random_uuid()';",
        "CREATE DOMAIN code3 AS VARCHAR(3); CREATE FUNCTION f(OUT code code3) LANGUAGE sql AS 'SELECT ''abc''';",
        "CREATE PROCEDURE p() LANGUAGE sql AS 'SELECT 1';",
    ] {
        assert_eq!(messages(sql), Vec::<String>::new(), "{sql}");
    }
}
