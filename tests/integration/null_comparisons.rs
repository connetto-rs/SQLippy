//! Comparisons with a `NULL` literal. Measured on PostgreSQL 18:
//! `WHERE x = NULL`, `x <> NULL`, `x < NULL` and `NULL = x` matched no row,
//! and `CHECK (x <> NULL)` accepted `NULL` and `1` alike.

use crate::{common::parse, rule_findings::statement};
use sqlippy::prelude::*;

const SCHEMA: &str = "CREATE TABLE t (id INT, x INT);";

const PROBLEM: &str = "which is NULL whatever the other side holds, so a filter keeps no row and a check rejects none";

fn constrainer() -> GenericConstrainer<ParserDB> {
    NullComparison::default().into()
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
fn every_comparison_operator_with_null_is_reported() {
    for comparison in [
        "x = NULL",
        "x <> NULL",
        "x != NULL",
        "x < NULL",
        "x <= NULL",
        "x > NULL",
        "x >= NULL",
        "NULL = x",
        "x = NULL::INT",
        "x = CAST(NULL AS INT)",
        "x = (NULL)",
    ] {
        let sql = format!("SELECT id FROM t WHERE {comparison}");
        let found = statement_messages(&sql);
        assert_eq!(found.len(), 1, "{sql}: {found:?}");
        assert!(found[0].starts_with("The statement uses `"), "{found:?}");
        assert!(found[0].ends_with(&format!(", {PROBLEM}.")), "{found:?}");
    }
}

#[test]
fn comparisons_are_reported_wherever_the_schema_writes_them() {
    assert_eq!(
        schema_messages(
            "CREATE VIEW v AS SELECT id FROM t WHERE x = NULL;
             CREATE MATERIALIZED VIEW mv AS SELECT id FROM t WHERE x <> NULL;
             CREATE POLICY p ON t USING (x < NULL);
             ALTER TABLE t ADD CONSTRAINT positive CHECK (x <> NULL);
             CREATE FUNCTION f() RETURNS SETOF INT LANGUAGE sql
               AS $$ SELECT id FROM t WHERE x >= NULL $$;
             CREATE FUNCTION g(y INT) RETURNS BOOLEAN LANGUAGE sql RETURN y = NULL;"
        ),
        [
            format!("View 'v' uses `x = NULL`, {PROBLEM}."),
            format!("Materialized view 'mv' uses `x <> NULL`, {PROBLEM}."),
            format!("Policy 'p' on 't' uses `x < NULL` in its USING clause, {PROBLEM}."),
            format!("Check `x <> NULL` on 't' uses `x <> NULL`, {PROBLEM}."),
            format!("Function 'f()' uses `x >= NULL`, {PROBLEM}."),
            format!("Function 'g(INT)' uses `y = NULL`, {PROBLEM}."),
        ]
    );
}

#[test]
fn a_statement_reports_each_comparison() {
    assert_eq!(
        statement_messages("UPDATE t SET x = 1 WHERE x = NULL OR id <> NULL").len(),
        2
    );
}

#[test]
fn plpgsql_cursor_counts_handlers_and_raise_options_are_walked() {
    assert_eq!(
        schema_messages(
            "CREATE FUNCTION paged() RETURNS void LANGUAGE plpgsql AS $$
             DECLARE c SCROLL CURSOR FOR SELECT id FROM t; n int;
             BEGIN
               OPEN c;
               FETCH ABSOLUTE (SELECT count(*) FROM t WHERE x = NULL) FROM c INTO n;
               MOVE BACKWARD (SELECT count(*) FROM t WHERE x <> NULL) IN c;
               FETCH FIRST FROM c INTO n;
               CLOSE c;
               RAISE 'paged' USING DETAIL = (SELECT count(*) FROM t WHERE x < NULL);
             EXCEPTION WHEN others THEN
               PERFORM id FROM t WHERE x > NULL;
             END $$;"
        ),
        [
            format!("Function 'paged()' uses `x = NULL`, {PROBLEM}."),
            format!("Function 'paged()' uses `x <> NULL`, {PROBLEM}."),
            format!("Function 'paged()' uses `x < NULL`, {PROBLEM}."),
            format!("Function 'paged()' uses `x > NULL`, {PROBLEM}."),
        ]
    );
}

#[test]
fn null_tests_and_assignments_are_not_reported() {
    for sql in [
        "SELECT id FROM t WHERE x IS NULL",
        "SELECT id FROM t WHERE x IS NOT NULL",
        "SELECT id FROM t WHERE x IS DISTINCT FROM NULL",
        "SELECT id FROM t WHERE x IS NOT DISTINCT FROM NULL",
        "SELECT id FROM t WHERE x = NULLIF(id, 0)",
        "SELECT id FROM t WHERE x + NULL > 0 IS NULL",
        "UPDATE t SET x = NULL WHERE id = 1",
        "SELECT id FROM t WHERE x = COALESCE(NULL, 1)",
    ] {
        assert_eq!(statement_messages(sql), Vec::<String>::new(), "{sql}");
    }
}
