//! `NOT IN` lists and `<> ALL` arrays holding a `NULL`. Measured on
//! PostgreSQL 18: `NOT IN (NULL)`, `NOT IN (2, NULL::int)` and
//! `<> ALL (ARRAY[2, NULL])` matched no row.

use crate::{common::parse, rule_findings::statement};
use sqlippy::prelude::*;

const SCHEMA: &str = "CREATE TABLE t (id INT, x INT);";

const PROBLEM: &str = "which is never true once the list holds a NULL, so a filter keeps no row and a check rejects none";

fn constrainer() -> GenericConstrainer<ParserDB> {
    NotInNullList::default().into()
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
fn lists_and_arrays_holding_null_are_reported() {
    for (filter, shown) in [
        ("x NOT IN (NULL)", "x NOT IN (NULL)"),
        ("x NOT IN (2, NULL)", "x NOT IN (2, NULL)"),
        ("x NOT IN (2, NULL::INT)", "x NOT IN (2, NULL::INT)"),
        ("x NOT IN (2, (NULL))", "x NOT IN (2, (NULL))"),
        ("x <> ALL (ARRAY[2, NULL])", "x <> ALL(ARRAY[2, NULL])"),
        (
            "x <> ALL (ARRAY[2, NULL]::INT[])",
            "x <> ALL(ARRAY[2, NULL]::INT[])",
        ),
    ] {
        assert_eq!(
            statement_messages(&format!("SELECT id FROM t WHERE {filter}")),
            [format!("The statement uses `{shown}`, {PROBLEM}.")],
            "{filter}"
        );
    }
}

#[test]
fn lists_are_reported_wherever_the_schema_writes_them() {
    assert_eq!(
        schema_messages(
            "CREATE VIEW v AS SELECT id FROM t WHERE x NOT IN (1, NULL);
             CREATE POLICY p ON t USING (x <> ALL (ARRAY[1, NULL]));
             ALTER TABLE t ADD CONSTRAINT allowed CHECK (x NOT IN (1, NULL));
             CREATE FUNCTION f() RETURNS SETOF INT LANGUAGE sql
               AS $$ SELECT id FROM t WHERE x NOT IN (NULL) $$;"
        ),
        [
            format!("View 'v' uses `x NOT IN (1, NULL)`, {PROBLEM}."),
            format!(
                "Policy 'p' on 't' uses `x <> ALL(ARRAY[1, NULL])` in its USING clause, {PROBLEM}."
            ),
            format!("Check `x NOT IN (1, NULL)` on 't' uses `x NOT IN (1, NULL)`, {PROBLEM}."),
            format!("Function 'f()' uses `x NOT IN (NULL)`, {PROBLEM}."),
        ]
    );
}

#[test]
fn lists_without_null_and_matching_forms_are_not_reported() {
    for filter in [
        "x NOT IN (1, 2)",
        "x IN (1, NULL)",
        "x = ANY (ARRAY[1, NULL])",
        "x <> ANY (ARRAY[1, NULL])",
        "x <> ALL (ARRAY[1, 2])",
        "x NOT IN (1, NULLIF(id, 0))",
        "x NOT IN (SELECT 1)",
    ] {
        assert_eq!(
            statement_messages(&format!("SELECT id FROM t WHERE {filter}")),
            Vec::<String>::new(),
            "{filter}"
        );
    }
}
