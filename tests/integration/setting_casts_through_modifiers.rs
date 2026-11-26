//! Setting reads cast through a type modifier, measured on PostgreSQL 18
//! with `app.installation_id = 'abcd'`, where
//! `NULLIF(current_setting('app.installation_id', true), '')::varchar(3)` is
//! `abc`, `'1.23456'::numeric(5,2)` is `1.23`, `'1 day 3 hours'::interval day`
//! is `1 day` and `'abcd'::char` is `a`.

use crate::{common::parse, rule_findings::statement};
use sqlippy::prelude::*;

const SCHEMA: &str = "CREATE TABLE objects (id INT, installation_id TEXT);";

const PROBLEM: &str =
    "so the modifier truncates, rounds or rejects the value the request sent before it is used";

fn constrainer() -> GenericConstrainer<ParserDB> {
    SettingCastThroughModifier::default().into()
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
fn policy_comparing_a_truncated_setting_is_reported() {
    assert_eq!(
        schema_messages(
            "CREATE POLICY local_inline ON objects USING (installation_id = NULLIF(current_setting('app.installation_id', true), '')::varchar(3));"
        ),
        [format!(
            "Policy 'local_inline' on 'objects' uses setting 'app.installation_id' cast to `VARCHAR(3)` in its USING clause, {PROBLEM}."
        )]
    );
}

#[test]
fn every_modifier_postgresql_applies_on_a_cast_is_reported() {
    for (cast, written) in [
        ("::varchar(3)", "VARCHAR(3)"),
        ("::character varying(3)", "CHARACTER VARYING(3)"),
        ("::char(3)", "CHAR(3)"),
        ("::character(3)", "CHARACTER(3)"),
        ("::numeric(5,2)", "NUMERIC(5,2)"),
        ("::numeric(5)", "NUMERIC(5)"),
        ("::decimal(5,2)", "DECIMAL(5,2)"),
        ("::timestamp(0)", "TIMESTAMP(0)"),
        (
            "::timestamp(3) with time zone",
            "TIMESTAMP(3) WITH TIME ZONE",
        ),
        ("::time(0)", "TIME(0)"),
        ("::interval(2)", "INTERVAL(2)"),
        ("::interval day", "INTERVAL DAY"),
        ("::bit(2)", "BIT(2)"),
        ("::bit varying(2)", "BIT VARYING(2)"),
        ("::varchar(3)[]", "VARCHAR(3)[]"),
        ("::char", "CHAR"),
        ("::character", "CHARACTER"),
        ("::char[]", "CHAR[]"),
        ("::bit", "BIT"),
    ] {
        let sql = format!("SELECT current_setting('app.value'){cast}");
        assert_eq!(
            statement_messages(&sql),
            [format!(
                "The statement uses setting 'app.value' cast to `{written}`, {PROBLEM}."
            )],
            "{sql}"
        );
    }
}

#[test]
fn setting_reads_are_followed_through_wrappers() {
    for read in [
        "pg_catalog.current_setting('app.value', true)",
        "CURRENT_SETTING('app.value')",
        "(current_setting('app.value', true))",
        "NULLIF(current_setting('app.value', true), '')",
        "COALESCE(current_setting('app.value', true), 'none')",
        "current_setting('app.value', true)::text",
    ] {
        for sql in [
            format!("SELECT {read}::varchar(3)"),
            format!("SELECT CAST({read} AS varchar(3))"),
        ] {
            assert_eq!(statement_messages(&sql).len(), 1, "{sql}");
        }
    }
}

#[test]
fn a_dynamic_setting_name_is_reported_by_its_read() {
    assert_eq!(
        statement_messages("SELECT current_setting(lower('APP.VALUE'))::varchar(3)"),
        [format!(
            "The statement uses setting read `current_setting(lower('APP.VALUE'))` cast to `VARCHAR(3)`, {PROBLEM}."
        )]
    );
}

#[test]
fn casts_without_a_modifier_and_other_values_pass() {
    for sql in [
        "SELECT current_setting('app.value')::varchar",
        "SELECT current_setting('app.value')::text",
        "SELECT NULLIF(current_setting('app.value', true), '')::uuid",
        "SELECT current_setting('app.value')::numeric",
        "SELECT current_setting('app.value')::timestamp with time zone",
        "SELECT current_setting('app.value')::interval",
        "SELECT current_setting('app.value')::float(24)",
        "SELECT current_setting('app.value')::varchar[]",
        "SELECT current_setting('app.value')::bpchar",
        "SELECT 'abcd'::varchar(3)",
        "SELECT installation_id::varchar(3) FROM objects",
        "SELECT NULLIF(installation_id, current_setting('app.value'))::varchar(3) FROM objects",
        "SELECT app.current_setting('app.value')::varchar(3)",
        "SELECT length(current_setting('app.value'))::numeric(5,2)",
    ] {
        assert_eq!(statement_messages(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_cast_through_two_modifiers_is_reported_once() {
    assert_eq!(
        statement_messages("SELECT current_setting('app.value')::varchar(5)::varchar(3)"),
        [format!(
            "The statement uses setting 'app.value' cast to `VARCHAR(5)`, {PROBLEM}."
        )]
    );
}

#[test]
fn casts_are_reported_wherever_the_schema_writes_them() {
    let found = schema_messages(
        "CREATE VIEW mine AS SELECT id FROM objects WHERE installation_id = current_setting('app.installation_id')::varchar(3);
         CREATE FUNCTION acting() RETURNS TEXT LANGUAGE sql
           AS $$ SELECT current_setting('app.installation_id')::varchar(3) $$;
         CREATE FUNCTION acting_procedural() RETURNS TEXT LANGUAGE plpgsql
           AS $$ BEGIN RETURN current_setting('app.installation_id')::varchar(3); END $$;",
    );
    assert_eq!(
        found,
        [
            format!(
                "View 'mine' uses setting 'app.installation_id' cast to `VARCHAR(3)`, {PROBLEM}."
            ),
            format!(
                "Function 'acting()' uses setting 'app.installation_id' cast to `VARCHAR(3)`, {PROBLEM}."
            ),
            format!(
                "Function 'acting_procedural()' uses setting 'app.installation_id' cast to `VARCHAR(3)`, {PROBLEM}."
            ),
        ]
    );
}
