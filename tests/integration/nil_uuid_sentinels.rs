//! Comparisons with the nil UUID as an absence sentinel. Measured on
//! PostgreSQL 18: the uuid input reads `'00000000000000000000000000000000'`,
//! `'{00000000-0000-0000-0000-000000000000}'` and
//! `'0000-0000-0000-0000-0000-0000-0000-0000'` as the nil UUID and rejects a
//! leading or trailing space or hyphen, a doubled hyphen, a hyphen inside a
//! group of four digits and an unclosed brace. A `uuid[]` literal trims the
//! space around an element, drops the quotes and a backslash before a
//! character, and reads `'[1:1]={...}'` and `'{{...}}'` alike.

use crate::{common::parse, rule_findings::statement};
use sqlippy::prelude::*;

const SCHEMA: &str =
    "CREATE TABLE docs (id UUID PRIMARY KEY, installation_id UUID, owners UUID[]);";

const NIL: &str = "'00000000-0000-0000-0000-000000000000'";

const PROBLEM: &str = "which encodes absence as a magic value every writer must bind and every reader must know, where NULL states it directly";

fn constrainer() -> GenericConstrainer<ParserDB> {
    NilUuidSentinel::default().into()
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
fn every_test_against_the_nil_uuid_is_reported() {
    for test in [
        format!("installation_id = {NIL}"),
        format!("{NIL} = installation_id"),
        format!("installation_id <> {NIL}"),
        format!("installation_id != {NIL}"),
        format!("installation_id = {NIL}::uuid"),
        format!("installation_id = CAST({NIL} AS UUID)"),
        format!("installation_id = ({NIL})"),
        format!("installation_id IS DISTINCT FROM {NIL}"),
        format!("installation_id IS NOT DISTINCT FROM {NIL}"),
        format!("installation_id IN (id, {NIL})"),
        format!("installation_id NOT IN ({NIL})"),
        format!("{NIL} IN (SELECT installation_id FROM docs)"),
        format!("NULLIF(installation_id, {NIL}) IS NULL"),
        format!("installation_id = ANY (ARRAY[id, {NIL}::uuid])"),
        format!("installation_id <> ALL (ARRAY[{NIL}]::uuid[])"),
        format!("{NIL} = ANY (owners)"),
        format!("CASE installation_id WHEN {NIL} THEN false ELSE true END"),
        format!("CASE {NIL} WHEN installation_id THEN false ELSE true END"),
        "installation_id = uuid_nil()".to_owned(),
        "installation_id = extensions.uuid_nil()".to_owned(),
    ] {
        let sql = format!("SELECT id FROM docs WHERE {test}");
        let found = statement_messages(&sql);
        assert_eq!(found.len(), 1, "{sql}: {found:?}");
        assert!(found[0].starts_with("The statement uses `"), "{found:?}");
        assert!(found[0].ends_with(&format!(", {PROBLEM}.")), "{found:?}");
    }
}

#[test]
fn every_spelling_postgresql_reads_as_the_nil_uuid_is_reported() {
    for nil in [
        "'00000000000000000000000000000000'",
        "'{00000000-0000-0000-0000-000000000000}'",
        "'0000-0000-0000-0000-0000-0000-0000-0000'",
        "'00000000-00000000-0000-000000000000'",
        "UUID '00000000-0000-0000-0000-000000000000'",
        "E'00000000-0000-0000-0000-000000000000'",
        "$$00000000-0000-0000-0000-000000000000$$",
    ] {
        let sql = format!("SELECT id FROM docs WHERE installation_id = {nil}");
        assert_eq!(statement_messages(&sql).len(), 1, "{sql}");
    }
    for array in [
        "'{00000000-0000-0000-0000-000000000000}'",
        "'{11111111-1111-1111-1111-111111111111, \"00000000-0000-0000-0000-000000000000\"}'",
        "'{ 00000000-0000-0000-0000-000000000000 }'",
        "'[1:1]={00000000-0000-0000-0000-000000000000}'",
        "'{{00000000-0000-0000-0000-000000000000}}'",
        "'{\"{00000000-0000-0000-0000-000000000000}\"}'",
        "'{0000\\0000-0000-0000-0000-000000000000}'",
    ] {
        let sql = format!("SELECT id FROM docs WHERE installation_id = ANY ({array}::uuid[])");
        assert_eq!(statement_messages(&sql).len(), 1, "{sql}");
    }
}

#[test]
fn strings_postgresql_reads_as_another_uuid_or_rejects_are_not_reported() {
    for other in [
        "'00000000-0000-0000-0000-000000000001'",
        "'00000000-0000-0000-0000-00000000000'",
        "'00000000-0000-0000-0000-0000000000000'",
        "'{00000000-0000-0000-0000-000000000000'",
        "'00000000-0000-0000-0000-000000000000}'",
        "'000-00000-0000-0000-0000-000000000000'",
        "'00000000--0000-0000-0000-000000000000'",
        "'-00000000-0000-0000-0000-000000000000'",
        "'00000000-0000-0000-0000-000000000000-'",
        "' 00000000-0000-0000-0000-000000000000'",
        "'00000000-0000-0000-0000-000000000000 '",
        "''",
        "0",
    ] {
        let sql = format!("SELECT id FROM docs WHERE installation_id = {other}");
        assert_eq!(statement_messages(&sql), Vec::<String>::new(), "{sql}");
    }
    for array in [
        "'{11111111-1111-1111-1111-111111111111}'",
        "'{0000 0000-0000-0000-0000-000000000000}'",
        "'[1:1]{00000000-0000-0000-0000-000000000000}'",
        "'{\"00000000-0000-0000-0000-000000000000 \"}'",
    ] {
        let sql = format!("SELECT id FROM docs WHERE installation_id = ANY ({array}::uuid[])");
        assert_eq!(statement_messages(&sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn ordering_null_tests_and_written_values_are_not_reported() {
    for sql in [
        format!("SELECT id FROM docs WHERE installation_id < {NIL}"),
        format!("SELECT id FROM docs WHERE installation_id > ANY (ARRAY[{NIL}::uuid])"),
        format!("SELECT id FROM docs WHERE CASE WHEN installation_id IS NULL THEN {NIL} END = id"),
        format!("INSERT INTO docs (id) VALUES ({NIL})"),
        format!("UPDATE docs SET installation_id = {NIL} WHERE id = installation_id"),
        format!("SELECT {NIL}::uuid"),
        "SELECT id FROM docs WHERE installation_id IS NULL".to_owned(),
        "SELECT id FROM docs WHERE installation_id = NULLIF(current_setting('app.installation_id', true), '')::uuid".to_owned(),
        "SELECT id FROM docs WHERE installation_id = uuid_generate_v4()".to_owned(),
    ] {
        assert_eq!(statement_messages(&sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn tests_are_reported_wherever_the_schema_writes_them() {
    assert_eq!(
        schema_messages(&format!(
            "CREATE VIEW v AS SELECT id FROM docs WHERE installation_id = {NIL};
             CREATE MATERIALIZED VIEW mv AS SELECT id FROM docs WHERE installation_id <> {NIL}::uuid;
             CREATE POLICY p ON docs USING (installation_id IS DISTINCT FROM {NIL});
             ALTER TABLE docs ADD CONSTRAINT tagged CHECK (installation_id IN ({NIL}, id));
             CREATE FUNCTION f() RETURNS SETOF UUID LANGUAGE sql
               AS $$ SELECT id FROM docs WHERE NULLIF(installation_id, {NIL}) IS NULL $$;
             CREATE FUNCTION g(installation UUID) RETURNS BOOLEAN LANGUAGE sql
               RETURN installation = {NIL};
             CREATE FUNCTION stamp() RETURNS TRIGGER LANGUAGE plpgsql AS $$
             BEGIN
               IF NEW.installation_id = {NIL} THEN
                 NEW.installation_id := NULL;
               END IF;
               RETURN NEW;
             END $$;"
        )),
        [
            format!("View 'v' uses `installation_id = {NIL}`, {PROBLEM}."),
            format!("Materialized view 'mv' uses `installation_id <> {NIL}::UUID`, {PROBLEM}."),
            format!(
                "Policy 'p' on 'docs' uses `installation_id IS DISTINCT FROM {NIL}` in its USING clause, {PROBLEM}."
            ),
            format!(
                "Check `installation_id IN ({NIL}, id)` on 'docs' uses `installation_id IN ({NIL}, id)`, {PROBLEM}."
            ),
            format!("Function 'f()' uses `NULLIF(installation_id, {NIL})`, {PROBLEM}."),
            format!("Function 'g(UUID)' uses `installation = {NIL}`, {PROBLEM}."),
            format!("Function 'stamp()' uses `NEW.installation_id = {NIL}`, {PROBLEM}."),
        ]
    );
}

#[test]
fn checks_that_only_reject_the_nil_uuid_are_not_reported() {
    for check in [
        format!("installation_id <> {NIL}"),
        format!("{NIL}::uuid <> installation_id"),
        format!("installation_id != {NIL}"),
        format!("(installation_id IS DISTINCT FROM {NIL})"),
        format!("installation_id NOT IN ({NIL})"),
        format!("id IS NOT NULL AND (installation_id <> {NIL} AND id <> installation_id)"),
    ] {
        let sql = format!("ALTER TABLE docs ADD CONSTRAINT known CHECK ({check});");
        assert_eq!(schema_messages(&sql), Vec::<String>::new(), "{sql}");
    }
    assert_eq!(
        schema_messages(&format!(
            "CREATE TABLE installs (id UUID CHECK (id <> {NIL}), parent UUID CHECK (parent <> {NIL}));"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn a_rejection_the_check_does_not_enforce_is_reported() {
    for check in [
        format!("installation_id <> {NIL} OR id IS NULL"),
        format!("NOT (installation_id <> {NIL})"),
        format!("id <> installation_id AND installation_id = {NIL}"),
        format!("NULLIF(installation_id, {NIL}) <> id"),
    ] {
        let sql = format!("ALTER TABLE docs ADD CONSTRAINT known CHECK ({check});");
        assert_eq!(schema_messages(&sql).len(), 1, "{sql}");
    }
    assert_eq!(
        schema_messages(&format!(
            "CREATE POLICY p ON docs USING (installation_id <> {NIL});"
        ))
        .len(),
        1
    );
}

#[test]
fn the_setting_read_as_null_replaces_the_sentinel() {
    let sentinel = format!(
        "CREATE POLICY docs_installation ON docs AS RESTRICTIVE FOR SELECT
           USING (current_setting('app.installation_id', true)::uuid = {NIL}
             OR installation_id = current_setting('app.installation_id', true)::uuid);"
    );
    assert_eq!(
        schema_messages(&sentinel),
        [format!(
            "Policy 'docs_installation' on 'docs' uses `current_setting('app.installation_id', true)::UUID = {NIL}` in its USING clause, {PROBLEM}."
        )]
    );
    let absent = "CREATE POLICY docs_installation ON docs AS RESTRICTIVE FOR SELECT
           USING (NULLIF(current_setting('app.installation_id', true), '')::uuid IS NULL
             OR installation_id = NULLIF(current_setting('app.installation_id', true), '')::uuid);";
    assert_eq!(schema_messages(absent), Vec::<String>::new());
}
