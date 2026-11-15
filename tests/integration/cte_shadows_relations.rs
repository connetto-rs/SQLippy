//! `WITH` items named like a relation the search path reaches, observed
//! through the public constrainer API. The behaviour each rule cites was
//! measured on PostgreSQL 18.6.

use crate::rule_findings::{findings, statement_findings};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT);
    CREATE TABLE grants (group_id INT NOT NULL, principal TEXT NOT NULL);
    CREATE TABLE docs (id INT PRIMARY KEY, group_id INT NOT NULL);
    CREATE VIEW granted AS SELECT group_id FROM grants;
    CREATE SCHEMA authz;
    CREATE TABLE authz.members (uid TEXT);";

fn shadowing(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = CteShadowsRelation::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(SCHEMA).expect("schema parses");
    statement_findings(&constrainer, &database, sql)
        .into_iter()
        .map(|(rule, level, object)| {
            assert_eq!((rule, level), ("cte_shadows_relation", Level::Warn));
            object
        })
        .collect()
}

#[test]
fn an_item_named_like_a_table_or_view_on_the_path_is_reported() {
    for (sql, item) in [
        (
            "WITH grants AS (SELECT 1 AS group_id) SELECT group_id FROM grants",
            "grants AS (SELECT 1 AS group_id)",
        ),
        (
            "WITH Granted AS (SELECT 1 AS group_id) SELECT group_id FROM granted",
            "Granted AS (SELECT 1 AS group_id)",
        ),
        (
            "SELECT id FROM docs WHERE group_id IN (WITH groups AS (SELECT 1 AS id) SELECT id FROM groups)",
            "groups AS (SELECT 1 AS id)",
        ),
    ] {
        assert_eq!(shadowing(sql), [item], "{sql}");
    }
}

#[test]
fn an_item_whose_name_no_relation_on_the_path_holds_passes() {
    for sql in [
        "WITH granted_groups AS (SELECT group_id FROM grants) SELECT group_id FROM granted_groups",
        "WITH members AS (SELECT uid FROM authz.members) SELECT uid FROM members",
        "WITH \"Grants\" AS (SELECT 1 AS group_id) SELECT group_id FROM \"Grants\"",
    ] {
        assert_eq!(shadowing(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_function_body_is_judged_under_its_own_search_path() {
    let constrainer: GenericConstrainer<ParserDB> = CteShadowsRelation::default().into();
    let found: Vec<String> = findings(
        &constrainer,
        "cte_shadows_relation",
        &format!(
            "{SCHEMA}
             CREATE FUNCTION public_path() RETURNS SETOF INT LANGUAGE sql
               AS $$ WITH grants AS (SELECT 1 AS group_id) SELECT group_id FROM grants $$;
             CREATE FUNCTION empty_path() RETURNS SETOF INT LANGUAGE sql SET search_path = ''
               AS $$ WITH grants AS (SELECT 1 AS group_id) SELECT group_id FROM grants $$;
             CREATE FUNCTION authz_path() RETURNS SETOF TEXT LANGUAGE sql SET search_path = authz
               AS $$ WITH members AS (SELECT 'x'::text AS uid) SELECT uid FROM members $$;
             CREATE FUNCTION plpgsql_body() RETURNS SETOF INT LANGUAGE plpgsql AS $$
               BEGIN RETURN QUERY WITH docs AS (SELECT 1 AS id) SELECT id FROM docs; END $$;"
        ),
    )
    .into_iter()
    .map(|(_, object, _)| object)
    .collect();
    assert_eq!(found, ["authz_path()", "plpgsql_body()", "public_path()"]);
}

#[test]
fn a_shadowing_item_in_a_policy_is_reported_on_the_policy() {
    let constrainer: GenericConstrainer<ParserDB> = CteShadowsRelation::default().into();
    let found = findings(
        &constrainer,
        "cte_shadows_relation",
        &format!(
            "{SCHEMA}
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_shadow ON docs FOR SELECT USING (
               group_id IN (WITH grants AS (SELECT g.id AS group_id, 'x'::text AS principal FROM groups g)
                            SELECT group_id FROM grants WHERE principal = 'x'));"
        ),
    );
    let [(level, object, message)] = found.as_slice() else {
        panic!("one finding: {found:?}");
    };
    assert_eq!((*level, object.as_str()), (Level::Warn, "docs.docs_shadow"));
    assert!(message.contains("table 'grants'"), "{message}");
}

#[test]
fn the_default_constrainer_warns_about_shadowing_items() {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{SCHEMA} CREATE VIEW v AS WITH docs AS (SELECT 1 AS id) SELECT id FROM docs;"
    ))
    .expect("schema parses");
    assert!(
        DefaultConstrainer::<ParserDB>::default()
            .diagnostics(&database)
            .iter()
            .any(|error| matches!(
                error,
                Error::Violation(violation)
                    if violation.rule().name == "cte_shadows_relation"
                        && violation.rule().group == LintGroup::Suspicious
                        && violation.level() == Level::Warn
            ))
    );
}

#[test]
fn an_item_named_like_a_foreign_table_is_reported() {
    let constrainer: GenericConstrainer<ParserDB> = CteShadowsRelation::default().into();
    let found = findings(
        &constrainer,
        "cte_shadows_relation",
        "CREATE FOREIGN DATA WRAPPER shadow_wrapper;
         CREATE SERVER shadow_server FOREIGN DATA WRAPPER shadow_wrapper;
         CREATE FOREIGN TABLE external_grants (group_id INT) SERVER shadow_server;
         CREATE VIEW foreign_shadow AS
           WITH external_grants AS (SELECT 1 AS group_id)
           SELECT group_id FROM external_grants;",
    );
    let [(level, object, message)] = found.as_slice() else {
        panic!("expected one finding, got {found:?}");
    };
    assert_eq!((*level, object.as_str()), (Level::Warn, "foreign_shadow"));
    assert!(
        message.contains("foreign table 'external_grants'"),
        "{message}"
    );
}

#[test]
fn an_item_named_like_a_materialized_view_is_reported() {
    let constrainer: GenericConstrainer<ParserDB> = CteShadowsRelation::default().into();
    let found = findings(
        &constrainer,
        "cte_shadows_relation",
        "CREATE MATERIALIZED VIEW cached_grants AS SELECT 1 AS group_id;
         CREATE VIEW materialized_shadow AS
           WITH cached_grants AS (SELECT 2 AS group_id)
           SELECT group_id FROM cached_grants;",
    );
    let [(level, object, message)] = found.as_slice() else {
        panic!("expected one finding, got {found:?}");
    };
    assert_eq!(
        (*level, object.as_str()),
        (Level::Warn, "materialized_shadow")
    );
    assert!(
        message.contains("materialized view 'cached_grants'"),
        "{message}"
    );
}
