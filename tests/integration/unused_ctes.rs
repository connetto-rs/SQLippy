//! `WITH` items no part of their statement reads, observed through the public
//! constrainer API. The behaviour each rule cites was measured on PostgreSQL
//! 18.6.

use crate::rule_findings::{findings, statement_findings};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "CREATE TABLE audit (n INT);
    CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT);";

fn unused(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = UnusedCte::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(SCHEMA).expect("schema parses");
    statement_findings(&constrainer, &database, sql)
        .into_iter()
        .map(|(rule, level, object)| {
            assert_eq!((rule, level), ("unused_cte", Level::Warn));
            object
        })
        .collect()
}

#[test]
fn an_item_nothing_reads_is_reported() {
    for (sql, item) in [
        ("WITH u AS (SELECT 1 / 0) SELECT 1", "u AS (SELECT 1 / 0)"),
        (
            "WITH u AS (INSERT INTO audit VALUES (4) RETURNING n) SELECT 1",
            "u AS (INSERT INTO audit VALUES (4) RETURNING n)",
        ),
        (
            "SELECT 1 FROM (WITH u AS (SELECT 1 / 0) SELECT 1) AS s",
            "u AS (SELECT 1 / 0)",
        ),
        (
            "WITH a AS (SELECT 1 AS x), b AS (SELECT x FROM a) SELECT x FROM a",
            "b AS (SELECT x FROM a)",
        ),
    ] {
        assert_eq!(unused(sql), [item], "{sql}");
    }
}

#[test]
fn a_recursive_item_reading_only_itself_is_reported() {
    assert_eq!(
        unused(
            "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id)
             SELECT 1"
        )
        .len(),
        1
    );
}

#[test]
fn an_item_another_item_or_the_statement_reads_passes() {
    for sql in [
        "WITH u AS (SELECT 1 AS x) SELECT x FROM u",
        "WITH a AS (SELECT 1 AS x), b AS (SELECT x FROM a) SELECT x FROM b",
        "WITH RECURSIVE b AS (SELECT x FROM a), a AS (SELECT 1 AS x) SELECT x FROM b",
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id)
         SELECT id FROM r",
        "WITH u AS (SELECT 1 AS n) INSERT INTO audit SELECT n FROM u",
        "WITH u AS (SELECT 1 AS n) SELECT * FROM groups WHERE id IN (SELECT n FROM u)",
        // PostgreSQL 18 returns the item's rows for each `TABLE` read.
        "WITH u AS (SELECT 1 AS x) TABLE u",
        "WITH u AS (SELECT 1 AS x) SELECT 2 UNION TABLE u",
        "WITH a AS (SELECT 3 AS x), c AS (TABLE a) TABLE c",
        "WITH u AS (SELECT 1 AS n) SELECT * FROM groups WHERE id IN (TABLE u)",
        "SELECT 1 FROM groups",
    ] {
        assert_eq!(unused(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_name_an_inner_item_or_an_own_body_shadows_reads_another_relation() {
    for sql in [
        "WITH u AS (SELECT 1 AS x) SELECT x FROM (WITH u AS (SELECT 2 AS x) SELECT x FROM u) AS s",
        "WITH audit AS (SELECT n FROM audit) SELECT 1",
    ] {
        assert_eq!(unused(sql).len(), 1, "{sql}");
    }
}

#[test]
fn unused_items_are_reported_wherever_the_schema_writes_them() {
    let constrainer: GenericConstrainer<ParserDB> = UnusedCte::default().into();
    let found: Vec<String> = findings(
        &constrainer,
        "unused_cte",
        &format!(
            "{SCHEMA}
             ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
             CREATE VIEW v AS WITH u AS (SELECT 1) SELECT id FROM groups;
             CREATE POLICY p ON groups USING (id IN (WITH u AS (SELECT 1) SELECT parent_id FROM groups));
             CREATE FUNCTION f() RETURNS INT LANGUAGE sql AS $$ WITH u AS (SELECT 1) SELECT 2 $$;
             CREATE FUNCTION g() RETURNS INT LANGUAGE plpgsql AS $$
               DECLARE x INT; BEGIN WITH d AS (DELETE FROM audit RETURNING n) SELECT 1 INTO x; RETURN x; END $$;"
        ),
    )
    .into_iter()
    .map(|(_, object, message)| {
        assert!(message.contains("'u'") || message.contains("'d'"), "{message}");
        object
    })
    .collect();
    assert_eq!(found, ["v", "groups.p", "f()", "g()"]);
}

#[test]
fn the_message_says_whether_the_item_runs() {
    let constrainer: GenericConstrainer<ParserDB> = UnusedCte::default().into();
    let messages: Vec<String> = findings(
        &constrainer,
        "unused_cte",
        &format!(
            "{SCHEMA}
             CREATE VIEW skipped AS WITH u AS (SELECT 1 / 0) SELECT 1;
             CREATE FUNCTION f() RETURNS INT LANGUAGE sql
               AS $$ WITH u AS (INSERT INTO audit VALUES (4) RETURNING n) SELECT 1 $$;"
        ),
    )
    .into_iter()
    .map(|(_, _, message)| message)
    .collect();
    let [skipped, runs] = messages.as_slice() else {
        panic!("one finding per item: {messages:?}");
    };
    assert!(skipped.contains("never evaluates"), "{skipped}");
    assert!(runs.contains("still runs"), "{runs}");
}

#[test]
fn the_default_constrainer_warns_about_unused_items() {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{SCHEMA} CREATE VIEW v AS WITH u AS (SELECT 1) SELECT id FROM groups;"
    ))
    .expect("schema parses");
    assert!(
        DefaultConstrainer::<ParserDB>::default()
            .diagnostics(&database)
            .iter()
            .any(|error| matches!(
                error,
                Error::Violation(violation)
                    if violation.rule().name == "unused_cte"
                        && violation.rule().group == LintGroup::Suspicious
                        && violation.level() == Level::Warn
            ))
    );
}
