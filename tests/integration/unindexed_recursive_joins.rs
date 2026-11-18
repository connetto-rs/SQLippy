//! Recursive walks joining the walked table on no index, observed through
//! the public constrainer API. The behaviour each rule cites was measured on
//! PostgreSQL 18.6.

use crate::rule_findings::{findings, statement_findings};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT);
    CREATE TABLE teams (id INT PRIMARY KEY, parent_id INT);
    CREATE INDEX teams_parent ON teams (parent_id);
    CREATE TABLE units (id INT PRIMARY KEY, parent_id INT, active BOOLEAN);
    CREATE INDEX units_active_parent ON units (parent_id) WHERE active;
    CREATE INDEX units_parent_plus ON units ((parent_id + 0));";

fn unindexed(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = UnindexedRecursiveJoin::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(SCHEMA).expect("schema parses");
    statement_findings(&constrainer, &database, sql)
        .into_iter()
        .map(|(rule, level, object)| {
            assert_eq!((rule, level), ("unindexed_recursive_join", Level::Warn));
            object
        })
        .collect()
}

#[test]
fn a_join_on_a_column_no_index_leads_with_is_reported() {
    for sql in [
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.id FROM groups AS g JOIN r ON r.id = g.parent_id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.id FROM groups AS g, r WHERE g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT groups.id FROM groups JOIN r ON parent_id = r.id) SELECT id FROM r",
        // A partial index and an expression index serve neither join.
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT u.id FROM units AS u JOIN r ON u.parent_id = r.id) SELECT id FROM r",
        // A column alias list renames the stored columns by position.
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.gid FROM groups AS g(gid, up) JOIN r ON g.up = r.id) SELECT id FROM r",
    ] {
        assert_eq!(unindexed(sql).len(), 1, "{sql}");
    }
}

#[test]
fn a_join_an_index_serves_passes() {
    for sql in [
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT t.id FROM teams AS t JOIN r ON t.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT t.tid FROM teams AS t(tid, up) JOIN r ON t.up = r.id) SELECT id FROM r",
        // Walking up joins on the primary key.
        "WITH RECURSIVE r(id, parent_id) AS (SELECT id, parent_id FROM groups WHERE id = 3 UNION SELECT g.id, g.parent_id FROM groups AS g JOIN r ON g.id = r.parent_id) SELECT id FROM r",
        // Without RECURSIVE nothing is walked.
        "WITH r(id) AS (SELECT g.id FROM groups AS g JOIN teams AS t ON g.parent_id = t.id) SELECT id FROM r",
    ] {
        assert_eq!(unindexed(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn an_unindexed_foreign_key_is_reported_once_by_its_own_rule() {
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT REFERENCES groups (id));
         CREATE VIEW below_one AS WITH RECURSIVE r(id) AS (SELECT 1
           UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r;",
    )
    .expect("schema parses");
    let mut rules: Vec<&str> = DefaultConstrainer::<ParserDB>::default()
        .diagnostics(&database)
        .iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name.starts_with("unindexed_") => {
                Some(violation.rule().name)
            }
            _ => None,
        })
        .collect();
    rules.sort_unstable();
    assert_eq!(rules, ["unindexed_foreign_key"]);
}

#[test]
fn a_function_body_resolves_the_walked_table_on_its_own_search_path() {
    let constrainer: GenericConstrainer<ParserDB> = UnindexedRecursiveJoin::default().into();
    let found = findings(
        &constrainer,
        "unindexed_recursive_join",
        &format!(
            "{SCHEMA}
             CREATE SCHEMA authz;
             CREATE TABLE authz.groups (id INT PRIMARY KEY, parent_id INT);
             CREATE INDEX authz_groups_parent ON authz.groups (parent_id);
             CREATE FUNCTION public_below(root INT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$
               WITH RECURSIVE r(id) AS (SELECT root UNION SELECT g.id FROM groups g JOIN r ON g.parent_id = r.id) SELECT id FROM r $$;
             CREATE FUNCTION authz_below(root INT) RETURNS SETOF INT LANGUAGE sql STABLE SET search_path = authz AS $$
               WITH RECURSIVE r(id) AS (SELECT root UNION SELECT g.id FROM groups g JOIN r ON g.parent_id = r.id) SELECT id FROM r $$;
             CREATE FUNCTION plpgsql_below(root INT) RETURNS SETOF INT LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
             BEGIN
               RETURN QUERY WITH RECURSIVE r(id) AS (SELECT root UNION SELECT g.id FROM public.groups g JOIN r ON g.parent_id = r.id) SELECT id FROM r;
             END $$;"
        ),
    );
    let mut objects: Vec<&str> = found
        .iter()
        .map(|(level, object, message)| {
            assert_eq!(*level, Level::Warn);
            assert!(message.contains("on 'parent_id'"), "{message}");
            object.as_str()
        })
        .collect();
    objects.sort_unstable();
    assert_eq!(objects, ["plpgsql_below(INT)", "public_below(INT)"]);
}
