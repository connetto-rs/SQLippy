//! `UNION ALL` walks that produce a row once per path reaching it, observed
//! through the public constrainer API. The behaviour each rule cites was
//! measured on PostgreSQL 18.6.

use crate::rule_findings::{findings, statement_findings};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT);
    CREATE TABLE dag_edges (child INT, parent INT, PRIMARY KEY (child, parent));
    CREATE TABLE links (child INT NOT NULL, parent INT);
    CREATE UNIQUE INDEX links_child ON links (child);";

fn duplicating(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = DuplicatingRecursiveCte::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(SCHEMA).expect("schema parses");
    statement_findings(&constrainer, &database, sql)
        .into_iter()
        .map(|(rule, level, object)| {
            assert_eq!((rule, level), ("duplicating_recursive_cte", Level::Warn));
            object
        })
        .collect()
}

#[test]
fn a_union_all_walk_over_a_non_unique_column_is_reported() {
    for sql in [
        // 2,097,151 rows over a 20-layer graph of two parents per node, 41 under UNION.
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT e.child FROM dag_edges AS e JOIN r ON e.parent = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT child FROM dag_edges JOIN r ON parent = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id, depth) AS (SELECT 0, 0 UNION ALL SELECT e.child, r.depth + 1 FROM dag_edges AS e JOIN r ON e.parent = r.id WHERE r.depth < 20) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT e.child FROM public.dag_edges AS e, r WHERE e.parent = r.id) SELECT id FROM r",
        // Upward over a graph, the joined child column is no key on its own.
        "WITH RECURSIVE r(id) AS (SELECT 40 UNION ALL SELECT e.parent FROM dag_edges AS e JOIN r ON e.child = r.id) SELECT id FROM r",
    ] {
        assert_eq!(duplicating(sql).len(), 1, "{sql}");
    }
}

#[test]
fn a_walk_that_reaches_each_row_once_passes() {
    for sql in [
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION ALL SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT l.child FROM links AS l JOIN r ON l.parent = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION SELECT e.child FROM dag_edges AS e JOIN r ON e.parent = r.id) SELECT id FROM r",
        // The walked name reads the sibling item, not the table.
        "WITH RECURSIVE dag_edges(child, parent) AS (SELECT 1, 0), r(id) AS (SELECT 0 UNION ALL SELECT e.child FROM dag_edges AS e JOIN r ON e.parent = r.id) SELECT id FROM r",
        // Two walked relations are out of the rule's reach.
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT e.child FROM dag_edges AS e JOIN r ON e.parent = r.id JOIN groups AS g ON g.id = e.child) SELECT id FROM r",
        // 3 rows, each step joins one row by the primary key.
        "WITH RECURSIVE r(id) AS (SELECT 6 UNION ALL SELECT g.parent_id FROM groups AS g JOIN r ON g.id = r.id WHERE g.parent_id IS NOT NULL) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 6 UNION ALL SELECT g.parent_id FROM groups AS g, r WHERE r.id = g.id) SELECT id FROM r",
        // 2 rows, the walked name reads the item body's own WITH.
        "WITH RECURSIVE r(id) AS (WITH dag_edges(child, parent) AS (VALUES (1, 0)) SELECT 0 UNION ALL SELECT e.child FROM dag_edges AS e JOIN r ON e.parent = r.id) SELECT id FROM r",
        // PostgreSQL refuses a name of four parts, so no table is walked.
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT e.child FROM postgres.public.dag_edges.extra e JOIN r ON e.parent = r.id) SELECT id FROM r",
    ] {
        assert_eq!(duplicating(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn resolved_aliases_wildcards_and_catalog_names_report_walked_columns() {
    for sql in [
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT e.child FROM postgres.public.dag_edges e JOIN r ON e.parent = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id, parent) AS (SELECT 0, 0 UNION ALL SELECT e.* FROM dag_edges e JOIN r ON e.parent = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT e.renamed AS next_id FROM dag_edges e(renamed, parent) JOIN r ON e.parent = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id, parent) AS (SELECT 0, 0 UNION ALL SELECT e.* FROM dag_edges e(renamed) JOIN r ON e.parent = r.id) SELECT id FROM r",
    ] {
        assert_eq!(duplicating(sql).len(), 1, "{sql}");
    }
}

#[test]
fn aliases_and_wildcards_preserve_single_column_keys() {
    for sql in [
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION ALL SELECT g.renamed FROM groups g(renamed) JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id, parent) AS (SELECT 1, 0 UNION ALL SELECT g.* FROM groups g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 6 UNION ALL SELECT g.parent_id FROM groups g(renamed) JOIN r ON g.renamed = r.id) SELECT id FROM r",
    ] {
        assert_eq!(duplicating(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_keyed_tree_behind_a_derived_table_or_view_is_not_reported() {
    let constrainer: GenericConstrainer<ParserDB> = DuplicatingRecursiveCte::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{SCHEMA} CREATE VIEW group_view AS SELECT id, parent_id FROM groups;"
    ))
    .expect("schema parses");
    for sql in [
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION ALL SELECT g.id FROM (SELECT id, parent_id FROM groups) g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION ALL SELECT g.id FROM group_view g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
    ] {
        assert_eq!(
            statement_findings(&constrainer, &database, sql),
            [],
            "{sql}"
        );
    }
}

#[test]
fn a_projection_without_walked_columns_is_outside_the_rule_scope() {
    for sql in [
        "WITH RECURSIVE r(id, depth) AS (SELECT 0, 0 UNION ALL SELECT 1, r.depth + 1 FROM dag_edges e JOIN r ON e.parent = r.id WHERE r.depth < 20) SELECT id FROM r",
        "WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT r.* FROM dag_edges e JOIN r ON e.parent = r.id WHERE r.id < 0) SELECT id FROM r",
        // A system column is no stored column of the table.
        "WITH RECURSIVE r(id) AS (SELECT 0::oid UNION ALL SELECT e.tableoid FROM dag_edges e JOIN r ON e.parent::oid = r.id) SELECT id FROM r",
    ] {
        assert_eq!(duplicating(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn the_first_schema_on_the_search_path_decides_the_walked_keys() {
    let constrainer: GenericConstrainer<ParserDB> = DuplicatingRecursiveCte::default().into();
    let found = findings(
        &constrainer,
        "duplicating_recursive_cte",
        "CREATE SCHEMA tree;
         CREATE SCHEMA graph;
         CREATE TABLE tree.edges (child INT PRIMARY KEY, parent INT);
         CREATE TABLE graph.edges (child INT, parent INT, PRIMARY KEY (child, parent));
         CREATE FUNCTION tree_first() RETURNS SETOF INT LANGUAGE sql SET search_path = tree, graph AS $$
           WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT e.child FROM edges e JOIN r ON e.parent = r.id) SELECT id FROM r $$;
         CREATE FUNCTION graph_first() RETURNS SETOF INT LANGUAGE sql SET search_path = graph, tree AS $$
           WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT e.child FROM edges e JOIN r ON e.parent = r.id) SELECT id FROM r $$;",
    );
    assert_eq!(
        found
            .iter()
            .map(|(level, object, _)| (*level, object.as_str()))
            .collect::<Vec<_>>(),
        [(Level::Warn, "graph_first()")]
    );
}

#[test]
fn a_function_body_resolves_the_walked_table_on_its_own_search_path() {
    let constrainer: GenericConstrainer<ParserDB> = DuplicatingRecursiveCte::default().into();
    let found = findings(
        &constrainer,
        "duplicating_recursive_cte",
        &format!(
            "{SCHEMA}
             CREATE SCHEMA aps;
             CREATE TABLE aps.dag_edges (child INT PRIMARY KEY, parent INT);
             CREATE FUNCTION public_below(root INT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$
               WITH RECURSIVE r(id) AS (SELECT root UNION ALL SELECT e.child FROM dag_edges e JOIN r ON e.parent = r.id) SELECT id FROM r $$;
             CREATE FUNCTION aps_below(root INT) RETURNS SETOF INT LANGUAGE sql STABLE SET search_path = aps AS $$
               WITH RECURSIVE r(id) AS (SELECT root UNION ALL SELECT e.child FROM dag_edges e JOIN r ON e.parent = r.id) SELECT id FROM r $$;
             CREATE FUNCTION plpgsql_below(root INT) RETURNS SETOF INT LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
             BEGIN
               RETURN QUERY WITH RECURSIVE r(id) AS (SELECT root UNION ALL SELECT e.child FROM public.dag_edges e JOIN r ON e.parent = r.id) SELECT id FROM r;
             END $$;"
        ),
    );
    let mut objects: Vec<&str> = found
        .iter()
        .map(|(level, object, message)| {
            assert_eq!(*level, Level::Warn);
            assert!(message.contains("`e.child` of 'dag_edges'"), "{message}");
            object.as_str()
        })
        .collect();
    objects.sort_unstable();
    assert_eq!(objects, ["plpgsql_below(INT)", "public_below(INT)"]);
}
