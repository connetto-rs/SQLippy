//! Recursive `WITH` items a cycle in the walked data keeps running, observed
//! through the public constrainer API. The behaviour each rule cites was
//! measured on PostgreSQL 18.6 with `groups` holding the cycle 1, 2, 3.

use crate::rule_findings::{findings, statement_findings};
use sqlippy::prelude::*;
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};

const SCHEMA: &str =
    "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT, owner TEXT, active BOOLEAN);
    CREATE TABLE grants (group_id INT NOT NULL, principal TEXT NOT NULL);
    CREATE TABLE docs (id INT PRIMARY KEY, group_id INT NOT NULL);";

fn unending(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = NonterminatingRecursiveCte::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(SCHEMA).expect("schema parses");
    statement_findings(&constrainer, &database, sql)
        .into_iter()
        .map(|(rule, level, object)| {
            assert_eq!((rule, level), ("nonterminating_recursive_cte", Level::Deny));
            object
        })
        .collect()
}

#[test]
fn a_walk_that_keeps_repeated_or_growing_rows_is_reported() {
    for sql in [
        // Canceled by a 3 second statement timeout.
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION ALL SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        // Canceled by a 3 second statement timeout.
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION SELECT g.id, r.depth + 1 FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r AS (SELECT 1 AS id, ARRAY[1] AS path UNION SELECT g.id, w.path || g.id FROM groups AS g JOIN r AS w ON g.parent_id = w.id) SELECT id FROM r",
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION SELECT id, depth + 1 FROM groups JOIN r USING (id)) SELECT id FROM r",
        "SELECT id FROM docs WHERE group_id IN (WITH RECURSIVE r(id) AS (SELECT 1 UNION ALL SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r)",
    ] {
        assert_eq!(unending(sql).len(), 1, "{sql}");
    }
}

#[test]
fn a_bound_that_does_not_cap_a_rising_counter_is_reported() {
    // Each canceled by a 2 second statement timeout.
    for sql in [
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION ALL SELECT g.id, r.depth FROM groups AS g JOIN r ON g.parent_id = r.id WHERE r.depth < 20) SELECT id FROM r",
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION ALL SELECT g.id, r.depth + 0 FROM groups AS g JOIN r ON g.parent_id = r.id WHERE r.depth < 20) SELECT id FROM r",
        "WITH RECURSIVE r(id, depth, cap) AS (SELECT 1, 0, 5 UNION ALL SELECT g.id, r.depth + 1, r.cap + 2 FROM groups AS g JOIN r ON g.parent_id = r.id WHERE r.depth < r.cap) SELECT id FROM r",
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION ALL SELECT g.id, r.depth - 1 FROM groups AS g JOIN r ON g.parent_id = r.id WHERE r.depth < 20) SELECT id FROM r",
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION ALL SELECT g.id, r.depth + 1 FROM r LEFT JOIN groups AS g ON g.parent_id = r.id AND r.depth < 20) SELECT id FROM r",
        "WITH RECURSIVE d(day) AS (SELECT TIMESTAMP '2024-01-01' UNION ALL SELECT d.day + INTERVAL '0 days' FROM d WHERE d.day < TIMESTAMP '2024-12-31') SELECT day FROM d",
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION SELECT g.id, r.depth - 1 FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id, path) AS (SELECT 1, ARRAY[1] UNION SELECT g.id, array_append(r.path, g.id) FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
    ] {
        assert_eq!(unending(sql).len(), 1, "{sql}");
    }
}

#[test]
fn a_walk_that_stops_on_any_data_passes() {
    for sql in [
        // 3 rows.
        "WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        // 21 rows, repeating.
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION ALL SELECT g.id, r.depth + 1 FROM groups AS g JOIN r ON g.parent_id = r.id WHERE r.depth < 20) SELECT id FROM r",
        "WITH RECURSIVE r AS (SELECT 1 AS id, 0 AS depth UNION ALL SELECT g.id, 1 + depth FROM groups AS g JOIN r ON g.parent_id = r.id WHERE 20 >= depth) SELECT id FROM r",
        "WITH RECURSIVE r(id, root) AS (SELECT id, id FROM groups UNION SELECT g.id, r.root FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE t(n) AS (VALUES (1) UNION ALL SELECT n + 1 FROM t WHERE n < 100) SELECT sum(n) FROM t",
        // 4 rows, the cap read from the walked key.
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION ALL SELECT g.id, r.depth + 1 FROM groups AS g JOIN r ON g.parent_id = r.id WHERE r.depth < r.id) SELECT id FROM r",
        // Without RECURSIVE the body's `r` reads no item.
        "WITH r(id) AS (SELECT 1 UNION ALL SELECT 2) SELECT id FROM r",
        // 21 rows, the cap in the inner join's ON.
        "WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION ALL SELECT g.id, r.depth + 1 FROM groups AS g JOIN r ON g.parent_id = r.id AND r.depth < 20) SELECT id FROM r",
        // 366 rows each, an interval step.
        "WITH RECURSIVE d(day) AS (SELECT TIMESTAMP '2024-01-01' UNION ALL SELECT d.day + INTERVAL '1 day' FROM d WHERE d.day < TIMESTAMP '2024-12-31') SELECT day FROM d",
        "WITH RECURSIVE d(day) AS (SELECT TIMESTAMP '2024-01-01' UNION ALL SELECT d.day + '1 day'::INTERVAL FROM d WHERE d.day < TIMESTAMP '2024-12-31') SELECT day FROM d",
        // 11 rows, a countdown to a floor.
        "WITH RECURSIVE t(n) AS (SELECT 10 UNION ALL SELECT t.n - 1 FROM t WHERE t.n > 0) SELECT n FROM t",
        // 3, 5 and 6 rows, a column drawn from finitely many values.
        "WITH RECURSIVE r(id, owner) AS (SELECT id, owner FROM groups WHERE id = 1 UNION SELECT g.id, coalesce(g.owner, r.owner) FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id, live) AS (SELECT 1, true UNION SELECT g.id, r.live AND g.active FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
        "WITH RECURSIVE r(id, flag) AS (SELECT 1, 0 UNION SELECT g.id, CASE WHEN r.flag = 0 THEN 1 ELSE 0 END FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r",
    ] {
        assert_eq!(unending(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_walk_that_consumes_a_string_passes() {
    for sql in [
        // 4 rows each, the remaining text cut past the separator it holds.
        "WITH RECURSIVE s(element, rest) AS (SELECT NULL, '1,2,3' UNION ALL SELECT CASE WHEN strpos(rest, ',') > 0 THEN substr(rest, 1, strpos(rest, ',') - 1) ELSE rest END, CASE WHEN strpos(rest, ',') > 0 THEN substr(rest, strpos(rest, ',') + 1) ELSE NULL END FROM s WHERE s.rest <> '') SELECT element FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN position(',' IN rest) >= 1 THEN substr(rest, 1 + position(',' IN rest)) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN 0 < pg_catalog.strpos(rest, ',') THEN substr(rest, pg_catalog.strpos(rest, ',') + 1) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN 1 <= position(',' IN rest) THEN substr(rest, position(',' IN rest) + 1) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
    ] {
        assert_eq!(unending(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_string_walk_that_does_not_shrink_its_text_is_reported() {
    // Each canceled by a 2 second statement timeout.
    for sql in [
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT substr(rest, strpos(rest, ',') + 1) FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN strpos(rest, ',') > 0 THEN substr(rest, strpos(rest, ',') + 1) ELSE rest END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN strpos(rest, ',') > 0 THEN substr(rest, strpos(rest, ',') + 1) END FROM s) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1;2' UNION ALL SELECT CASE WHEN strpos(rest, ';') > 0 THEN substr(rest, strpos(rest, ',') + 1) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN strpos(rest, ',') > 0 THEN substr(rest, strpos(rest, ',') + 0) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT rest || ',' FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN strpos(rest, ',') > 0 THEN substr(rest, strpos(rest, ',') + 1) END FROM s WHERE rest IS NULL OR rest <> '') SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT s.* FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN strpos(rest, ',') > 0 THEN rest END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN strpos(rest, ',') > 0 THEN substr(rest, 1) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN true THEN substr(rest, 1 + 1) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN strpos(rest, ',') IS NOT NULL THEN substr(rest, strpos(rest, ',') + 1) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        "WITH RECURSIVE s(rest) AS (SELECT '123' UNION ALL SELECT CASE WHEN strpos(rest, ',') = 0 THEN substr(rest, strpos(rest, ',') + 1) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
        // Oracle's `instr` takes a start position, which PostgreSQL and SQLite lack.
        "WITH RECURSIVE s(rest) AS (SELECT '1,2,3' UNION ALL SELECT CASE WHEN instr(rest, ',', 1) > 0 THEN substr(rest, instr(rest, ',', 1) + 1) END FROM s WHERE rest IS NOT NULL) SELECT rest FROM s",
    ] {
        assert_eq!(unending(sql).len(), 1, "{sql}");
    }
}

#[test]
fn a_split_of_a_delimited_setting_in_a_sqlite_view_passes() {
    // SQLite answers 1, 2 and 3 with `links` holding 1 to 4.
    let constrainer: GenericConstrainer<ParserDB> = NonterminatingRecursiveCte::default().into();
    let database = ParserDB::parse::<SQLiteDialect>(
        "CREATE TABLE links (id TEXT PRIMARY KEY CHECK (length(id) <= 36));
        CREATE VIEW visible_links AS SELECT id FROM links WHERE id IN (
          WITH RECURSIVE pg2sqlite_split (pg2sqlite_element, pg2sqlite_rest) AS (
            SELECT NULL, '1,2,3'
            UNION ALL
            SELECT CASE WHEN instr(pg2sqlite_rest, ',') > 0 THEN SUBSTR(pg2sqlite_rest, 1, instr(pg2sqlite_rest, ',') - 1) ELSE pg2sqlite_rest END,
                   CASE WHEN instr(pg2sqlite_rest, ',') > 0 THEN SUBSTR(pg2sqlite_rest, instr(pg2sqlite_rest, ',') + 1) END
            FROM pg2sqlite_split WHERE pg2sqlite_rest IS NOT NULL
          )
          SELECT pg2sqlite_element FROM pg2sqlite_split WHERE pg2sqlite_element IS NOT NULL
        );",
    )
    .expect("schema parses");
    assert!(constrainer.validate_schema(&database).is_ok());
}

#[test]
fn a_helper_a_policy_calls_is_reported_on_the_function() {
    let constrainer: GenericConstrainer<ParserDB> = NonterminatingRecursiveCte::default().into();
    let found = findings(
        &constrainer,
        "nonterminating_recursive_cte",
        &format!(
            "{SCHEMA}
             CREATE SCHEMA authz;
             CREATE FUNCTION authz.groups_readable_all() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
               WITH RECURSIVE r(id) AS (SELECT group_id FROM public.grants WHERE principal = current_setting('app.user_id', true)
                 UNION ALL SELECT g.id FROM public.groups g JOIN r ON g.parent_id = r.id) SELECT id FROM r $$;
             CREATE FUNCTION authz.groups_below(root INT) RETURNS SETOF INT LANGUAGE plpgsql STABLE AS $$
             BEGIN
               RETURN QUERY WITH RECURSIVE r(id) AS (SELECT root UNION ALL SELECT g.id FROM public.groups g JOIN r ON g.parent_id = r.id) SELECT id FROM r;
             END $$;
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_read ON docs FOR SELECT USING (group_id = ANY (ARRAY(SELECT authz.groups_readable_all())));"
        ),
    );
    let mut objects: Vec<&str> = found
        .iter()
        .map(|(level, object, message)| {
            assert_eq!(*level, Level::Deny);
            assert!(message.contains("`UNION ALL`"), "{message}");
            object.as_str()
        })
        .collect();
    objects.sort_unstable();
    assert_eq!(objects, ["groups_below(INT)", "groups_readable_all()"]);
}

#[test]
fn a_walk_in_a_policy_is_reported_on_the_policy() {
    let constrainer: GenericConstrainer<ParserDB> = NonterminatingRecursiveCte::default().into();
    let found = findings(
        &constrainer,
        "nonterminating_recursive_cte",
        &format!(
            "{SCHEMA}
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_read ON docs FOR SELECT USING (group_id IN (
               WITH RECURSIVE r(id, depth) AS (SELECT 1, 0 UNION SELECT g.id, r.depth + 1 FROM groups g JOIN r ON g.parent_id = r.id)
               SELECT id FROM r));"
        ),
    );
    let [(level, object, message)] = found.as_slice() else {
        panic!("one finding: {found:?}");
    };
    assert_eq!((*level, object.as_str()), (Level::Deny, "docs.docs_read"));
    assert!(message.contains("`r.depth + 1`"), "{message}");
}
