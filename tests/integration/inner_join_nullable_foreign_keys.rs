//! Inner joins over a foreign key whose referencing column can be `NULL`,
//! observed through the public constrainer API.

use crate::rule_findings::{check_query_rule, findings};
use sqlippy::prelude::*;

const RULE: &str = "inner_join_nullable_foreign_key";

const SCHEMA: &str = "CREATE TABLE departments (id INT PRIMARY KEY, name TEXT);
    CREATE TABLE employees (id INT PRIMARY KEY, department_id INT REFERENCES departments (id), name TEXT);
    CREATE TABLE badges (id INT PRIMARY KEY, department_id INT REFERENCES departments (id));
    CREATE TABLE assigned (id INT PRIMARY KEY, department_id INT NOT NULL REFERENCES departments (id));
    CREATE TABLE checked (id INT PRIMARY KEY, department_id INT REFERENCES departments (id) CHECK (department_id IS NOT NULL));
    CREATE TABLE floors (department_id INT, number INT, PRIMARY KEY (department_id, number));
    CREATE TABLE full_offices (department_id INT, floor INT NOT NULL,
      FOREIGN KEY (department_id, floor) REFERENCES floors (department_id, number) MATCH FULL);
    CREATE TABLE simple_offices (department_id INT, floor INT NOT NULL,
      FOREIGN KEY (department_id, floor) REFERENCES floors (department_id, number));
    CREATE TABLE regions (region_id INT PRIMARY KEY);
    CREATE TABLE stores (id INT PRIMARY KEY, region_id INT REFERENCES regions (region_id));
    CREATE TABLE negated (id INT PRIMARY KEY, department_id INT REFERENCES departments (id) CHECK (NOT (department_id IS NULL)));
    CREATE TABLE positive (id INT PRIMARY KEY, department_id INT REFERENCES departments (id) CHECK (department_id > 0));";

fn constrainer() -> GenericConstrainer<ParserDB> {
    InnerJoinNullableForeignKey::default().into()
}

/// The objects the rule reports on views written over `SCHEMA`, one per
/// query.
fn views(queries: &[&str]) -> Vec<String> {
    let views: Vec<String> = queries
        .iter()
        .enumerate()
        .map(|(position, query)| format!("CREATE VIEW v{position:02} AS {query};"))
        .collect();
    findings(
        &constrainer(),
        RULE,
        &format!("{SCHEMA} {}", views.join("\n")),
    )
    .into_iter()
    .map(|(_, object, _)| object)
    .collect()
}

#[test]
fn an_inner_join_over_a_nullable_reference_is_reported_wherever_it_is_written() {
    let found = findings(
        &constrainer(),
        RULE,
        &format!(
            "{SCHEMA}
             ALTER TABLE badges ENABLE ROW LEVEL SECURITY;
             CREATE VIEW v AS SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id;
             CREATE MATERIALIZED VIEW mv AS SELECT e.id FROM employees e INNER JOIN departments d ON d.id = e.department_id;
             CREATE POLICY p ON badges USING (EXISTS (SELECT 1 FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.id = badges.id));
             CREATE FUNCTION f() RETURNS SETOF INT LANGUAGE sql
               AS $$ SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id $$;
             CREATE FUNCTION g() RETURNS SETOF INT LANGUAGE plpgsql AS $$
               BEGIN RETURN QUERY SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id; END $$;"
        ),
    );
    let objects: Vec<&str> = found.iter().map(|(_, object, _)| object.as_str()).collect();
    assert_eq!(objects, ["v", "mv", "badges.p", "f()", "g()"]);
    assert_eq!(
        found[0].2,
        "View 'v' uses an inner join from nullable `e.department_id` to `d.id`, which drops every row whose reference is NULL."
    );
}

#[test]
fn every_inner_join_form_over_a_nullable_reference_is_reported() {
    assert_eq!(
        views(&[
            "SELECT e.id FROM departments d JOIN employees e ON e.department_id = d.id",
            "SELECT e.id FROM employees e, departments d WHERE e.department_id = d.id",
            "SELECT e.id FROM employees e CROSS JOIN departments d WHERE d.id = e.department_id",
            "SELECT e.id FROM employees e JOIN departments d USING (id)",
            "SELECT s.id FROM stores s JOIN regions USING (region_id)",
            "SELECT s.id FROM regions NATURAL JOIN stores s",
            "SELECT e.id FROM employees e JOIN LATERAL (SELECT id FROM departments) d ON e.department_id = d.id",
            "SELECT o.floor FROM simple_offices o JOIN floors f ON o.department_id = f.department_id AND o.floor = f.number",
            "SELECT a.id FROM departments x LEFT JOIN assigned a ON a.id = x.id JOIN departments d ON a.department_id = d.id",
            "WITH staff AS (SELECT * FROM employees) SELECT s.id FROM staff s JOIN departments d ON s.department_id = d.id",
            "WITH s AS (SELECT a.* FROM departments x LEFT JOIN assigned a ON a.id = x.id) SELECT s.id FROM s JOIN departments d ON s.department_id = d.id",
            "SELECT e.id FROM (employees e JOIN badges b ON b.id = e.id) JOIN departments d ON e.department_id = d.id",
            "SELECT e.id FROM employees e JOIN badges b ON b.id = e.id JOIN departments d ON e.department_id = d.id AND b.id = e.id",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id AND e.name IS NULL",
            "SELECT e.id FROM employees e, departments d WHERE e.department_id = d.id AND e.name IS NULL",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE (e.name IS NULL AND e.id > 0) OR e.department_id = 1",
            "SELECT s.id FROM regions JOIN (stores s JOIN employees e ON e.id = s.id) USING (region_id)",
            "SELECT p.id FROM positive p JOIN departments d ON p.department_id = d.id",
        ]),
        [
            "v00", "v01", "v02", "v04", "v05", "v06", "v07", "v08", "v09", "v10", "v11", "v12",
            "v13", "v14", "v15", "v16", "v17"
        ]
    );
}

#[test]
fn joins_that_keep_or_cannot_hold_a_row_without_parent_pass() {
    assert_eq!(
        views(&[
            "SELECT e.id FROM employees e LEFT JOIN departments d ON e.department_id = d.id",
            "SELECT e.id FROM departments d LEFT JOIN employees e ON e.department_id = d.id",
            "SELECT e.id FROM employees e RIGHT JOIN departments d ON e.department_id = d.id",
            "SELECT e.id FROM employees e FULL JOIN departments d ON e.department_id = d.id",
            "SELECT e.id FROM employees e WHERE EXISTS (SELECT 1 FROM departments d WHERE d.id = e.department_id)",
            "SELECT a.id FROM assigned a JOIN departments d ON a.department_id = d.id",
            "SELECT c.id FROM checked c JOIN departments d ON c.department_id = d.id",
            "SELECT o.floor FROM full_offices o JOIN floors f ON o.department_id = f.department_id AND o.floor = f.number",
            "SELECT e.id FROM employees e JOIN departments d ON e.name = d.name",
            "SELECT e.id FROM employees e WHERE e.department_id IN (SELECT id FROM departments)",
            "SELECT e.id FROM employees e WHERE e.department_id = ANY (SELECT id FROM departments)",
            "SELECT a.id FROM assigned a JOIN departments d ON a.department_id = d.id RIGHT JOIN floors f ON f.department_id = d.id",
            "SELECT a.id FROM departments x LEFT JOIN (assigned a JOIN departments d ON a.department_id = d.id) ON a.id = x.id",
            "SELECT n.id FROM negated n JOIN departments d ON n.department_id = d.id",
            "SELECT e.id FROM employees e JOIN (SELECT id FROM departments) d USING (id)",
            "SELECT e.id FROM employees e WHERE EXISTS (SELECT 1 FROM departments d, badges b WHERE d.id = e.department_id AND b.id = e.id)",
            "SELECT e.id FROM (badges b JOIN employees e ON b.department_id = e.department_id) JOIN departments d ON e.department_id = d.id",
            "SELECT e.id FROM departments d JOIN (employees e JOIN badges b ON b.department_id = e.department_id) ON e.department_id = d.id",
            "SELECT e.id FROM employees e JOIN generate_series(1, 3) g(n) ON g.n = e.department_id",
        ]),
        Vec::<String>::new()
    );
}

#[test]
fn a_conjunct_a_left_join_cannot_escape_documents_the_inner_join() {
    assert_eq!(
        views(&[
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.department_id IS NOT NULL",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.department_id > 3",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE d.name = 'x'",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.department_id = 1 OR e.department_id = 2",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id JOIN badges b ON b.department_id = e.department_id",
            "SELECT e.id FROM employees e, departments d WHERE e.department_id = d.id AND d.name = 'x'",
            "WITH staff AS (SELECT * FROM employees WHERE department_id IS NOT NULL) SELECT s.id FROM staff s JOIN departments d ON s.department_id = d.id",
            "SELECT s.id FROM (SELECT id, department_id FROM employees WHERE department_id IS NOT NULL) s JOIN departments d ON s.department_id = d.id",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.department_id IS NOT NULL OR d.name = 'x'",
            "SELECT e.id FROM employees e, departments d, badges b WHERE e.department_id = d.id AND b.department_id = e.department_id",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE (e.department_id > 0 AND e.name = 'x') OR e.department_id < 0",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.id > e.department_id",
            "SELECT department_id FROM employees JOIN badges USING (department_id) JOIN departments d ON department_id = d.id",
            "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE (e.name IS NULL AND e.id IS NULL) OR e.department_id = 1",
        ]),
        Vec::<String>::new()
    );
}

#[test]
fn a_view_filtering_the_reference_passes_and_one_keeping_it_is_followed() {
    let found = findings(
        &constrainer(),
        RULE,
        &format!(
            "{SCHEMA}
             CREATE VIEW staffed AS SELECT * FROM employees WHERE department_id IS NOT NULL;
             CREATE VIEW staff AS SELECT * FROM employees;
             CREATE VIEW filtered AS SELECT s.id FROM staffed s JOIN departments d ON s.department_id = d.id;
             CREATE VIEW unfiltered AS SELECT s.id FROM staff s JOIN departments d ON s.department_id = d.id;
             CREATE VIEW twice AS SELECT s.id FROM staff s JOIN departments d ON s.department_id = d.id
               UNION ALL SELECT s.id FROM staff s JOIN departments d ON s.department_id = d.id;
             CREATE VIEW merged AS SELECT department_id FROM employees JOIN badges USING (department_id);
             CREATE VIEW over_merged AS SELECT m.department_id FROM merged m JOIN departments d ON m.department_id = d.id;
             CREATE VIEW unioned AS SELECT id, department_id FROM employees UNION ALL SELECT id, department_id FROM badges;
             CREATE VIEW over_unioned AS SELECT u.id FROM unioned u JOIN departments d ON u.department_id = d.id;
             CREATE MATERIALIZED VIEW stored_staff AS SELECT * FROM employees;
             CREATE VIEW over_stored AS SELECT m.id FROM stored_staff m JOIN departments d ON m.department_id = d.id;"
        ),
    );
    let objects: Vec<&str> = found.iter().map(|(_, object, _)| object.as_str()).collect();
    assert_eq!(objects, ["over_stored", "twice", "twice", "unfiltered"]);
}

#[test]
fn a_reference_is_followed_through_at_most_sixteen_relations() {
    let chain = |length: usize| {
        let links: Vec<String> = (1..length)
            .map(|link| format!("CREATE VIEW l{link:02} AS SELECT * FROM l{:02};", link - 1))
            .collect();
        let sql = format!(
            "{SCHEMA} CREATE VIEW l00 AS SELECT * FROM employees; {} CREATE VIEW joined AS SELECT l.id FROM l{:02} l JOIN departments d ON l.department_id = d.id;",
            links.join(" "),
            length - 1
        );
        findings(&constrainer(), RULE, &sql)
            .into_iter()
            .map(|(_, object, _)| object)
            .collect::<Vec<_>>()
    };
    assert_eq!(chain(15), ["joined"]);
    assert_eq!(chain(16), Vec::<String>::new());
}

#[test]
fn only_the_referencing_columns_the_join_equates_are_judged() {
    let found = findings(
        &constrainer(),
        RULE,
        "CREATE TABLE projects (organization_id UUID NOT NULL, id UUID NOT NULL, archived BOOLEAN NOT NULL,
           active BOOLEAN, PRIMARY KEY (organization_id, id), UNIQUE (organization_id, id, archived));
         CREATE TABLE tasks (organization_id UUID NOT NULL, id UUID PRIMARY KEY, project_id UUID NOT NULL,
           project_archived BOOLEAN,
           FOREIGN KEY (organization_id, project_id, project_archived) REFERENCES projects (organization_id, id, archived));
         CREATE VIEW keyed AS SELECT t.id FROM tasks t JOIN projects p ON p.organization_id = t.organization_id AND p.id = t.project_id;
         CREATE VIEW unrelated AS SELECT t.id FROM tasks t JOIN projects p ON p.organization_id = t.organization_id AND p.id = t.project_id AND p.active = t.project_archived;
         CREATE VIEW copied AS SELECT t.id FROM tasks t JOIN projects p ON p.organization_id = t.organization_id AND p.id = t.project_id AND p.archived = t.project_archived;",
    );
    let objects: Vec<&str> = found.iter().map(|(_, object, _)| object.as_str()).collect();
    assert_eq!(objects, ["copied"]);
}

#[test]
fn a_filter_a_validated_check_ties_to_the_reference_documents_the_inner_join() {
    let found = findings(
        &constrainer(),
        RULE,
        "CREATE TABLE resources (id INT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('organization', 'folder', 'project')),
           parent_id INT REFERENCES resources (id), CHECK ((kind = 'organization') = (parent_id IS NULL)));
         CREATE TABLE drafts (id INT PRIMARY KEY, kind TEXT NOT NULL, parent_id INT REFERENCES resources (id));
         ALTER TABLE drafts ADD CONSTRAINT rooted CHECK ((kind = 'organization') = (parent_id IS NULL)) NOT VALID;
         CREATE FUNCTION folders_under(root INT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$
           WITH RECURSIVE reached (id) AS (
             SELECT resource.id FROM resources resource WHERE resource.id = root
             UNION
             SELECT child.id FROM reached JOIN resources child ON child.parent_id = reached.id
             WHERE child.kind IN ('folder', 'project'))
           SELECT id FROM reached $$;
         CREATE FUNCTION all_under(root INT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$
           WITH RECURSIVE reached (id) AS (
             SELECT resource.id FROM resources resource WHERE resource.id = root
             UNION
             SELECT child.id FROM reached JOIN resources child ON child.parent_id = reached.id)
           SELECT id FROM reached $$;
         CREATE FUNCTION kinds_under(wanted TEXT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$
           SELECT c.id FROM resources c JOIN resources p ON c.parent_id = p.id WHERE c.kind = wanted $$;
         CREATE VIEW folders AS SELECT c.id FROM resources c JOIN resources p ON c.parent_id = p.id WHERE c.kind = 'folder';
         CREATE VIEW linked_folders AS SELECT c.id FROM resources c, resources p WHERE c.parent_id = p.id AND c.kind <> 'organization';
         CREATE VIEW folder_rows AS SELECT * FROM resources WHERE kind = 'folder';
         CREATE VIEW over_folder_rows AS SELECT f.id FROM folder_rows f JOIN resources p ON f.parent_id = p.id;
         CREATE VIEW derived_folders AS SELECT f.id FROM (SELECT id, parent_id FROM resources WHERE kind = 'project') f
           JOIN resources p ON f.parent_id = p.id;
         CREATE VIEW joined_filter AS SELECT c.id FROM resources c JOIN resources p ON c.parent_id = p.id
           JOIN resources s ON s.id = c.id AND c.kind = 'folder';
         CREATE VIEW own_on AS SELECT c.id FROM resources c JOIN resources p ON c.parent_id = p.id AND c.kind = 'folder';
         CREATE VIEW any_kind AS SELECT c.id FROM resources c JOIN resources p ON c.parent_id = p.id
           WHERE c.kind IN ('organization', 'folder');
         CREATE VIEW either AS SELECT c.id FROM resources c JOIN resources p ON c.parent_id = p.id
           WHERE c.kind = 'folder' OR p.kind = 'folder';
         CREATE VIEW unvalidated AS SELECT d.id FROM drafts d JOIN resources p ON d.parent_id = p.id WHERE d.kind = 'folder';",
    );
    let objects: Vec<&str> = found.iter().map(|(_, object, _)| object.as_str()).collect();
    assert_eq!(
        objects,
        [
            "any_kind",
            "either",
            "own_on",
            "unvalidated",
            "all_under(INT)",
            "kinds_under(TEXT)"
        ]
    );
}

#[test]
fn statements_report_their_joins_but_not_the_link_to_the_written_table() {
    check_query_rule(
        SCHEMA,
        InnerJoinNullableForeignKey::default(),
        &[
            (
                "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id",
                &["JOIN departments d ON e.department_id = d.id"],
            ),
            (
                "SELECT e.id FROM employees e, departments d WHERE e.department_id = d.id",
                &["e.department_id = d.id"],
            ),
            (
                "UPDATE employees e SET name = d.name FROM departments d WHERE e.department_id = d.id",
                &[],
            ),
            (
                "DELETE FROM departments d USING employees e WHERE e.department_id = d.id",
                &[],
            ),
            (
                "UPDATE badges b SET department_id = d.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE b.id = e.id",
                &["JOIN departments d ON e.department_id = d.id"],
            ),
            (
                "UPDATE badges b SET department_id = d.id FROM employees e, departments d WHERE e.department_id = d.id AND b.id = e.id",
                &["e.department_id = d.id"],
            ),
            (
                "SELECT s.id FROM regions NATURAL JOIN stores s",
                &["NATURAL JOIN stores s"],
            ),
            (
                "WITH staff AS (SELECT * FROM employees) SELECT s.id FROM staff s JOIN departments d ON s.department_id = d.id",
                &["JOIN departments d ON s.department_id = d.id"],
            ),
            (
                "WITH s AS (SELECT u.*, e.department_id FROM employees e CROSS JOIN missing u) SELECT s.department_id FROM s JOIN departments d ON s.department_id = d.id",
                &[],
            ),
            (
                "WITH m AS (SELECT department_id FROM employees JOIN badges USING (department_id)) SELECT m.department_id FROM m JOIN departments d ON m.department_id = d.id",
                &[],
            ),
            (
                "WITH ids AS (SELECT id FROM badges) UPDATE employees e SET name = d.name FROM departments d WHERE e.department_id = d.id AND e.id IN (SELECT id FROM ids)",
                &[],
            ),
            (
                "WITH u AS (SELECT id, department_id FROM employees UNION ALL SELECT id, department_id FROM badges) SELECT u.id FROM u JOIN departments d ON u.department_id = d.id",
                &[],
            ),
            (
                "INSERT INTO badges SELECT e.id, d.id FROM employees e JOIN departments d ON e.department_id = d.id",
                &["JOIN departments d ON e.department_id = d.id"],
            ),
        ],
    );
}
