//! Equality joins whose columns cover a unique key of neither table,
//! observed through the public constrainer API.

use crate::rule_findings::{findings, statement_findings};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "CREATE TABLE projects (id INT PRIMARY KEY, location INT, code INT);
    CREATE TABLE employees (id INT PRIMARY KEY, location INT, project_id INT REFERENCES projects (id));
    CREATE TABLE sites (location INT PRIMARY KEY, name TEXT);
    CREATE TABLE badges (location INT, serial INT, UNIQUE (location, serial));
    CREATE TABLE stamps (location INT UNIQUE DEFERRABLE);
    CREATE VIEW located AS SELECT location FROM projects;";

fn constrainer() -> GenericConstrainer<ParserDB> {
    JoinOnNonKeyColumns::default().into()
}

/// The objects the rule reports on `sql` run against `SCHEMA`.
fn joins(sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(SCHEMA).expect("schema parses");
    statement_findings(&constrainer(), &database, sql)
        .into_iter()
        .map(|(rule, _, object)| {
            assert_eq!(rule, "join_on_non_key_columns");
            object
        })
        .collect()
}

/// The messages the rule reports on the schema objects `sql` adds to
/// `SCHEMA`.
fn schema_messages(sql: &str) -> Vec<String> {
    findings(
        &constrainer(),
        "join_on_non_key_columns",
        &format!("{SCHEMA} {sql}"),
    )
    .into_iter()
    .map(|(_, _, message)| message)
    .collect()
}

#[test]
fn a_join_on_columns_that_are_a_key_of_neither_table_is_reported() {
    for (sql, object) in [
        (
            "SELECT e.id FROM employees e JOIN projects p ON e.location = p.location",
            "e.location = p.location",
        ),
        (
            "SELECT e.id FROM employees e, projects p WHERE p.location = e.location",
            "p.location = e.location",
        ),
        (
            "SELECT e.id FROM employees e LEFT JOIN projects p ON e.location = p.location AND p.code = 3",
            "e.location = p.location",
        ),
        (
            "SELECT e.id FROM employees e JOIN projects p USING (location)",
            "e.location = p.location",
        ),
        (
            "SELECT b.serial FROM badges b NATURAL JOIN projects p",
            "b.\"location\" = p.\"location\"",
        ),
        // A column of a derived table or a view varies with its rows, so it
        // fixes no key column it equals.
        (
            "SELECT e.id FROM employees e JOIN (SELECT location AS x FROM sites) d ON e.id = d.x JOIN projects p ON e.location = p.location",
            "e.location = p.location",
        ),
        (
            "SELECT e.id FROM employees e JOIN located l ON e.id = l.location JOIN projects p ON e.location = p.location",
            "e.location = p.location",
        ),
        (
            "SELECT a.id FROM employees a JOIN employees b ON a.location = b.location",
            "a.location = b.location",
        ),
        (
            "SELECT e.id FROM (employees e JOIN projects p ON e.location = p.location)",
            "e.location = p.location",
        ),
        (
            "UPDATE employees SET project_id = p.id FROM projects p WHERE employees.location = p.location",
            "employees.location = p.location",
        ),
        // One column of a composite key leaves each row several partners.
        (
            "SELECT e.id FROM employees e JOIN badges b ON b.location = e.location",
            "b.location = e.location",
        ),
        // A deferrable key may hold duplicates until its check runs.
        (
            "SELECT e.id FROM employees e JOIN stamps s ON s.location = e.location",
            "s.location = e.location",
        ),
    ] {
        assert_eq!(joins(sql), [object], "{sql}");
    }
}

#[test]
fn a_join_covering_a_unique_key_of_one_table_is_accepted() {
    for sql in [
        "SELECT e.id FROM employees e JOIN projects p ON e.project_id = p.id",
        "SELECT e.id FROM projects p JOIN employees e ON p.id = e.project_id",
        "SELECT e.id FROM employees e JOIN projects p ON e.project_id = p.id AND e.location = p.location",
        // A unique key passes without a foreign key.
        "SELECT e.id FROM employees e JOIN sites s ON s.location = e.location",
        "SELECT e.id FROM employees e JOIN sites s USING (location)",
        "SELECT a.id FROM employees a JOIN employees b ON a.project_id = b.id",
        // A fixed value completes the key.
        "SELECT e.id FROM employees e JOIN badges b ON b.location = e.location AND b.serial = 7",
        "SELECT e.id FROM employees e JOIN badges b ON b.location = e.location WHERE b.serial = $1",
        "SELECT e.id FROM employees e JOIN projects p ON e.location = p.location WHERE p.id = 1",
        "SELECT e.id FROM employees e JOIN badges b ON b.location = e.location AND b.serial = e.id",
    ] {
        assert!(joins(sql).is_empty(), "{sql}");
    }
}

#[test]
fn semi_joins_derived_relations_and_other_joins_are_not_judged() {
    for sql in [
        "SELECT e.id FROM employees e WHERE EXISTS (SELECT 1 FROM projects p WHERE p.location = e.location)",
        "SELECT e.id FROM employees e WHERE e.location IN (SELECT p.location FROM projects p)",
        "WITH p AS (SELECT location FROM projects) SELECT e.id FROM employees e JOIN p ON p.location = e.location",
        "SELECT e.id FROM employees e JOIN (SELECT location FROM projects) p ON p.location = e.location",
        "WITH projects AS (SELECT location FROM projects) SELECT e.id FROM employees e JOIN projects ON projects.location = e.location",
        "SELECT e.id FROM employees e JOIN located l ON l.location = e.location",
        "SELECT e.id FROM employees e CROSS JOIN projects p",
        "SELECT e.id FROM employees e JOIN projects p ON e.location < p.location",
        "SELECT e.id FROM employees e JOIN projects p ON e.location = p.location OR e.project_id = p.id",
    ] {
        assert!(joins(sql).is_empty(), "{sql}");
    }
}

#[test]
fn a_correlated_column_fixes_the_key_of_a_subquery_join() {
    assert_eq!(
        joins(
            "SELECT e.id FROM employees e WHERE EXISTS (SELECT 1 FROM projects p JOIN badges b ON b.location = p.location WHERE b.serial = e.id)"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        joins(
            "SELECT e.id FROM employees e WHERE EXISTS (SELECT 1 FROM projects p JOIN badges b ON b.location = p.location WHERE p.code = e.id)"
        ),
        ["b.location = p.location"]
    );
}

#[test]
fn views_policies_and_function_bodies_are_read() {
    let join = "SELECT e.id FROM employees e JOIN projects p ON e.location = p.location";
    assert_eq!(
        schema_messages(&format!("CREATE VIEW crossed AS {join};")),
        [
            "View 'crossed' uses a join of 'employees' and 'projects' on `e.location = p.location` instead of their foreign key `e.project_id = p.id`, whose columns cover a unique key of neither table, so a row of either side can pair with several rows of the other and the result holds pairs no stored row relates."
        ]
    );
    assert_eq!(
        schema_messages(&format!("CREATE MATERIALIZED VIEW crossed AS {join};")).len(),
        1
    );
    assert_eq!(
        schema_messages(&format!(
            "CREATE FUNCTION crossed() RETURNS SETOF INT LANGUAGE sql AS $$ {join} $$;"
        ))
        .len(),
        1
    );
    assert_eq!(
        schema_messages(&format!(
            "CREATE FUNCTION crossed() RETURNS SETOF INT LANGUAGE plpgsql AS $$ BEGIN RETURN QUERY {join}; END $$;"
        ))
        .len(),
        1
    );
    assert_eq!(
        schema_messages(
            "CREATE POLICY crossed ON employees USING (id IN (SELECT p.id FROM projects p JOIN badges b ON p.location = b.location));"
        ),
        [
            "Policy 'crossed' on 'employees' uses a join of 'projects' and 'badges' on `p.location = b.location` in its USING clause, whose columns cover a unique key of neither table, so a row of either side can pair with several rows of the other and the result holds pairs no stored row relates."
        ]
    );
}

#[test]
fn a_function_parameter_fixes_a_key_column() {
    assert_eq!(
        schema_messages(
            "CREATE FUNCTION paired(wanted INT) RETURNS SETOF INT LANGUAGE sql AS $$ SELECT e.id FROM employees e JOIN badges b ON b.location = e.location WHERE b.serial = wanted $$;"
        ),
        Vec::<String>::new()
    );
}
