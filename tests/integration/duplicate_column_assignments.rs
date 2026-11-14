//! Statements assigning or listing one column more than once.

use crate::{
    common::parse,
    rule_findings::{query_rule, statement_objects},
};
use sqlippy::prelude::*;
use sqlparser::{dialect::SnowflakeDialect, parser::Parser};

const TABLES: &str = "CREATE TYPE pair AS (x INT, y INT);
    CREATE TABLE u (id INT PRIMARY KEY, a INT, b INT, p pair);";

/// The columns the rule reports on `sql`.
fn duplicated(sql: &str) -> Vec<String> {
    statement_objects(
        &query_rule(DuplicateColumnAssignment::default()),
        &parse(TABLES),
        sql,
    )
}

#[test]
fn a_column_assigned_twice_is_reported() {
    for (sql, column) in [
        ("UPDATE u SET a = 1, a = 2", "a"),
        ("UPDATE u SET (a, b) = (1, 2), a = 3", "a"),
        ("UPDATE u SET a = 1, A = 2", "a"),
        ("UPDATE u SET a = 1, \"a\" = 2", "a"),
        ("UPDATE u SET (p.x, b) = (1, 2), p = ROW(1, 1)", "p"),
        ("INSERT INTO u (id, id) VALUES (5, 5)", "id"),
        ("INSERT INTO u (id, p, p.x) VALUES (3, ROW(1, 1), 2)", "p"),
        (
            "INSERT INTO u (id, a) VALUES (1, 1) ON CONFLICT (id) DO UPDATE SET a = 1, a = 2",
            "a",
        ),
        (
            "MERGE INTO u USING (SELECT 1 AS id) s ON u.id = s.id WHEN MATCHED THEN UPDATE SET a = 1, a = 2",
            "a",
        ),
        (
            "MERGE INTO u USING (SELECT 9 AS id) s ON u.id = s.id WHEN NOT MATCHED THEN INSERT (id, id) VALUES (9, 9)",
            "id",
        ),
        (
            "WITH w AS (UPDATE u SET a = 1, a = 2 RETURNING id) SELECT * FROM w",
            "a",
        ),
    ] {
        assert_eq!(duplicated(sql), [column], "{sql}");
    }
}

#[test]
fn each_duplicated_column_and_clause_is_reported_once() {
    assert_eq!(
        duplicated("UPDATE u SET a = 1, b = 2, a = 3, b = 4, a = 5"),
        ["a", "b"]
    );
    assert_eq!(
        duplicated(
            "INSERT INTO u (id, id, a) VALUES (1, 1, 1) ON CONFLICT (id) DO UPDATE SET a = 1, a = 2"
        ),
        ["id", "a"]
    );
}

#[test]
fn distinct_columns_and_fields_alone_pass() {
    for sql in [
        "UPDATE u SET a = 1, b = 2",
        "UPDATE u SET p.x = 1, p.y = 2",
        "UPDATE u SET p.x = 1, p.x = 2",
        "UPDATE u SET (p.x, p.y) = (1, 2), p.x = 3",
        "UPDATE u SET a = 1, \"A\" = 2",
        "INSERT INTO u (id, p.x, p.y) VALUES (2, 1, 2)",
        "INSERT INTO u (id, p.x, p.x) VALUES (4, 1, 2)",
        "INSERT INTO u VALUES (6, 1, 1, ROW(1, 1)) ON CONFLICT (id) DO NOTHING",
        "MERGE INTO u USING (SELECT 1 AS id) s ON u.id = s.id WHEN MATCHED THEN DELETE",
        "WITH w AS (UPDATE u SET a = 1, b = 2 RETURNING id) SELECT count(*) FROM w",
        "SELECT a, a FROM u",
    ] {
        assert_eq!(duplicated(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_target_named_by_a_function_is_not_compared() {
    let statement = &Parser::parse_sql(
        &SnowflakeDialect {},
        "UPDATE u SET IDENTIFIER('a') = 1, IDENTIFIER('a') = 2",
    )
    .unwrap()[0];
    assert!(
        query_rule(DuplicateColumnAssignment::default())
            .validate_statement(&parse(TABLES), statement)
            .is_ok()
    );
}
