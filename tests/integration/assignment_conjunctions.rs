//! Assignment conjunction diagnostics.

use crate::{common::parse, rule_findings::statement};
use sqlippy::prelude::*;

const SCHEMA: &str = "CREATE TABLE t (id INT PRIMARY KEY, a INT, b INT, flag BOOLEAN, verified BOOLEAN, role TEXT, is_admin BOOLEAN, \"B\" INT); CREATE TABLE other (id INT, other_table_col INT);";

/// Returns the conjunction diagnostics for one statement.
fn diagnostics(sql: &str) -> Vec<String> {
    DefaultConstrainer::default()
        .statement_diagnostics(&parse(SCHEMA), &statement(sql))
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(v) if v.rule().name == "assignment_conjunction" => Some(v.to_string()),
            Error::Violation(_) => None,
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn constants_before_comparisons_report_the_two_columns() {
    for value in [
        "true AND b = 2",
        "1 AND b = 2",
        "false OR b = 2",
        "(true AND b = 2)",
        "NULL AND b = 2",
        "-1 AND b = 2",
        "+1 AND b = 2",
        "DATE '2020-01-01' AND b = 2",
        "INTERVAL '1 day' AND b = 2",
        "'x' AND b = 2",
        "(true) AND (b = 2)",
    ] {
        let sql = format!("UPDATE t SET flag = {value}");
        let found = diagnostics(&sql);
        assert_eq!(found.len(), 1, "{sql}");
        assert!(
            found[0].contains("'flag'") && found[0].contains("'b'"),
            "{}",
            found[0]
        );
    }
}

#[test]
fn comparisons_resolve_either_side_and_fold_names() {
    for comparison in [
        "b = 2",
        "b <> 2",
        "b < 2",
        "b <= 2",
        "b > 2",
        "b >= 2",
        "b IS DISTINCT FROM 2",
        "b IS NOT DISTINCT FROM 2",
        "2 = b",
        "2 IS DISTINCT FROM b",
        "B = 2",
        "\"b\" = 2",
        "\"B\" = 2",
        "t.b = 2",
    ] {
        assert_eq!(
            diagnostics(&format!("UPDATE t SET a = 1 AND {comparison}")).len(),
            1,
            "{comparison}"
        );
    }
    assert_eq!(
        diagnostics("UPDATE t AS x SET flag = true AND x.b = 2").len(),
        1
    );
}

#[test]
fn every_assignment_clause_reports_once_per_assignment() {
    for sql in [
        "INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET flag = true AND b = 2",
        "MERGE INTO t USING other ON t.id = other.id WHEN MATCHED THEN UPDATE SET flag = true AND b = 2",
        "WITH changed AS (UPDATE t SET flag = true AND b = 2 RETURNING *) SELECT * FROM changed",
    ] {
        assert_eq!(diagnostics(sql).len(), 1, "{sql}");
    }
    assert_eq!(
        diagnostics("UPDATE t SET flag = true AND b = a, a = 1 AND b = 2").len(),
        2
    );
}

#[test]
fn deliberate_expressions_and_other_tables_pass() {
    for sql in [
        "UPDATE t SET is_admin = verified AND role = 'admin'",
        "UPDATE t SET flag = true AND other_table_col = 2 FROM other",
        "UPDATE t SET flag = true AND other.id = 2 FROM other",
        "UPDATE t SET flag = true",
        "UPDATE t SET flag = (b = 2)",
        "UPDATE t SET flag = true AND b + 1 = 2",
        "UPDATE t SET flag = true AND b IS NULL",
        "UPDATE t SET flag = true AND b IN (2)",
        "UPDATE t SET flag = b = 2 AND true",
        "UPDATE t SET flag = random() AND b = 2",
        "UPDATE t SET flag = $1 AND b = 2",
        "UPDATE missing SET flag = true AND b = 2",
    ] {
        assert!(diagnostics(sql).is_empty(), "{sql}");
    }
}
