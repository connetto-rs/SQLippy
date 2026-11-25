//! Boolean expressions with a shorter form reading every term, observed
//! through the public constrainer API.

use crate::rule_findings::{findings, statement_findings};
use pg_diesel::PgDieselDatabase;
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// The object, the written expression and the shorter form of every finding
/// of `nonminimal_boolean_expression` on `sql`, sorted.
fn reported(sql: &str) -> Vec<(String, String, String)> {
    let constrainer: GenericConstrainer<ParserDB> = NonminimalBooleanExpression::default().into();
    let mut found: Vec<_> = findings(&constrainer, "nonminimal_boolean_expression", sql)
        .into_iter()
        .map(|(_, object, message)| {
            let quoted: Vec<&str> = message.split('`').skip(1).step_by(2).collect();
            let [written, form] = quoted.as_slice() else {
                panic!("the message quotes the expression and its form: {message}")
            };
            (object, (*written).to_owned(), (*form).to_owned())
        })
        .collect();
    found.sort();
    found
}

/// A finding on `object` of `written`, which `form` says alike.
fn finding(object: &str, written: &str, form: &str) -> (String, String, String) {
    (object.to_owned(), written.to_owned(), form.to_owned())
}

#[test]
fn a_filter_with_a_shorter_form_is_reported_whatever_its_terms_hold() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN, b BOOLEAN);
             CREATE POLICY p ON t USING (a AND (NOT a OR b));
             CREATE VIEW v AS SELECT 1 FROM t WHERE a AND (NOT a OR b);"
        ),
        [
            finding("t.p", "a AND (NOT a OR b)", "a AND b"),
            finding("v", "a AND (NOT a OR b)", "a AND b"),
        ]
    );
}

#[test]
fn a_check_takes_the_shorter_form_only_when_null_cannot_tell_them_apart() {
    let schema =
        |a: &str| format!("CREATE TABLE t (a BOOLEAN {a}, b BOOLEAN, CHECK (a AND (NOT a OR b)));");
    assert_eq!(reported(&schema("")), []);
    assert_eq!(
        reported(&schema("NOT NULL")),
        [finding("t", "a AND (NOT a OR b)", "a AND b")]
    );
}

#[test]
fn a_domain_check_is_reported() {
    assert_eq!(
        reported("CREATE DOMAIN positive AS INT CHECK (NOT (NOT VALUE > 0));"),
        [finding("positive", "NOT (NOT VALUE > 0)", "VALUE > 0")]
    );
}

#[test]
fn a_value_must_agree_on_null_too() {
    let schema = |a: &str| {
        format!(
            "CREATE TABLE t (a BOOLEAN {a}, b BOOLEAN NOT NULL);
             CREATE VIEW v AS SELECT a AND (NOT a OR b) AS c FROM t;"
        )
    };
    assert_eq!(reported(&schema("")), []);
    assert_eq!(
        reported(&schema("NOT NULL")),
        [finding("v", "a AND (NOT a OR b)", "a AND b")]
    );
}

#[test]
fn a_form_dropping_a_term_is_left_to_overly_complex_boolean_expression() {
    assert_eq!(
        reported("CREATE TABLE t (a BOOLEAN, b BOOLEAN, CHECK ((a AND b) OR (a AND NOT b)));"),
        []
    );
}

#[test]
fn a_de_morgan_rewrite_trading_negations_for_a_grouped_not_is_not_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN, b BOOLEAN, x INT, y INT, status TEXT);
             CREATE POLICY p ON t USING (NOT a AND NOT b);
             CREATE POLICY q ON t USING (NOT (a OR b));
             CREATE POLICY r ON t USING (NOT (x < y OR x < 0));
             CREATE POLICY s ON t USING (NOT (status = 'a' OR status = 'b'));"
        ),
        []
    );
}

#[test]
fn a_negated_comparison_is_reported_as_its_converse_wherever_it_sits() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN, x INT, y INT);
             CREATE POLICY p ON t USING (NOT (x < y));
             CREATE POLICY q ON t USING (a AND NOT (x < y));"
        ),
        [
            finding("t.p", "NOT (x < y)", "x >= y"),
            finding("t.q", "a AND NOT (x < y)", "a AND x >= y"),
        ]
    );
}

#[test]
fn a_term_redundant_term_reports_is_left_to_it() {
    assert_eq!(
        reported(
            "CREATE TABLE t (x INT, b BOOLEAN);
             CREATE VIEW v AS SELECT 1 FROM t WHERE x > 5 AND (NOT x > 5 OR b) AND x > 3;"
        ),
        []
    );
}

#[test]
fn a_generated_column_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN NOT NULL, b BOOLEAN NOT NULL,
                 c BOOLEAN GENERATED ALWAYS AS (a AND (NOT a OR b)) STORED);"
        ),
        [finding("t.c", "a AND (NOT a OR b)", "a AND b")]
    );
}

#[test]
fn a_script_where_clause_is_reported() {
    let constrainer: GenericConstrainer<ParserDB> = NonminimalBooleanExpression::default().into();
    let database =
        ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (a BOOLEAN, b BOOLEAN);").unwrap();
    let found = statement_findings(
        &constrainer,
        &database,
        "DELETE FROM t WHERE a AND (NOT a OR b)",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "nonminimal_boolean_expression");
}

#[test]
fn a_plpgsql_condition_and_value_are_read_where_the_body_evaluates_them() {
    let body = |first: &str| {
        format!(
            "CREATE FUNCTION pick(flag BOOLEAN, ready BOOLEAN) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
             BEGIN {first} IF flag AND (NOT flag OR ready) THEN RETURN true; END IF;
             RETURN flag AND (NOT flag OR ready); END $$;"
        )
    };
    let written = |found: Vec<(String, String, String)>| {
        found
            .into_iter()
            .map(|(object, written, form)| {
                assert_eq!(object, "pick(BOOLEAN, BOOLEAN)");
                (written, form)
            })
            .collect::<Vec<_>>()
    };
    let condition = (
        "flag AND (NOT flag OR ready)".to_owned(),
        "flag AND ready".to_owned(),
    );
    assert_eq!(
        written(reported(&body(""))),
        std::slice::from_ref(&condition)
    );
    assert_eq!(
        written(reported(&body("flag := coalesce(flag, false);"))),
        [condition.clone(), condition]
    );
}

#[test]
fn live_schema_expressions_are_reported() {
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        "CREATE TABLE t (a BOOLEAN NOT NULL, b BOOLEAN, c BOOLEAN GENERATED ALWAYS AS (a AND (NOT a OR b)) STORED); CREATE POLICY p ON t USING (a AND (NOT a OR b)); CREATE INDEX i ON t (a) WHERE a AND (NOT a OR b); CREATE TABLE u (a BOOLEAN NOT NULL, b BOOLEAN, CHECK (a AND (NOT a OR b)));",
    );
    let constrainer: GenericConstrainer<PgDieselDatabase> =
        NonminimalBooleanExpression::default().into();
    let mut objects: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    objects.sort();
    assert_eq!(objects, ["t.c", "t.i", "t.p", "u"]);
}
