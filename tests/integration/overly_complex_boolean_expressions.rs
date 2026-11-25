//! Boolean expressions whose minimal form reads fewer terms, observed through
//! the public constrainer API.

use crate::rule_findings::{findings, statement_findings};
use pg_diesel::PgDieselDatabase;
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// The object, the written expression and the minimal form of every finding
/// of `overly_complex_boolean_expression` on `sql`.
fn reported(sql: &str) -> Vec<(String, String, String)> {
    let constrainer: GenericConstrainer<ParserDB> =
        OverlyComplexBooleanExpression::default().into();
    findings(&constrainer, "overly_complex_boolean_expression", sql)
        .into_iter()
        .map(|(_, object, message)| {
            let quoted: Vec<&str> = message.split('`').skip(1).step_by(2).collect();
            let [written, form, ..] = quoted.as_slice() else {
                panic!("the message quotes the expression and its form: {message}")
            };
            (object, (*written).to_owned(), (*form).to_owned())
        })
        .collect()
}

/// A finding on `object` of `written`, which `form` decides alike.
fn finding(object: &str, written: &str, form: &str) -> (String, String, String) {
    (object.to_owned(), written.to_owned(), form.to_owned())
}

#[test]
fn a_check_whose_minimal_form_drops_a_comparison_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE orders (paid BOOLEAN, amount INT, CHECK ((paid AND amount > 0) OR (paid AND amount <= 0)));"
        ),
        [finding(
            "orders",
            "(paid AND amount > 0) OR (paid AND amount <= 0)",
            "paid"
        )]
    );
}

#[test]
fn a_domain_check_whose_minimal_form_drops_a_comparison_is_reported() {
    assert_eq!(
        reported(
            "CREATE DOMAIN even_positive AS INT CHECK ((VALUE > 0 AND VALUE % 2 = 0) OR (VALUE > 0 AND NOT VALUE % 2 = 0));"
        ),
        [finding(
            "even_positive",
            "(VALUE > 0 AND VALUE % 2 = 0) OR (VALUE > 0 AND NOT VALUE % 2 = 0)",
            "VALUE > 0"
        )]
    );
}

#[test]
fn a_comparison_another_term_implies_is_left_to_redundant_term() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (amount INT, CHECK ((amount > 0 AND amount < 100) OR (amount > 0 AND amount >= 100)));"
        ),
        []
    );
}

#[test]
fn a_filter_drops_a_term_only_when_the_term_is_never_null() {
    let schema = |b: &str| {
        format!(
            "CREATE TABLE t (a BOOLEAN, b BOOLEAN {b});
             CREATE POLICY p ON t USING ((a AND b) OR (a AND NOT b));
             CREATE INDEX i ON t (a) WHERE (a AND b) OR (a AND NOT b);"
        )
    };
    assert_eq!(reported(&schema("")), []);
    assert_eq!(
        reported(&schema("NOT NULL")),
        [
            finding("t.p", "(a AND b) OR (a AND NOT b)", "a"),
            finding("t.i", "(a AND b) OR (a AND NOT b)", "a"),
        ]
    );
}

#[test]
fn a_check_drops_a_nullable_term_as_it_admits_null() {
    assert_eq!(
        reported("CREATE TABLE t (a BOOLEAN, b BOOLEAN, CHECK ((a AND b) OR (a AND NOT b)));"),
        [finding("t", "(a AND b) OR (a AND NOT b)", "a")]
    );
}

#[test]
fn a_term_redundant_term_reports_is_left_to_it() {
    assert_eq!(
        reported("CREATE TABLE t (a BOOLEAN, b BOOLEAN, CHECK (a OR (a AND b)));"),
        []
    );
}

#[test]
fn a_shorter_form_reading_every_term_is_not_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN NOT NULL, b BOOLEAN NOT NULL);
             CREATE VIEW v AS SELECT 1 FROM t WHERE a AND (NOT a OR b);"
        ),
        []
    );
}

#[test]
fn volatile_and_raising_terms_are_never_dropped() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN, x INT NOT NULL,
                 CHECK ((a AND random() > 0.5) OR (a AND NOT random() > 0.5)),
                 CHECK ((a AND 10 / x > 1) OR (a AND NOT 10 / x > 1)));"
        ),
        []
    );
}

#[test]
fn view_filters_and_values_are_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN NOT NULL, b BOOLEAN NOT NULL);
             CREATE VIEW v AS SELECT (a AND b) OR (a AND NOT b) AS c FROM t WHERE (b AND a) OR (NOT b AND a);"
        ),
        [
            finding("v", "(b AND a) OR (NOT b AND a)", "a"),
            finding("v", "(a AND b) OR (a AND NOT b)", "a"),
        ]
    );
}

#[test]
fn a_value_must_agree_on_null_too() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN NOT NULL, b BOOLEAN);
             CREATE VIEW v AS SELECT (a AND b) OR (a AND NOT b) AS c FROM t;"
        ),
        []
    );
}

#[test]
fn a_generated_column_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN NOT NULL, b BOOLEAN NOT NULL,
                 c BOOLEAN GENERATED ALWAYS AS ((a AND b) OR (a AND NOT b)) STORED);"
        ),
        [finding("t.c", "(a AND b) OR (a AND NOT b)", "a")]
    );
}

#[test]
fn a_script_where_clause_is_reported() {
    let constrainer: GenericConstrainer<ParserDB> =
        OverlyComplexBooleanExpression::default().into();
    let database =
        ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (a BOOLEAN, b BOOLEAN NOT NULL);")
            .unwrap();
    let found = statement_findings(
        &constrainer,
        &database,
        "SELECT 1 FROM t WHERE (a AND b) OR (a AND NOT b)",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "overly_complex_boolean_expression");
}

/// The written expression and minimal form of every finding on the PL/pgSQL
/// `body` of a function taking `flag BOOLEAN` and `x INT`.
fn body_findings(body: &str) -> Vec<(String, String)> {
    reported(&format!(
        "CREATE FUNCTION pick(flag BOOLEAN, x INT) RETURNS INT LANGUAGE plpgsql AS $$ {body} $$;"
    ))
    .into_iter()
    .map(|(object, written, form)| {
        assert_eq!(object, "pick(BOOLEAN, INT)");
        (written, form)
    })
    .collect()
}

#[test]
fn a_plpgsql_condition_drops_a_term_the_path_makes_never_null() {
    let condition = "(flag AND x > 0) OR (flag AND NOT x > 0)";
    assert_eq!(
        body_findings(&format!(
            "BEGIN IF {condition} THEN RETURN 1; END IF; RETURN 0; END"
        )),
        []
    );
    assert_eq!(
        body_findings(&format!(
            "BEGIN x := coalesce(x, 0); IF {condition} THEN RETURN 1; END IF; RETURN 0; END"
        )),
        [(condition.to_owned(), "flag".to_owned())]
    );
}

#[test]
fn a_plpgsql_assigned_value_is_reported() {
    assert_eq!(
        body_findings(
            "DECLARE r BOOLEAN; BEGIN x := coalesce(x, 0); r := (flag AND x > 0) OR (flag AND NOT x > 0); RETURN 0; END"
        ),
        [(
            "(flag AND x > 0) OR (flag AND NOT x > 0)".to_owned(),
            "flag".to_owned()
        )]
    );
}

#[test]
fn live_schema_expressions_are_reported() {
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        "CREATE TABLE t (a BOOLEAN, b BOOLEAN NOT NULL, CHECK ((a AND b) OR (a AND NOT b)), c BOOLEAN GENERATED ALWAYS AS ((a AND b) OR (a AND NOT b)) STORED); CREATE POLICY p ON t USING ((a AND b) OR (a AND NOT b)); CREATE INDEX i ON t (a) WHERE (a AND b) OR (a AND NOT b);",
    );
    let constrainer: GenericConstrainer<PgDieselDatabase> =
        OverlyComplexBooleanExpression::default().into();
    let mut objects: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    objects.sort();
    assert_eq!(objects, ["t", "t.c", "t.i", "t.p"]);
}
