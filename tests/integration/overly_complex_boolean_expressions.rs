//! Boolean expressions whose minimal form reads fewer terms, observed through
//! the public constrainer API.

use crate::rule_findings::{findings, statement_findings};
use pg_diesel::PgDieselDatabase;
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// The object, the written expression and the minimal form of every finding
/// of `overly_complex_boolean_expression` on `sql`, sorted.
fn reported(sql: &str) -> Vec<(String, String, String)> {
    let constrainer: GenericConstrainer<ParserDB> =
        OverlyComplexBooleanExpression::default().into();
    let mut found: Vec<_> = findings(&constrainer, "overly_complex_boolean_expression", sql)
        .into_iter()
        .map(|(_, object, message)| {
            let quoted: Vec<&str> = message.split('`').skip(1).step_by(2).collect();
            let [written, form, ..] = quoted.as_slice() else {
                panic!("the message quotes the expression and its form: {message}")
            };
            (object, (*written).to_owned(), (*form).to_owned())
        })
        .collect();
    found.sort();
    found
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
            finding("t.i", "(a AND b) OR (a AND NOT b)", "a"),
            finding("t.p", "(a AND b) OR (a AND NOT b)", "a"),
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
            finding("v", "(a AND b) OR (a AND NOT b)", "a"),
            finding("v", "(b AND a) OR (NOT b AND a)", "a"),
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
fn a_plpgsql_declared_default_and_embedded_statement_are_reported() {
    let value = "(flag IS TRUE AND x IS NOT NULL) OR (flag IS TRUE AND NOT x IS NOT NULL)";
    assert_eq!(
        reported(&format!(
            "CREATE TABLE t (a BOOLEAN NOT NULL, b BOOLEAN NOT NULL);
             CREATE FUNCTION pick(flag BOOLEAN, x INT) RETURNS INT LANGUAGE plpgsql AS $$
             DECLARE r BOOLEAN := {value};
             BEGIN DELETE FROM t WHERE (a AND b) OR (a AND NOT b); RETURN 0; END $$;"
        )),
        [
            finding("pick(BOOLEAN, INT)", "(a AND b) OR (a AND NOT b)", "a"),
            finding("pick(BOOLEAN, INT)", value, "flag IS TRUE"),
        ]
    );
}

#[test]
fn a_plpgsql_query_value_reads_variables_where_it_runs() {
    let schema = |first: &str| {
        format!(
            "CREATE TABLE t (a BOOLEAN);
             CREATE FUNCTION pick(flag BOOLEAN, x INT) RETURNS INT LANGUAGE plpgsql AS $$
             BEGIN {first} INSERT INTO t SELECT (flag AND x > 0) OR (flag AND NOT x > 0); RETURN 0; END $$;"
        )
    };
    assert_eq!(reported(&schema("")), []);
    assert_eq!(
        reported(&schema("x := coalesce(x, 0);")),
        [finding(
            "pick(BOOLEAN, INT)",
            "(flag AND x > 0) OR (flag AND NOT x > 0)",
            "flag"
        )]
    );
}

#[test]
fn a_plpgsql_condition_the_body_never_reaches_is_not_reported() {
    assert_eq!(
        body_findings(
            "BEGIN RETURN 0; IF (flag IS TRUE AND x IS NOT NULL) OR (flag IS TRUE AND NOT x IS NOT NULL) THEN RETURN 1; END IF; END"
        ),
        []
    );
}

#[test]
fn sql_function_bodies_are_reported_when_their_value_agrees_on_null() {
    let value = "(a IS TRUE AND b IS TRUE) OR (a IS TRUE AND NOT b IS TRUE)";
    assert_eq!(
        reported(&format!(
            "CREATE TABLE t (a BOOLEAN NOT NULL, b BOOLEAN NOT NULL);
             CREATE FUNCTION f(a BOOLEAN, b BOOLEAN) RETURNS BOOLEAN LANGUAGE sql RETURN {value};
             CREATE FUNCTION g() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT 1 FROM t WHERE (a AND b) OR (a AND NOT b) $$;
             CREATE FUNCTION h(a BOOLEAN, b BOOLEAN) RETURNS BOOLEAN LANGUAGE sql RETURN (a AND b) OR (a AND NOT b);"
        )),
        [
            finding("f(BOOLEAN, BOOLEAN)", value, "a IS TRUE"),
            finding("g()", "(a AND b) OR (a AND NOT b)", "a"),
        ]
    );
}

#[test]
fn join_conditions_and_materialized_views_are_reported() {
    let condition = "(t.a AND u.b) OR (t.a AND NOT u.b)";
    assert_eq!(
        reported(&format!(
            "CREATE TABLE t (id INT, a BOOLEAN NOT NULL);
             CREATE TABLE u (id INT, b BOOLEAN NOT NULL);
             CREATE MATERIALIZED VIEW m AS SELECT 1 FROM t JOIN u ON {condition};
             CREATE VIEW v AS SELECT 1 FROM (t JOIN u ON {condition});"
        )),
        [
            finding("m", condition, "t.a"),
            finding("v", condition, "t.a"),
        ]
    );
}

#[test]
fn a_filter_redundant_term_reports_is_left_to_it() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a BOOLEAN NOT NULL, b BOOLEAN NOT NULL);
             CREATE POLICY p ON t USING (a OR (a AND b));
             CREATE INDEX i ON t (a) WHERE a OR (a AND b);
             CREATE VIEW v AS SELECT 1 FROM t WHERE a OR (a AND b);"
        ),
        []
    );
}

#[test]
fn a_domain_check_is_read_under_the_domain_s_other_checks() {
    let check = "(VALUE > 5 AND VALUE % 2 = 0) OR (VALUE > 5 AND NOT VALUE % 2 = 0)";
    assert_eq!(
        reported(&format!(
            "CREATE DOMAIN d AS INT CHECK (VALUE > 0) CHECK ({check});
             CREATE DOMAIN e AS INT CHECK (VALUE > 0) CHECK (VALUE > 5 OR (VALUE > 5 AND VALUE < 9));"
        )),
        [finding("d", check, "VALUE > 5")]
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
