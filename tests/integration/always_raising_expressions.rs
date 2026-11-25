//! Expressions that raise on every row.

use crate::rule_findings::findings;
use pg_diesel::PgDieselDatabase;
use sqlippy::prelude::*;

fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = AlwaysRaisingExpression::default().into();
    findings(&constrainer, "always_raising_expression", sql)
        .into_iter()
        .map(|(_, object, _)| object)
        .collect()
}

#[test]
fn a_raising_check_belongs_only_to_the_raising_rule() {
    let sql = "CREATE TABLE payments (amount INT, CONSTRAINT broken CHECK (1 / 0 = 1));";
    assert_eq!(reported(sql), ["payments"]);
    let constrainer: GenericConstrainer<ParserDB> = UnsatisfiableCheck::default().into();
    assert_eq!(findings(&constrainer, "unsatisfiable_check", sql), []);
}

#[test]
fn raising_defaults_and_generated_columns_are_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (amount INT DEFAULT 1 / 0, total INT GENERATED ALWAYS AS (1 / 0) STORED);"
        ),
        ["payments.amount", "payments.total"]
    );
}

#[test]
fn integer_overflow_is_reported() {
    assert_eq!(
        reported("CREATE TABLE payments (amount INT DEFAULT 2147483647 + 1);"),
        ["payments.amount"]
    );
}

#[test]
fn every_raising_index_key_and_predicate_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (amount INT); CREATE INDEX broken ON payments (amount, (1 / 0), (2 / 0)) WHERE 1 / 0 = 1;"
        ),
        ["payments.broken", "payments.broken", "payments.broken"]
    );
}

#[test]
fn both_raising_policy_clauses_are_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (amount INT); CREATE POLICY broken ON payments USING (1 / 0 = 1) WITH CHECK (2 / 0 = 1);"
        ),
        ["payments.broken", "payments.broken"]
    );
}

#[test]
fn sometimes_raising_and_nonraising_expressions_are_clean() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (amount INT CHECK (10 / amount > 0), initial INT DEFAULT 1, total INT GENERATED ALWAYS AS (10 / amount) STORED); CREATE INDEX variable ON payments ((10 / amount)) WHERE amount > 0; CREATE POLICY variable ON payments USING (10 / amount > 0) WITH CHECK (amount > 0);"
        ),
        [] as [String; 0]
    );
}

#[test]
fn an_unvalidated_raising_check_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (amount INT); ALTER TABLE payments ADD CONSTRAINT broken CHECK (1 / 0 = 1) NOT VALID;"
        ),
        ["payments"]
    );
}

#[test]
fn contradictory_checks_do_not_make_other_expressions_raise() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (amount INT DEFAULT 1, CHECK (amount > 0), CHECK (amount < 0));"
        ),
        [] as [String; 0]
    );
}

#[test]
fn the_message_names_the_site_object_and_expression() {
    let constrainer: GenericConstrainer<ParserDB> = AlwaysRaisingExpression::default().into();
    let [(_, _, message)] = findings(
        &constrainer,
        "always_raising_expression",
        "CREATE TABLE payments (amount INT DEFAULT 1 / 0);",
    )
    .try_into()
    .expect("one finding");
    assert!(message.contains("default"), "{message}");
    assert!(message.contains("'payments.amount'"), "{message}");
    assert!(message.contains("`1 / 0`"), "{message}");
}

#[test]
fn live_raising_schema_expressions_are_reported() {
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        "CREATE TABLE checked (amount INT, CHECK (1 / 0 = 1)); CREATE TABLE defaults (amount INT DEFAULT 1 / 0); CREATE TABLE generated (amount INT NOT NULL, total INT GENERATED ALWAYS AS (amount / 0) STORED); CREATE TABLE indexed (amount INT NOT NULL); CREATE INDEX broken ON indexed ((amount / 0)); CREATE INDEX partial ON indexed (amount) WHERE amount / 0 = 1; CREATE TABLE guarded (amount INT); CREATE POLICY broken ON guarded USING (1 / 0 = 1) WITH CHECK (2 / 0 = 1);",
    );
    let constrainer: GenericConstrainer<PgDieselDatabase> =
        AlwaysRaisingExpression::default().into();
    let mut objects: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    objects.sort();
    assert_eq!(
        objects,
        [
            "checked",
            "defaults.amount",
            "generated.total",
            "guarded.broken",
            "guarded.broken",
            "indexed.broken",
            "indexed.partial"
        ]
    );
}

/// Messages of every finding for the PL/pgSQL `body` of a function taking
/// `x INT` and returning `INT`.
fn body_messages(body: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = AlwaysRaisingExpression::default().into();
    findings(
        &constrainer,
        "always_raising_expression",
        &format!("CREATE FUNCTION pick(x INT) RETURNS INT LANGUAGE plpgsql AS $$ {body} $$;"),
    )
    .into_iter()
    .map(|(_, object, message)| {
        assert_eq!(object, "pick(INT)");
        message
    })
    .collect()
}

#[test]
fn plpgsql_conditions_and_values_raising_on_every_path_are_reported() {
    for (body, found) in [
        (
            "DECLARE d INT := 0; BEGIN IF 1 / d > 3 THEN RETURN 1; END IF; RETURN 0; END",
            "the IF condition `1 / d > 3` raises an error on every path reaching it",
        ),
        (
            "DECLARE d INT := 0; BEGIN ASSERT 5 / d = 1; RETURN 0; END",
            "the ASSERT condition `5 / d = 1` raises an error on every path reaching it",
        ),
        (
            "DECLARE d INT := 0; q INT; BEGIN q := 10 / d; RETURN q; END",
            "the assigned value `10 / d` raises an error on every path reaching it",
        ),
        (
            "DECLARE big INT := 2147483647; q INT := big + 1; BEGIN RETURN q; END",
            "the declared default `big + 1` raises an error on every path reaching it",
        ),
    ] {
        assert_eq!(
            body_messages(body),
            [format!("In function 'pick(INT)', {found}.")],
            "{body}"
        );
    }
}

#[test]
fn plpgsql_expressions_some_path_evaluates_are_clean() {
    for body in [
        "BEGIN IF 10 / x > 3 THEN RETURN 1; END IF; RETURN 0; END",
        "DECLARE d INT := 0; q INT; BEGIN IF x > 0 THEN d := x; END IF; q := 10 / d; RETURN q; END",
        "DECLARE d INT := 0; q INT; BEGIN RETURN 0; q := 10 / d; END",
    ] {
        assert_eq!(body_messages(body), Vec::<String>::new(), "{body}");
    }
}
