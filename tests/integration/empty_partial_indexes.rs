//! Partial indexes whose predicate no row of the table can satisfy, observed
//! through the public constrainer API.

use crate::rule_findings::findings;
use pg_diesel::PgDieselDatabase;
use sqlippy::prelude::*;

fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = EmptyPartialIndex::default().into();
    findings(&constrainer, "empty_partial_index", sql)
        .into_iter()
        .map(|(_, object, _)| object)
        .collect()
}

#[test]
fn a_predicate_the_checks_contradict_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));
             CREATE INDEX refunds ON payments (id) WHERE amount < 0;"
        ),
        ["payments.refunds"]
    );
}

#[test]
fn a_predicate_never_true_on_its_own_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (id INT PRIMARY KEY, amount INT);
             CREATE UNIQUE INDEX odd ON payments (id) WHERE amount > 5 AND amount < 3;"
        ),
        ["payments.odd"]
    );
}

#[test]
fn a_predicate_a_domain_check_contradicts_is_reported() {
    assert_eq!(
        reported(
            "CREATE DOMAIN positive AS INT CHECK (VALUE > 0);
             CREATE TABLE payments (id INT PRIMARY KEY, amount positive);
             CREATE INDEX refunds ON payments (id) WHERE amount <= 0;"
        ),
        ["payments.refunds"]
    );
}

#[test]
fn the_message_names_the_predicate_and_the_table() {
    let constrainer: GenericConstrainer<ParserDB> = EmptyPartialIndex::default().into();
    let [(_, _, message)] = findings(
        &constrainer,
        "empty_partial_index",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));
         CREATE INDEX refunds ON payments (id) WHERE amount < 0;",
    )
    .try_into()
    .expect("one finding");
    assert!(message.contains("amount < 0"), "{message}");
    assert!(message.contains("payments"), "{message}");
}

#[test]
fn a_predicate_some_row_satisfies_is_clean() {
    for sql in [
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));
         CREATE INDEX large ON payments (id) WHERE amount > 1000;",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT);
         CREATE INDEX unpaid ON payments (id) WHERE amount IS NULL;",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT);
         CREATE INDEX every ON payments (id);",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_check_postgresql_has_not_validated_proves_nothing() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (id INT PRIMARY KEY, amount INT);
             ALTER TABLE payments ADD CONSTRAINT positive CHECK (amount > 0) NOT VALID;
             CREATE INDEX refunds ON payments (id) WHERE amount < 0;"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_table_whose_checks_admit_no_row_is_left_to_the_check_rules() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (
                 id INT PRIMARY KEY,
                 amount INT NOT NULL CHECK (amount > 0) CHECK (amount < 0)
             );
             CREATE INDEX refunds ON payments (id) WHERE amount < 0;"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_live_predicate_the_checks_contradict_is_reported() {
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));
         CREATE INDEX refunds ON payments (id) WHERE amount < 0;
         CREATE INDEX large ON payments (id) WHERE amount > 1000;",
    );
    let constrainer: GenericConstrainer<PgDieselDatabase> = EmptyPartialIndex::default().into();
    let objects: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    assert_eq!(objects, ["payments.refunds"]);
}
