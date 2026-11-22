//! Partial indexes whose predicate every row of the table satisfies,
//! observed through the public constrainer API.

use crate::rule_findings::findings;
use pg_diesel::PgDieselDatabase;
use sqlippy::prelude::*;

fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = NeedlessIndexPredicate::default().into();
    findings(&constrainer, "needless_index_predicate", sql)
        .into_iter()
        .map(|(_, object, _)| object)
        .collect()
}

#[test]
fn a_predicate_the_checks_guarantee_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL CHECK (amount > 0));
             CREATE INDEX paid ON payments (id) WHERE amount > -5;"
        ),
        ["payments.paid"]
    );
}

#[test]
fn a_predicate_not_null_guarantees_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL);
             CREATE UNIQUE INDEX present ON payments (id) WHERE amount IS NOT NULL;"
        ),
        ["payments.present"]
    );
}

#[test]
fn the_message_names_the_predicate_and_the_table() {
    let constrainer: GenericConstrainer<ParserDB> = NeedlessIndexPredicate::default().into();
    let [(_, _, message)] = findings(
        &constrainer,
        "needless_index_predicate",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL CHECK (amount > 0));
         CREATE INDEX paid ON payments (id) WHERE amount > -5;",
    )
    .try_into()
    .expect("one finding");
    assert!(message.contains("amount > -5"), "{message}");
    assert!(message.contains("payments"), "{message}");
}

#[test]
fn a_predicate_that_leaves_out_null_rows_is_clean() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));
             CREATE INDEX paid ON payments (id) WHERE amount > 0;"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_predicate_some_row_fails_is_clean() {
    for sql in [
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL CHECK (amount > 0));
         CREATE INDEX large ON payments (id) WHERE amount > 1000;",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL);
         CREATE INDEX every ON payments (id);",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_check_postgresql_has_not_validated_proves_nothing() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL);
             ALTER TABLE payments ADD CONSTRAINT positive CHECK (amount > 0) NOT VALID;
             CREATE INDEX paid ON payments (id) WHERE amount > 0;"
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
             CREATE INDEX paid ON payments (id) WHERE amount > 0;"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_live_predicate_the_checks_guarantee_is_reported() {
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL CHECK (amount > 0));
         CREATE INDEX paid ON payments (id) WHERE amount > -5;
         CREATE INDEX large ON payments (id) WHERE amount > 1000;",
    );
    let constrainer: GenericConstrainer<PgDieselDatabase> =
        NeedlessIndexPredicate::default().into();
    let objects: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    assert_eq!(objects, ["payments.paid"]);
}
