//! Check constraints that are never true but may be `NULL`, observed through
//! the public constrainer API.

use crate::rule_findings::findings;
use pg_diesel::PgDieselDatabase;
use sqlippy::prelude::*;

fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = NullOnlyCheck::default().into();
    findings(&constrainer, "null_only_check", sql)
        .into_iter()
        .map(|(_, object, _)| object)
        .collect()
}

#[test]
fn a_check_only_a_null_column_passes_is_reported() {
    for sql in [
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 10 AND amount < 5));",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT, CHECK (amount <> amount));",
        "CREATE TABLE payments (id INT PRIMARY KEY, note TEXT, CHECK (length(note) < 0));",
    ] {
        assert_eq!(reported(sql), ["payments"], "{sql}");
    }
}

#[test]
fn the_message_names_the_check_and_the_columns_it_reads() {
    let constrainer: GenericConstrainer<ParserDB> = NullOnlyCheck::default().into();
    let [(_, _, message)] = findings(
        &constrainer,
        "null_only_check",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 10 AND amount < 5));",
    )
    .try_into()
    .expect("one finding");
    assert!(message.contains("amount > 10 AND amount < 5"), "{message}");
    assert!(message.contains("payments"), "{message}");
    assert!(message.contains("NULL"), "{message}");
}

#[test]
fn a_check_some_value_satisfies_is_clean() {
    for sql in [
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 0));",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount IS NULL));",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 5 OR amount <= 5));",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_check_admitting_no_row_is_left_to_unsatisfiable_check() {
    for sql in [
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT NOT NULL CHECK (amount > 10 AND amount < 5));",
        "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (false));",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_check_that_is_always_null_is_left_to_tautological_check() {
    assert_eq!(
        reported("CREATE TABLE payments (id INT PRIMARY KEY, amount INT, CHECK (NULL));"),
        Vec::<String>::new()
    );
}

#[test]
fn each_null_only_check_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (
                 id INT PRIMARY KEY,
                 amount INT CHECK (amount > 10 AND amount < 5),
                 fee INT CHECK (fee < 0 AND fee > 0),
                 CHECK (amount > 0)
             );"
        ),
        ["payments", "payments"]
    );
}

#[test]
fn a_live_null_only_check_is_reported() {
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        "CREATE TABLE payments (
             id INT PRIMARY KEY,
             amount INT CHECK (amount > 10 AND amount < 5),
             fee INT CHECK (fee > 0)
         );",
    );
    let constrainer: GenericConstrainer<PgDieselDatabase> = NullOnlyCheck::default().into();
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    let [message] = &messages[..] else {
        panic!("one finding expected, got {messages:?}")
    };
    assert!(message.contains("amount"), "{message}");
}
