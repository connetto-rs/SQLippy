//! Tables holding one attribute in numbered columns.

use sqlippy::prelude::*;
use sqlparser::dialect::SQLiteDialect;

use crate::common::parse;

/// The table and stem of every `numbered_columns` finding on `database`.
fn reported(database: &ParserDB) -> Vec<(String, String)> {
    let constrainer: GenericConstrainer<ParserDB> = NumberedColumns::default().into();
    constrainer
        .diagnostics(database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.object().to_owned(),
                violation
                    .message()
                    .split('\'')
                    .nth(3)
                    .expect("the message names the stem")
                    .to_owned(),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

/// The stems reported on a table `t` declaring `columns`.
fn stems(columns: &str) -> Vec<String> {
    reported(&parse(&format!(
        "CREATE TABLE t (id INT PRIMARY KEY, {columns});"
    )))
    .into_iter()
    .map(|(_, stem)| stem)
    .collect()
}

#[test]
fn slots_numbered_from_one_are_reported_once_per_stem() {
    assert_eq!(
        stems("phone1 TEXT, phone2 TEXT, phone3 TEXT, fax1 TEXT, fax2 TEXT"),
        ["phone", "fax"]
    );
}

#[test]
fn an_underscore_before_the_number_and_letter_case_join_one_stem() {
    assert_eq!(
        stems("address_line_1 TEXT, address_line_2 TEXT"),
        ["address_line"]
    );
    assert_eq!(stems("phone1 TEXT, \"Phone_2\" TEXT"), ["phone"]);
}

#[test]
fn a_bare_stem_counts_as_a_slot() {
    assert_eq!(stems("email TEXT, email2 TEXT"), ["email"]);
    assert_eq!(stems("email TEXT, email_1 TEXT"), ["email"]);
    assert_eq!(stems("slot0 INT, slot1 INT"), ["slot"]);
}

#[test]
fn box_corners_are_a_known_false_positive() {
    assert_eq!(stems("x1 INT, x2 INT, y1 INT, y2 INT"), ["x", "y"]);
}

#[test]
fn numbers_that_do_not_run_from_the_first_slot_are_not_reported() {
    for columns in [
        "ipv4 INET, ipv6 INET",
        "sha1 BYTEA, sha256 BYTEA",
        "phone1 TEXT, phone3 TEXT",
        "email2 TEXT, email3 TEXT",
        "revenue_2020 INT, revenue_2021 INT",
        "phone1 TEXT",
        "email TEXT, email3 TEXT",
        "\"1\" INT, \"2\" INT",
    ] {
        assert_eq!(stems(columns), [] as [&str; 0], "{columns}");
    }
}

#[test]
fn the_finding_sits_on_the_table_and_names_every_slot() {
    let database = parse(
        "CREATE TABLE contacts (id INT PRIMARY KEY, email TEXT, phone TEXT, email2 TEXT, email3 TEXT);",
    );
    let constrainer: GenericConstrainer<ParserDB> = NumberedColumns::default().into();
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| error.to_string())
        .collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(
        messages[0].contains("'email', 'email2', 'email3'"),
        "{}",
        messages[0]
    );
}

#[test]
fn sqlite_is_judged() {
    let database = ParserDB::parse::<SQLiteDialect>(
        "CREATE TABLE contacts (id INTEGER PRIMARY KEY, phone1 TEXT, phone2 TEXT);",
    )
    .expect("schema parses");
    assert_eq!(
        reported(&database),
        [("contacts".to_owned(), "phone".to_owned())]
    );
}
