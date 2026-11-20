//! Text columns a check holds to a JSON document, which carry the same
//! document a `json` or `jsonb` column would.

use sqlippy::prelude::*;
use sqlparser::dialect::{Dialect, PostgreSqlDialect, SQLiteDialect};

/// Objects of every `unbounded_text_column` finding over `sql` parsed in
/// `D`, sorted.
fn unbounded<D: Dialect + Default>(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = UnboundedTextColumn::default().into();
    let database = ParserDB::parse::<D>(sql).expect("schema parses");
    let mut objects: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    objects.sort();
    objects
}

#[test]
fn a_sqlite_text_column_held_to_json_valid_is_a_json_document() {
    let raised = unbounded::<SQLiteDialect>(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, payload TEXT NOT NULL CHECK (json_valid(payload))) STRICT;",
    );
    assert_eq!(raised, Vec::<String>::new());
}

#[test]
fn json_valid_holds_the_column_through_and_and_a_null_arm_of_or() {
    let raised = unbounded::<SQLiteDialect>(
        "CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            payload TEXT CHECK (payload <> '' AND JSON_VALID(payload, 6)),
            previous TEXT CHECK ((previous IS NULL) OR json_valid(previous))
        );",
    );
    assert_eq!(raised, Vec::<String>::new());
}

#[test]
fn json_valid_under_or_with_an_arm_admitting_other_text_does_not_hold_the_column() {
    let raised = unbounded::<SQLiteDialect>(
        "CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            payload TEXT CHECK (json_valid(payload) OR payload LIKE 'raw:%'),
            other TEXT CHECK (json_valid(payload) OR other IS NULL)
        );",
    );
    assert_eq!(raised, vec!["events.other", "events.payload"]);
}

#[test]
fn json_valid_of_another_column_leaves_the_column_unbounded() {
    let raised = unbounded::<SQLiteDialect>(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, payload TEXT, note TEXT, CHECK (json_valid(payload) AND note IS NOT NULL));",
    );
    assert_eq!(raised, vec!["events.note"]);
}

#[test]
fn a_postgres_text_column_held_to_is_json_is_a_json_document() {
    let raised = unbounded::<PostgreSqlDialect>(
        "CREATE TABLE events (
            id INT PRIMARY KEY,
            payload TEXT CHECK (payload IS JSON OBJECT),
            raw TEXT CHECK (raw IS NOT JSON)
        );",
    );
    assert_eq!(raised, vec!["events.raw"]);
}
