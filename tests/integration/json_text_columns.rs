//! Text columns a check holds to a JSON document, which carry the same
//! document a `json` or `jsonb` column would. A JSON document is never the
//! empty string, so such a column passes both `unbounded_text_column` and
//! `empty_text_allowed`.

use sqlippy::prelude::*;
use sqlparser::dialect::{Dialect, PostgreSqlDialect, SQLiteDialect};

/// Objects of every finding of `constrainer` over `sql` parsed in `D`,
/// sorted.
fn raised<D: Dialect + Default>(
    constrainer: &GenericConstrainer<ParserDB>,
    sql: &str,
) -> Vec<String> {
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

/// Asserts that `unbounded_text_column` and `empty_text_allowed` each raise
/// exactly `expected` over `sql` parsed in `D`.
fn assert_raised<D: Dialect + Default>(sql: &str, expected: &[&str]) {
    let unbounded: GenericConstrainer<ParserDB> = UnboundedTextColumn::default().into();
    let empty: GenericConstrainer<ParserDB> = EmptyTextAllowed::default().into();
    assert_eq!(
        raised::<D>(&unbounded, sql),
        expected,
        "unbounded_text_column"
    );
    assert_eq!(raised::<D>(&empty, sql), expected, "empty_text_allowed");
}

#[test]
fn a_sqlite_text_column_held_to_json_valid_is_a_json_document() {
    assert_raised::<SQLiteDialect>(
        "CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            payload TEXT NOT NULL CHECK (json_valid(payload)),
            previous TEXT CHECK (json_valid(previous))
        ) STRICT;",
        &[],
    );
}

#[test]
fn json_valid_holds_the_column_through_and_and_a_null_arm_of_or() {
    assert_raised::<SQLiteDialect>(
        "CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            payload TEXT CHECK (payload <> 'null' AND JSON_VALID(payload, 6)),
            previous TEXT CHECK ((previous IS NULL) OR json_valid(previous))
        );",
        &[],
    );
}

#[test]
fn json_valid_under_or_with_an_arm_admitting_other_text_does_not_hold_the_column() {
    assert_raised::<SQLiteDialect>(
        "CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            payload TEXT CHECK (json_valid(payload) OR payload LIKE 'raw:%'),
            other TEXT CHECK (json_valid(payload) OR other IS NULL)
        );",
        &["events.other", "events.payload"],
    );
}

#[test]
fn json_valid_of_another_column_leaves_the_column_unbounded() {
    assert_raised::<SQLiteDialect>(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, payload TEXT, note TEXT, CHECK (json_valid(payload) AND note IS NOT NULL));",
        &["events.note"],
    );
}

#[test]
fn a_reference_to_a_json_document_is_a_json_document() {
    assert_raised::<SQLiteDialect>(
        "CREATE TABLE documents (body TEXT PRIMARY KEY CHECK (json_valid(body))) STRICT;
         CREATE TABLE copies (id INTEGER PRIMARY KEY, body TEXT REFERENCES documents (body)) STRICT;",
        &[],
    );
}

#[test]
fn a_postgres_text_column_held_to_is_json_is_a_json_document() {
    assert_raised::<PostgreSqlDialect>(
        "CREATE TABLE events (
            id INT PRIMARY KEY,
            payload TEXT CHECK (payload IS JSON OBJECT),
            raw TEXT CHECK (raw IS NOT JSON)
        );",
        &["events.raw"],
    );
    assert_raised::<PostgreSqlDialect>(
        "CREATE TABLE events (
             id INT PRIMARY KEY,
             payload TEXT CHECK (payload IS JSON OBJECT) NOT ENFORCED,
             raw TEXT CHECK (raw IS NOT JSON)
         );",
        &["events.payload", "events.raw"],
    );
}
