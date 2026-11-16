//! Primary keys strictly containing another unique key, observed through the
//! public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = SuperkeyPrimaryKey::default().into();
    findings(&constrainer, "superkey_primary_key", sql)
        .into_iter()
        .map(|(_, _, message)| message)
        .collect()
}

#[test]
fn a_primary_key_holding_a_unique_key_is_reported() {
    for sql in [
        "CREATE TABLE entries (id INT UNIQUE NOT NULL, kind TEXT, PRIMARY KEY (id, kind));",
        "CREATE TABLE entries (id INT, kind TEXT, PRIMARY KEY (kind, id), UNIQUE (id));",
        "CREATE TABLE entries (id INT, kind TEXT, PRIMARY KEY (id, kind));
         CREATE UNIQUE INDEX entries_id ON entries (id);",
        "CREATE TABLE entries (a INT, b INT, c INT, PRIMARY KEY (a, b, c), UNIQUE (b, a));",
        // A nullable unique column still pins rows once the key makes it NOT NULL.
        "CREATE TABLE entries (id INT UNIQUE NULLS DISTINCT, kind TEXT, PRIMARY KEY (id, kind));",
    ] {
        assert_eq!(reported(sql).len(), 1, "{sql}");
    }
}

#[test]
fn every_contained_key_is_named_in_one_finding() {
    let messages = reported(
        "CREATE TABLE entries (a INT UNIQUE, b INT, c INT, PRIMARY KEY (a, b, c), UNIQUE (a, b));",
    );
    assert_eq!(messages.len(), 1);
    assert!(
        messages[0].contains("(a)") && messages[0].contains("(a, b)"),
        "{}",
        messages[0]
    );
}

#[test]
fn a_primary_key_with_no_narrower_unique_key_passes() {
    for sql in [
        "CREATE TABLE entries (id INT PRIMARY KEY, kind TEXT UNIQUE);",
        "CREATE TABLE entries (id INT, kind TEXT, PRIMARY KEY (id, kind));",
        // A unique key reaching outside the primary key is a key of its own.
        "CREATE TABLE entries (id INT, kind TEXT, tag TEXT, PRIMARY KEY (id, kind), UNIQUE (id, tag));",
        // A partial unique index pins only the rows its predicate admits.
        "CREATE TABLE entries (id INT, kind TEXT, PRIMARY KEY (id, kind));
         CREATE UNIQUE INDEX entries_id ON entries (id) WHERE kind = 'note';",
        // An expression index does not make the column itself unique.
        "CREATE TABLE entries (id INT, kind TEXT, PRIMARY KEY (id, kind));
         CREATE UNIQUE INDEX entries_kind ON entries (lower(kind));",
        "CREATE TABLE entries (id INT, kind TEXT);",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}
