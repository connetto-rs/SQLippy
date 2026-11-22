//! Unique keys that tell a client role whether a row it cannot read exists,
//! observed through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

/// Object and message of every finding on `sql`.
fn reported(sql: &str) -> Vec<(String, String)> {
    let mut constrainer: GenericConstrainer<ParserDB> = UniqueKeyExistenceOracle::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("app"));
    findings(
        &constrainer,
        "unique_key_existence_oracle",
        &format!("CREATE ROLE app; {sql}"),
    )
    .into_iter()
    .map(|(_, object, message)| (object, message))
    .collect()
}

/// Objects of every finding on `sql`.
fn objects(sql: &str) -> Vec<String> {
    reported(sql)
        .into_iter()
        .map(|(object, _)| object)
        .collect()
}

const NOTES: &str = "CREATE TABLE notes (id INT CONSTRAINT notes_pkey PRIMARY KEY, body TEXT,
        slug TEXT DEFAULT 'x', CONSTRAINT notes_slug UNIQUE (slug));
    ALTER TABLE notes ENABLE ROW LEVEL SECURITY;";

#[test]
fn a_key_the_writer_inserts_over_rows_it_cannot_read_is_reported() {
    let findings = reported(&format!(
        "{NOTES} CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (true);
         GRANT INSERT (id, body), SELECT ON notes TO app;"
    ));
    assert_eq!(findings.len(), 1, "{findings:?}");
    let (object, message) = &findings[0];
    assert_eq!(object, "notes.notes_pkey");
    assert!(message.contains("'app'"), "{message}");
    assert!(message.contains("INSERT"), "{message}");
}

#[test]
fn an_insert_only_table_hides_every_row() {
    assert_eq!(
        objects(
            "CREATE TABLE events (id INT CONSTRAINT events_pkey PRIMARY KEY);
             GRANT INSERT ON events TO app;"
        ),
        ["events.events_pkey"]
    );
    assert_eq!(
        objects(
            "CREATE TABLE events (id INT CONSTRAINT events_pkey PRIMARY KEY);
             GRANT INSERT, SELECT ON events TO app;"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        objects(
            "CREATE TABLE events (id INT CONSTRAINT events_pkey PRIMARY KEY, body TEXT);
             GRANT INSERT, SELECT (body) ON events TO app;"
        ),
        ["events.events_pkey"]
    );
}

#[test]
fn a_key_the_writer_cannot_choose_is_clean() {
    assert_eq!(
        objects(&format!(
            "{NOTES} CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (true);
             GRANT INSERT (body) ON notes TO app;"
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        objects(&format!(
            "{NOTES} GRANT INSERT ON notes TO app;
             CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (false);"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn updating_a_key_column_reaches_the_key() {
    assert_eq!(
        objects(&format!(
            "{NOTES} CREATE POLICY notes_update ON notes FOR UPDATE TO app USING (true);
             GRANT UPDATE (slug) ON notes TO app;"
        )),
        ["notes.notes_slug"]
    );
}

#[test]
fn a_key_confined_to_rows_the_writer_reads_is_clean() {
    for (check, expected) in [
        ("id IN (SELECT readable())", vec![]),
        ("id IN (SELECT readable()) OR id IS NULL", vec![]),
        ("id > 0", vec!["notes.notes_pkey"]),
    ] {
        assert_eq!(
            objects(&format!(
                "CREATE FUNCTION readable() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;
                 {NOTES}
                 CREATE POLICY notes_read ON notes FOR SELECT TO app USING (id IN (SELECT readable()));
                 CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK ({check});
                 GRANT INSERT (id, body), SELECT ON notes TO app;"
            )),
            expected,
            "{check}"
        );
    }
}

#[test]
fn a_null_key_a_unique_key_compares_reaches_the_key() {
    for (nulls, expected) in [("", vec![]), ("NULLS NOT DISTINCT", vec!["tags.tags_slug"])] {
        assert_eq!(
            objects(&format!(
                "CREATE FUNCTION readable() RETURNS SETOF TEXT LANGUAGE sql STABLE AS $$ SELECT 'a' $$;
                 CREATE TABLE tags (slug TEXT, CONSTRAINT tags_slug UNIQUE {nulls} (slug));
                 ALTER TABLE tags ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY tags_read ON tags FOR SELECT TO app USING (slug IN (SELECT readable()));
                 CREATE POLICY tags_write ON tags FOR INSERT TO app
                   WITH CHECK (slug IN (SELECT readable()) OR slug IS NULL);
                 GRANT INSERT, SELECT ON tags TO app;"
            )),
            expected,
            "{nulls}"
        );
    }
}
