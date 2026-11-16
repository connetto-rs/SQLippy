//! Tables differing only in the tables their foreign keys reference,
//! observed through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

const SUBJECTS: &str = "CREATE TABLE teams (id INT PRIMARY KEY);
    CREATE TABLE people (id INT PRIMARY KEY);
    CREATE TABLE bots (id INT PRIMARY KEY);";

fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = ParallelTables::default().into();
    findings(
        &constrainer,
        "parallel_tables",
        &format!("{SUBJECTS} {sql}"),
    )
    .into_iter()
    .map(|(_, object, _)| object)
    .collect()
}

#[test]
fn tables_differing_only_in_a_reference_target_are_reported_once() {
    assert_eq!(
        reported(
            "CREATE TABLE team_grants (id INT PRIMARY KEY, subject_id INT NOT NULL REFERENCES teams (id), permission TEXT NOT NULL CHECK (permission <> ''));
             CREATE TABLE person_grants (id INT PRIMARY KEY, subject_id INT NOT NULL REFERENCES people (id), permission TEXT NOT NULL CHECK (permission <> ''));"
        )
        .len(),
        1
    );
}

#[test]
fn each_later_parallel_table_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE team_grants (subject_id INT REFERENCES teams (id), permission TEXT);
             CREATE TABLE person_grants (subject_id INT REFERENCES people (id), permission TEXT);
             CREATE TABLE bot_grants (subject_id INT REFERENCES bots (id), permission TEXT);"
        )
        .len(),
        2
    );
}

#[test]
fn serial_columns_on_their_own_sequences_do_not_hide_parallel_tables() {
    for sql in [
        "CREATE TABLE team_grants (id SERIAL PRIMARY KEY, subject_id INT REFERENCES teams (id));
         CREATE TABLE person_grants (id SERIAL PRIMARY KEY, subject_id INT REFERENCES people (id));",
        "CREATE TABLE team_grants (id BIGSERIAL PRIMARY KEY, subject_id INT REFERENCES teams (id));
         CREATE TABLE person_grants (id BIGSERIAL PRIMARY KEY, subject_id INT REFERENCES people (id));",
    ] {
        assert_eq!(reported(sql).len(), 1, "{sql}");
    }
}

#[test]
fn tables_differing_in_anything_else_pass() {
    for sql in [
        // Same targets: duplicates, not parallels.
        "CREATE TABLE team_grants (subject_id INT REFERENCES teams (id), permission TEXT);
         CREATE TABLE team_grants_copy (subject_id INT REFERENCES teams (id), permission TEXT);",
        // No foreign key at all.
        "CREATE TABLE a (id INT PRIMARY KEY);
         CREATE TABLE b (id INT PRIMARY KEY);",
        // A column type.
        "CREATE TABLE team_grants (subject_id INT REFERENCES teams (id), permission TEXT);
         CREATE TABLE person_grants (subject_id INT REFERENCES people (id), permission VARCHAR(20));",
        // A column name.
        "CREATE TABLE team_grants (subject_id INT REFERENCES teams (id), permission TEXT);
         CREATE TABLE person_grants (subject_id INT REFERENCES people (id), privilege TEXT);",
        // Nullability.
        "CREATE TABLE team_grants (subject_id INT REFERENCES teams (id), permission TEXT NOT NULL);
         CREATE TABLE person_grants (subject_id INT REFERENCES people (id), permission TEXT);",
        // A check.
        "CREATE TABLE team_grants (subject_id INT REFERENCES teams (id), permission TEXT CHECK (permission <> ''));
         CREATE TABLE person_grants (subject_id INT REFERENCES people (id), permission TEXT);",
        // A unique key.
        "CREATE TABLE team_grants (subject_id INT REFERENCES teams (id), permission TEXT, UNIQUE (subject_id, permission));
         CREATE TABLE person_grants (subject_id INT REFERENCES people (id), permission TEXT);",
        // A referential action.
        "CREATE TABLE team_grants (subject_id INT REFERENCES teams (id) ON DELETE CASCADE, permission TEXT);
         CREATE TABLE person_grants (subject_id INT REFERENCES people (id), permission TEXT);",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}
