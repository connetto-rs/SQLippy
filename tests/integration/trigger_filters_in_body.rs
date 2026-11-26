//! Row filters a trigger function tests that `WHEN` could test instead.

use std::fmt::Write;

use sqlippy::prelude::*;
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};

/// Messages of every finding for `function` and its triggers on `notes`.
fn findings(function: &str, triggers: &[&str]) -> Vec<String> {
    let mut created = String::new();
    for (index, events) in triggers.iter().enumerate() {
        write!(
            created,
            "CREATE TRIGGER on_note_{index} {events} ON notes FOR EACH ROW EXECUTE FUNCTION on_note();"
        )
        .expect("writing to a String succeeds");
    }
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);
         CREATE TABLE audit (note_id INT);
         CREATE FUNCTION on_note() RETURNS trigger LANGUAGE plpgsql AS $$ {function} $$;
         {created}"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = TriggerFilterInBody::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Perf);
                violation.to_string()
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

/// A body returning when `condition` holds and auditing otherwise.
fn filtered(condition: &str) -> String {
    format!(
        "BEGIN IF {condition} THEN RETURN NULL; END IF; INSERT INTO audit VALUES (NEW.id); RETURN NULL; END"
    )
}

#[test]
fn the_suggested_when_is_the_exact_negation() {
    for (condition, when) in [
        (
            "OLD.body IS NOT DISTINCT FROM NEW.body",
            "WHEN (OLD.body IS DISTINCT FROM NEW.body)",
        ),
        (
            "OLD.body IS DISTINCT FROM NEW.body",
            "WHEN (OLD.body IS NOT DISTINCT FROM NEW.body)",
        ),
        ("NEW.body IS NULL", "WHEN (NEW.body IS NOT NULL)"),
        ("(NEW.body IS NULL)", "WHEN (NEW.body IS NOT NULL)"),
        ("NEW.body IS NOT NULL", "WHEN (NEW.body IS NULL)"),
        (
            "lower(NEW.body) = 'x'",
            "WHEN ((lower(NEW.body) = 'x') IS NOT TRUE)",
        ),
        (
            "OLD.body = NEW.body",
            "WHEN ((OLD.body = NEW.body) IS NOT TRUE)",
        ),
        (
            "(OLD.*) IS NOT DISTINCT FROM (NEW.*)",
            "WHEN ((OLD.*) IS DISTINCT FROM (NEW.*))",
        ),
    ] {
        let found = findings(&filtered(condition), &["AFTER UPDATE"]);
        assert_eq!(found.len(), 1, "{condition}: {found:?}");
        assert!(found[0].contains(when), "{when}: {found:?}");
    }
}

#[test]
fn every_trigger_on_the_function_is_reported_when_all_can_move_the_filter() {
    let found = findings(
        &filtered("NEW.body IS NULL"),
        &["AFTER INSERT", "AFTER UPDATE"],
    );
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn filters_when_cannot_take_are_not_reported() {
    for (function, triggers) in [
        (filtered("OLD.body IS NULL"), &["AFTER INSERT"][..]),
        (filtered("NEW.body IS NULL"), &["AFTER DELETE"][..]),
        (filtered("NEW.body IS NULL"), &["BEFORE UPDATE"][..]),
        (
            filtered("NEW.body IS NULL"),
            &["AFTER UPDATE", "BEFORE UPDATE"][..],
        ),
        (
            filtered("NEW.body = current_setting('app.mode')"),
            &["AFTER UPDATE"][..],
        ),
        (
            filtered("EXISTS (SELECT 1 FROM audit WHERE note_id = NEW.id)"),
            &["AFTER UPDATE"][..],
        ),
        (filtered("TG_OP = 'UPDATE'"), &["AFTER UPDATE"][..]),
        (filtered("no_such_function(NEW.body)"), &["AFTER UPDATE"][..]),
        (
            filtered("vault.public.lower(NEW.body) = 'x'"),
            &["AFTER UPDATE"][..],
        ),
        (
            filtered("on_note.new.body IS NOT DISTINCT FROM on_note.old.body"),
            &["AFTER UPDATE"][..],
        ),
        (
            "BEGIN IF NEW.body IS NULL THEN RETURN NULL; ELSIF NEW.id = 0 THEN RETURN NULL; END IF; INSERT INTO audit VALUES (NEW.id); RETURN NULL; END".to_owned(),
            &["AFTER UPDATE"][..],
        ),
        (
            "DECLARE seen INT := 0; BEGIN IF NEW.body IS NULL THEN RETURN NULL; END IF; INSERT INTO audit VALUES (NEW.id); RETURN NULL; END".to_owned(),
            &["AFTER UPDATE"][..],
        ),
        (
            "BEGIN INSERT INTO audit VALUES (NEW.id); IF NEW.body IS NULL THEN RETURN NULL; END IF; RETURN NULL; END".to_owned(),
            &["AFTER UPDATE"][..],
        ),
        (
            "BEGIN IF NEW.body IS NULL THEN INSERT INTO audit VALUES (0); RETURN NULL; END IF; RETURN NULL; END".to_owned(),
            &["AFTER UPDATE"][..],
        ),
    ] {
        assert!(findings(&function, triggers).is_empty(), "{function} {triggers:?}");
    }
}

/// Message and advice of every finding for the SQLite trigger `trigger`.
fn sqlite_findings(trigger: &str) -> Vec<(String, String)> {
    let database = ParserDB::parse::<SQLiteDialect>(&format!(
        "CREATE TABLE frames (id INTEGER PRIMARY KEY, owner TEXT);
         CREATE TABLE child (id INTEGER PRIMARY KEY, parent INTEGER);
         CREATE TABLE records (frame INTEGER, key INTEGER);
         {trigger}"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = TriggerFilterInBody::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Perf);
                (
                    violation.message().to_owned(),
                    violation.resolution().to_owned(),
                )
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

/// The SQLite trigger `record` after an insert on `child`, without `WHEN`,
/// running `body`.
fn record(body: &str) -> String {
    format!("CREATE TRIGGER record AFTER INSERT ON child FOR EACH ROW BEGIN {body} END;")
}

const RECORDING: &str = "INSERT INTO records (frame, key) SELECT (SELECT max(id) FROM frames), NEW.parent WHERE EXISTS (SELECT 1 FROM frames WHERE owner = 'body');";

#[test]
fn a_sqlite_guard_every_statement_repeats_is_reported() {
    assert_eq!(
        sqlite_findings(&record(RECORDING)),
        [(
            "Trigger 'record' on 'child' runs its body for every row, and every statement of the body tests `EXISTS (SELECT 1 FROM frames WHERE owner = 'body')`.".to_owned(),
            "Move `EXISTS (SELECT 1 FROM frames WHERE owner = 'body')` into a WHEN clause of trigger 'record', so a row that fails it skips the body.".to_owned(),
        )]
    );
}

#[test]
fn the_guard_is_the_conjuncts_every_statement_shares() {
    for (body, guard) in [
        (
            "INSERT INTO records (frame, key) SELECT 1, NEW.parent WHERE NEW.parent IS NOT NULL AND new.id > 0;
             UPDATE frames SET owner = 'x' WHERE id = NEW.parent AND (NEW.parent IS NOT NULL);
             DELETE FROM records WHERE NEW.parent IS NOT NULL AND key = NEW.id;",
            "NEW.parent IS NOT NULL",
        ),
        (
            "INSERT INTO records (frame, key) SELECT 1, NEW.parent WHERE NEW.parent > 0 AND NEW.id > 0;
             INSERT INTO records (frame, key) SELECT 2, NEW.parent WHERE NEW.id > 0 AND NEW.parent > 0;",
            "NEW.parent > 0 AND NEW.id > 0",
        ),
        (
            "INSERT INTO records (frame, key) SELECT 1, NEW.parent WHERE NOT EXISTS (SELECT 1 FROM records WHERE key = NEW.parent);",
            "NOT EXISTS (SELECT 1 FROM records WHERE key = NEW.parent)",
        ),
        (
            "SELECT RAISE(ABORT, 'orphan') WHERE NOT EXISTS (SELECT 1 FROM frames WHERE id = NEW.parent);",
            "NOT EXISTS (SELECT 1 FROM frames WHERE id = NEW.parent)",
        ),
    ] {
        let found = sqlite_findings(&record(body));
        assert_eq!(found.len(), 1, "{body}: {found:?}");
        assert!(found[0].0.ends_with(&format!("tests `{guard}`.")), "{body}: {found:?}");
    }
}

#[test]
fn sqlite_guards_that_cannot_move_are_not_reported() {
    for trigger in [
        // Already filtered by WHEN.
        "CREATE TRIGGER record AFTER INSERT ON child FOR EACH ROW WHEN NEW.parent > 0 BEGIN INSERT INTO records (frame, key) SELECT 1, NEW.parent WHERE NEW.parent > 0; END;".to_owned(),
        // A statement runs unguarded.
        record("INSERT INTO records (frame, key) SELECT 1, NEW.parent WHERE NEW.parent > 0; INSERT INTO records VALUES (2, NEW.parent);"),
        record("INSERT INTO records (frame, key) SELECT 1, NEW.parent WHERE NEW.parent > 0; INSERT INTO records (frame, key) SELECT 2, NEW.parent WHERE NEW.id > 0;"),
        // The guard reads the written rows.
        record("DELETE FROM records WHERE key = NEW.id;"),
        record("UPDATE frames SET owner = 'x' WHERE owner = 'body';"),
        record("INSERT INTO records (frame, key) SELECT f.id, NEW.parent FROM frames AS f WHERE f.owner = 'body';"),
        record("INSERT INTO records (frame, key) SELECT f.id, NEW.parent FROM frames AS f WHERE EXISTS (SELECT 1 FROM child AS c WHERE c.id = f.id);"),
        record("INSERT INTO records (frame, key) SELECT id, NEW.parent FROM frames WHERE EXISTS (SELECT 1 FROM child WHERE parent = owner);"),
        // The guard calls a function answering differently at each call.
        record("INSERT INTO records (frame, key) SELECT 1, NEW.parent WHERE random() > 0;"),
        record("INSERT INTO records (frame, key) SELECT 1, NEW.parent WHERE NEW.id > changes();"),
        // An earlier statement writes what the guard reads.
        record("INSERT INTO records (frame, key) SELECT 1, NEW.parent WHERE NOT EXISTS (SELECT 1 FROM records WHERE key = NEW.parent);
                INSERT INTO frames (owner) SELECT 'x' WHERE NOT EXISTS (SELECT 1 FROM records WHERE key = NEW.parent);"),
        // The statement returns a row whatever its WHERE admits.
        record("INSERT INTO records (frame, key) SELECT max(id), NEW.parent FROM frames WHERE NEW.parent > 0;"),
        record("INSERT INTO records (frame, key) SELECT group_concat(owner), NEW.parent FROM frames WHERE NEW.parent > 0;"),
        record("INSERT INTO records (frame, key) SELECT 1, NEW.parent FROM frames WHERE NEW.parent > 0 HAVING count(*) = 0;"),
    ] {
        assert!(sqlite_findings(&trigger).is_empty(), "{trigger}");
    }
}
