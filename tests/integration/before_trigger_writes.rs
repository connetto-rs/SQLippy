//! Row-level `BEFORE INSERT` triggers writing other tables.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for a trigger on `notes` running `body`.
fn findings(timing: &str, events: &str, body: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE TABLE notes (id INT PRIMARY KEY);
         CREATE TABLE audit (note_id INT);
         CREATE FUNCTION audit_note(note INT) RETURNS void LANGUAGE sql AS $$ INSERT INTO audit VALUES (note) $$;
         CREATE FUNCTION on_note() RETURNS trigger LANGUAGE plpgsql AS $$ {body} $$;
         CREATE TRIGGER on_note {timing} {events} ON notes FOR EACH ROW EXECUTE FUNCTION on_note();"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = BeforeTriggerWritesOtherTable::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Suspicious);
                violation.to_string()
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn writes_reaching_another_table_are_reported() {
    for write in [
        "INSERT INTO audit VALUES (NEW.id);",
        "UPDATE audit SET note_id = NEW.id;",
        "DELETE FROM audit WHERE note_id = NEW.id;",
        "PERFORM audit_note(NEW.id);",
        "IF NEW.id > 0 THEN INSERT INTO audit VALUES (NEW.id); END IF;",
    ] {
        let found = findings(
            "BEFORE",
            "INSERT OR UPDATE",
            &format!("BEGIN {write} RETURN NEW; END"),
        );
        assert_eq!(found.len(), 1, "{write}: {found:?}");
        assert!(found[0].contains("ON CONFLICT DO NOTHING"), "{found:?}");
    }
}

#[test]
fn routing_the_row_elsewhere_gets_its_own_message() {
    let found = findings(
        "BEFORE",
        "INSERT",
        "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("returns NULL"), "{found:?}");
}

#[test]
fn after_update_and_same_table_triggers_and_skipping_without_a_write_are_not_reported() {
    for (timing, events, body) in [
        (
            "AFTER",
            "INSERT",
            "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NEW; END",
        ),
        (
            "BEFORE",
            "UPDATE",
            "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NEW; END",
        ),
        (
            "BEFORE",
            "INSERT",
            "BEGIN NEW.id := NEW.id + 1; RETURN NEW; END",
        ),
        (
            "BEFORE",
            "INSERT",
            "BEGIN UPDATE notes SET id = id WHERE id = NEW.id; RETURN NEW; END",
        ),
        ("BEFORE", "INSERT", "BEGIN RETURN NULL; END"),
    ] {
        assert!(
            findings(timing, events, body).is_empty(),
            "{timing} {events} {body}"
        );
    }
}
