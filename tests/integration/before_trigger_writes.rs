//! Row-level `BEFORE INSERT` triggers writing other tables.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for a trigger on `notes` running `body`.
fn findings(timing: &str, events: &str, body: &str) -> Vec<String> {
    diagnostics(&format!(
        "CREATE TABLE notes (id INT PRIMARY KEY);
         CREATE TABLE audit (note_id INT);
         CREATE FUNCTION audit_note(note INT) RETURNS void LANGUAGE sql AS $$ INSERT INTO audit VALUES (note) $$;
         CREATE FUNCTION purge_note(note INT) RETURNS void LANGUAGE plpgsql AS $$ BEGIN DELETE FROM audit WHERE note_id = note; END $$;
         CREATE FUNCTION move_note(note INT) RETURNS void LANGUAGE plpgsql AS $$ BEGIN UPDATE audit SET note_id = note; END $$;
         CREATE FUNCTION lock_note(note INT) RETURNS void LANGUAGE plpgsql AS $$ BEGIN PERFORM 1 FROM audit WHERE note_id = note FOR UPDATE; END $$;
         CREATE FUNCTION on_note() RETURNS trigger LANGUAGE plpgsql AS $$ {body} $$;
         CREATE TRIGGER on_note {timing} {events} ON notes FOR EACH ROW EXECUTE FUNCTION on_note();"
    ))
}

/// Messages of every finding for the schema `sql`.
fn diagnostics(sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
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
        "PERFORM purge_note(NEW.id);",
        "PERFORM move_note(NEW.id);",
        "MERGE INTO audit USING (SELECT NEW.id AS id) AS source ON audit.note_id = source.id WHEN NOT MATCHED THEN INSERT VALUES (source.id);",
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
    // A `CASE` without `ELSE` ends every other path with `case_not_found`.
    for body in [
        "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        "BEGIN INSERT INTO audit VALUES (NEW.id); CASE WHEN NEW.id > 0 THEN RETURN NULL; END CASE; RETURN NEW; END",
    ] {
        let found = findings("BEFORE", "INSERT", body);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("writes the row to another table and returns NULL"),
            "{body}: {found:?}"
        );
    }
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
        (
            "BEFORE",
            "INSERT",
            "BEGIN PERFORM lock_note(NEW.id); RETURN NEW; END",
        ),
    ] {
        assert!(
            findings(timing, events, body).is_empty(),
            "{timing} {events} {body}"
        );
    }
}

#[test]
fn a_trigger_function_in_another_language_is_not_read() {
    let found = diagnostics(
        "CREATE TABLE notes (id INT PRIMARY KEY);
         CREATE FUNCTION on_note() RETURNS trigger LANGUAGE c AS 'library', 'on_note';
         CREATE TRIGGER on_note BEFORE INSERT ON notes FOR EACH ROW EXECUTE FUNCTION on_note();",
    );
    assert_eq!(found, Vec::<String>::new());
}
