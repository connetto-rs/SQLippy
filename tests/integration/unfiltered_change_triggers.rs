//! `AFTER UPDATE` triggers writing another table for unchanged rows.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for a trigger declared as `trigger` running
/// `body`.
fn findings(trigger: &str, body: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);
         CREATE TABLE audit (note_id INT);
         CREATE FUNCTION audit_note(note INT) RETURNS void LANGUAGE sql AS $$ INSERT INTO audit VALUES (note) $$;
         CREATE FUNCTION on_note() RETURNS trigger LANGUAGE plpgsql AS $$ {body} $$;
         CREATE TRIGGER on_note {trigger} EXECUTE FUNCTION on_note();"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = UnfilteredChangeTrigger::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Pedantic);
                violation.to_string()
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

const ROW_UPDATE: &str = "AFTER UPDATE ON notes FOR EACH ROW";

#[test]
fn unguarded_writes_to_another_table_are_reported() {
    for (trigger, body) in [
        (
            ROW_UPDATE,
            "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        ),
        (
            "AFTER INSERT OR UPDATE ON notes FOR EACH ROW",
            "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        ),
        (
            "AFTER UPDATE OF body ON notes FOR EACH ROW",
            "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        ),
        (
            ROW_UPDATE,
            "BEGIN PERFORM audit_note(NEW.id); RETURN NULL; END",
        ),
        (
            ROW_UPDATE,
            "BEGIN INSERT INTO audit VALUES (NEW.id); IF OLD.body IS DISTINCT FROM NEW.body THEN RETURN NULL; END IF; RETURN NULL; END",
        ),
        (
            ROW_UPDATE,
            "BEGIN IF NEW.id > 0 THEN INSERT INTO audit VALUES (NEW.id); END IF; RETURN NULL; END",
        ),
    ] {
        let found = findings(trigger, body);
        assert_eq!(found.len(), 1, "{trigger} {body}: {found:?}");
        assert!(found[0].contains("changed no value"), "{found:?}");
    }
}

#[test]
fn guarded_statement_level_and_non_writing_triggers_are_not_reported() {
    for (trigger, body) in [
        (
            "AFTER UPDATE ON notes FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)",
            "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        ),
        (
            "AFTER UPDATE ON notes FOR EACH ROW WHEN (OLD.body IS DISTINCT FROM NEW.body)",
            "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        ),
        (
            ROW_UPDATE,
            "BEGIN IF OLD.body IS DISTINCT FROM NEW.body THEN INSERT INTO audit VALUES (NEW.id); END IF; RETURN NULL; END",
        ),
        (
            ROW_UPDATE,
            "BEGIN IF OLD IS NOT DISTINCT FROM NEW THEN RETURN NULL; END IF; INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        ),
        (
            ROW_UPDATE,
            "BEGIN CASE WHEN OLD.body <> NEW.body THEN INSERT INTO audit VALUES (NEW.id); ELSE NULL; END CASE; RETURN NULL; END",
        ),
        (
            "AFTER UPDATE ON notes FOR EACH STATEMENT",
            "BEGIN INSERT INTO audit VALUES (0); RETURN NULL; END",
        ),
        (
            "BEFORE UPDATE ON notes FOR EACH ROW",
            "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NEW; END",
        ),
        (
            "AFTER INSERT ON notes FOR EACH ROW",
            "BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        ),
        (
            ROW_UPDATE,
            "BEGIN UPDATE notes SET body = body WHERE id = -1; RETURN NULL; END",
        ),
    ] {
        assert_eq!(
            findings(trigger, body),
            Vec::<String>::new(),
            "{trigger} {body}"
        );
    }
}
