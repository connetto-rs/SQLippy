//! Row filters a trigger function tests that `WHEN` could test instead.

use std::fmt::Write;

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

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
