//! Triggers repeating the authorization a row level security policy makes.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// The schema `sql` after a table of notes and an ownership helper.
fn schema(sql: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE TABLE notes (id INT PRIMARY KEY, owner_id UUID NOT NULL, body TEXT NOT NULL);
         CREATE FUNCTION owns_note(subject UUID) RETURNS BOOLEAN LANGUAGE sql STABLE AS
           $$ SELECT subject = current_setting('app.user_id')::uuid $$;
         {sql}"
    ))
    .expect("schema parses")
}

/// Messages of every finding for `sql` after a table of notes and an
/// ownership helper.
fn findings(sql: &str) -> Vec<String> {
    let database = schema(sql);
    let constrainer: GenericConstrainer<ParserDB> = AuthorizationInTrigger::default().into();
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

/// A trigger on `events` running a function whose body checks `check`.
fn trigger(events: &str, check: &str) -> String {
    format!(
        "CREATE FUNCTION check_note() RETURNS trigger LANGUAGE plpgsql AS
           $$ BEGIN IF NOT {check} THEN RAISE EXCEPTION 'rejected'; END IF; RETURN NEW; END $$;
         CREATE TRIGGER check_note BEFORE {events} ON notes FOR EACH ROW EXECUTE FUNCTION check_note();"
    )
}

const SECURED: &str = "ALTER TABLE notes ENABLE ROW LEVEL SECURITY;";

#[test]
fn a_trigger_calling_the_policy_helper_for_a_covered_command_is_reported() {
    for (policy, events) in [
        ("FOR INSERT WITH CHECK (owns_note(owner_id))", "INSERT"),
        ("FOR UPDATE USING (owns_note(owner_id))", "UPDATE"),
        (
            "FOR UPDATE USING (true) WITH CHECK (owns_note(owner_id))",
            "UPDATE OR DELETE",
        ),
        ("FOR ALL USING (owns_note(owner_id))", "DELETE"),
    ] {
        let found = findings(&format!(
            "{SECURED} CREATE POLICY guard ON notes {policy}; {}",
            trigger(events, "owns_note(NEW.owner_id)")
        ));
        assert_eq!(found.len(), 1, "{policy} / {events}: {found:?}");
        assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
    }
}

#[test]
fn a_helper_reached_through_another_function_is_reported() {
    let found = findings(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE FUNCTION may_write(subject UUID) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$ SELECT owns_note(subject) $$;
         {}",
        trigger("INSERT", "may_write(NEW.owner_id)")
    ));
    assert_eq!(found.len(), 1, "{found:?}");
}

/// A `BEFORE` trigger on `events` running a function with the declaration
/// section `declared` whose body runs `body`.
fn raising(events: &str, declared: &str, body: &str) -> String {
    format!(
        "CREATE FUNCTION check_note() RETURNS trigger LANGUAGE plpgsql AS
           $$ {declared} BEGIN {body} RETURN NEW; END $$;
         CREATE TRIGGER check_note BEFORE {events} ON notes FOR EACH ROW EXECUTE FUNCTION check_note();"
    )
}

#[test]
fn raising_insufficient_privilege_for_a_covered_command_is_reported() {
    for body in [
        "IF NEW.owner_id IS NULL THEN RAISE insufficient_privilege; END IF;",
        "IF NEW.owner_id IS NULL THEN RAISE EXCEPTION SQLSTATE '42501'; END IF;",
        "IF NEW.owner_id IS NULL THEN RAISE EXCEPTION 'not yours' USING ERRCODE = 'insufficient_privilege'; END IF;",
        "IF NEW.owner_id IS NULL THEN RAISE EXCEPTION 'not yours' USING ERRCODE = '42501'; END IF;",
        "BEGIN PERFORM 1 / 0; EXCEPTION WHEN division_by_zero THEN RAISE insufficient_privilege; END;",
        "CASE WHEN NEW.owner_id IS NOT NULL THEN NULL; ELSE RAISE insufficient_privilege; END CASE;",
        "FOR i IN 1..1 LOOP IF NEW.owner_id IS NULL THEN RAISE insufficient_privilege; END IF; END LOOP;",
    ] {
        let found = findings(&format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owner_id IS NOT NULL); {}",
            raising("INSERT", "", body)
        ));
        assert_eq!(found.len(), 1, "{body}: {found:?}");
        assert!(
            found[0].contains("raises insufficient_privilege"),
            "{found:?}"
        );
    }
}

#[test]
fn other_errors_and_uncovered_commands_are_not_reported() {
    for sql in [
        format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owner_id IS NOT NULL); {}",
            raising(
                "INSERT",
                "",
                "IF NEW.body = '' THEN RAISE EXCEPTION 'empty' USING ERRCODE = 'check_violation'; END IF;"
            )
        ),
        format!(
            "{SECURED} CREATE POLICY guard ON notes FOR SELECT USING (owner_id IS NOT NULL); {}",
            raising("INSERT", "", "RAISE insufficient_privilege;")
        ),
        format!(
            "CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owner_id IS NOT NULL); {}",
            raising("INSERT", "", "RAISE insufficient_privilege;")
        ),
        format!(
            "{SECURED} CREATE POLICY guard ON notes USING (owner_id IS NOT NULL);
             CREATE FUNCTION check_truncate() RETURNS trigger LANGUAGE plpgsql AS
               $$ BEGIN RAISE insufficient_privilege; END $$;
             CREATE TRIGGER check_truncate BEFORE TRUNCATE ON notes FOR EACH STATEMENT EXECUTE FUNCTION check_truncate();"
        ),
    ] {
        assert_eq!(findings(&sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn other_commands_tables_without_row_security_and_other_checks_are_not_reported() {
    for sql in [
        format!(
            "{SECURED} CREATE POLICY guard ON notes FOR SELECT USING (owns_note(owner_id)); {}",
            trigger("INSERT", "owns_note(NEW.owner_id)")
        ),
        format!(
            "CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id)); {}",
            trigger("INSERT", "owns_note(NEW.owner_id)")
        ),
        format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id)); {}",
            trigger("INSERT", "length(NEW.body) > 0")
        ),
    ] {
        assert!(findings(&sql).is_empty(), "{sql}");
    }
}

#[test]
fn a_policy_helper_that_cannot_be_resolved_is_a_lookup_failure() {
    let database = schema(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (vault.public.owns_note(owner_id)); {}",
        trigger("INSERT", "owns_note(NEW.owner_id)")
    ));
    let constrainer: GenericConstrainer<ParserDB> = AuthorizationInTrigger::default().into();
    assert!(matches!(
        constrainer.validate_schema(&database),
        Err(Error::Lookup(_))
    ));
}

/// A `BEFORE` trigger on `events` running a function with the declaration
/// section `declared` whose body runs `body`, after an audit table and a
/// function storing one row of it.
fn auditing(events: &str, declared: &str, body: &str) -> String {
    format!(
        "CREATE TABLE note_events (id INT, own BOOLEAN);
         CREATE FUNCTION record_own(own BOOLEAN) RETURNS VOID LANGUAGE sql AS
           $$ INSERT INTO note_events (id, own) VALUES (NEW.id, own) $$;
         CREATE FUNCTION check_note() RETURNS trigger LANGUAGE plpgsql AS
           $$ {declared} BEGIN {body} RETURN NEW; END $$;
         CREATE TRIGGER check_note BEFORE {events} ON notes FOR EACH ROW EXECUTE FUNCTION check_note();"
    )
}

#[test]
fn a_helper_stored_as_a_value_is_not_reported() {
    for (declared, body) in [
        // The result of the call is stored in the row the trigger inserts.
        (
            "",
            "INSERT INTO note_events (id, own) VALUES (NEW.id, owns_note(NEW.owner_id));",
        ),
        // ...assigned to a variable the body never tests.
        ("DECLARE own BOOLEAN;", "own := owns_note(NEW.owner_id);"),
        // ...passed as a value to a function that stores it.
        ("", "PERFORM record_own(owns_note(NEW.owner_id));"),
        // ...set as the value a change assigns.
        (
            "",
            "UPDATE notes SET body = owns_note(NEW.owner_id) WHERE id = NEW.id;",
        ),
    ] {
        let found = findings(&format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id)); {}",
            auditing("INSERT", declared, body)
        ));
        assert_eq!(found.len(), 0, "{body}: {found:?}");
    }
}

#[test]
fn a_helper_reaching_a_condition_of_the_body_is_reported() {
    for (declared, body) in [
        // An `ELSIF` condition.
        (
            "",
            "IF NEW.id > 0 THEN RETURN NEW; ELSIF owns_note(NEW.owner_id) THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A `CASE` condition.
        (
            "",
            "CASE WHEN owns_note(NEW.owner_id) THEN RETURN NEW; ELSE RAISE EXCEPTION 'no'; END CASE;",
        ),
        // A `WHILE` condition.
        (
            "",
            "WHILE owns_note(NEW.owner_id) LOOP PERFORM 1; END LOOP;",
        ),
        // An `EXIT WHEN` condition.
        (
            "",
            "LOOP PERFORM 1; EXIT WHEN owns_note(NEW.owner_id); END LOOP;",
        ),
        // An `ASSERT` condition.
        ("", "ASSERT owns_note(NEW.owner_id), 'no';"),
        // The `WHERE` of a query the body runs.
        (
            "",
            "PERFORM 1 FROM note_events WHERE own = owns_note(NEW.owner_id);",
        ),
        // The `HAVING` of a query the body runs.
        (
            "",
            "PERFORM count(*) FROM note_events GROUP BY own HAVING owns_note(NEW.owner_id);",
        ),
        // The `ON` of a join the body runs.
        (
            "",
            "PERFORM 1 FROM note_events JOIN notes ON note_events.own = owns_note(notes.owner_id);",
        ),
        // A variable the body declares, assigns the result to, then tests in a condition.
        (
            "DECLARE own BOOLEAN;",
            "own := owns_note(NEW.owner_id); IF own THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A function the body calls, deciding with the result in its own condition.
        ("", "PERFORM guard_note();"),
    ] {
        let found = findings(&format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
             CREATE TABLE note_events (id INT, own BOOLEAN);
             CREATE FUNCTION guard_note() RETURNS VOID LANGUAGE plpgsql AS
               $$ BEGIN IF NOT owns_note(NEW.owner_id) THEN RAISE EXCEPTION 'no'; END IF; END $$;
             {}",
            raising("INSERT", declared, body)
        ));
        assert_eq!(found.len(), 1, "{body}: {found:?}");
        assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
    }
}

#[test]
fn a_helper_in_the_trigger_when_clause_is_reported() {
    let found = findings(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE FUNCTION check_note() RETURNS trigger LANGUAGE plpgsql AS
           $$ BEGIN PERFORM 1; RETURN NEW; END $$;
         CREATE TRIGGER check_note BEFORE INSERT ON notes FOR EACH ROW
           WHEN (owns_note(NEW.owner_id)) EXECUTE FUNCTION check_note();"
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
}
