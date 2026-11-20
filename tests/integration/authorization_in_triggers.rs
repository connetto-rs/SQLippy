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

/// A view has no row level security of its own, so neither the `INSTEAD OF`
/// trigger that makes it writable nor a statement trigger on it repeats a
/// policy, even one of the table below it.
#[test]
fn triggers_on_a_view_over_a_secured_table_are_not_reported() {
    let found = findings(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE VIEW my_notes AS SELECT id, owner_id, body FROM notes;
         CREATE FUNCTION write_note() RETURNS trigger LANGUAGE plpgsql AS
           $$ BEGIN
                IF NOT owns_note(NEW.owner_id) THEN RAISE insufficient_privilege; END IF;
                INSERT INTO notes VALUES (NEW.id, NEW.owner_id, NEW.body);
                RETURN NEW;
              END $$;
         CREATE TRIGGER write_note INSTEAD OF INSERT ON my_notes FOR EACH ROW EXECUTE FUNCTION write_note();
         CREATE FUNCTION check_writer() RETURNS trigger LANGUAGE plpgsql AS
           $$ BEGIN RAISE insufficient_privilege; END $$;
         CREATE TRIGGER check_writer BEFORE INSERT ON my_notes FOR EACH STATEMENT EXECUTE FUNCTION check_writer();"
    ));
    assert!(found.is_empty(), "{found:?}");
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

/// A `BEFORE` trigger on `events` running a function with the declaration
/// section `declared`, whose body runs `body`, after the objects `extra`.
fn extended(events: &str, declared: &str, extra: &str, body: &str) -> String {
    format!("{extra}{}", raising(events, declared, body))
}

/// After `extra`, a trigger function whose body runs `check`, and the
/// trigger on `notes` that runs it.
fn callee(extra: &str, check: &str) -> String {
    format!(
        "{extra}
         CREATE FUNCTION check_note() RETURNS trigger LANGUAGE plpgsql AS
           $$ BEGIN {check} RETURN NEW; END $$;
         CREATE TRIGGER check_note BEFORE INSERT ON notes FOR EACH ROW EXECUTE FUNCTION check_note();"
    )
}

#[test]
fn a_helper_in_the_conditions_of_other_statement_kinds_is_reported() {
    let note_events = "CREATE TABLE note_events (id INT, own BOOLEAN);";
    for (declared, extra, body) in [
        // The `WHERE` of a `CTE` the body reads.
        (
            "",
            note_events,
            "PERFORM own FROM (WITH c AS (SELECT own FROM note_events WHERE own = owns_note(NEW.owner_id)) SELECT own FROM c) x;",
        ),
        // The `WHERE` of one side of a set operation the body runs.
        (
            "",
            note_events,
            "PERFORM count(*) FROM note_events UNION ALL SELECT count(*) FROM note_events WHERE own = owns_note(NEW.owner_id);",
        ),
        // The `WHERE` of the source and the `ON` of a `MERGE` the body runs.
        (
            "",
            note_events,
            "MERGE INTO note_events USING (SELECT id FROM notes WHERE id = NEW.id AND owns_note(NEW.owner_id)) src ON note_events.id = src.id WHEN MATCHED AND note_events.own = false THEN UPDATE SET own = true;",
        ),
        // The `FROM` and the `WHERE` of an `UPDATE` the body runs.
        (
            "",
            note_events,
            "UPDATE note_events SET own = true FROM notes WHERE note_events.id = notes.id AND owns_note(NEW.owner_id);",
        ),
        // The `WHERE` of a `DELETE` the body runs.
        (
            "",
            note_events,
            "DELETE FROM note_events WHERE own = owns_note(NEW.owner_id);",
        ),
        // The `USING` source and the `WHERE` of a `DELETE` the body runs.
        (
            "",
            note_events,
            "DELETE FROM note_events USING notes WHERE note_events.id = notes.id AND owns_note(NEW.owner_id);",
        ),
        // The `WHERE` of the source of an `INSERT` the body runs.
        (
            "",
            note_events,
            "INSERT INTO note_events (id, own) SELECT id, true FROM notes WHERE id = NEW.id AND owns_note(NEW.owner_id);",
        ),
        // The `WHERE` of a data-modifying `CTE` the body runs.
        (
            "",
            note_events,
            "WITH x AS (DELETE FROM note_events WHERE own = owns_note(NEW.owner_id)) SELECT 1;",
        ),
        // The `WHERE` of a parenthesized subquery a `CTE` reads.
        (
            "",
            note_events,
            "WITH x AS ((SELECT own FROM note_events WHERE own = owns_note(NEW.owner_id))) SELECT 1 FROM x;",
        ),
        // A declared cursor an `OPEN` opens on its stored query.
        (
            "DECLARE c CURSOR FOR SELECT id FROM note_events WHERE own = owns_note(NEW.owner_id);",
            note_events,
            "OPEN c;",
        ),
        // The `ON` of a nested join the body reads.
        (
            "",
            note_events,
            "PERFORM 1 FROM (notes JOIN note_events e2 ON e2.id = notes.id AND owns_note(notes.owner_id));",
        ),
    ] {
        let found = findings(&format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id)); {}",
            extended("INSERT", declared, extra, body)
        ));
        assert_eq!(found.len(), 1, "{body}: {found:?}");
        assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
    }
}

#[test]
fn a_helper_in_the_conditions_of_control_flow_is_reported() {
    let note_events = "CREATE TABLE note_events (id INT, own BOOLEAN);";
    for (declared, extra, body) in [
        // The subject of a valued `CASE`.
        (
            "",
            "",
            "CASE owns_note(NEW.owner_id) WHEN true THEN RETURN NEW; ELSE RAISE EXCEPTION 'no'; END CASE;",
        ),
        // A `CASE` without an `ELSE`.
        (
            "",
            "",
            "CASE WHEN owns_note(NEW.owner_id) THEN RETURN NEW; END CASE;",
        ),
        // The array a `FOREACH` loop iterates.
        (
            "",
            note_events,
            "FOREACH t IN ARRAY (SELECT id FROM note_events WHERE own = owns_note(NEW.owner_id)) LOOP PERFORM 1; END LOOP;",
        ),
        // The query a `FOR` loop iterates.
        (
            "",
            note_events,
            "FOR r IN SELECT id FROM note_events WHERE own = owns_note(NEW.owner_id) LOOP PERFORM 1; END LOOP;",
        ),
        // The query a cursor a `FOR` loop opens is bound to.
        (
            "DECLARE c CURSOR FOR SELECT id FROM note_events WHERE own = owns_note(NEW.owner_id);",
            note_events,
            "FOR r IN c LOOP PERFORM 1; END LOOP;",
        ),
        // The query an `OPEN` opens a cursor on.
        (
            "",
            note_events,
            "OPEN c FOR SELECT id FROM note_events WHERE own = owns_note(NEW.owner_id);",
        ),
        // A plain `LOOP` with a bare `EXIT`, beside a deciding condition.
        (
            "",
            "",
            "IF owns_note(NEW.owner_id) THEN PERFORM 1; END IF; LOOP PERFORM 1; EXIT; END LOOP;",
        ),
        // A nested block with an `ELSE` branch and an exception handler.
        (
            "",
            "",
            "BEGIN IF owns_note(NEW.owner_id) THEN RAISE EXCEPTION 'no'; ELSE PERFORM 1; END IF; PERFORM 1; EXCEPTION WHEN division_by_zero THEN PERFORM 1; END;",
        ),
        // A catalog function beside the helper in a condition.
        (
            "",
            "",
            "IF coalesce(NEW.id, 0) > 0 AND owns_note(NEW.owner_id) THEN RAISE EXCEPTION 'no'; END IF;",
        ),
    ] {
        let found = findings(&format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id)); {}",
            extended("INSERT", declared, extra, body)
        ));
        assert_eq!(found.len(), 1, "{body}: {found:?}");
        assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
    }

    // The `WHERE` a `RETURN QUERY` reads, the body's own return included.
    let found = findings(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE TABLE note_events (id INT, own BOOLEAN);
         CREATE FUNCTION check_note() RETURNS trigger LANGUAGE plpgsql AS
           $$ BEGIN RETURN QUERY SELECT id FROM note_events WHERE own = owns_note(NEW.owner_id); END $$;
         CREATE TRIGGER check_note BEFORE INSERT ON notes FOR EACH ROW EXECUTE FUNCTION check_note();"
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
}

#[test]
fn a_helper_reached_only_outside_a_condition_is_not_reported() {
    let note_events = "CREATE TABLE note_events (id INT, own BOOLEAN);";
    let sql_callee = "CREATE FUNCTION may_write(subject UUID) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$ SELECT owns_note(subject) $$;";
    let audit_objects = format!(
        "{note_events}
         CREATE FUNCTION record_own(own BOOLEAN) RETURNS VOID LANGUAGE sql AS
           $$ INSERT INTO note_events (id, own) VALUES (NEW.id, own) $$;"
    );
    for (declared, extra, body) in [
        // A `CROSS JOIN` has no condition to decide on.
        (
            "",
            note_events,
            "PERFORM 1 FROM note_events CROSS JOIN notes;",
        ),
        // A `USING` join joins on a column, not a condition.
        (
            "",
            note_events,
            "PERFORM 1 FROM note_events JOIN notes USING (id);",
        ),
        // A `CROSS APPLY` join has no condition to decide on.
        (
            "",
            note_events,
            "PERFORM 1 FROM notes CROSS APPLY note_events;",
        ),
        // An `UPDATE` without a `WHERE`.
        ("", note_events, "UPDATE note_events SET own = true;"),
        // A `MERGE` with no clause predicate.
        (
            "",
            note_events,
            "MERGE INTO note_events USING notes ON note_events.id = notes.id WHEN MATCHED THEN UPDATE SET own = true;",
        ),
        // The result of a callee, stored in a variable the body never tests.
        (
            "DECLARE own BOOLEAN;",
            sql_callee,
            "own := may_write(NEW.owner_id);",
        ),
        // The result of a callee, stored in a qualified target.
        (
            "DECLARE rec RECORD;",
            sql_callee,
            "rec := may_write(NEW.owner_id); rec.field := rec.field + 1;",
        ),
        // A chain of assignments the body never tests.
        (
            "DECLARE a BOOLEAN; DECLARE b BOOLEAN;",
            sql_callee,
            "a := b; b := may_write(NEW.owner_id);",
        ),
        // The result of a callee, passed on and passed on.
        (
            "",
            &audit_objects,
            "PERFORM record_own(may_write(NEW.owner_id));",
        ),
        // A condition that calls a callee whose value never carries the helper.
        (
            "",
            "CREATE FUNCTION is_active(id INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$ SELECT 1 $$;",
            "IF is_active(NEW.id) THEN RAISE EXCEPTION 'no'; END IF;",
        ),
    ] {
        let found = findings(&format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id)); {}",
            extended("INSERT", declared, extra, body)
        ));
        assert_eq!(found.len(), 0, "{body}: {found:?}");
    }

    // The result of a callee, assigned and never tested, after a bare `EXIT`.
    let found = findings(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE FUNCTION may_write(subject UUID) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$ SELECT owns_note(subject) $$;
         {}",
        extended(
            "INSERT",
            "DECLARE own BOOLEAN;",
            "",
            "LOOP own := may_write(NEW.owner_id); EXIT; END LOOP;"
        )
    ));
    assert_eq!(found.len(), 0, "{found:?}");
}

#[test]
fn a_body_that_does_not_decide_with_the_helper_is_not_reported() {
    let note_events = "CREATE TABLE note_events (id INT, own BOOLEAN);";
    let sql_callee = "CREATE FUNCTION may_write(subject UUID) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$ SELECT owns_note(subject) $$;";
    let plain_callee =
        "CREATE FUNCTION is_active(id INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$ SELECT 1 $$;";
    let multi_callee =
        "CREATE FUNCTION multi(id INT) RETURNS INT LANGUAGE sql AS $$ SELECT 1; SELECT 2; $$;";
    let plain_where_callee = "CREATE FUNCTION plain_rows(id INT) RETURNS INT LANGUAGE sql STABLE AS $$ SELECT count(*) FROM note_events WHERE id > 0 $$;";
    let noop_callee =
        "CREATE FUNCTION noop(id INT) RETURNS VOID LANGUAGE plpgsql AS $$ BEGIN PERFORM 1; END $$;";
    let literal_callee = "CREATE FUNCTION literal(id INT) RETURNS INT LANGUAGE plpgsql AS $$ BEGIN RETURN 1; END $$;";
    let atomic_update_callee = "CREATE FUNCTION clear_events(id INT) RETURNS VOID LANGUAGE sql BEGIN ATOMIC UPDATE note_events SET own = false; END;";
    for (declared, extra, body) in [
        // A variable assigned a value that does not reach, then tested.
        (
            "DECLARE x INT;",
            "",
            "x := NEW.id; IF x > 0 THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // The helper result stored in a variable the condition does not read.
        (
            "DECLARE own BOOLEAN;",
            sql_callee,
            "own := may_write(NEW.owner_id); IF NEW.id IS NULL THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A callee whose body is not one query.
        ("", multi_callee, "PERFORM multi(NEW.id);"),
        // A condition that calls the same callee twice, whose value does not carry.
        (
            "",
            plain_callee,
            "IF is_active(NEW.id) AND is_active(NEW.id) THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A condition that calls a callee whose body has no value it returns.
        (
            "",
            noop_callee,
            "IF noop(NEW.id) THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A condition that calls a callee returning a value that never carries.
        (
            "",
            literal_callee,
            "IF literal(NEW.id) THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A `DELETE` without a `WHERE`.
        ("", note_events, "DELETE FROM note_events;"),
        // An `INSERT` without a source.
        (
            "",
            note_events,
            "INSERT INTO note_events (id, own) VALUES (NEW.id, true);",
        ),
        // An `INSERT` with no query it reads at all.
        ("", note_events, "INSERT INTO note_events DEFAULT VALUES;"),
        // A condition that calls a callee whose body is a bare `RETURN`.
        (
            "",
            "CREATE FUNCTION bump(id INT) RETURNS INT LANGUAGE sql STABLE RETURN id + 1;",
            "IF bump(NEW.id) > 0 THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A statement that reads no condition at all.
        ("", note_events, "TRUNCATE note_events;"),
        // A callee whose `BEGIN ATOMIC` body ends in a non-query statement.
        (
            "",
            &format!("{note_events}{atomic_update_callee}"),
            "IF clear_events(NEW.id) IS NULL THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A callee whose query decides on nothing the helper decides.
        (
            "",
            &format!("{note_events}{plain_where_callee}"),
            "PERFORM plain_rows(NEW.id);",
        ),
    ] {
        let found = findings(&format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id)); {}",
            extended("INSERT", declared, extra, body)
        ));
        assert_eq!(found.len(), 0, "{body}: {found:?}");
    }
}

#[test]
fn a_helper_result_carried_out_of_a_callee_is_reported() {
    let sql_callee = "CREATE FUNCTION may_write(subject UUID) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$ SELECT owns_note(subject) $$;";
    for (declared, extra, body) in [
        // A condition that calls a callee whose value carries the helper.
        (
            "",
            sql_callee,
            "IF may_write(NEW.owner_id) THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A callee called twice in one condition.
        (
            "",
            sql_callee,
            "IF may_write(NEW.owner_id) OR may_write(NEW.owner_id) THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A condition that reads a variable a callee assigned through.
        (
            "DECLARE own BOOLEAN;",
            sql_callee,
            "own := may_write(NEW.owner_id); IF own THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A variable a declared default assigns, then tests in a condition.
        (
            "DECLARE own BOOLEAN DEFAULT owns_note(NEW.owner_id);",
            "",
            "IF own THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A condition that reads a quoted variable.
        (
            r#"DECLARE "Own" BOOLEAN;"#,
            sql_callee,
            r#""Own" := may_write(NEW.owner_id); IF "Own" THEN RAISE EXCEPTION 'no'; END IF;"#,
        ),
        // A condition that reads a variable a chain of assignments carries.
        (
            "DECLARE a BOOLEAN; DECLARE b BOOLEAN;",
            sql_callee,
            "b := may_write(NEW.owner_id); a := b; IF a THEN RAISE EXCEPTION 'no'; END IF;",
        ),
        // A condition that reads a non-carrying variable before a carrying one.
        (
            "DECLARE own BOOLEAN; DECLARE other INT;",
            sql_callee,
            "own := may_write(NEW.owner_id); other := NEW.id; IF other > 0 OR own THEN RAISE EXCEPTION 'no'; END IF;",
        ),
    ] {
        let found = findings(&format!(
            "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id)); {}",
            extended("INSERT", declared, extra, body)
        ));
        assert_eq!(found.len(), 1, "{body}: {found:?}");
        assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
    }

    // A condition that reads the value a callee returns, which the callee's
    // `RETURN` evaluates directly.
    let found = findings(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE FUNCTION is_owner(subject UUID) RETURNS BOOLEAN LANGUAGE plpgsql AS
           $$ BEGIN RETURN owns_note(subject); END $$;
         {}",
        callee(
            "",
            "IF is_owner(NEW.owner_id) THEN RAISE EXCEPTION 'no'; END IF;"
        )
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("owns_note(UUID)"), "{found:?}");

    // A condition that reads the value a callee returns, which the callee
    // assigns to a variable its `RETURN` reads.
    let found = findings(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE FUNCTION row_owner(subject UUID) RETURNS BOOLEAN LANGUAGE plpgsql AS
           $$ DECLARE result BOOLEAN; BEGIN result := owns_note(subject); RETURN result; END $$;
         {}",
        callee(
            "",
            "IF row_owner(NEW.owner_id) THEN RAISE EXCEPTION 'no'; END IF;"
        )
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
}

#[test]
fn a_helper_result_carried_by_an_atomic_callee_is_reported() {
    let found = findings(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE FUNCTION last_read(subject UUID) RETURNS BOOLEAN LANGUAGE sql
           BEGIN ATOMIC
             SELECT true;
             SELECT owns_note(subject);
           END;
         {}",
        callee(
            "",
            "IF last_read(NEW.owner_id) THEN RAISE EXCEPTION 'no'; END IF;"
        )
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
}

#[test]
fn a_helper_decided_in_a_callee_query_is_reported() {
    let found = findings(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE FUNCTION guarded_rows(subject UUID) RETURNS INT LANGUAGE sql STABLE AS
           $$ SELECT count(*) FROM notes WHERE owns_note(subject) $$;
         {}",
        callee("", "PERFORM guarded_rows(NEW.owner_id);")
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("owns_note(UUID)"), "{found:?}");
}

#[test]
fn a_callee_that_cannot_be_resolved_is_a_lookup_failure() {
    let database = schema(&format!(
        "{SECURED} CREATE POLICY guard ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
         CREATE FUNCTION may_write(subject UUID) RETURNS BOOLEAN LANGUAGE sql STABLE AS
           $$ SELECT vault.public.missing(subject) $$;
         {}",
        callee(
            "",
            "IF may_write(NEW.owner_id) THEN RAISE EXCEPTION 'no'; END IF;"
        )
    ));
    let constrainer: GenericConstrainer<ParserDB> = AuthorizationInTrigger::default().into();
    assert!(matches!(
        constrainer.validate_schema(&database),
        Err(Error::Lookup(_))
    ));
}
