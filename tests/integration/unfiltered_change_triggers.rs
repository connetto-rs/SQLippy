//! `AFTER UPDATE` triggers writing another table for unchanged rows.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for a trigger declared as `trigger` running
/// `body`.
fn findings(trigger: &str, body: &str) -> Vec<String> {
    diagnostics(&format!(
        "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);
         CREATE TABLE audit (note_id INT);
         CREATE FUNCTION audit_note(note INT) RETURNS void LANGUAGE sql AS $$ INSERT INTO audit VALUES (note) $$;
         CREATE FUNCTION audit_count(note INT) RETURNS INT LANGUAGE sql AS $$ INSERT INTO audit VALUES (note) RETURNING note_id $$;
         CREATE FUNCTION on_note() RETURNS trigger LANGUAGE plpgsql AS $$ {body} $$;
         CREATE TRIGGER on_note {trigger} EXECUTE FUNCTION on_note();"
    ))
}

/// Messages of every finding for the schema `sql`.
fn diagnostics(sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
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
fn writes_anywhere_the_body_evaluates_sql_are_reported() {
    for body in [
        "DECLARE n INT := audit_count(NEW.id); BEGIN RETURN NULL; END",
        "BEGIN BEGIN INSERT INTO audit VALUES (NEW.id); END; RETURN NULL; END",
        "BEGIN PERFORM 1 / 0; RETURN NULL; EXCEPTION WHEN division_by_zero THEN INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        "BEGIN CASE NEW.id WHEN 1 THEN INSERT INTO audit VALUES (NEW.id); ELSE NULL; END CASE; RETURN NULL; END",
        "BEGIN IF found THEN INSERT INTO audit VALUES (NEW.id); END IF; RETURN NULL; END",
        "BEGIN IF count(*) = 0 FROM audit WHERE note_id = NEW.id THEN INSERT INTO audit VALUES (NEW.id); END IF; RETURN NULL; END",
        "BEGIN LOOP INSERT INTO audit VALUES (NEW.id); EXIT; END LOOP; RETURN NULL; END",
        "BEGIN LOOP EXIT WHEN audit_count(NEW.id) > 0; END LOOP; RETURN NULL; END",
        "BEGIN WHILE audit_count(NEW.id) > 0 LOOP EXIT; END LOOP; RETURN NULL; END",
        "BEGIN FOR i IN 1..audit_count(NEW.id) LOOP NULL; END LOOP; RETURN NULL; END",
        "BEGIN FOR i IN REVERSE 3..1 BY audit_count(NEW.id) LOOP NULL; END LOOP; RETURN NULL; END",
        "BEGIN FOR i IN 1..2 LOOP CONTINUE WHEN i = 1; INSERT INTO audit VALUES (NEW.id); END LOOP; RETURN NULL; END",
        "DECLARE r RECORD; BEGIN FOR r IN EXECUTE 'SELECT $1' USING audit_count(NEW.id) LOOP NULL; END LOOP; RETURN NULL; END",
        "DECLARE x INT; BEGIN FOREACH x IN ARRAY ARRAY[audit_count(NEW.id)] LOOP NULL; END LOOP; RETURN NULL; END",
        "DECLARE c CURSOR (note INT) FOR SELECT note; BEGIN FOR r IN c(audit_count(NEW.id)) LOOP NULL; END LOOP; RETURN NULL; END",
        "BEGIN EXECUTE 'SELECT $1' USING audit_count(NEW.id); RETURN NULL; END",
        "DECLARE c CURSOR (note INT) FOR SELECT note; x INT; BEGIN OPEN c(audit_count(NEW.id)); FETCH c INTO x; CLOSE c; RETURN NULL; END",
        "DECLARE c CURSOR FOR SELECT 1; x INT; BEGIN OPEN c; FETCH RELATIVE audit_count(NEW.id) FROM c INTO x; RETURN NULL; END",
        "DECLARE c CURSOR FOR SELECT 1; BEGIN OPEN c; MOVE FORWARD audit_count(NEW.id) FROM c; RETURN NULL; END",
        "DECLARE a INT[] := '{}'; BEGIN a[audit_count(NEW.id)] := 1; RETURN NULL; END",
        "DECLARE a INT[] := '{1,2,3}'; BEGIN a[1:audit_count(NEW.id)] := '{9}'; RETURN NULL; END",
        "DECLARE a notes[]; BEGIN a[1].body := 'x'; INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        "BEGIN RAISE NOTICE '%', audit_count(NEW.id); RETURN NULL; END",
    ] {
        let found = findings(ROW_UPDATE, body);
        assert_eq!(found.len(), 1, "{body}: {found:?}");
    }
}

#[test]
fn writes_reached_through_loop_queries_cursors_and_exits_are_reported() {
    for body in [
        "DECLARE r RECORD; BEGIN FOR r IN INSERT INTO audit VALUES (NEW.id) RETURNING note_id LOOP NULL; END LOOP; RETURN NULL; END",
        "DECLARE c CURSOR FOR SELECT audit_count(NEW.id); BEGIN FOR r IN c LOOP NULL; END LOOP; RETURN NULL; END",
        "DECLARE c CURSOR FOR SELECT audit_count(NEW.id); BEGIN OPEN c; RETURN NULL; END",
        "BEGIN <<skip>> BEGIN IF NEW.id > 0 THEN EXIT skip; END IF; RETURN NULL; END; INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        "BEGIN <<outer>> LOOP LOOP EXIT outer; END LOOP; END LOOP; INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
    ] {
        let found = findings(ROW_UPDATE, body);
        assert_eq!(found.len(), 1, "{body}: {found:?}");
    }
}

#[test]
fn comparisons_guarding_through_exits_loops_asserts_and_quoted_rows_are_not_reported() {
    for body in [
        "BEGIN LOOP EXIT WHEN OLD.body IS NOT DISTINCT FROM NEW.body; INSERT INTO audit VALUES (NEW.id); EXIT; END LOOP; RETURN NULL; END",
        "BEGIN FOR i IN 1..2 LOOP CONTINUE WHEN OLD.body IS NOT DISTINCT FROM NEW.body; INSERT INTO audit VALUES (NEW.id); END LOOP; RETURN NULL; END",
        "BEGIN WHILE OLD.body IS DISTINCT FROM NEW.body LOOP INSERT INTO audit VALUES (NEW.id); EXIT; END LOOP; RETURN NULL; END",
        "BEGIN ASSERT OLD.body IS DISTINCT FROM NEW.body; INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
        "BEGIN IF \"old\".body IS DISTINCT FROM \"new\".body THEN INSERT INTO audit VALUES (NEW.id); END IF; RETURN NULL; END",
        "BEGIN IF (OLD.*) IS DISTINCT FROM (NEW.*) THEN INSERT INTO audit VALUES (NEW.id); END IF; RETURN NULL; END",
        "BEGIN LOOP EXIT on_note; END LOOP; INSERT INTO audit VALUES (NEW.id); RETURN NULL; END",
    ] {
        assert_eq!(findings(ROW_UPDATE, body), Vec::<String>::new(), "{body}");
    }
}

#[test]
fn a_trigger_function_in_another_language_is_not_read() {
    let found = diagnostics(
        "CREATE TABLE notes (id INT PRIMARY KEY);
         CREATE FUNCTION on_note() RETURNS trigger LANGUAGE c AS 'library', 'on_note';
         CREATE TRIGGER on_note AFTER UPDATE ON notes FOR EACH ROW EXECUTE FUNCTION on_note();",
    );
    assert_eq!(found, Vec::<String>::new());
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
