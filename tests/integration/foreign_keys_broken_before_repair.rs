//! PL/pgSQL body statements that leave a row referencing a missing row,
//! which PostgreSQL refuses at the end of the statement even when a later
//! statement of the same body would repair the reference.

use diesel::{PgConnection, connection::SimpleConnection};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// `parents`, and `children` referencing it through a key declared as `key`.
fn tables(key: &str) -> String {
    format!(
        "CREATE TABLE parents (id INT PRIMARY KEY);
         CREATE TABLE children (id INT PRIMARY KEY, parent INT REFERENCES parents (id) {key}, payload INT);"
    )
}

/// The schema whose trigger function `fix()` runs `body`, under `trigger`.
fn schema(key: &str, body: &str, trigger: &str) -> String {
    format!(
        "{}
         CREATE FUNCTION fix() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {body} RETURN NULL; END $$;
         {trigger}",
        tables(key)
    )
}

/// Messages of every finding on `sql`.
fn findings(sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = ForeignKeyBrokenBeforeRepair::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Correctness);
                violation.message().to_owned()
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

/// Named to fire before the key's own check of the inserted row, which
/// PostgreSQL runs in name order with the row's other `AFTER` triggers.
const AFTER_INSERT: &str =
    "CREATE TRIGGER \"A_fix\" AFTER INSERT ON children FOR EACH ROW EXECUTE FUNCTION fix();";

/// Named to fire after the key's own check of the inserted row.
const LATE_AFTER_INSERT: &str =
    "CREATE TRIGGER fix AFTER INSERT ON children FOR EACH ROW EXECUTE FUNCTION fix();";

#[test]
fn removing_a_parent_before_deleting_its_children_is_reported() {
    assert_eq!(
        findings(&schema(
            "",
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = OLD.parent;",
            ""
        )),
        [
            "Function 'fix()' deletes rows of 'parents' that rows of 'children' may still reference through (parent), and only a later statement of the body deletes those rows, but PostgreSQL checks the foreign key at the end of each statement of a function body and raises 23503 (foreign_key_violation) first."
        ]
    );
}

#[test]
fn a_restricting_key_raises_its_own_error_even_when_deferred() {
    for key in [
        "ON DELETE RESTRICT",
        "ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED",
    ] {
        assert_eq!(
            findings(&schema(
                key,
                "DELETE FROM parents WHERE id = OLD.parent; UPDATE children SET parent = NULL WHERE parent = OLD.parent;",
                ""
            )),
            [
                "Function 'fix()' deletes rows of 'parents' that rows of 'children' may still reference through (parent), and only a later statement of the body repoints those rows, but PostgreSQL checks the foreign key at the end of each statement of a function body and raises 23001 (restrict_violation) first."
            ],
            "{key}"
        );
    }
}

#[test]
fn rekeying_a_parent_before_repointing_its_children_is_reported() {
    assert_eq!(
        findings(&schema(
            "DEFERRABLE INITIALLY IMMEDIATE",
            "UPDATE parents SET id = NEW.id WHERE id = OLD.id; UPDATE children SET parent = NEW.id WHERE parent = OLD.id;",
            ""
        )),
        [
            "Function 'fix()' changes the key of rows of 'parents' that rows of 'children' may still reference through (parent), and only a later statement of the body repoints those rows, but PostgreSQL checks the foreign key at the end of each statement of a function body and raises 23503 (foreign_key_violation) first."
        ]
    );
}

#[test]
fn writing_children_before_inserting_their_parent_is_reported() {
    for body in [
        "INSERT INTO children (id, parent) VALUES (NEW.id, NEW.parent); INSERT INTO parents VALUES (NEW.parent);",
        "INSERT INTO children VALUES (NEW.id, new.parent, 0); INSERT INTO parents (id) VALUES (NEW.parent) ON CONFLICT DO NOTHING;",
        "UPDATE children SET parent = NEW.parent WHERE id = NEW.id; IF NEW.parent IS NOT NULL THEN INSERT INTO parents (id) VALUES (NEW.parent); END IF;",
    ] {
        assert_eq!(
            findings(&schema("", body, "")),
            [
                "Function 'fix()' writes rows of 'children' referencing through (parent) a row of 'parents' that only a later statement of the body inserts, but PostgreSQL checks the foreign key at the end of each statement of a function body and raises 23503 (foreign_key_violation) first."
            ],
            "{body}"
        );
    }
}

#[test]
fn updating_the_inserted_row_before_inserting_its_parent_is_reported() {
    for body in [
        "UPDATE children SET payload = 1 WHERE id = NEW.id; INSERT INTO parents VALUES (NEW.parent);",
        "UPDATE children SET payload = 1 WHERE \"id\" = NEW.\"id\"; INSERT INTO parents VALUES (NEW.parent);",
    ] {
        assert_eq!(
            findings(&schema("", body, AFTER_INSERT)),
            [
                "Function 'fix()' updates the row of 'children' its AFTER INSERT trigger fired for, whose unchanged key through (parent) PostgreSQL checks again since the transaction wrote the row, and only a later statement of the body inserts the row of 'parents' it references, but PostgreSQL checks the foreign key at the end of each statement of a function body and raises 23503 (foreign_key_violation) first."
            ],
            "{body}"
        );
    }
}

#[test]
fn a_later_statement_on_any_path_after_the_break_counts() {
    for body in [
        "DELETE FROM parents WHERE id = OLD.parent; IF FOUND THEN DELETE FROM children WHERE parent = OLD.parent; END IF;",
        "BEGIN DELETE FROM parents WHERE id = OLD.parent; END; DELETE FROM children WHERE parent = OLD.parent;",
        "IF OLD.parent > 0 THEN DELETE FROM parents WHERE id = OLD.parent; END IF; DELETE FROM children c WHERE c.parent = OLD.parent;",
        "CASE WHEN OLD.parent > 0 THEN DELETE FROM parents WHERE id = OLD.parent; ELSE RAISE NOTICE 'kept'; END CASE; DELETE FROM children WHERE parent = OLD.parent;",
        "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE (parent) = OLD.parent AND payload = 0 AND payload > 0;",
        "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM public.children WHERE public.children.parent = OLD.parent;",
    ] {
        assert_eq!(findings(&schema("", body, "")).len(), 1, "{body}");
    }
}

#[test]
fn deferred_or_acting_keys_are_not_reported() {
    let delete = "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = OLD.parent;";
    let insert = "INSERT INTO children VALUES (NEW.id, NEW.parent, 0); INSERT INTO parents VALUES (NEW.parent);";
    for (key, body) in [
        ("DEFERRABLE INITIALLY DEFERRED", delete),
        ("DEFERRABLE INITIALLY DEFERRED", insert),
        ("ON DELETE CASCADE", delete),
        ("ON DELETE SET NULL", delete),
        ("ON DELETE SET DEFAULT", delete),
        ("NOT ENFORCED", delete),
    ] {
        assert!(findings(&schema(key, body, "")).is_empty(), "{key}: {body}");
    }
}

#[test]
fn repairs_that_come_first_or_reach_other_rows_are_not_reported() {
    for (body, trigger) in [
        // The children go first.
        (
            "DELETE FROM children WHERE parent = OLD.parent; DELETE FROM parents WHERE id = OLD.parent;",
            "",
        ),
        (
            "INSERT INTO parents VALUES (NEW.parent); INSERT INTO children VALUES (NEW.id, NEW.parent, 0);",
            "",
        ),
        // The later statement reaches other rows.
        (
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = OLD.id;",
            "",
        ),
        (
            "INSERT INTO children VALUES (NEW.id, NEW.parent, 0); INSERT INTO parents VALUES (NEW.id);",
            "",
        ),
        (
            "DELETE FROM parents WHERE id = OLD.parent; UPDATE children SET payload = 0 WHERE parent = OLD.parent;",
            "",
        ),
        // Exclusive branches.
        (
            "IF OLD.id > 0 THEN DELETE FROM parents WHERE id = OLD.parent; ELSE DELETE FROM children WHERE parent = OLD.parent; END IF;",
            "",
        ),
        // One statement holds both writes, and PostgreSQL checks at its end.
        (
            "WITH gone AS (DELETE FROM children WHERE parent = OLD.parent) DELETE FROM parents WHERE id = OLD.parent;",
            "",
        ),
        // An exception handler catches the error.
        (
            "BEGIN DELETE FROM parents WHERE id = OLD.parent; EXCEPTION WHEN foreign_key_violation THEN NULL; END; DELETE FROM children WHERE parent = OLD.parent;",
            "",
        ),
        // Each iteration repairs before it breaks.
        (
            "FOR row IN SELECT id FROM parents LOOP DELETE FROM children WHERE parent = row.id; DELETE FROM parents WHERE id = row.id; END LOOP;",
            "",
        ),
        // Rows committed before the transaction keep their unchanged key unchecked.
        (
            "UPDATE children SET payload = 1 WHERE parent = OLD.id; UPDATE children SET parent = NULL WHERE parent = OLD.id;",
            "CREATE TRIGGER fix AFTER DELETE ON parents FOR EACH ROW EXECUTE FUNCTION fix();",
        ),
        (
            "UPDATE children SET payload = 1 WHERE id = NEW.id; INSERT INTO parents VALUES (NEW.parent);",
            "CREATE TRIGGER fix BEFORE INSERT ON children FOR EACH ROW EXECUTE FUNCTION fix();",
        ),
        (
            "UPDATE children SET payload = 1 WHERE id = NEW.id; INSERT INTO parents VALUES (NEW.parent);",
            "CREATE TRIGGER fix AFTER INSERT ON parents FOR EACH ROW EXECUTE FUNCTION fix();",
        ),
        (
            "UPDATE children SET payload = 1 WHERE payload = NEW.id; INSERT INTO parents VALUES (NEW.parent);",
            AFTER_INSERT,
        ),
        // The key's own check of the inserted row runs before the trigger.
        (
            "UPDATE children SET payload = 1 WHERE id = NEW.id; INSERT INTO parents VALUES (NEW.parent);",
            LATE_AFTER_INSERT,
        ),
        // The later statement names the rows by a value that may change.
        (
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = id;",
            "",
        ),
        (
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = abs(OLD.parent);",
            "",
        ),
        (
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = (SELECT OLD.parent);",
            "",
        ),
        // The later statement writes another table.
        (
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM elsewhere WHERE parent = OLD.parent;",
            "",
        ),
        (
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children AS c (a, b, d) WHERE a = OLD.parent;",
            "",
        ),
        (
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children, parents WHERE parent = OLD.parent;",
            "",
        ),
        // Writes the rule does not read.
        (
            "DELETE FROM parents WHERE id = OLD.parent; UPDATE children SET (parent, payload) = (NULL, 0) WHERE parent = OLD.parent;",
            "",
        ),
        (
            "INSERT INTO children SELECT NEW.id, NEW.parent, 0; INSERT INTO parents VALUES (NEW.parent);",
            "",
        ),
        // The function's own exception handler catches the error.
        (
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = OLD.parent; RETURN NULL; EXCEPTION WHEN foreign_key_violation THEN",
            "",
        ),
    ] {
        assert!(findings(&schema("", body, trigger)).is_empty(), "{body}");
    }
}

/// The error PostgreSQL raises for `firing`, run on a fresh database
/// holding `fixture`, or `None` when it succeeds.
fn raised(connection: &mut PgConnection, fixture: &str, firing: &str) -> Option<String> {
    connection
        .batch_execute("DROP SCHEMA IF EXISTS case_under_test CASCADE; CREATE SCHEMA case_under_test; SET search_path = case_under_test;")
        .expect("schema resets");
    connection.batch_execute(fixture).expect("fixture applies");
    connection
        .batch_execute(firing)
        .err()
        .map(|error| error.to_string())
}

#[test]
fn postgresql_refuses_what_the_rule_reports_and_accepts_the_reordered_bodies() {
    let (_container, mut connection) = crate::live_catalog::postgres();
    let delete_trigger =
        "CREATE TRIGGER fix AFTER DELETE ON children FOR EACH ROW EXECUTE FUNCTION fix();";
    let deleting = "INSERT INTO parents VALUES (1); INSERT INTO children VALUES (1, 1, 0), (2, 1, 0); DELETE FROM children WHERE id = 1;";
    let inserting = "INSERT INTO children VALUES (1, 999, 0);";
    for (key, body, trigger, firing, error) in [
        (
            "",
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = OLD.parent;",
            delete_trigger,
            deleting,
            Some("violates foreign key constraint"),
        ),
        (
            "ON DELETE RESTRICT",
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = OLD.parent;",
            delete_trigger,
            deleting,
            Some("violates RESTRICT setting of foreign key constraint"),
        ),
        (
            "ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED",
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = OLD.parent;",
            delete_trigger,
            deleting,
            Some("violates RESTRICT setting of foreign key constraint"),
        ),
        (
            "",
            "DELETE FROM children WHERE parent = OLD.parent; DELETE FROM parents WHERE id = OLD.parent;",
            delete_trigger,
            deleting,
            None,
        ),
        (
            "DEFERRABLE INITIALLY DEFERRED",
            "DELETE FROM parents WHERE id = OLD.parent; DELETE FROM children WHERE parent = OLD.parent;",
            delete_trigger,
            deleting,
            None,
        ),
        (
            "",
            "UPDATE children SET payload = 1 WHERE id = NEW.id; INSERT INTO parents VALUES (NEW.parent);",
            AFTER_INSERT,
            inserting,
            Some("violates foreign key constraint"),
        ),
        (
            "",
            "INSERT INTO parents VALUES (NEW.parent); UPDATE children SET payload = 1 WHERE id = NEW.id;",
            AFTER_INSERT,
            inserting,
            None,
        ),
    ] {
        let fixture = schema(key, body, trigger);
        assert_eq!(
            findings(&fixture).len(),
            usize::from(error.is_some()),
            "{key}: {body}"
        );
        match (error, raised(&mut connection, &fixture, firing)) {
            (Some(expected), Some(found)) => assert!(found.contains(expected), "{body}: {found}"),
            (None, None) => {}
            (expected, found) => {
                panic!("{key}: {body}: expected {expected:?}, PostgreSQL gave {found:?}")
            }
        }
    }
    for body in [
        "UPDATE children SET payload = 1 WHERE id = NEW.id; INSERT INTO parents VALUES (NEW.parent);",
        "INSERT INTO parents VALUES (NEW.parent); UPDATE children SET payload = 1 WHERE id = NEW.id;",
    ] {
        let fixture = schema("", body, LATE_AFTER_INSERT);
        assert!(findings(&fixture).is_empty(), "{body}");
        assert!(
            raised(&mut connection, &fixture, inserting)
                .is_some_and(|found| found.contains("violates foreign key constraint")),
            "the key's check runs before {body}"
        );
    }
    assert_eq!(
        raised(
            &mut connection,
            &tables(""),
            "INSERT INTO parents VALUES (1); INSERT INTO children VALUES (1, 1, 0); \
             WITH gone AS (DELETE FROM parents WHERE id = 1) DELETE FROM children WHERE parent = 1;"
        ),
        None,
        "the outermost statement repairs before its end"
    );
}
