//! Deferred constraint triggers requiring a related row of a row that may
//! have been deleted before they run.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const TABLES: &str = "CREATE TABLE parents (id INT PRIMARY KEY, region INT NOT NULL, code INT NOT NULL, UNIQUE (region, code));
     CREATE TABLE children (parent_id INT PRIMARY KEY REFERENCES parents (id));
     CREATE TABLE audit (parent_id INT);
     CREATE FUNCTION has_child(parent INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
       SELECT EXISTS (SELECT FROM children WHERE parent_id = parent) $$;
     CREATE FUNCTION parent_exists(parent INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
       SELECT EXISTS (SELECT FROM parents WHERE id = parent) $$;
     CREATE FUNCTION parent_at(at_region INT, at_code INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
       SELECT EXISTS (SELECT FROM parents WHERE region = at_region AND code = at_code) $$;
     CREATE FUNCTION has_child_in(region INT, parent INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
       SELECT EXISTS (SELECT FROM children WHERE parent_id = parent) $$;
     CREATE FUNCTION has_child_procedurally(parent INT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$
       BEGIN RETURN EXISTS (SELECT FROM children WHERE parent_id = parent); END $$;
     CREATE FUNCTION has_children(parent INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
       SELECT count(*) > 0 FROM children WHERE parent_id = parent $$;
     CREATE FUNCTION has_any_child(VARIADIC parents INT[]) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
       SELECT EXISTS (SELECT FROM children WHERE parent_id = ANY (parents)) $$;";

/// The schema whose `check_parent()` runs `body` from a trigger on
/// `parents` created with `trigger`.
fn schema(body: &str, trigger: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{TABLES}
         CREATE FUNCTION check_parent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {body} RETURN NULL; END $$;
         {trigger}"
    ))
    .expect("schema parses")
}

const DEFERRED: &str = "CREATE CONSTRAINT TRIGGER parent_checked AFTER INSERT ON parents
     DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_parent();";

/// Messages of every finding on `database`.
fn findings_in<DB: DatabaseLike + 'static>(database: &DB) -> Vec<String> {
    let constrainer: GenericConstrainer<DB> = DeferredCheckDeletedRow::default().into();
    constrainer
        .diagnostics(database)
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

/// Messages of every finding for `body` run by `trigger`.
fn findings(body: &str, trigger: &str) -> Vec<String> {
    findings_in(&schema(body, trigger))
}

/// A body raising when `condition` holds.
fn raising(condition: &str) -> String {
    format!("IF {condition} THEN RAISE EXCEPTION 'parent % is incomplete', NEW.id; END IF;")
}

/// A body returning when `guard` holds and raising when no child exists.
fn guarded(guard: &str) -> String {
    format!(
        "IF {guard} THEN RETURN NULL; END IF; {}",
        raising("NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id)")
    )
}

#[test]
fn a_deferrable_completeness_check_without_a_guard_is_reported() {
    let unguarded = raising("NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id)");
    for trigger in [
        DEFERRED,
        "CREATE CONSTRAINT TRIGGER parent_checked AFTER INSERT ON parents
         DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION check_parent();",
        "CREATE CONSTRAINT TRIGGER parent_checked AFTER UPDATE ON parents
         DEFERRABLE FOR EACH ROW EXECUTE FUNCTION check_parent();",
        "CREATE CONSTRAINT TRIGGER parent_checked AFTER INSERT ON parents
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.id > 0) EXECUTE FUNCTION check_parent();",
    ] {
        let found = findings(&unguarded, trigger);
        assert_eq!(found.len(), 1, "{trigger}: {found:?}");
        assert!(
            found[0].contains("'parent_checked' on 'parents'")
                && found[0].contains("NOT EXISTS (SELECT FROM parents WHERE id = NEW.id)"),
            "{found:?}"
        );
    }
}

#[test]
fn triggers_that_run_before_a_deletion_can_follow_are_not_reported() {
    let unguarded = raising("NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id)");
    for trigger in [
        "CREATE CONSTRAINT TRIGGER parent_checked AFTER INSERT ON parents
         NOT DEFERRABLE FOR EACH ROW EXECUTE FUNCTION check_parent();",
        "CREATE CONSTRAINT TRIGGER parent_checked AFTER INSERT ON parents
         FOR EACH ROW EXECUTE FUNCTION check_parent();",
        "CREATE TRIGGER parent_checked AFTER INSERT ON parents
         FOR EACH ROW EXECUTE FUNCTION check_parent();",
        "CREATE CONSTRAINT TRIGGER parent_checked AFTER DELETE ON parents
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_parent();",
    ] {
        assert!(findings(&unguarded, trigger).is_empty(), "{trigger}");
    }
}

#[test]
fn a_check_of_the_triggering_row_on_a_whole_key_guards_the_rejection() {
    for body in [
        guarded("NOT EXISTS (SELECT FROM parents WHERE id = NEW.id)"),
        guarded("NOT EXISTS (SELECT 1 FROM public.parents parent WHERE NEW.id = parent.id)"),
        guarded("NOT EXISTS (SELECT FROM parents WHERE region = NEW.region AND code = NEW.code)"),
        guarded("NOT parent_exists(NEW.id)"),
        guarded("NOT parent_exists(parent => NEW.id)"),
        guarded("NOT parent_at(at_code => NEW.code, at_region => NEW.region)"),
        guarded("NOT EXISTS (SELECT FROM parents WHERE id = NEW.id AND code > 0)"),
        guarded("NOT EXISTS (SELECT FROM parents WHERE id = NEW.id) OR NEW.id IS NULL"),
        format!(
            "IF EXISTS (SELECT FROM parents WHERE id = NEW.id) THEN {} END IF;",
            raising("NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id)")
        ),
        "IF NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id) THEN
           IF NOT EXISTS (SELECT FROM parents WHERE id = NEW.id) THEN RETURN NULL; END IF;
           RAISE EXCEPTION 'parent % requires a child', NEW.id;
         END IF;"
            .to_owned(),
    ] {
        assert!(findings(&body, DEFERRED).is_empty(), "{body}");
    }
}

#[test]
fn a_check_that_does_not_pin_the_triggering_row_is_no_guard() {
    for body in [
        guarded("NOT EXISTS (SELECT FROM parents WHERE region = NEW.region)"),
        guarded("NOT EXISTS (SELECT FROM parents WHERE id = NEW.code)"),
        guarded("NOT EXISTS (SELECT FROM parents)"),
        guarded("NOT EXISTS (SELECT FROM audit WHERE parent_id = NEW.id)"),
        guarded("NOT EXISTS (SELECT FROM parents JOIN audit ON true WHERE id = NEW.id)"),
        guarded("NOT EXISTS (SELECT FROM parents WHERE id = NEW.id) AND NEW.id > 0"),
        guarded("NOT has_child(NEW.id)"),
        guarded("NOT parent_at(at_code => NEW.region, at_region => NEW.code)"),
        guarded("NOT EXISTS (SELECT FROM parents AS parent (code, id) WHERE id = NEW.id)"),
        guarded("NOT EXISTS (SELECT FROM generate_series(NEW.id, NEW.id) AS id WHERE id = NEW.id)"),
        guarded(
            "NOT EXISTS (SELECT FROM parents WHERE id = NEW.id
             UNION ALL SELECT FROM audit WHERE parent_id = NEW.id)",
        ),
        format!(
            "IF EXISTS (SELECT FROM parents WHERE id = NEW.id) THEN NULL; END IF; {}",
            raising("NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id)")
        ),
    ] {
        assert_eq!(findings(&body, DEFERRED).len(), 1, "{body}");
    }
}

#[test]
fn a_check_reading_child_tables_is_no_guard_unless_it_reads_only_the_parent() {
    let schema = |body: &str| {
        ParserDB::parse::<PostgreSqlDialect>(&format!(
            "{TABLES}
             CREATE TABLE archived_parents () INHERITS (parents);
             CREATE FUNCTION check_parent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {body} RETURN NULL; END $$;
             {DEFERRED}"
        ))
        .expect("schema parses")
    };
    for (guard, reported) in [
        ("NOT EXISTS (SELECT FROM parents WHERE id = NEW.id)", 1),
        ("NOT parent_exists(NEW.id)", 1),
        ("NOT EXISTS (SELECT FROM ONLY parents WHERE id = NEW.id)", 0),
        (
            "NOT EXISTS (SELECT FROM ONLY parents AS parent WHERE parent.id = NEW.id)",
            0,
        ),
    ] {
        let found = findings_in(&schema(&guarded(guard)));
        assert_eq!(found.len(), reported, "{guard}: {found:?}");
    }
}

#[test]
fn every_spelling_of_a_missing_related_row_is_a_rejection() {
    for body in [
        raising("NOT has_child(NEW.id)"),
        raising("NOT has_child(parent => NEW.id)"),
        raising("NOT has_child_in(parent => NEW.id, region => 0)"),
        raising("NEW.id > 0 AND NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id)"),
        raising("NOT (EXISTS (SELECT FROM children WHERE parent_id = NEW.id) OR NEW.id < 0)"),
        "IF EXISTS (SELECT FROM children WHERE parent_id = NEW.id) THEN RETURN NULL; END IF;
         RAISE EXCEPTION 'parent % requires a child', NEW.id;"
            .to_owned(),
        "ASSERT EXISTS (SELECT FROM children WHERE parent_id = NEW.id);".to_owned(),
    ] {
        assert_eq!(findings(&body, DEFERRED).len(), 1, "{body}");
    }
}

#[test]
fn checks_that_reject_nothing_missing_are_not_reported() {
    for body in [
        "INSERT INTO audit VALUES (NEW.id);".to_owned(),
        raising("EXISTS (SELECT FROM audit WHERE parent_id = NEW.id)"),
        raising("NOT EXISTS (SELECT FROM children)"),
        raising("NOT vault.public.has_child(NEW.id)"),
        raising("NEW.id < 0"),
        raising("NOT pg_is_in_recovery()"),
        raising("NOT undeclared_helper(NEW.id)"),
        raising("NOT has_child(children.*)"),
        raising("NOT has_any_child(NEW.id, NEW.code)"),
        "IF count(*) = 0 FROM children WHERE parent_id = NEW.id THEN
           RAISE EXCEPTION 'parent % requires a child', NEW.id;
         END IF;"
            .to_owned(),
        raising("NOT CURRENT_USER"),
        raising("NOT has_child_procedurally(NEW.id)"),
        raising("NOT has_children(NEW.id)"),
        "IF NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id) THEN
           RAISE NOTICE 'parent % has no child yet', NEW.id;
         END IF;"
            .to_owned(),
        format!(
            "IF NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id) THEN
               INSERT INTO audit VALUES (NEW.id);
             END IF; {}",
            raising("NEW.id < 0")
        ),
    ] {
        assert!(findings(&body, DEFERRED).is_empty(), "{body}");
    }
}

#[test]
fn a_trigger_function_in_another_language_is_not_read() {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{TABLES}
         CREATE FUNCTION check_parent() RETURNS trigger LANGUAGE plpython3u AS $$
           if not plpy.execute('SELECT FROM children'): raise Exception('parent requires a child')
         $$;
         {DEFERRED}"
    ))
    .expect("schema parses");
    let found = findings_in(&database);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_table_without_a_key_is_told_to_gain_one() {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{TABLES}
         CREATE TABLE drafts (parent_id INT);
         CREATE FUNCTION check_draft() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
           IF NOT EXISTS (SELECT FROM drafts WHERE parent_id = NEW.parent_id) THEN RETURN NULL; END IF;
           IF NOT has_child(NEW.parent_id) THEN RAISE EXCEPTION 'draft needs a child'; END IF;
           RETURN NULL; END $$;
         CREATE CONSTRAINT TRIGGER draft_checked AFTER INSERT ON drafts
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_draft();"
    ))
    .expect("schema parses");
    let found = findings_in(&database);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("Give 'drafts' a primary key"),
        "{found:?}"
    );
}

#[test]
fn a_check_meant_to_refuse_the_deletion_is_excused_on_its_table() {
    let database = schema(
        &raising("NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id)"),
        DEFERRED,
    );
    let mut constrainer: GenericConstrainer<ParserDB> = DeferredCheckDeletedRow::default().into();
    constrainer.allow_table(
        "deferred_check_deleted_row",
        TargetName::new("parents", false),
    );
    assert!(constrainer.validate_schema(&database).is_ok());
}

#[test]
fn a_live_catalog_answers_the_deferral_of_its_triggers() {
    let unguarded = raising("NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id)");
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        &format!(
            "{TABLES}
             CREATE FUNCTION check_parent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {unguarded} RETURN NULL; END $$;
             {DEFERRED}
             CREATE CONSTRAINT TRIGGER parent_fixed AFTER INSERT ON parents
               FOR EACH ROW EXECUTE FUNCTION check_parent();"
        ),
    );
    let found = findings_in(&database);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("'parent_checked'"), "{found:?}");
}
