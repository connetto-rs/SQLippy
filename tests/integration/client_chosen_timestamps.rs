//! Event times a client role may write, unless a row trigger stamps them from
//! the database's clock, observed through the public constrainer API.

use crate::common::{ROLES, parse};
use sqlippy::prelude::*;

/// The resources table of the examples, with `app` revoked from writing it.
const RESOURCES: &str = "
    CREATE ROLE app;
    CREATE TABLE resources (id INTEGER PRIMARY KEY, name TEXT, archived_at TIMESTAMPTZ);
    REVOKE INSERT, UPDATE ON resources FROM app;";

/// The stamping trigger function `connetto-schema` ships for `archived_at`.
const STAMP_ARCHIVED_AT: &str = "
    CREATE FUNCTION stamp_archived_at() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
    BEGIN
      IF NEW.archived_at IS NOT NULL THEN
        IF TG_OP = 'UPDATE' AND OLD.archived_at IS NOT NULL THEN
          NEW.archived_at := OLD.archived_at;
        ELSE
          NEW.archived_at := now();
        END IF;
      END IF;
      RETURN NEW;
    END
    $$;";

fn app() -> Deployment {
    Deployment::default().with_app_role("app")
}

/// Object and message of every `client_chosen_timestamp` finding.
fn reported(deployment: Deployment, sql: &str) -> Vec<(String, String)> {
    let mut constrainer: GenericConstrainer<ParserDB> = ClientChosenTimestamp::default().into();
    constrainer.set_deployment(deployment);
    constrainer
        .diagnostics(&parse(&format!("{ROLES}{sql}")))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.object().to_owned(),
                violation.message().to_owned(),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

/// The commands the single finding on `resources.archived_at` names.
fn unstamped_commands(deployment: Deployment, sql: &str) -> Vec<&'static str> {
    let findings = reported(deployment, sql);
    let [(object, message)] = findings.as_slice() else {
        panic!("expected one finding, got {findings:?}");
    };
    assert_eq!(object, "resources.archived_at");
    ["INSERT", "UPDATE"]
        .into_iter()
        .filter(|command| message.contains(command))
        .collect()
}

/// A trigger running `function` before the `events` on `resources`.
fn trigger(events: &str, function: &str) -> String {
    format!(
        "CREATE TRIGGER stamp BEFORE {events} ON resources FOR EACH ROW EXECUTE FUNCTION {function}();"
    )
}

/// A trigger function named `stamp` with this PL/pgSQL body.
fn function(body: &str) -> String {
    format!("CREATE FUNCTION stamp() RETURNS trigger LANGUAGE plpgsql AS $$ {body} $$;")
}

#[test]
fn a_column_a_client_role_may_write_is_reported_for_each_writing_command() {
    assert_eq!(
        unstamped_commands(
            app(),
            "CREATE ROLE app; CREATE TABLE resources (id INTEGER PRIMARY KEY, archived_at TIMESTAMPTZ);"
        ),
        ["INSERT", "UPDATE"]
    );
    assert_eq!(
        unstamped_commands(
            app(),
            &format!("{RESOURCES} GRANT UPDATE (archived_at) ON resources TO app;")
        ),
        ["UPDATE"]
    );
    assert_eq!(
        unstamped_commands(
            app(),
            &format!(
                "{RESOURCES} CREATE ROLE archivers; GRANT archivers TO app;
                 GRANT INSERT ON resources TO archivers;"
            )
        ),
        ["INSERT"]
    );
}

#[test]
fn the_resolution_offers_a_trigger_for_the_written_commands_and_a_clock_check() {
    let mut constrainer: GenericConstrainer<ParserDB> = ClientChosenTimestamp::default().into();
    constrainer.set_deployment(app());
    let schema = parse(&format!(
        "{RESOURCES} GRANT UPDATE (archived_at) ON resources TO app;"
    ));
    let diagnostics = constrainer.diagnostics(&schema);
    let [Error::Violation(violation)] = diagnostics.as_slice() else {
        panic!("expected one finding, got {diagnostics:?}");
    };
    let resolution = violation.resolution();
    assert!(
        resolution.contains("`BEFORE UPDATE OF archived_at ON resources FOR EACH ROW`"),
        "{resolution}"
    );
    assert!(
        resolution.contains("`CHECK (archived_at <= now())`"),
        "{resolution}"
    );
}

#[test]
fn a_clock_check_accepts_a_column_a_client_role_may_write() {
    assert_eq!(
        reported(
            app(),
            &format!(
                "{RESOURCES} GRANT INSERT, UPDATE ON resources TO app;
                 ALTER TABLE resources ADD CHECK (archived_at <= now() + interval '6 hours');"
            )
        ),
        []
    );
}

#[test]
fn a_column_no_client_role_may_write_is_not_reported() {
    for sql in [
        RESOURCES.to_owned(),
        format!("{RESOURCES} GRANT UPDATE (name) ON resources TO app;"),
        format!("{RESOURCES} GRANT UPDATE (archived_at) ON resources TO reporting;"),
    ] {
        assert_eq!(reported(app(), &sql), [], "{sql}");
    }
}

#[test]
fn a_declared_role_the_schema_never_creates_may_write() {
    assert_eq!(
        unstamped_commands(
            Deployment::default().with_anonymous_role("visitor"),
            RESOURCES
        ),
        ["INSERT", "UPDATE"]
    );
}

#[test]
fn without_declared_client_roles_any_role_may_write() {
    assert_eq!(
        unstamped_commands(
            Deployment::default(),
            "CREATE TABLE resources (id INTEGER PRIMARY KEY, archived_at TIMESTAMPTZ DEFAULT now());"
        ),
        ["INSERT", "UPDATE"]
    );
}

#[test]
fn a_default_clock_does_not_stop_a_client_writing_the_column() {
    assert_eq!(
        unstamped_commands(
            app(),
            "CREATE ROLE app;
             CREATE TABLE resources (id INTEGER PRIMARY KEY, archived_at TIMESTAMPTZ DEFAULT now());
             GRANT INSERT ON resources TO app;"
        ),
        ["INSERT", "UPDATE"]
    );
}

#[test]
fn a_trigger_stamping_every_value_a_client_sets_covers_its_commands() {
    let writable = format!("{RESOURCES} GRANT INSERT, UPDATE ON resources TO app;");
    for stamping in [
        format!(
            "{STAMP_ARCHIVED_AT} {}",
            trigger("INSERT OR UPDATE OF archived_at", "stamp_archived_at")
        ),
        format!(
            "{} {}",
            function("BEGIN NEW.archived_at := now(); RETURN NEW; END"),
            trigger("INSERT OR UPDATE", "stamp")
        ),
        format!(
            "{} {}",
            function(
                "BEGIN NEW.archived_at = date_trunc('second', CURRENT_TIMESTAMP)::timestamptz; RETURN NEW; END"
            ),
            trigger("UPDATE OR INSERT", "stamp")
        ),
        format!(
            "{} {}",
            function(
                "BEGIN
                   IF NEW.archived_at IS NULL THEN RETURN NEW; END IF;
                   IF TG_OP = 'UPDATE' AND OLD.archived_at IS NOT NULL THEN
                     RAISE EXCEPTION 'archived_at is set once';
                   END IF;
                   NEW.archived_at := clock_timestamp();
                   RETURN NEW;
                 END"
            ),
            trigger("INSERT OR UPDATE", "stamp")
        ),
        format!(
            "{} {}",
            function(
                "BEGIN
                   IF NEW.archived_at IS NOT NULL AND NEW.name IS NULL THEN RETURN NULL;
                   ELSIF NEW.archived_at IS NOT NULL THEN NEW.archived_at := statement_timestamp();
                   END IF;
                   RETURN NEW;
                 END"
            ),
            trigger("INSERT OR UPDATE", "stamp")
        ),
        format!(
            "{} {} {}",
            function("BEGIN NEW.archived_at := transaction_timestamp(); RETURN NEW; END"),
            trigger("INSERT", "stamp"),
            "CREATE TRIGGER restamp BEFORE UPDATE OF name, archived_at ON resources
             FOR EACH ROW EXECUTE FUNCTION stamp();"
        ),
        format!(
            "{} {}",
            function("BEGIN BEGIN NEW.archived_at := now(); END; RETURN NEW; END"),
            trigger("INSERT OR UPDATE", "stamp")
        ),
        format!(
            "{} {}",
            function(
                "DECLARE
                   pending CURSOR FOR SELECT 1;
                   counted INT;
                 BEGIN
                   OPEN pending;
                   FETCH pending INTO counted;
                   MOVE pending;
                   CLOSE pending;
                   PERFORM 1;
                   ASSERT counted IS NOT NULL;
                   GET DIAGNOSTICS counted = ROW_COUNT;
                   RAISE NOTICE 'stamping %', counted;
                   IF (NEW.archived_at IS NULL) THEN RETURN (NEW); END IF;
                   NEW.archived_at := now();
                   RETURN NEW;
                 END"
            ),
            trigger("INSERT OR UPDATE", "stamp")
        ),
        format!(
            "{} {}",
            function(
                "BEGIN
                   CASE WHEN NEW.archived_at IS NULL THEN RETURN NEW;
                   ELSE NEW.archived_at := now();
                   END CASE;
                   CASE TG_OP WHEN 'INSERT' THEN NEW.archived_at := now();
                   ELSE NEW.archived_at := clock_timestamp();
                   END CASE;
                   RETURN NEW;
                 END"
            ),
            trigger("INSERT OR UPDATE", "stamp")
        ),
    ] {
        assert_eq!(
            reported(app(), &format!("{writable}{stamping}")),
            [],
            "{stamping}"
        );
    }
}

#[test]
fn a_case_without_else_refuses_the_commands_no_branch_stamps() {
    let body =
        "BEGIN CASE TG_OP WHEN 'INSERT' THEN NEW.archived_at := now(); END CASE; RETURN NEW; END";
    assert_eq!(
        reported(
            app(),
            &format!(
                "{RESOURCES} GRANT INSERT, UPDATE ON resources TO app; {} {}",
                function(body),
                trigger("INSERT OR UPDATE", "stamp")
            )
        ),
        []
    );
}

#[test]
fn a_trigger_keeping_a_value_the_client_chose_stamps_nothing() {
    let writable = format!("{RESOURCES} GRANT INSERT, UPDATE ON resources TO app;");
    for body in [
        "BEGIN IF NEW.archived_at IS NULL THEN NEW.archived_at := now(); END IF; RETURN NEW; END",
        "BEGIN IF NEW.archived_at IS NOT NULL THEN RETURN NEW; END IF; NEW.archived_at := now(); RETURN NEW; END",
        "BEGIN NEW.archived_at := now() - interval '1 year' * NEW.id; RETURN NEW; END",
        "BEGIN NEW.archived_at := GREATEST(NEW.archived_at, now()); RETURN NEW; END",
        "BEGIN NEW.archived_at := now(); NEW.archived_at := OLD.archived_at + interval '1 day'; RETURN NEW; END",
        "BEGIN IF NEW.name IS NULL THEN NEW.archived_at := now(); END IF; RETURN NEW; END",
        "BEGIN NEW.name := lower(NEW.name); RETURN NEW; END",
        "BEGIN NEW.archived_at := now(); RETURN OLD; END",
        "BEGIN FOR i IN 1..2 LOOP NEW.archived_at := now(); END LOOP; RETURN NEW; END",
        "BEGIN NEW.archived_at := now(); RETURN NEW; EXCEPTION WHEN others THEN RETURN NEW; END",
        "BEGIN SELECT NEW.archived_at INTO NEW.archived_at; RETURN NEW; END",
        "BEGIN NEW := OLD; NEW.archived_at := now(); RETURN NEW; END",
        "BEGIN NEW.archived_at[1] := now(); RETURN NEW; END",
        "DECLARE fresh ALIAS FOR NEW; BEGIN NEW.archived_at := now(); RETURN fresh; END",
        "BEGIN NEW.archived_at := now(); RETURN 1; END",
        "BEGIN CASE TG_OP WHEN 'INSERT' THEN NEW.archived_at := now(); ELSE END CASE; RETURN NEW; END",
        "BEGIN NEW.archived_at := now() RETURN NEW; END",
    ] {
        assert_eq!(
            unstamped_commands(
                app(),
                &format!(
                    "{writable}{} {}",
                    function(body),
                    trigger("INSERT OR UPDATE", "stamp")
                )
            ),
            ["INSERT", "UPDATE"],
            "{body}"
        );
    }
}

#[test]
fn a_trigger_function_in_another_language_stamps_nothing() {
    assert_eq!(
        unstamped_commands(
            app(),
            &format!(
                "{RESOURCES} GRANT INSERT, UPDATE ON resources TO app;
                 CREATE FUNCTION stamp() RETURNS trigger LANGUAGE plpython3u AS $$
                 TD['new']['archived_at'] = plpy.execute('SELECT now()')[0]['now']
                 return 'MODIFY'
                 $$;
                 {}",
                trigger("INSERT OR UPDATE", "stamp")
            )
        ),
        ["INSERT", "UPDATE"]
    );
}

#[test]
fn a_trigger_that_does_not_fire_before_each_written_row_covers_nothing() {
    let writable = format!(
        "{RESOURCES} GRANT INSERT, UPDATE ON resources TO app;
         {}",
        function("BEGIN NEW.archived_at := now(); RETURN NEW; END")
    );
    for (trigger, unstamped) in [
        (
            "CREATE TRIGGER stamp AFTER INSERT OR UPDATE ON resources FOR EACH ROW EXECUTE FUNCTION stamp();",
            &["INSERT", "UPDATE"][..],
        ),
        (
            "CREATE TRIGGER stamp BEFORE INSERT OR UPDATE ON resources FOR EACH STATEMENT EXECUTE FUNCTION stamp();",
            &["INSERT", "UPDATE"],
        ),
        (
            "CREATE TRIGGER stamp BEFORE INSERT ON resources FOR EACH ROW EXECUTE FUNCTION stamp();",
            &["UPDATE"],
        ),
        (
            "CREATE TRIGGER stamp BEFORE INSERT OR UPDATE OF name ON resources FOR EACH ROW EXECUTE FUNCTION stamp();",
            &["UPDATE"],
        ),
        (
            "CREATE TRIGGER stamp BEFORE UPDATE OR DELETE ON resources FOR EACH ROW EXECUTE FUNCTION stamp();",
            &["INSERT"],
        ),
    ] {
        assert_eq!(
            unstamped_commands(app(), &format!("{writable}{trigger}")),
            unstamped,
            "{trigger}"
        );
    }
}

/// A row trigger running `stamp` before `events` on `resources` when the
/// condition holds.
fn conditional_trigger(events: &str, condition: &str) -> String {
    format!(
        "CREATE TRIGGER stamp BEFORE {events} ON resources FOR EACH ROW WHEN ({condition}) EXECUTE FUNCTION stamp();"
    )
}

#[test]
fn a_condition_skipping_only_rows_without_a_chosen_value_keeps_the_trigger_stamping() {
    let writable = format!(
        "{RESOURCES} GRANT INSERT, UPDATE ON resources TO app;
         {}",
        function("BEGIN NEW.archived_at := now(); RETURN NEW; END")
    );
    for triggers in [
        conditional_trigger("INSERT OR UPDATE", "NEW.archived_at IS NOT NULL"),
        conditional_trigger(
            "INSERT OR UPDATE OF archived_at",
            "NOT (NEW.archived_at IS NULL) OR NEW.name IS NULL",
        ),
        format!(
            "{} CREATE TRIGGER stamp_insert BEFORE INSERT ON resources FOR EACH ROW EXECUTE FUNCTION stamp();",
            conditional_trigger(
                "UPDATE OF archived_at",
                "OLD.archived_at IS DISTINCT FROM NEW.archived_at"
            )
        ),
        conditional_trigger("INSERT OR UPDATE", "(NEW.archived_at IS NOT NULL)"),
        conditional_trigger(
            "INSERT OR UPDATE",
            "NEW.name IS NULL OR NEW.archived_at IS NOT NULL",
        ),
    ] {
        assert_eq!(
            reported(app(), &format!("{writable}{triggers}")),
            [],
            "{triggers}"
        );
    }
}

#[test]
fn a_condition_skipping_rows_with_a_chosen_value_stops_the_trigger_stamping() {
    let writable = format!(
        "{RESOURCES} GRANT INSERT, UPDATE ON resources TO app;
         {}",
        function("BEGIN NEW.archived_at := now(); RETURN NEW; END")
    );
    for (trigger, unstamped) in [
        (
            conditional_trigger("INSERT OR UPDATE", "NEW.archived_at IS NULL"),
            &["INSERT", "UPDATE"][..],
        ),
        (
            conditional_trigger("INSERT OR UPDATE", "NEW.name IS NOT NULL"),
            &["INSERT", "UPDATE"],
        ),
        (
            conditional_trigger(
                "INSERT OR UPDATE",
                "NEW.archived_at IS NOT NULL AND NEW.name IS NOT NULL",
            ),
            &["INSERT", "UPDATE"],
        ),
        (
            conditional_trigger("UPDATE", "OLD.archived_at <> NEW.archived_at"),
            &["INSERT", "UPDATE"],
        ),
        (
            conditional_trigger("UPDATE", "OLD.name IS DISTINCT FROM NEW.name"),
            &["INSERT", "UPDATE"],
        ),
    ] {
        assert_eq!(
            unstamped_commands(app(), &format!("{writable}{trigger}")),
            unstamped,
            "{trigger}"
        );
    }
}

#[test]
fn only_a_trigger_firing_in_client_sessions_stamps() {
    let stamped = format!(
        "{RESOURCES} GRANT INSERT, UPDATE ON resources TO app;
         {} {}",
        function("BEGIN NEW.archived_at := now(); RETURN NEW; END"),
        trigger("INSERT OR UPDATE", "stamp")
    );
    for (alteration, unstamped) in [
        ("", &[][..]),
        ("ALTER TABLE resources ENABLE ALWAYS TRIGGER stamp;", &[]),
        (
            "ALTER TABLE resources DISABLE TRIGGER stamp;",
            &["INSERT", "UPDATE"],
        ),
        (
            "ALTER TABLE resources DISABLE TRIGGER ALL;",
            &["INSERT", "UPDATE"],
        ),
        (
            "ALTER TABLE resources ENABLE REPLICA TRIGGER stamp;",
            &["INSERT", "UPDATE"],
        ),
    ] {
        let sql = format!("{stamped}{alteration}");
        let commands = if unstamped.is_empty() {
            assert_eq!(reported(app(), &sql), [], "{alteration}");
            Vec::new()
        } else {
            unstamped_commands(app(), &sql)
        };
        assert_eq!(commands, unstamped, "{alteration}");
    }
}

#[test]
fn names_of_future_instants_are_not_reported() {
    assert_eq!(
        reported(
            app(),
            "CREATE ROLE app; CREATE TABLE links (id INT, expires_at TIMESTAMPTZ, revoked_on TIMESTAMPTZ);"
        ),
        []
    );
}
