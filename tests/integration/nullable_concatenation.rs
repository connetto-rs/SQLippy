//! Nullable operands of scalar concatenation.

use sqlippy::prelude::*;

use crate::{
    common::parse,
    rule_findings::{findings, statement_objects},
};

const SCHEMA: &str = "CREATE TABLE people (id TEXT PRIMARY KEY, first TEXT NOT NULL, mid TEXT, nick VARCHAR, age INT, doc JSONB, tags TEXT[]);";

/// A constrainer running both sites of the rule.
fn rule() -> GenericConstrainer<ParserDB> {
    NullableConcatenation::default().into()
}

#[test]
fn nullable_concatenation_reports_views_and_materialized_views() {
    for kind in ["VIEW", "MATERIALIZED VIEW"] {
        let sql = format!(
            "{SCHEMA} CREATE {kind} names AS SELECT first || ' ' || mid AS name FROM people;"
        );
        let found = findings(&rule(), "nullable_concatenation", &sql);
        assert_eq!(found.len(), 1, "{sql}");
        assert_eq!(found[0].0, Level::Warn);
        assert!(found[0].2.contains("people.mid"), "{found:?}");
    }
}

#[test]
fn nullable_concatenation_reports_statements_and_scalar_types() {
    let database = parse(SCHEMA);
    for sql in [
        "SELECT first || ' ' || mid FROM people",
        "SELECT first || nick FROM people",
        "SELECT first || age FROM people",
        "SELECT doc || '{}'::jsonb FROM people",
        "SELECT p.first || p.mid FROM people AS p",
        "UPDATE people SET first = first || mid",
        "INSERT INTO people (first) SELECT first || mid FROM people",
        "SELECT (SELECT p.mid || '!' FROM people p)",
        "SELECT '!' || (first || mid) FROM people",
        "SELECT upper(first || mid) FROM people",
        "DELETE FROM people RETURNING mid || '!'",
        "UPDATE people SET first = 'x' RETURNING mid || '!'",
        "SELECT first FROM people WHERE mid || '!' = '!'",
        "WITH names AS (SELECT mid FROM people) SELECT mid || '!' FROM names",
        "SELECT middle || '!' FROM (SELECT mid AS middle FROM people) names",
    ] {
        assert_eq!(statement_objects(&rule(), &database, sql).len(), 1, "{sql}");
    }
}

#[test]
fn nullable_concatenation_excludes_arrays_and_protected_columns() {
    let database = parse(SCHEMA);
    for sql in [
        "SELECT first || id FROM people",
        "SELECT concat(first, mid), concat_ws(' ', first, mid) FROM people",
        "SELECT first || coalesce(mid, '') FROM people",
        "SELECT tags || mid FROM people",
        "SELECT mid || ARRAY['a'] FROM people",
        "SELECT mid || NULL::text[] FROM people",
        "SELECT mid || 'x' || ARRAY['a'] FROM people",
        "SELECT (mid || 'x') || coalesce(tags, ARRAY['a']) FROM people",
        "SELECT mid || (SELECT tags FROM people LIMIT 1) FROM people",
        "SELECT a.first || b.id FROM people a LEFT JOIN people b ON a.id = b.id",
        "SELECT middle || '!' FROM (SELECT coalesce(mid, '') AS middle FROM people) names",
        "SELECT 'a' || 'b'",
    ] {
        assert!(
            statement_objects(&rule(), &database, sql).is_empty(),
            "{sql}"
        );
    }
}

#[test]
fn nullable_concatenation_reports_generated_columns() {
    let sql = "CREATE TABLE people (mid TEXT, label TEXT GENERATED ALWAYS AS (mid || '!') STORED);";
    assert_eq!(
        findings(&rule(), "nullable_concatenation", sql).len(),
        1,
        "{sql}"
    );
}

#[test]
fn nullable_concatenation_reports_sql_function_bodies() {
    for body in [
        "AS $$ SELECT first || mid FROM people $$",
        "RETURN (SELECT first || mid FROM people)",
        "BEGIN ATOMIC SELECT first || mid FROM people; END",
    ] {
        let sql = format!("{SCHEMA} CREATE FUNCTION label() RETURNS TEXT LANGUAGE SQL {body};");
        assert_eq!(
            findings(&rule(), "nullable_concatenation", &sql).len(),
            1,
            "{sql}"
        );
    }
    let sql =
        "CREATE FUNCTION label(mid TEXT) RETURNS TEXT LANGUAGE SQL AS $$ SELECT mid || '!' $$;";
    assert_eq!(
        findings(&rule(), "nullable_concatenation", sql),
        Vec::<(Level, String, String)>::new()
    );
}

#[test]
fn nullable_concatenation_reports_plpgsql_function_bodies() {
    let sql = format!(
        "{SCHEMA} CREATE FUNCTION label() RETURNS SETOF TEXT LANGUAGE plpgsql
           AS $$ BEGIN RETURN QUERY SELECT first || mid FROM people; END $$;"
    );
    assert_eq!(findings(&rule(), "nullable_concatenation", &sql).len(), 1);
}

#[test]
fn nullable_concatenation_does_not_parse_foreign_function_bodies_as_sql() {
    let sql = format!(
        "{SCHEMA} CREATE FUNCTION label() RETURNS TEXT LANGUAGE plperl
         AS $$ SELECT first || mid FROM people $$;"
    );
    assert_eq!(
        findings(&rule(), "nullable_concatenation", &sql),
        Vec::<(Level, String, String)>::new()
    );
}

#[test]
fn nullable_concatenation_reports_plpgsql_expression_sites() {
    for body in [
        "DECLARE label TEXT := (SELECT first || mid FROM people);
         BEGIN RETURN; END",
        "BEGIN BEGIN PERFORM first || mid FROM people; END; END",
        "BEGIN PERFORM 1;
         EXCEPTION WHEN division_by_zero THEN PERFORM first || mid FROM people; END",
        "BEGIN EXECUTE (SELECT first || mid FROM people); END",
        "BEGIN EXECUTE 'SELECT $1' USING (SELECT first || mid FROM people); END",
        "BEGIN IF (SELECT first || mid FROM people) IS NULL THEN RETURN; END IF; END",
        "BEGIN IF FALSE THEN RETURN;
         ELSIF (SELECT first || mid FROM people) IS NULL THEN RETURN; END IF; END",
        "BEGIN IF TRUE THEN PERFORM first || mid FROM people; END IF; END",
        "BEGIN IF FALSE THEN RETURN; ELSE PERFORM first || mid FROM people; END IF; END",
        "BEGIN CASE (SELECT first || mid FROM people)
         WHEN 'label' THEN RETURN; ELSE RETURN; END CASE; END",
        "BEGIN CASE WHEN (SELECT first || mid FROM people) IS NULL
         THEN RETURN; ELSE RETURN; END CASE; END",
        "BEGIN CASE WHEN TRUE THEN PERFORM first || mid FROM people;
         ELSE RETURN; END CASE; END",
        "BEGIN CASE WHEN FALSE THEN RETURN;
         ELSE PERFORM first || mid FROM people; END CASE; END",
        "BEGIN LOOP PERFORM first || mid FROM people; EXIT; END LOOP; END",
        "BEGIN WHILE (SELECT first || mid FROM people) IS NULL LOOP EXIT; END LOOP; END",
        "DECLARE label TEXT;
         BEGIN FOR label IN SELECT first || mid FROM people LOOP NULL; END LOOP; END",
        "DECLARE label TEXT;
         BEGIN FOREACH label IN ARRAY ARRAY[(SELECT first || mid FROM people)]
         LOOP NULL; END LOOP; END",
        "BEGIN FOR counter IN length((SELECT first || mid FROM people))..10
         LOOP NULL; END LOOP; END",
        "BEGIN FOR counter IN 1..length((SELECT first || mid FROM people))
         LOOP NULL; END LOOP; END",
        "BEGIN FOR counter IN 1..10 BY length((SELECT first || mid FROM people))
         LOOP NULL; END LOOP; END",
        "DECLARE labels CURSOR FOR SELECT first || mid FROM people;
         BEGIN FOR label IN labels LOOP NULL; END LOOP; END",
        "DECLARE labels CURSOR (label TEXT) FOR SELECT label;
         BEGIN FOR item IN labels((SELECT first || mid FROM people))
         LOOP NULL; END LOOP; END",
        "DECLARE label TEXT;
         BEGIN FOR label IN EXECUTE (SELECT first || mid FROM people)
         LOOP NULL; END LOOP; END",
        "DECLARE label TEXT;
         BEGIN FOR label IN EXECUTE 'SELECT $1' USING (SELECT first || mid FROM people)
         LOOP NULL; END LOOP; END",
        "DECLARE label TEXT;
         BEGIN SELECT first || mid INTO label FROM people; END",
        "DECLARE label TEXT;
         BEGIN EXECUTE (SELECT first || mid FROM people) INTO label; END",
        "DECLARE label TEXT;
         BEGIN label := (SELECT first || mid FROM people); END",
        "DECLARE labels TEXT[];
         BEGIN labels[length((SELECT first || mid FROM people))] := 'label'; END",
        "DECLARE labels TEXT[];
         BEGIN labels[1:length((SELECT first || mid FROM people))] := ARRAY['label']; END",
        "BEGIN LOOP EXIT WHEN (SELECT first || mid FROM people) IS NULL; END LOOP; END",
        "BEGIN LOOP CONTINUE WHEN (SELECT first || mid FROM people) IS NULL; EXIT; END LOOP; END",
        "BEGIN RAISE NOTICE '%', (SELECT first || mid FROM people); END",
        "BEGIN RAISE EXCEPTION USING MESSAGE = (SELECT first || mid FROM people); END",
        "BEGIN ASSERT (SELECT first || mid FROM people) IS NULL; END",
        "BEGIN ASSERT TRUE, (SELECT first || mid FROM people); END",
        "DECLARE labels CURSOR FOR SELECT first || mid FROM people;
         BEGIN OPEN labels; END",
        "DECLARE labels CURSOR (label TEXT) FOR SELECT label;
         BEGIN OPEN labels((SELECT first || mid FROM people)); END",
        "DECLARE labels REFCURSOR;
         BEGIN OPEN labels FOR SELECT first || mid FROM people; END",
        "DECLARE labels REFCURSOR;
         BEGIN OPEN labels FOR EXECUTE (SELECT first || mid FROM people); END",
        "DECLARE labels REFCURSOR;
         BEGIN OPEN labels FOR EXECUTE 'SELECT $1' USING (SELECT first || mid FROM people); END",
        "DECLARE labels REFCURSOR; label TEXT;
         BEGIN FETCH RELATIVE length((SELECT first || mid FROM people)) FROM labels INTO label;
         END",
    ] {
        let sql = format!(
            "{SCHEMA} CREATE FUNCTION label() RETURNS VOID LANGUAGE plpgsql AS $$ {body} $$;"
        );
        assert_eq!(
            findings(&rule(), "nullable_concatenation", &sql).len(),
            1,
            "{body}"
        );
    }
}

#[test]
fn nullable_concatenation_reports_plpgsql_returned_values() {
    let sql = format!(
        "{SCHEMA} CREATE FUNCTION label() RETURNS TEXT LANGUAGE plpgsql
           AS $$ BEGIN RETURN (SELECT first || mid FROM people); END $$;"
    );
    assert_eq!(findings(&rule(), "nullable_concatenation", &sql).len(), 1);
}

#[test]
fn nullable_concatenation_ignores_policies_checks_and_view_filters() {
    let sql = format!(
        "{SCHEMA}
        CREATE POLICY p ON people USING (mid || '!' = '!');
        CREATE TABLE checked (mid TEXT CHECK (mid || '!' = '!'));
        CREATE VIEW names AS SELECT first FROM people WHERE mid || '!' = '!';"
    );
    assert_eq!(
        findings(&rule(), "nullable_concatenation", &sql),
        Vec::<(Level, String, String)>::new()
    );
}

#[test]
fn nullable_concatenation_does_not_judge_domain_columns() {
    let sql = "CREATE DOMAIN nullable_name AS TEXT;
        CREATE TABLE people (optional nullable_name);
        CREATE VIEW names AS SELECT optional || '!' FROM people;";
    assert_eq!(
        findings(&rule(), "nullable_concatenation", sql),
        Vec::<(Level, String, String)>::new()
    );
}

#[test]
fn nullable_concatenation_does_not_treat_function_parameters_as_columns() {
    let sql = format!("{SCHEMA}
        CREATE FUNCTION label(mid TEXT) RETURNS TEXT LANGUAGE SQL AS $$ SELECT mid || '!' $$;
        CREATE FUNCTION bound(mid TEXT) RETURNS TEXT LANGUAGE SQL AS $$ SELECT people.mid || '!' FROM people $$;");
    assert_eq!(findings(&rule(), "nullable_concatenation", &sql).len(), 1);
}

#[test]
fn nullable_concatenation_reports_independent_chains_inside_calls() {
    assert_eq!(
        statement_objects(
            &rule(),
            &parse(SCHEMA),
            "SELECT mid || upper(nick || '!') FROM people"
        )
        .len(),
        2
    );
}

#[test]
fn nullable_concatenation_does_not_judge_unknown_operand_types() {
    assert_eq!(
        statement_objects(
            &rule(),
            &parse(SCHEMA),
            "SELECT mid || unknown_function() FROM people"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn nullable_concatenation_excludes_not_null_domains_in_postgres() {
    use diesel::{Connection, PgConnection, connection::SimpleConnection};
    use pg_diesel::{PgDieselDatabase, database::PgDieselDatabaseBuilder};
    use testcontainers::{
        GenericImage, ImageExt,
        core::{IntoContainerPort, WaitFor},
        runners::SyncRunner,
    };

    let container = GenericImage::new("postgres", "18-alpine")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", "user")
        .with_env_var("POSTGRES_PASSWORD", "password")
        .with_env_var("POSTGRES_DB", "concat")
        .with_startup_timeout(std::time::Duration::from_secs(120))
        .start()
        .expect("PostgreSQL starts");
    let host = container.get_host().expect("container host");
    let port = container
        .get_host_port_ipv4(5432)
        .expect("published PostgreSQL port");
    let mut connection = PgConnection::establish(&format!(
        "host={host} port={port} user=user password=password dbname=concat connect_timeout=10 options='-c statement_timeout=30000'"
    )).expect("PostgreSQL connection");
    connection
        .batch_execute(
            "CREATE SCHEMA concatenation;
         CREATE DOMAIN concatenation.nonnull_name AS TEXT NOT NULL;
         CREATE TABLE concatenation.people (name concatenation.nonnull_name, middle TEXT);
         CREATE VIEW concatenation.names AS SELECT name || '!' AS label FROM concatenation.people;",
        )
        .expect("fixture applies");
    let database = PgDieselDatabase::try_from(
        PgDieselDatabaseBuilder::default()
            .connection(&mut connection)
            .catalog("concat")
            .schema("concatenation"),
    )
    .expect("live catalog loads");
    let constrainer: GenericConstrainer<PgDieselDatabase> = NullableConcatenation::default().into();
    let errors = constrainer.diagnostics(&database);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(
        constrainer
            .statement_diagnostics(
                &database,
                &crate::rule_findings::statement("SELECT middle || '!' FROM concatenation.people")
            )
            .len(),
        1
    );
}
