//! `NOT IN` over nullable columns, time-dependent checks and impure
//! immutable functions, observed through the public constrainer API. The
//! behaviour each rule cites was measured on PostgreSQL 17.11 and 18.6.

use std::time::Duration;

use crate::rule_findings::findings;
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

fn objects<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    rule: &str,
    sql: &str,
) -> Vec<String> {
    findings(constrainer, rule, sql)
        .into_iter()
        .map(|(_, object, _)| object)
        .collect()
}

const PAIRS: &str = "CREATE TABLE a (id INT NOT NULL, team INT);
    CREATE TABLE b (a_id INT, team INT NOT NULL);";

#[test]
fn not_in_over_a_nullable_column_is_reported_wherever_it_is_written() {
    let constrainer: GenericConstrainer<ParserDB> = NotInNullableSubquery::default().into();
    let found = objects(
        &constrainer,
        "NotInNullableSubquery",
        &format!(
            "{PAIRS}
             ALTER TABLE a ENABLE ROW LEVEL SECURITY;
             CREATE VIEW v AS SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b);
             CREATE MATERIALIZED VIEW mv AS SELECT id FROM a WHERE id NOT IN (SELECT b.a_id FROM b);
             CREATE POLICY p ON a USING (id NOT IN (SELECT a_id FROM b));
             CREATE FUNCTION f() RETURNS SETOF INT LANGUAGE sql
               AS $$ SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b) $$;
             CREATE FUNCTION g(x INT) RETURNS BOOLEAN LANGUAGE sql
               RETURN x NOT IN (SELECT a_id FROM b);"
        ),
    );
    assert_eq!(found, ["v", "mv", "a.p", "f()", "g(INT)"]);
}

#[test]
fn not_in_over_non_null_or_filtered_columns_and_other_forms_pass() {
    let constrainer: GenericConstrainer<ParserDB> = NotInNullableSubquery::default().into();
    for view in [
        "SELECT id FROM a WHERE team NOT IN (SELECT team FROM b)",
        "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b WHERE (a_id IS NOT NULL AND team > 0))",
        "SELECT id FROM a WHERE id IN (SELECT a_id FROM b)",
        "SELECT id FROM a WHERE id NOT IN (SELECT a_id + 1 FROM b)",
        "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b UNION SELECT team FROM b)",
        "SELECT id FROM a WHERE id NOT IN (SELECT a_id, team FROM b)",
        "SELECT id FROM a WHERE id NOT IN (1, 2)",
        "SELECT id FROM a WHERE NOT EXISTS (SELECT 1 FROM b WHERE b.a_id = a.id)",
    ] {
        assert_eq!(
            objects(
                &constrainer,
                "NotInNullableSubquery",
                &format!("{PAIRS} CREATE VIEW v AS {view};")
            ),
            Vec::<String>::new(),
            "{view}"
        );
    }
}

#[test]
fn checks_that_can_turn_false_are_reported() {
    let constrainer: GenericConstrainer<ParserDB> = TimeDependentCheck::default().into();
    for check in [
        "at >= now()",
        "expires > current_date",
        "now() < at",
        "at < now() OR x < random() + 1",
        "x < random() + 1",
        "stable_limit() > x",
        "at::date > CURRENT_DATE - 1",
        "at <= now() + x * interval '1 minute'",
    ] {
        let found = findings(
            &constrainer,
            "TimeDependentCheck",
            &format!(
                "CREATE FUNCTION stable_limit() RETURNS INT LANGUAGE sql STABLE AS 'SELECT 1';
                 CREATE TABLE t (at TIMESTAMPTZ, expires DATE, x INT, CHECK ({check}));"
            ),
        );
        assert_eq!(found.len(), 1, "{check}: {found:?}");
        assert_eq!(found[0].0, Level::Warn);
    }
}

#[test]
fn upper_bounds_by_the_current_time_and_immutable_checks_pass() {
    let constrainer: GenericConstrainer<ParserDB> = TimeDependentCheck::default().into();
    for check in [
        "at <= now()",
        "at <= now() + interval '5 minutes'",
        "at < current_timestamp",
        "expires <= current_date",
        "now() >= at",
        "(at)::date <= (now() - interval '1 day')::date",
        "lower(name) = name",
        "doubled(x) > 0",
        "unknown_check(x)",
        "name <> current_user",
    ] {
        assert_eq!(
            findings(
                &constrainer,
                "TimeDependentCheck",
                &format!(
                    "CREATE FUNCTION doubled(v INT) RETURNS INT LANGUAGE sql IMMUTABLE AS 'SELECT v * 2';
                     CREATE TABLE t (at TIMESTAMPTZ, expires DATE, x INT, name TEXT, CHECK ({check}));"
                ),
            ),
            Vec::<(Level, String, String)>::new(),
            "{check}"
        );
    }
}

#[test]
fn immutable_functions_reading_what_can_change_are_reported() {
    let constrainer: GenericConstrainer<ParserDB> = ImpureImmutableFunction::default().into();
    let found = findings(
        &constrainer,
        "ImpureImmutableFunction",
        "CREATE TABLE rates (rate NUMERIC);
         CREATE FUNCTION rate() RETURNS NUMERIC LANGUAGE sql IMMUTABLE
           SET search_path = '' AS $$ SELECT max(rate) FROM public.rates $$;
         CREATE FUNCTION stamped(x INT) RETURNS TEXT LANGUAGE sql IMMUTABLE
           AS $$ SELECT x || now()::text $$;
         CREATE FUNCTION twice(x NUMERIC) RETURNS NUMERIC LANGUAGE sql IMMUTABLE AS $$ SELECT x * 2 $$;
         CREATE FUNCTION stable_rate() RETURNS NUMERIC LANGUAGE sql STABLE
           SET search_path = '' AS $$ SELECT max(rate) FROM public.rates $$;
         CREATE FUNCTION opaque(x INT) RETURNS INT LANGUAGE plpgsql IMMUTABLE
           AS $$ BEGIN RETURN (SELECT count(*) FROM rates); END $$;
         CREATE FUNCTION native(x INT) RETURNS INT LANGUAGE internal IMMUTABLE AS 'int4abs';",
    );
    let summary: Vec<(String, bool)> = found
        .into_iter()
        .map(|(_, object, message)| (object, message.contains("reads 'rates'")))
        .collect();
    assert_eq!(
        summary,
        [
            ("opaque(INT)".to_owned(), true),
            ("rate()".to_owned(), true),
            ("stamped(INT)".to_owned(), false)
        ]
    );
}

/// Resolution of every `PastTimeColumnRule` finding on `sql` under `deployment`.
fn past_time_resolutions(deployment: Deployment, sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = PastTimeColumnRule::default().into();
    constrainer.set_deployment(deployment);
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == "PastTimeColumnRule" => {
                Some(violation.resolution().to_owned())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn checks_bounding_the_column_by_the_current_time_from_above_keep_it_in_the_past() {
    for check in [
        "created_at <= now()",
        "created_at <= now() + interval '5 minutes'",
        "created_at < current_timestamp",
        "now() >= created_at",
        "(created_at <= now() AND x > 0)",
        "t.created_at <= now()",
        "(created_at) <= now()",
    ] {
        assert_eq!(
            past_time_resolutions(
                Deployment::default(),
                &format!("CREATE TABLE t (created_at TIMESTAMPTZ, x INT, CHECK ({check}));")
            ),
            Vec::<String>::new(),
            "{check}"
        );
    }
}

#[test]
fn checks_that_do_not_bound_the_column_from_above_leave_it_unchecked() {
    for check in [
        "now() < created_at",
        "created_at > now() - interval '1 day'",
        "created_at < now() OR x > 0",
        "created_at <= now() + x * interval '1 minute'",
        "created_at::date <= now()::date",
    ] {
        assert_eq!(
            past_time_resolutions(
                Deployment::default(),
                &format!("CREATE TABLE t (created_at TIMESTAMPTZ, x INT, CHECK ({check}));")
            )
            .len(),
            1,
            "{check}"
        );
    }
}

#[test]
fn the_suggested_check_adds_the_declared_device_clock_tolerance() {
    let sql = "CREATE TABLE t (created_at TIMESTAMPTZ);";
    let suggests = |deployment: Deployment, clause: &str| {
        let [resolution] = past_time_resolutions(deployment, sql)
            .try_into()
            .expect("one finding");
        assert!(resolution.contains(clause), "{resolution}");
        assert!(!resolution.contains("restore"), "{resolution}");
    };
    suggests(Deployment::default(), "`CHECK (created_at <= now())`");
    suggests(
        Deployment::default().with_clock_tolerance(Duration::ZERO),
        "`CHECK (created_at <= now())`",
    );
    for (tolerance, interval) in [
        (Duration::from_secs(300), "5 minutes"),
        (Duration::from_secs(60), "1 minute"),
        (Duration::from_secs(90), "90 seconds"),
        (Duration::from_millis(1500), "1500 milliseconds"),
        (Duration::from_micros(1500), "1500 microseconds"),
    ] {
        suggests(
            Deployment::default().with_clock_tolerance(tolerance),
            &format!("`CHECK (created_at <= now() + interval '{interval}')`"),
        );
    }
}

#[test]
fn the_default_constrainer_warns_for_each_rule() {
    let sql = format!(
        "{PAIRS}
         CREATE TABLE t (at TIMESTAMPTZ CHECK (at > now()));
         CREATE VIEW v AS SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b);
         CREATE FUNCTION f() RETURNS TIMESTAMPTZ LANGUAGE sql IMMUTABLE AS $$ SELECT now() $$;"
    );
    let constrainer = DefaultConstrainer::<ParserDB>::default();
    for rule in [
        "NotInNullableSubquery",
        "TimeDependentCheck",
        "ImpureImmutableFunction",
    ] {
        let found = findings(&constrainer, rule, &sql);
        assert_eq!(found.len(), 1, "{rule}");
        assert_eq!(found[0].0, Level::Warn, "{rule}");
    }
}
