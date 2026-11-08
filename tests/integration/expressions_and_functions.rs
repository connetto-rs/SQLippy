//! `NOT IN` over nullable columns, time-dependent checks and impure
//! immutable functions, observed through the public constrainer API. The
//! behaviour each rule cites was measured on PostgreSQL 17.11 and 18.6.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

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
