//! Data types and temporal constructs, observed through the public
//! constrainer API wherever the schema holds them. The behaviour each rule
//! cites was measured on PostgreSQL 17.11 and 18.6.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Rule, level, object and message of every type finding.
fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    sql: &str,
) -> Vec<(String, Level, String, String)> {
    const TYPE_RULES: [&str; 8] = [
        "TimestampWithoutTimeZone",
        "TimeWithTimeZone",
        "ZeroPrecisionTimestamp",
        "BlankPaddedCharacter",
        "MoneyType",
        "JsonType",
        "ScaledNumeric",
        "ClientWrittenScaledNumeric",
    ];
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if TYPE_RULES.contains(&violation.rule().name) => Some((
                violation.rule().name.to_owned(),
                violation.level(),
                violation.object().to_owned(),
                violation.message().to_owned(),
            )),
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn every_rule() -> DefaultConstrainer<ParserDB> {
    let mut constrainer = DefaultConstrainer::default();
    constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
    constrainer.set_deployment(Deployment::default().with_client_written_table("public", "synced"));
    constrainer
}

/// Rule and object of every type finding under every rule.
fn reported(sql: &str) -> Vec<(String, String)> {
    findings(&every_rule(), sql)
        .into_iter()
        .map(|(rule, _, object, _)| (rule, object))
        .collect()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected
        .iter()
        .map(|(rule, object)| ((*rule).to_owned(), (*object).to_owned()))
        .collect()
}

#[test]
fn flawed_column_types_are_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a TIMESTAMP, b TIMESTAMP(3) WITHOUT TIME ZONE, c TIMETZ,
               d TIME WITH TIME ZONE, e TIMESTAMPTZ(0), f CHAR(5), g CHARACTER(2), h MONEY,
               i JSON, j NUMERIC(10, 2), k DECIMAL(5, 1), l JSON[], m TIMESTAMP(0), n NUMERIC(10));"
        ),
        pairs(&[
            ("TimestampWithoutTimeZone", "t.a"),
            ("TimestampWithoutTimeZone", "t.b"),
            ("TimestampWithoutTimeZone", "t.m"),
            ("TimeWithTimeZone", "t.c"),
            ("TimeWithTimeZone", "t.d"),
            ("ZeroPrecisionTimestamp", "t.e"),
            ("ZeroPrecisionTimestamp", "t.m"),
            ("BlankPaddedCharacter", "t.f"),
            ("BlankPaddedCharacter", "t.g"),
            ("MoneyType", "t.h"),
            ("JsonType", "t.i"),
            ("JsonType", "t.l"),
            ("ScaledNumeric", "t.j"),
            ("ScaledNumeric", "t.k"),
            ("ScaledNumeric", "t.n"),
        ])
    );
}

#[test]
fn sound_types_pass() {
    assert_eq!(
        reported(
            "CREATE TABLE t (a TIMESTAMPTZ, b TIMESTAMPTZ(3), c TIME, d VARCHAR(5), e TEXT,
               f JSONB, g NUMERIC, i BPCHAR, j INTEGER[], k DATE);"
        ),
        Vec::<(String, String)>::new()
    );
}

#[test]
fn casts_calls_and_declared_types_elsewhere_are_reported() {
    assert_eq!(
        reported(
            "CREATE DOMAIN stamp AS TIMESTAMP;
             CREATE TABLE t (at TIMESTAMPTZ DEFAULT now()::timestamptz(0), lunch TIME DEFAULT CURRENT_TIME,
               amount NUMERIC CHECK (amount::money > 0::money));
             ALTER TABLE t ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON t USING (at > '2020-01-01'::timestamp);
             CREATE VIEW v AS SELECT at::date, '{}'::json AS doc, '{}'::json[] AS docs, now()::timetz AS clock FROM t;
             CREATE MATERIALIZED VIEW mv AS SELECT CAST(at AS TIMESTAMP) FROM t;
             CREATE FUNCTION f(x CHAR(3)) RETURNS JSON LANGUAGE sql
               AS $$ SELECT CAST(x AS NUMERIC(4, 1))::text::json $$;
             CREATE FUNCTION g() RETURNS TEXT LANGUAGE sql RETURN TIMESTAMP '2020-01-01 00:00'::text;
             CREATE FUNCTION h() RETURNS TEXT LANGUAGE plpgsql
               AS $$ BEGIN RETURN now()::timestamp::text; END $$;"
        ),
        pairs(&[
            ("TimestampWithoutTimeZone", "t.p"),
            ("TimestampWithoutTimeZone", "stamp"),
            ("TimestampWithoutTimeZone", "mv"),
            ("TimestampWithoutTimeZone", "g()"),
            ("TimeWithTimeZone", "t.lunch"),
            ("TimeWithTimeZone", "v"),
            ("ZeroPrecisionTimestamp", "t.at"),
            ("BlankPaddedCharacter", "f(CHAR)"),
            ("MoneyType", "t"),
            ("MoneyType", "t"),
            ("JsonType", "v"),
            ("JsonType", "v"),
            ("JsonType", "f(CHAR)"),
            ("JsonType", "f(CHAR)"),
            ("ScaledNumeric", "f(CHAR)"),
        ])
    );
}

#[test]
fn client_written_tables_get_the_echo_and_the_suspicious_numeric_rule() {
    let found = findings(
        &every_rule(),
        "CREATE TABLE synced (a TIMESTAMPTZ(0), b CHAR(2), c JSON, d NUMERIC(10, 2),
           CHECK (b::CHAR(2) <> ''));
         ALTER TABLE synced ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON synced USING (c::text::json IS NOT NULL);
         CREATE TABLE other (a TIMESTAMPTZ(0), d NUMERIC(10, 2));",
    );
    let summary: Vec<(String, Level, String, bool)> = found
        .into_iter()
        .map(|(rule, level, object, message)| (rule, level, object, message.contains("echo")))
        .collect();
    let expected: Vec<(String, Level, String, bool)> = [
        ("ZeroPrecisionTimestamp", Level::Warn, "other.a", false),
        ("ZeroPrecisionTimestamp", Level::Warn, "synced.a", true),
        ("BlankPaddedCharacter", Level::Warn, "synced.b", true),
        ("BlankPaddedCharacter", Level::Warn, "synced", true),
        ("JsonType", Level::Warn, "synced.c", true),
        ("JsonType", Level::Warn, "synced.p", true),
        ("ScaledNumeric", Level::Warn, "other.d", false),
        ("ClientWrittenScaledNumeric", Level::Warn, "synced.d", true),
    ]
    .into_iter()
    .map(|(rule, level, object, echo)| (rule.to_owned(), level, object.to_owned(), echo))
    .collect();
    assert_eq!(summary, expected);
}

#[test]
fn a_rule_registered_alone_runs_at_warn() {
    let constrainer: GenericConstrainer<ParserDB> = ScaledNumeric::default().into();
    assert_eq!(
        findings(&constrainer, "CREATE TABLE t (x NUMERIC(4, 2));")
            .into_iter()
            .map(|(rule, level, _, _)| (rule, level))
            .collect::<Vec<_>>(),
        [("ScaledNumeric".to_owned(), Level::Warn)]
    );
}

#[test]
fn the_default_constrainer_applies_each_group() {
    let found = findings(
        &DefaultConstrainer::<ParserDB>::default(),
        "CREATE TABLE t (a TIMESTAMP, b JSON, c NUMERIC(4, 2));",
    );
    let levels: Vec<(String, Level)> = found
        .into_iter()
        .map(|(rule, level, _, _)| (rule, level))
        .collect();
    assert_eq!(
        levels,
        [
            ("TimestampWithoutTimeZone".to_owned(), Level::Warn),
            ("JsonType".to_owned(), Level::Warn),
        ]
    );
}
