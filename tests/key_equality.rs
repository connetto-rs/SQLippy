//! Keys over types without exact equality, observed through the public
//! constrainer API. Each refused or missed key was measured on PostgreSQL 17
//! and 18.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Level and column of every finding of the rule, failing on any error other
/// than a rule the deployment leaves inactive.
fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    sql: &str,
) -> Vec<(Level, String)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let mut found: Vec<(Level, String)> = constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) => (violation.rule().name == "KeyWithoutExactEquality")
                .then(|| (violation.level(), violation.object().to_owned())),
            Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    found.sort();
    found
}

fn columns(sql: &str) -> Vec<String> {
    findings(
        &GenericConstrainer::from(KeyWithoutExactEquality::default()),
        sql,
    )
    .into_iter()
    .map(|(_, column)| column)
    .collect()
}

#[test]
fn every_key_kind_over_an_interval_or_a_float_is_reported() {
    assert_eq!(
        columns(
            "CREATE TABLE spans (span INTERVAL PRIMARY KEY);
             CREATE TABLE readings (id INT PRIMARY KEY, value DOUBLE PRECISION UNIQUE);
             CREATE TABLE samples (at REAL, site TEXT, PRIMARY KEY (site, at));
             CREATE TABLE samples_by_mark (mark FLOAT8 PRIMARY KEY);
             CREATE TABLE marks (mark FLOAT8 REFERENCES samples_by_mark);
             CREATE TABLE weights (id INT PRIMARY KEY, weight FLOAT4);
             CREATE UNIQUE INDEX weights_weight ON weights (weight);
             CREATE TABLE lengths (id INT PRIMARY KEY, length INTERVAL);
             CREATE UNIQUE INDEX lengths_length ON lengths ((lengths.length));",
        ),
        [
            "lengths.length",
            "marks.mark",
            "readings.value",
            "samples.at",
            "samples_by_mark.mark",
            "spans.span",
            "weights.weight",
        ]
    );
}

#[test]
fn a_column_in_several_keys_is_reported_for_each() {
    assert_eq!(
        columns(
            "CREATE TABLE parents (span INTERVAL PRIMARY KEY);
             CREATE TABLE children (span INTERVAL PRIMARY KEY REFERENCES parents);",
        ),
        ["children.span", "children.span", "parents.span"]
    );
}

#[test]
fn arrays_of_intervals_or_floats_are_keys_without_exact_equality() {
    assert_eq!(
        columns(
            "CREATE TABLE schedules (id INT PRIMARY KEY, spans INTERVAL[] UNIQUE);
             CREATE TABLE vectors (coordinates FLOAT8[] PRIMARY KEY);",
        ),
        ["schedules.spans", "vectors.coordinates"]
    );
}

#[test]
fn domains_over_intervals_or_floats_and_arrays_of_them_are_keys_without_exact_equality() {
    assert_eq!(
        columns(
            "CREATE DOMAIN span AS INTERVAL;
             CREATE DOMAIN short_span AS span;
             CREATE DOMAIN spans AS INTERVAL[];
             CREATE DOMAIN code AS TEXT;
             CREATE TABLE direct (key span PRIMARY KEY);
             CREATE TABLE chained (key short_span PRIMARY KEY);
             CREATE TABLE listed (key spans PRIMARY KEY);
             CREATE TABLE arrayed (key span[] PRIMARY KEY);
             CREATE TABLE coded (key code PRIMARY KEY);",
        ),
        ["arrayed.key", "chained.key", "direct.key", "listed.key"]
    );
}

#[test]
fn exact_keys_ordinary_columns_and_expression_or_plain_indices_pass() {
    assert_eq!(
        columns(
            "CREATE TABLE events (
               id BIGINT PRIMARY KEY,
               code TEXT UNIQUE,
               token UUID UNIQUE,
               amount NUMERIC(12, 2) UNIQUE,
               duration INTERVAL,
               score DOUBLE PRECISION
             );
             CREATE INDEX events_score ON events (score);
             CREATE UNIQUE INDEX events_score_text ON events ((score::text), code);",
        ),
        Vec::<String>::new()
    );
}

#[test]
fn the_default_constrainer_warns() {
    assert_eq!(
        findings(
            &DefaultConstrainer::<ParserDB>::default(),
            "CREATE TABLE spans (span INTERVAL PRIMARY KEY);",
        ),
        [(Level::Warn, "spans.span".to_owned())]
    );
}
