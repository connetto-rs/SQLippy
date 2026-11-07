//! Statement rules that read column types, observed through the public
//! constrainer API. The behaviour each rule cites was measured on PostgreSQL
//! 17.11 and 18.6.

use crate::{
    common::parse,
    rule_findings::{check_query_rule, statement_findings},
};
use sql_rules::prelude::*;

const EVENTS: &str = "CREATE TABLE events (
    id INT PRIMARY KEY,
    at TIMESTAMPTZ,
    local_at TIMESTAMP,
    day DATE,
    slot TIME,
    score INT,
    total BIGINT,
    ratio NUMERIC
);";

#[test]
fn between_on_a_time_column_is_reported() {
    check_query_rule(
        EVENTS,
        TimestampBetween::default(),
        &[
            (
                "SELECT id FROM events WHERE at BETWEEN '2026-01-01' AND '2026-01-02'",
                &["at BETWEEN '2026-01-01' AND '2026-01-02'"],
            ),
            (
                "SELECT id FROM events WHERE local_at NOT BETWEEN $1 AND $2",
                &["local_at NOT BETWEEN $1 AND $2"],
            ),
            (
                "SELECT id FROM events WHERE slot BETWEEN '09:00' AND '17:00'",
                &["slot BETWEEN '09:00' AND '17:00'"],
            ),
            (
                "SELECT e.id FROM events AS e JOIN events AS f ON f.at BETWEEN e.at AND e.at + INTERVAL '1 day'",
                &["f.at BETWEEN e.at AND e.at + INTERVAL '1 day'"],
            ),
            (
                "SELECT id FROM events WHERE id IN (SELECT id FROM events WHERE at BETWEEN $1 AND $2)",
                &["at BETWEEN $1 AND $2"],
            ),
            (
                "DELETE FROM events WHERE at BETWEEN $1 AND $2",
                &["at BETWEEN $1 AND $2"],
            ),
            (
                "UPDATE events SET score = score + 1 WHERE at BETWEEN $1 AND $2",
                &["at BETWEEN $1 AND $2"],
            ),
            (
                "WITH recent AS (SELECT 1 AS one) UPDATE events SET score = 0 WHERE slot BETWEEN $1 AND $2",
                &["slot BETWEEN $1 AND $2"],
            ),
            (
                "SELECT d.x FROM (SELECT at AS x FROM events) AS d WHERE d.x BETWEEN $1 AND $2",
                &["d.x BETWEEN $1 AND $2"],
            ),
            (
                "SELECT d.x FROM (SELECT at::TIMESTAMP AS x FROM events) AS d WHERE d.x BETWEEN $1 AND $2",
                &["d.x BETWEEN $1 AND $2"],
            ),
            (
                "SELECT id FROM events WHERE at BETWEEN $1 AND $2 UNION SELECT id FROM events WHERE slot BETWEEN $3 AND $4",
                &["at BETWEEN $1 AND $2", "slot BETWEEN $3 AND $4"],
            ),
            ("SELECT id FROM events WHERE day BETWEEN $1 AND $2", &[]),
            ("SELECT id FROM events WHERE score BETWEEN 1 AND 10", &[]),
            (
                "SELECT id FROM events WHERE at::date BETWEEN $1 AND $2",
                &[],
            ),
            ("SELECT id FROM events WHERE at >= $1 AND at < $2", &[]),
            (
                "SELECT g FROM generate_series(1, 3) AS g WHERE g BETWEEN 1 AND 2",
                &[],
            ),
            ("INSERT INTO events (id) VALUES (1)", &[]),
            ("SET TIME ZONE 'UTC'", &[]),
        ],
    );
}

#[test]
fn results_that_depend_on_the_session_time_zone_are_reported() {
    check_query_rule(
        EVENTS,
        SessionTimeZoneDependence::default(),
        &[
            ("SELECT at::date FROM events", &["at::DATE"]),
            (
                "UPDATE events SET day = at::date WHERE id = $1",
                &["at::DATE"],
            ),
            ("SELECT CAST(at AS TIME) FROM events", &["CAST(at AS TIME)"]),
            (
                "SELECT date_trunc('day', at) FROM events",
                &["date_trunc('day', at)"],
            ),
            (
                "SELECT id FROM events WHERE local_at < now()",
                &["local_at < now()"],
            ),
            (
                "SELECT id FROM events WHERE local_at = at",
                &["local_at = at"],
            ),
            (
                "SELECT id FROM events WHERE CURRENT_TIMESTAMP > (local_at)",
                &["CURRENT_TIMESTAMP > (local_at)"],
            ),
            (
                "SELECT id FROM events WHERE local_at < local_at::TIMESTAMPTZ",
                &["local_at < local_at::TIMESTAMPTZ"],
            ),
            ("SELECT (at AT TIME ZONE 'UTC')::date FROM events", &[]),
            ("SELECT date_trunc('day', at, 'UTC') FROM events", &[]),
            ("SELECT local_at::date FROM events", &[]),
            ("SELECT id FROM events WHERE at < now()", &[]),
            ("SELECT id FROM events WHERE local_at < localtimestamp", &[]),
            ("SELECT id FROM events WHERE local_at < at::TIMESTAMP", &[]),
            ("SELECT id FROM events WHERE local_at > $1", &[]),
            ("SELECT id FROM events WHERE score < total", &[]),
            ("SELECT score::NUMERIC FROM events", &[]),
        ],
    );
}

#[test]
fn integer_division_scaled_afterwards_is_reported() {
    check_query_rule(
        EVENTS,
        TruncatingIntegerDivision::default(),
        &[
            (
                "SELECT score / total * 100 FROM events",
                &["score / total * 100"],
            ),
            (
                "SELECT (score / total) * 100 FROM events",
                &["(score / total) * 100"],
            ),
            ("SELECT score / 3 * 100 FROM events", &["score / 3 * 100"]),
            (
                "SELECT id FROM events WHERE ratio::INT / CAST(total AS SMALLINT) * 10 > 5",
                &["ratio::INT / CAST(total AS SMALLINT) * 10"],
            ),
            ("SELECT score * 100 / total FROM events", &[]),
            ("SELECT score / total FROM events", &[]),
            ("SELECT ratio / total * 100 FROM events", &[]),
            ("SELECT score::NUMERIC / total * 100 FROM events", &[]),
            ("SELECT score / 2.5 * 100 FROM events", &[]),
            ("SELECT abs(score) / total * 100 FROM events", &[]),
        ],
    );
}

#[test]
fn the_default_constrainer_warns_on_column_type_shapes() {
    let constrainer = DefaultConstrainer::<ParserDB>::default();
    let database = parse(EVENTS);
    assert_eq!(
        statement_findings(
            &constrainer,
            &database,
            "SELECT score / total * 100, at::date FROM events WHERE at BETWEEN $1 AND $2"
        )
        .into_iter()
        .map(|(rule, level, _)| (rule, level))
        .collect::<Vec<_>>(),
        [
            ("TimestampBetween", Level::Warn),
            ("SessionTimeZoneDependence", Level::Warn),
            ("TruncatingIntegerDivision", Level::Warn),
        ]
    );
}
