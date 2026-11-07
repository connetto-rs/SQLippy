//! Statement rules that read indexes, observed through the public
//! constrainer API. The behaviour each rule cites was measured on PostgreSQL
//! 17.11 and 18.6.

use crate::{
    common::parse,
    rule_findings::{check_query_rule, statement_levels},
};
use sql_rules::prelude::*;

const USERS: &str = "
    CREATE TABLE teams (id INT PRIMARY KEY, name TEXT);
    CREATE TABLE users (
        id INT PRIMARY KEY,
        email TEXT,
        handle VARCHAR(40),
        team_id INT REFERENCES teams (id),
        score INT,
        created_at TIMESTAMPTZ,
        name TEXT
    );
    CREATE INDEX users_email ON users (email);
    CREATE INDEX users_handle ON users (handle);
    CREATE INDEX users_team ON users (team_id);
    CREATE INDEX users_created ON users (created_at);
    CREATE INDEX users_lower_name ON users (lower(name));
    CREATE INDEX users_upper_handle ON users (UPPER(handle));
    CREATE TABLE plain (a INT, b INT);";

#[test]
fn an_expression_around_an_indexed_column_is_reported() {
    check_query_rule(
        USERS,
        ExpressionDefeatsIndex::default(),
        &[
            (
                "SELECT id FROM users WHERE lower(email) = $1",
                &["lower(email)"],
            ),
            (
                "SELECT id FROM users WHERE coalesce(team_id, 0) = $1",
                &["coalesce(team_id, 0)"],
            ),
            (
                "SELECT id FROM users WHERE team_id + 0 = $1",
                &["team_id + 0"],
            ),
            (
                "SELECT id FROM users WHERE created_at::DATE = $1",
                &["created_at::DATE"],
            ),
            (
                "SELECT u.id FROM users AS u WHERE $1 > (u.team_id * 2)",
                &["(u.team_id * 2)"],
            ),
            (
                "DELETE FROM users WHERE lower(email) IN ('a', 'b')",
                &["lower(email)"],
            ),
            ("SELECT id FROM users WHERE email = lower($1)", &[]),
            (
                "SELECT id FROM users WHERE score = (SELECT max(team_id) FROM teams)",
                &[],
            ),
            ("SELECT id FROM users WHERE (email) = $1", &[]),
            (
                "SELECT id FROM users WHERE lower(\"email\") = $1",
                &["lower(\"email\")"],
            ),
            ("SELECT id FROM users WHERE (upper(handle)) = $1", &[]),
            ("SELECT id FROM users WHERE Upper(HANDLE) = $1", &[]),
            (
                "SELECT id FROM users WHERE lower(email) = $1 AND lower(email) = $1",
                &["lower(email)"],
            ),
            ("SELECT id FROM users WHERE handle::TEXT = $1", &[]),
            ("SELECT id FROM users WHERE lower(name) = $1", &[]),
            ("SELECT u.id FROM users AS u WHERE lower(u.name) = $1", &[]),
            ("SELECT id FROM users WHERE upper(handle) = $1", &[]),
            (
                "SELECT u.id FROM users AS u WHERE upper(u.handle) = $1",
                &[],
            ),
            ("SELECT id FROM users WHERE score + 1 = $1", &[]),
            ("SELECT id FROM users WHERE abs(id - team_id) = 0", &[]),
            ("SELECT id FROM users WHERE email = $1", &[]),
            (
                "SELECT d.x FROM (SELECT score + 1 AS x FROM users) AS d WHERE d.x * 2 = $1",
                &[],
            ),
        ],
    );
}

#[test]
fn a_where_no_index_can_serve_is_reported() {
    check_query_rule(
        USERS,
        UnindexedFilter::default(),
        &[
            ("SELECT id FROM users WHERE score = 1", &["score = 1"]),
            (
                "SELECT id FROM users WHERE team_id = 7 OR score = 1",
                &["team_id = 7 OR score = 1"],
            ),
            (
                "SELECT id FROM users WHERE lower(email) = $1",
                &["lower(email) = $1"],
            ),
            ("DELETE FROM users WHERE score > 3", &["score > 3"]),
            ("SELECT a FROM plain WHERE a = 1", &["a = 1"]),
            (
                "SELECT id FROM users WHERE team_id = score",
                &["team_id = score"],
            ),
            ("SELECT id FROM users WHERE team_id = 7", &[]),
            ("SELECT id FROM users WHERE lower(name) = $1", &[]),
            ("SELECT id FROM users WHERE (upper(handle)) = $1", &[]),
            ("SELECT id FROM users WHERE lower($1) = email", &[]),
            (
                "SELECT id FROM teams AS t WHERE t.id = 3 AND EXISTS (SELECT 1 FROM users AS u WHERE t.id = $1)",
                &["t.id = $1"],
            ),
            ("SELECT id FROM users WHERE id BETWEEN 500 AND 600", &[]),
            ("SELECT id FROM users WHERE team_id IS NOT NULL", &[]),
            (
                "SELECT id FROM users WHERE score BETWEEN 1 AND 2",
                &["score BETWEEN 1 AND 2"],
            ),
            (
                "SELECT id FROM users WHERE id NOT BETWEEN 1 AND 2",
                &["id NOT BETWEEN 1 AND 2"],
            ),
            (
                "SELECT id FROM users WHERE team_id IN (SELECT id FROM teams WHERE id = users.id)",
                &["team_id IN (SELECT id FROM teams WHERE id = users.id)"],
            ),
            (
                "SELECT id FROM users WHERE team_id = coalesce((SELECT max(id) FROM teams WHERE teams.id = users.score), 0)",
                &[
                    "team_id = coalesce((SELECT max(id) FROM teams WHERE teams.id = users.score), 0)",
                ],
            ),
            (
                "SELECT id FROM teams AS t WHERE t.id = 3 AND EXISTS (SELECT 1 FROM users AS u WHERE lower(t.name) = $1)",
                &["lower(t.name) = $1"],
            ),
            ("SELECT id FROM users WHERE team_id = 7 AND score = 1", &[]),
            ("SELECT id FROM users WHERE team_id = 7 OR email = $1", &[]),
            (
                "SELECT id FROM users WHERE (team_id = 7 AND score = 1) OR (email = $1)",
                &[],
            ),
            ("SELECT id FROM users WHERE team_id IS NULL", &[]),
            ("SELECT id FROM users WHERE team_id IN (1, 2)", &[]),
            (
                "SELECT id FROM users WHERE team_id IN (1, score)",
                &["team_id IN (1, score)"],
            ),
            (
                "SELECT id FROM users WHERE team_id IN (SELECT id FROM teams)",
                &[],
            ),
            ("SELECT id FROM users WHERE 7 = team_id", &[]),
            ("SELECT id FROM users", &[]),
            (
                "SELECT u.id FROM users AS u JOIN teams AS t ON t.id = u.team_id WHERE u.score = 1",
                &[],
            ),
            (
                "SELECT id FROM teams AS t WHERE t.id = 3 AND EXISTS (SELECT 1 FROM users AS u WHERE u.team_id = t.id)",
                &[],
            ),
        ],
    );
}

#[test]
fn a_correlated_select_list_subquery_over_an_unindexed_column_is_reported() {
    check_query_rule(
        USERS,
        UnindexedCorrelatedSelect::default(),
        &[
            (
                "SELECT t.id, (SELECT count(*) FROM plain AS p WHERE p.b > 0 AND p.a = t.id) FROM teams AS t",
                &["SELECT count(*) FROM plain AS p WHERE p.b > 0 AND p.a = t.id"],
            ),
            (
                "SELECT t.id, (SELECT max(b) FROM plain WHERE t.id = a) AS top FROM teams AS t",
                &["SELECT max(b) FROM plain WHERE t.id = a"],
            ),
            (
                "SELECT t.id, (SELECT count(*) FROM users AS u WHERE u.team_id = t.id) FROM teams AS t",
                &[],
            ),
            (
                "SELECT t.id, (SELECT count(*) FROM plain) FROM teams AS t",
                &[],
            ),
            (
                "SELECT t.id, (SELECT count(*) FROM plain AS p WHERE p.a = p.b) FROM teams AS t",
                &[],
            ),
            (
                "SELECT t.id FROM teams AS t WHERE EXISTS (SELECT 1 FROM plain AS p WHERE p.a = t.id)",
                &[],
            ),
            (
                "SELECT t.id, (SELECT count(*) FROM plain AS p WHERE p.a = t.id UNION SELECT 1) FROM teams AS t",
                &[],
            ),
        ],
    );
}

#[test]
fn the_default_constrainer_runs_index_rules_at_their_group_levels() {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    let database = parse(USERS);
    let sql = "SELECT id, (SELECT count(*) FROM plain WHERE plain.a = users.id) FROM users WHERE lower(email) = $1";
    let rules =
        |constrainer: &DefaultConstrainer<ParserDB>| statement_levels(constrainer, &database, sql);
    assert_eq!(
        rules(&constrainer),
        [
            ("ExpressionDefeatsIndex", Level::Warn),
            ("UnindexedCorrelatedSelect", Level::Warn)
        ]
    );
    constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
    assert_eq!(
        rules(&constrainer),
        [
            ("ExpressionDefeatsIndex", Level::Warn),
            ("UnindexedFilter", Level::Warn),
            ("UnindexedFilter", Level::Warn),
            ("UnindexedCorrelatedSelect", Level::Warn),
        ]
    );
}
