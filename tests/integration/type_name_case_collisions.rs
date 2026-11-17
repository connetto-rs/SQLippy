//! Types, domains and relations of one schema whose names PostgreSQL keeps
//! apart only by case, observed through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

/// Object and message of every finding of `TypeNameCaseCollision` on `sql`,
/// each at `deny`.
fn collisions(sql: &str) -> Vec<(String, String)> {
    let constrainer: GenericConstrainer<ParserDB> = TypeNameCaseCollision::default().into();
    findings(&constrainer, "type_name_case_collision", sql)
        .into_iter()
        .map(|(level, object, message)| {
            assert_eq!(level, Level::Deny);
            (object, message)
        })
        .collect()
}

#[test]
fn enums_differing_only_by_case_collide() {
    assert_eq!(
        collisions(
            "CREATE TYPE \"Mood\" AS ENUM ('a');
             CREATE TYPE mood AS ENUM ('b');
             CREATE TABLE people (id INT PRIMARY KEY, now_mood mood, then_mood \"Mood\");"
        ),
        [(
            "mood".to_owned(),
            "In schema public, type mood and type \"Mood\" have names that differ only by case."
                .to_owned()
        )]
    );
}

#[test]
fn same_names_in_two_schemas_do_not_collide() {
    assert_eq!(
        collisions(
            "CREATE SCHEMA app; CREATE SCHEMA audit;
             CREATE TYPE app.\"Mood\" AS ENUM ('a');
             CREATE TYPE audit.mood AS ENUM ('b');
             CREATE TABLE app.\"People\" (id INT);
             CREATE TABLE audit.people (id INT);"
        ),
        Vec::<(String, String)>::new()
    );
}

#[test]
fn an_unqualified_name_collides_in_public() {
    assert_eq!(
        collisions("CREATE TYPE \"Mood\" AS ENUM ('a'); CREATE TYPE public.mood AS ENUM ('b');"),
        [(
            "mood".to_owned(),
            "In schema public, type mood and type \"Mood\" have names that differ only by case."
                .to_owned()
        )]
    );
}

#[test]
fn a_table_collides_with_a_type() {
    assert_eq!(
        collisions("CREATE TYPE mood AS ENUM ('a'); CREATE TABLE \"Mood\" (id INT);"),
        [(
            "Mood".to_owned(),
            "In schema public, table \"Mood\" and type mood have names that differ only by case."
                .to_owned()
        )]
    );
}

#[test]
fn two_relations_collide() {
    assert_eq!(
        collisions(
            "CREATE TABLE \"People\" (id INT);
             CREATE VIEW people AS SELECT id FROM \"People\";"
        ),
        [(
            "people".to_owned(),
            "In schema public, view people and table \"People\" have names that differ only by case."
                .to_owned()
        )]
    );
}

#[test]
fn every_kind_of_type_and_domain_collides() {
    assert_eq!(
        collisions(
            "CREATE TYPE \"Pair\" AS (left_value INT, right_value INT);
             CREATE DOMAIN pair AS INT;
             CREATE TYPE \"Span\" AS RANGE (subtype = INT);
             CREATE MATERIALIZED VIEW span AS SELECT 1 AS id;"
        ),
        [
            (
                "pair".to_owned(),
                "In schema public, domain pair and type \"Pair\" have names that differ only by case."
                    .to_owned()
            ),
            (
                "span".to_owned(),
                "In schema public, materialized view span and type \"Span\" have names that differ only by case."
                    .to_owned()
            ),
        ]
    );
}

#[test]
fn three_spellings_report_every_pair() {
    let pairs: Vec<String> = collisions(
        "CREATE TYPE \"MOOD\" AS ENUM ('a');
         CREATE TYPE \"Mood\" AS ENUM ('b');
         CREATE TYPE mood AS ENUM ('c');",
    )
    .into_iter()
    .map(|(_, message)| message)
    .collect();
    assert_eq!(
        pairs,
        [
            "In schema public, type \"Mood\" and type \"MOOD\" have names that differ only by case.",
            "In schema public, type mood and type \"MOOD\" have names that differ only by case.",
            "In schema public, type mood and type \"Mood\" have names that differ only by case.",
        ]
    );
}
