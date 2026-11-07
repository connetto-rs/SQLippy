//! Statement rules that read which column a name binds to, observed through
//! the public constrainer API. The behaviour each rule cites was measured on
//! PostgreSQL 17.11 and 18.6.

use crate::rule_findings::check_query_rule;
use sql_rules::prelude::*;

const PEOPLE: &str = "
    CREATE TABLE people (id INT PRIMARY KEY, name TEXT, team INT);
    CREATE TABLE teams (id INT PRIMARY KEY, label TEXT);";

#[test]
fn a_grouping_or_window_name_bound_to_an_input_column_instead_of_its_alias_is_reported() {
    check_query_rule(
        PEOPLE,
        AliasShadowedByColumn::default(),
        &[
            (
                "SELECT lower(name) AS name, count(*) FROM people GROUP BY name",
                &["name"],
            ),
            (
                "SELECT lower(name) AS NAME, count(*) FROM people GROUP BY name",
                &["name"],
            ),
            (
                "SELECT team AS name, count(*) FROM people GROUP BY name",
                &["name"],
            ),
            (
                "SELECT lower(name) AS name, count(*) FROM people GROUP BY ROLLUP (name)",
                &["name"],
            ),
            (
                "SELECT lower(name) AS name, count(*) FROM people GROUP BY GROUPING SETS ((name), ())",
                &["name"],
            ),
            (
                "SELECT p.team AS id, row_number() OVER (PARTITION BY id ORDER BY p.id) FROM people AS p",
                &["id"],
            ),
            (
                "SELECT -p.id AS id, row_number() OVER (ORDER BY id) FROM people AS p",
                &["id"],
            ),
            (
                "SELECT p.team AS id, row_number() OVER w FROM people AS p WINDOW w AS (PARTITION BY id)",
                &["id"],
            ),
            (
                "SELECT * FROM (SELECT lower(name) AS name, count(*) FROM people GROUP BY name) AS g",
                &["name"],
            ),
        ],
    );
}

#[test]
fn names_bound_as_the_author_wrote_them_pass() {
    check_query_rule(
        PEOPLE,
        AliasShadowedByColumn::default(),
        &[
            ("SELECT lower(name) AS name FROM people ORDER BY name", &[]),
            (
                "SELECT name AS name, count(*) FROM people GROUP BY name",
                &[],
            ),
            (
                "SELECT p.name AS name, count(*) FROM people AS p GROUP BY name",
                &[],
            ),
            (
                "SELECT lower(name) AS low, count(*) FROM people GROUP BY low",
                &[],
            ),
            (
                "SELECT lower(p.name) AS name, count(*) FROM people AS p GROUP BY p.name",
                &[],
            ),
            (
                "SELECT lower(name) AS \"Name\", count(*) FROM people GROUP BY name",
                &[],
            ),
            (
                "SELECT lower(name) AS name, count(*) FROM people GROUP BY 1",
                &[],
            ),
            (
                "SELECT id, row_number() OVER (PARTITION BY team ORDER BY id) FROM people",
                &[],
            ),
        ],
    );
}

#[test]
fn a_column_compared_with_itself_is_reported() {
    check_query_rule(
        PEOPLE,
        SelfComparison::default(),
        &[
            ("SELECT id FROM people WHERE name = name", &["name = name"]),
            (
                "SELECT id FROM people AS p WHERE p.name = name",
                &["p.name = name"],
            ),
            (
                "SELECT id FROM people WHERE name <= name",
                &["name <= name"],
            ),
            (
                "SELECT id FROM people WHERE name <> name",
                &["name <> name"],
            ),
            (
                "SELECT p.id FROM people AS p JOIN teams AS t ON t.id = t.id",
                &["t.id = t.id"],
            ),
            (
                "SELECT id FROM people WHERE id IN (SELECT id FROM teams WHERE label = label)",
                &["label = label"],
            ),
            (
                "UPDATE people SET name = 'x' WHERE team = team",
                &["team = team"],
            ),
        ],
    );
}

#[test]
fn comparisons_of_different_columns_or_instances_pass() {
    check_query_rule(
        PEOPLE,
        SelfComparison::default(),
        &[
            (
                "SELECT a.id FROM people AS a JOIN people AS b ON a.team = b.team",
                &[],
            ),
            ("SELECT id FROM people WHERE id = team", &[]),
            ("SELECT id FROM people WHERE name IS NOT NULL", &[]),
            (
                "SELECT id FROM people AS p WHERE EXISTS (SELECT 1 FROM people AS q WHERE q.team = p.team)",
                &[],
            ),
            ("UPDATE people SET name = name WHERE id = 1", &[]),
            ("SELECT id FROM people WHERE lower(name) = name", &[]),
        ],
    );
}
