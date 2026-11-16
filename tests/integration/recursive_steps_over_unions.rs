//! Recursive steps over duplicate-eliminating derived relations.

use crate::rule_findings::{findings, statement_findings};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const TABLES: &str = "CREATE TABLE first_edges (parent_id INT, child_id INT);
CREATE TABLE second_edges (parent_id INT, child_id INT);";

/// Builds a recursive query with the supplied edge relation.
fn query(relation: &str) -> String {
    format!(
        "WITH RECURSIVE reachable(id) AS (SELECT 1 UNION SELECT edge.child_id FROM reachable JOIN {relation} ON edge.parent_id = reachable.id) SELECT id FROM reachable"
    )
}

/// Counts this rule's statement findings.
fn reported(query: &str) -> usize {
    let database = ParserDB::parse::<PostgreSqlDialect>(TABLES).unwrap();
    statement_findings(&DefaultConstrainer::default(), &database, query)
        .iter()
        .filter(|(rule, _, _)| *rule == "recursive_step_over_union")
        .count()
}

#[test]
fn duplicate_elimination_in_any_arm_is_reported() {
    for relation in [
        "(SELECT * FROM first_edges UNION SELECT * FROM second_edges) edge",
        "(SELECT * FROM first_edges UNION DISTINCT SELECT * FROM second_edges) edge",
        "(SELECT * FROM first_edges UNION ALL (SELECT * FROM second_edges UNION SELECT * FROM first_edges)) edge",
        "((SELECT * FROM first_edges UNION SELECT * FROM second_edges) UNION ALL SELECT * FROM first_edges) edge",
        "(SELECT * FROM (SELECT * FROM first_edges UNION SELECT * FROM second_edges) nested) edge",
    ] {
        assert_eq!(reported(&query(relation)), 1, "{relation}");
    }
}

#[test]
fn all_and_nonrecursive_unions_pass() {
    for statement in [
        query("(SELECT * FROM first_edges UNION ALL SELECT * FROM second_edges) edge"),
        query("first_edges edge"),
        "WITH reachable AS (SELECT * FROM first_edges UNION SELECT * FROM second_edges) SELECT * FROM reachable".into(),
        "WITH RECURSIVE edges AS (SELECT * FROM first_edges UNION SELECT * FROM second_edges), reachable(id) AS (SELECT 1 UNION SELECT edges.child_id FROM reachable JOIN edges ON edges.parent_id = reachable.id) SELECT * FROM reachable".into(),
    ] {
        assert_eq!(reported(&statement), 0, "{statement}");
    }
}

#[test]
fn schema_expression_sites_report_the_derived_union() {
    let query = query("(SELECT * FROM first_edges UNION SELECT * FROM second_edges) edge");
    for site in [
        format!("CREATE VIEW reachable_view AS {query};"),
        format!("CREATE MATERIALIZED VIEW reachable_view AS {query};"),
        format!("CREATE FUNCTION reachable_ids() RETURNS SETOF INT LANGUAGE sql AS $$ {query} $$;"),
        format!(
            "CREATE FUNCTION reachable_ids() RETURNS SETOF INT LANGUAGE plpgsql AS $$ BEGIN RETURN QUERY {query}; END $$;"
        ),
        format!(
            "ALTER TABLE first_edges ENABLE ROW LEVEL SECURITY; CREATE POLICY edges_read ON first_edges USING (child_id IN ({query}));"
        ),
    ] {
        assert_eq!(
            findings(
                &DefaultConstrainer::<ParserDB>::default(),
                "recursive_step_over_union",
                &format!("{TABLES} {site}")
            )
            .len(),
            1,
            "{site}"
        );
    }
}

#[test]
fn union_views_are_not_followed() {
    let schema = format!(
        "{TABLES} CREATE VIEW edges AS SELECT * FROM first_edges UNION SELECT * FROM second_edges; CREATE VIEW reachable_view AS {};",
        query("edges edge")
    );
    assert_eq!(
        findings(
            &DefaultConstrainer::<ParserDB>::default(),
            "recursive_step_over_union",
            &schema
        ),
        []
    );
}

#[test]
fn isolated_rule_checks_nested_joins_and_values() {
    let constrainer: GenericConstrainer<ParserDB> = RecursiveStepOverUnion::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(TABLES).unwrap();
    for (relation, expected) in [
        (
            "(first_edges JOIN (SELECT * FROM first_edges UNION SELECT * FROM second_edges) edge ON true)",
            1,
        ),
        ("(VALUES (1, 2)) edge(parent_id, child_id)", 0),
    ] {
        let statement = query(relation);
        assert_eq!(
            statement_findings(&constrainer, &database, &statement).len(),
            expected,
            "{relation}"
        );
    }
}
