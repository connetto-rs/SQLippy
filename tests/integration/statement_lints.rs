//! Rules checked against a single statement an application sends, observed
//! through the public constrainer API. The behaviour each rule cites was
//! measured on PostgreSQL 17.11 and 18.6.

use std::ops::ControlFlow;

use crate::rule_findings::{findings, statement};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const PAIRS: &str = "CREATE TABLE a (id INT NOT NULL, team INT);
    CREATE TABLE b (a_id INT, team INT NOT NULL);";

fn schema() -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(PAIRS).expect("schema parses")
}

fn statement_findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    sql: &str,
) -> Vec<(&'static str, Level, String)> {
    crate::rule_findings::statement_findings(constrainer, &schema(), sql)
}

fn not_in_rules() -> GenericConstrainer<ParserDB> {
    let mut constrainer: GenericConstrainer<ParserDB> = NotInNullableSubquery::default().into();
    constrainer.register_query_rule(Box::new(NotInSubquery::default()));
    constrainer.register_schema_rule(Box::new(NotInSubquery::default()));
    constrainer
}

const NOT_IN_OUTPUTS: &[(&str, bool)] = &[
    ("SELECT id FROM c UNION SELECT a_id FROM b", true),
    ("SELECT id FROM c UNION ALL SELECT a_id FROM b", true),
    ("SELECT a_id FROM b EXCEPT SELECT id FROM c", true),
    ("SELECT a_id FROM b INTERSECT SELECT a_id FROM b", true),
    ("VALUES (1), (NULL::int)", true),
    ("(SELECT a_id FROM b)", true),
    ("TABLE b", true),
    ("TABLE public.b", true),
    ("TABLE non_null", false),
    ("TABLE undeclared", false),
    ("SELECT c.id FROM b LEFT JOIN c ON c.id = b.a_id + 10", true),
    ("SELECT a_id + 0 FROM b", true),
    ("SELECT CASE WHEN id > 5 THEN id END FROM c", true),
    ("SELECT nullif(id, 1) FROM c", true),
    ("SELECT max(id) FROM c WHERE id > 5", true),
    ("SELECT NULL::int", true),
    ("SELECT (SELECT c.id FROM c WHERE c.id > 5)", true),
    ("SELECT (SELECT count(*) FROM c)", false),
    ("SELECT (SELECT max(id) FROM c)", true),
    ("SELECT (SELECT count(*) FROM c WHERE id > 5)", false),
    ("SELECT (SELECT max(id) FROM c WHERE id > 5)", true),
    ("SELECT (SELECT count(*) FROM c GROUP BY id)", true),
    ("SELECT (SELECT count(*) FROM c HAVING false)", true),
    ("SELECT (SELECT count(*) FROM c LIMIT 0)", true),
    ("SELECT (SELECT count(*) FROM c OFFSET 1)", true),
    ("SELECT (SELECT count(*) OVER () FROM c)", true),
    ("SELECT (SELECT count(*) + 1 FROM c)", false),
    (
        "SELECT (SELECT (SELECT count(*) FROM c) FROM b WHERE false)",
        true,
    ),
    ("SELECT a_id FROM b WHERE b.a_id IS NOT NULL", false),
    ("SELECT a_id FROM b WHERE a_id > 0", false),
    ("SELECT a_id FROM b WHERE NOT (a_id IS NULL)", false),
    ("SELECT b.a_id FROM b JOIN c ON c.a_id = b.a_id", false),
    ("SELECT a_id FROM b", true),
    ("SELECT id FROM c", false),
    ("SELECT coalesce(a_id, 0) FROM b", false),
    ("SELECT a_id FROM b EXCEPT SELECT NULL::int", false),
    ("SELECT a_id FROM b INTERSECT SELECT id FROM c", false),
    ("SELECT id FROM c UNION SELECT NULL::int", true),
    ("SELECT a_id FROM b WHERE a_id BETWEEN 1 AND 5", false),
    ("VALUES (NULL::int + 1)", true),
    ("VALUES (coalesce(NULL::int, 1))", false),
    (
        "SELECT CASE WHEN team > 0 THEN a_id ELSE 1 END FROM pairs",
        true,
    ),
    (
        "SELECT CASE WHEN team > 0 THEN 1 ELSE 2 END FROM pairs",
        false,
    ),
    ("SELECT -a_id FROM b", true),
    ("SELECT +team FROM pairs", false),
    ("SELECT count(*) FROM b", false),
    ("SELECT max(team) FROM pairs GROUP BY team", false),
    ("SELECT max(a_id) FROM pairs GROUP BY team", true),
    (
        "SELECT max(team) FILTER (WHERE team > 5) FROM pairs GROUP BY team",
        true,
    ),
    ("SELECT coalesce(a_id, NULL) FROM b", true),
    ("SELECT (SELECT 1)", false),
    ("SELECT (SELECT NULL::int)", true),
    ("SELECT (a_id IS NULL)::int FROM b", false),
    (
        "SELECT (a_id IS NOT DISTINCT FROM team)::int FROM pairs",
        false,
    ),
    ("SELECT (EXISTS (SELECT 1 FROM b))::int", false),
    (
        "SELECT a_id FROM b WHERE CAST(a_id AS TEXT) LIKE '1%'",
        false,
    ),
    (
        "SELECT a_id FROM b WHERE CAST(a_id AS TEXT) ILIKE '1%'",
        false,
    ),
    (
        "SELECT a_id FROM b WHERE CAST(a_id AS TEXT) SIMILAR TO '1%'",
        false,
    ),
    ("SELECT a_id FROM b WHERE a_id IN (1, 2)", false),
    ("SELECT a_id FROM b WHERE a_id = ANY(ARRAY[1, 2])", false),
    ("SELECT a_id FROM b WHERE a_id + 1 > 0", false),
    ("SELECT a_id FROM pairs WHERE a_id > 0 OR team > 0", true),
    (
        "SELECT first.a_id FROM pairs AS first JOIN pairs AS second ON second.a_id = first.team",
        true,
    ),
    (
        "SELECT pairs.team FROM a LEFT JOIN pairs ON pairs.a_id = a.id",
        true,
    ),
    ("SELECT a.id FROM a RIGHT JOIN b ON b.a_id = a.id", true),
    (
        "SELECT pairs.team FROM a FULL JOIN pairs ON pairs.a_id = a.id",
        true,
    ),
    (
        "SELECT pairs.team FROM a LEFT JOIN (pairs JOIN a AS other ON pairs.team = other.id) ON pairs.a_id = a.id",
        true,
    ),
    (
        "SELECT a_id FROM (SELECT a_id FROM b WHERE a_id > 0) AS nested",
        false,
    ),
    (
        "SELECT value FROM (WITH item AS (SELECT a_id FROM b WHERE a_id > 0) SELECT a_id AS value FROM item) AS nested",
        false,
    ),
    (
        "WITH item(first, second) AS (SELECT 1, NULL::int UNION SELECT 2, a_id FROM b) SELECT second FROM item",
        true,
    ),
    (
        "SELECT second FROM (SELECT 1 AS first, NULL::int AS second UNION SELECT 2, a_id FROM b) AS nested",
        true,
    ),
    ("SELECT a_id FROM b EXCEPT SELECT a_id FROM b", true),
    ("SELECT a_id FROM b EXCEPT (SELECT NULL::int LIMIT 0)", true),
    (
        "VALUES (NULL::int), (NULL::int) EXCEPT ALL SELECT NULL::int",
        true,
    ),
    (
        "WITH item AS (SELECT a_id FROM b EXCEPT SELECT NULL::int) SELECT a_id FROM item",
        false,
    ),
    (
        "SELECT c.id FROM a JOIN c ON a.id = c.id RIGHT JOIN b ON c.id = b.a_id + 10",
        true,
    ),
    (
        "SELECT c.id FROM a JOIN c ON a.id = c.id FULL JOIN b ON c.id = b.a_id + 10",
        true,
    ),
    (
        "SELECT b.a_id FROM a JOIN b ON a.id = b.a_id RIGHT JOIN c ON c.id = b.a_id + 10",
        true,
    ),
    ("SELECT b.a_id FROM (b JOIN c ON b.a_id = c.id)", false),
    (
        "SELECT b.a_id FROM a JOIN (b JOIN c ON b.a_id = c.id) ON a.id = c.id",
        false,
    ),
    ("SELECT a_id FROM b WHERE ((a_id > 0))", false),
    ("SELECT a_id FROM b WHERE NOT (a_id = 5)", false),
    (
        "SELECT a_id FROM (SELECT a_id FROM b INTERSECT SELECT a_id FROM b) AS item",
        true,
    ),
    (
        "SELECT a_id FROM (SELECT a_id FROM b EXCEPT SELECT id FROM c) AS item",
        true,
    ),
    (
        "WITH item AS (SELECT a_id FROM b INTERSECT SELECT a_id FROM b) SELECT a_id FROM item",
        true,
    ),
    (
        "WITH item AS (SELECT a_id FROM b EXCEPT SELECT id FROM c) SELECT a_id FROM item",
        true,
    ),
    ("SELECT a_id FROM b EXCEPT (SELECT NULL::int)", false),
    ("SELECT a_id FROM b EXCEPT VALUES (NULL::int)", false),
    (
        "SELECT derived.value FROM a LEFT JOIN (SELECT 1 AS value) AS derived ON true",
        true,
    ),
    (
        "WITH RECURSIVE item(value) AS (SELECT 1 UNION ALL SELECT value FROM item WHERE false) SELECT value FROM item",
        false,
    ),
    (
        "SELECT value FROM generate_series(1, 2) AS item(value)",
        false,
    ),
    ("SELECT 1 UNION SELECT abs(-1)", false),
    ("SELECT NULL::int INTERSECT SELECT abs(-1)", false),
    ("SELECT pg_catalog.abs(-1)", false),
    (
        "WITH item AS (SELECT * FROM (SELECT a_id FROM b UNION SELECT a_id FROM b) AS combined) SELECT a_id FROM item",
        true,
    ),
    (
        "WITH item AS (SELECT * FROM (SELECT a_id FROM b INTERSECT SELECT a_id FROM b) AS combined) SELECT a_id FROM item",
        true,
    ),
    (
        "WITH item AS (SELECT * FROM (SELECT a_id FROM b EXCEPT SELECT id FROM c) AS combined) SELECT a_id FROM item",
        true,
    ),
    ("VALUES (1, 2)", false),
    ("TABLE pairs", false),
    (
        "WITH item AS (SELECT a_id FROM b WHERE a_id IS NOT NULL UNION SELECT a_id FROM b WHERE a_id IS NOT NULL) SELECT a_id FROM item",
        false,
    ),
    (
        "WITH item AS (SELECT a_id FROM b WHERE a_id IS NOT NULL INTERSECT SELECT a_id FROM b) SELECT a_id FROM item",
        false,
    ),
    ("SELECT ((a_id = 1) OR true)::int FROM b", false),
    (
        "SELECT second FROM ((SELECT 1 AS first, NULL::int AS second)) AS item",
        true,
    ),
    (
        "SELECT (SELECT (SELECT 1) + count(*) FROM b WHERE false)",
        false,
    ),
    (
        "SELECT a_id FROM b EXCEPT SELECT NULL::int FROM c WHERE false",
        true,
    ),
    (
        "SELECT a_id FROM b EXCEPT SELECT NULL::int WHERE false",
        true,
    ),
    (
        "SELECT a_id FROM b EXCEPT SELECT NULL::int HAVING false",
        true,
    ),
    ("SELECT c.id FROM a RIGHT JOIN c ON false", false),
    (
        "SELECT b.a_id FROM a RIGHT JOIN (b JOIN c ON b.a_id = c.id) ON true",
        false,
    ),
    ("SELECT other.id FROM a LEFT JOIN c AS other ON false", true),
    (
        "WITH item(value) AS (SELECT (a_id IS NULL)::int FROM b UNION SELECT a_id FROM b WHERE a_id IS NOT NULL) SELECT value FROM item",
        false,
    ),
    (
        "SELECT a_id FROM b WHERE NOT (a_id = ANY ('{}'::int[]))",
        true,
    ),
    (
        "SELECT a_id FROM b WHERE (a_id = ANY ('{}'::int[])) IS NOT NULL",
        true,
    ),
    (
        "SELECT a_id FROM b WHERE NOT (a_id = ANY (SELECT team FROM pairs WHERE false))",
        true,
    ),
    (
        "SELECT a_id FROM b WHERE NOT (a_id > ANY (SELECT team FROM pairs WHERE team > 99))",
        true,
    ),
    (
        "SELECT a_id FROM b WHERE NOT (a_id = ANY (ARRAY[1, 2]))",
        false,
    ),
    ("SELECT (data ->> 'm')::int FROM j", true),
    ("SELECT (data -> 'm')::int FROM j", true),
    ("SELECT (data #>> '{m}')::int FROM j", true),
    ("SELECT (data #> '{m}')::int FROM j", true),
    ("SELECT ((data -> 'k') ->> 'y')::int FROM j", true),
    ("SELECT abs(a_id) FROM b", true),
    ("SELECT abs(id) FROM c", false),
];

#[test]
fn not_in_measured_output_nullability() {
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE a (id INT PRIMARY KEY);
         CREATE TABLE b (a_id INT);
         CREATE TABLE c (id INT PRIMARY KEY, a_id INT NOT NULL);
         CREATE TABLE pairs (a_id INT, team INT NOT NULL);
         CREATE TABLE non_null (value INT NOT NULL);
         CREATE TABLE j (data JSONB NOT NULL);",
    )
    .expect("schema parses");
    let constrainer = not_in_rules();
    let mut failures = Vec::new();
    for &(subquery, nullable) in NOT_IN_OUTPUTS {
        let sql = format!("SELECT id FROM a WHERE id NOT IN ({subquery})");
        let expected = if nullable {
            "not_in_nullable_subquery"
        } else {
            "not_in_subquery"
        };
        let found: Vec<_> = constrainer
            .statement_diagnostics(&database, &statement(&sql))
            .into_iter()
            .map(|error| match error {
                Error::Violation(violation) => {
                    if subquery == "SELECT other.id FROM a LEFT JOIN c AS other ON false" {
                        assert!(
                            violation.message().contains("c.id"),
                            "{}",
                            violation.message()
                        );
                    }
                    violation.rule().name
                }
                other => panic!("unexpected failure: {other}"),
            })
            .collect();
        if found != [expected] {
            failures.push(format!("{subquery} expected {expected}, found {found:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn not_in_over_a_nullable_column_is_reported_in_every_statement_kind() {
    let constrainer: GenericConstrainer<ParserDB> = NotInNullableSubquery::default().into();
    for sql in [
        "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)",
        "UPDATE a SET team = 1 WHERE id NOT IN (SELECT a_id FROM b)",
        "DELETE FROM a WHERE id NOT IN (SELECT a_id FROM b)",
    ] {
        assert_eq!(
            statement_findings(&constrainer, sql),
            [(
                "not_in_nullable_subquery",
                Level::Warn,
                "id NOT IN (SELECT a_id FROM b)".to_owned()
            )],
            "{sql}"
        );
    }
}

#[test]
fn a_statement_finding_names_the_nullable_column_and_the_statement() {
    let constrainer: GenericConstrainer<ParserDB> = NotInNullableSubquery::default().into();
    let sql = "select id from a where id not in (select a_id from b)";
    let Err(Error::Violation(violation)) =
        constrainer.validate_statement(&schema(), &statement(sql))
    else {
        panic!("the statement is reported");
    };
    let Location::Statement(site) = violation.location() else {
        panic!("a statement finding is located on the statement");
    };
    let normalized = "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)";
    assert_eq!(
        (site.statement(), site.expression()),
        (normalized, "id NOT IN (SELECT a_id FROM b)")
    );
    assert!(violation.message().contains("'b.a_id'"), "{violation}");
    assert!(
        violation
            .to_string()
            .contains(&format!("\n  in {normalized}")),
        "{violation}"
    );
}

#[test]
fn not_in_over_a_non_null_or_filtered_column_is_reported_as_slow_only() {
    let constrainer = not_in_rules();
    for (sql, expected) in [
        (
            "SELECT id FROM a WHERE team NOT IN (SELECT team FROM b)",
            ("not_in_subquery", "team NOT IN (SELECT team FROM b)"),
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b WHERE a_id IS NOT NULL)",
            (
                "not_in_subquery",
                "id NOT IN (SELECT a_id FROM b WHERE a_id IS NOT NULL)",
            ),
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)",
            ("not_in_nullable_subquery", "id NOT IN (SELECT a_id FROM b)"),
        ),
    ] {
        assert_eq!(
            statement_findings(&constrainer, sql),
            [(expected.0, Level::Warn, expected.1.to_owned())],
            "{sql}"
        );
    }
}

#[test]
fn not_in_over_a_with_item_reads_the_filters_the_output_passes_through() {
    let constrainer = not_in_rules();
    for (sql, expected) in [
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS (SELECT a_id FROM b WHERE a_id IS NOT NULL) SELECT a_id FROM t)",
            "not_in_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t(v) AS (SELECT a_id FROM b WHERE a_id IS NOT NULL) SELECT t.v FROM t)",
            "not_in_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS (SELECT a_id FROM b WHERE a_id IS NOT NULL), u AS (SELECT a_id AS x FROM t) SELECT x FROM u)",
            "not_in_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS (SELECT a_id FROM b) SELECT a_id FROM t WHERE a_id IS NOT NULL)",
            "not_in_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS (SELECT a_id FROM b) SELECT a_id FROM t)",
            "not_in_nullable_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS (SELECT a_id, team FROM b WHERE team IS NOT NULL) SELECT a_id FROM t)",
            "not_in_nullable_subquery",
        ),
    ] {
        let found: Vec<_> = statement_findings(&constrainer, sql)
            .into_iter()
            .map(|(rule, _, _)| rule)
            .collect();
        assert_eq!(found, [expected], "{sql}");
    }
}

#[test]
fn not_in_with_projection_shapes_preserves_nullable_sources() {
    let constrainer = not_in_rules();
    for (sql, expected) in [
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS (SELECT b.a_id FROM b WHERE b.a_id IS NOT NULL) SELECT a_id FROM t)",
            "not_in_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS (SELECT 1, b.a_id FROM b WHERE b.a_id IS NOT NULL) SELECT a_id FROM t)",
            "not_in_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS (SELECT * FROM b) SELECT a_id FROM t)",
            "not_in_nullable_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t(a_id, team) AS (SELECT * FROM b) SELECT a_id FROM t)",
            "not_in_nullable_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM (SELECT a_id FROM b) AS nested)",
            "not_in_nullable_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM public.b)",
            "not_in_nullable_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS ((SELECT a_id FROM b)) SELECT a_id FROM t)",
            "not_in_nullable_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH RECURSIVE t AS (SELECT a_id FROM b WHERE a_id IS NOT NULL) SELECT a_id FROM t)",
            "not_in_subquery",
        ),
    ] {
        let found: Vec<_> = statement_findings(&constrainer, sql)
            .into_iter()
            .map(|(rule, _, _)| rule)
            .collect();
        assert_eq!(found, [expected], "{sql}");
    }
}

#[test]
fn not_in_with_a_self_named_item_terminates() {
    let sql =
        "SELECT id FROM a WHERE id NOT IN (WITH b AS (SELECT a_id FROM b) SELECT a_id FROM b)";
    let found = statement_findings(&not_in_rules(), sql);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, Level::Warn);
    assert_eq!(
        found[0].2,
        "id NOT IN (WITH b AS (SELECT a_id FROM b) SELECT a_id FROM b)"
    );
}

#[test]
fn not_in_with_items_obey_postgresql_visibility() {
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{PAIRS} CREATE TABLE t (a_id INT);"))
            .expect("schema parses");
    let constrainer = not_in_rules();
    // PostgreSQL 18 returns no rows when the visible source contains a NULL.
    for (sql, expected) in [
        (
            "SELECT id FROM a WHERE id NOT IN (WITH u AS (SELECT a_id FROM t), t AS (SELECT a_id FROM b WHERE a_id IS NOT NULL) SELECT a_id FROM u)",
            "not_in_nullable_subquery",
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (WITH t AS (SELECT a_id FROM b), u AS (WITH v AS (SELECT a_id FROM t), t AS (SELECT a_id FROM b WHERE a_id IS NOT NULL) SELECT a_id FROM v) SELECT a_id FROM u)",
            "not_in_nullable_subquery",
        ),
    ] {
        let found: Vec<_> = crate::rule_findings::statement_findings(&constrainer, &database, sql)
            .into_iter()
            .map(|(rule, _, _)| rule)
            .collect();
        assert_eq!(found, [expected], "{sql}");
    }
}

#[test]
fn membership_tests_without_a_negated_subquery_pass() {
    let constrainer = not_in_rules();
    for sql in [
        "SELECT id FROM a WHERE id IN (SELECT a_id FROM b)",
        "SELECT id FROM a WHERE id NOT IN (1, 2)",
        "SELECT id FROM a WHERE NOT EXISTS (SELECT 1 FROM b WHERE b.a_id = a.id)",
    ] {
        assert_eq!(statement_findings(&constrainer, sql), [], "{sql}");
    }
}

#[test]
fn slow_not_in_is_reported_wherever_the_schema_writes_it() {
    let constrainer: GenericConstrainer<ParserDB> = NotInSubquery::default().into();
    let found: Vec<_> = findings(
        &constrainer,
        "not_in_subquery",
        &format!(
            "{PAIRS}
             ALTER TABLE a ENABLE ROW LEVEL SECURITY;
             CREATE VIEW v AS SELECT id FROM a WHERE team NOT IN (SELECT team FROM b);
             CREATE VIEW nullable AS SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b);
             CREATE MATERIALIZED VIEW mv AS SELECT id FROM a WHERE team NOT IN (SELECT team FROM b);
             CREATE POLICY p ON a USING (team NOT IN (SELECT team FROM b));
             CREATE FUNCTION f() RETURNS SETOF INT LANGUAGE sql
               AS $$ SELECT id FROM a WHERE team NOT IN (SELECT team FROM b) $$;
             CREATE FUNCTION g(x INT) RETURNS BOOLEAN LANGUAGE sql
               RETURN x NOT IN (SELECT team FROM b);"
        ),
    )
    .into_iter()
    .map(|(level, object, _)| (level, object))
    .collect();
    assert_eq!(
        found,
        ["v", "mv", "a.p", "f()", "g(INT)"].map(|object| (Level::Warn, object.to_owned()))
    );
}

#[test]
fn the_default_constrainer_checks_statements_with_query_rules_only() {
    let constrainer = DefaultConstrainer::<ParserDB>::default();
    assert_eq!(
        statement_findings(
            &constrainer,
            "SELECT id FROM a WHERE team NOT IN (SELECT team FROM b)"
        ),
        [(
            "not_in_subquery",
            Level::Warn,
            "team NOT IN (SELECT team FROM b)".to_owned()
        )]
    );
    assert_eq!(statement_findings(&constrainer, "SELECT id FROM a"), []);
}

#[test]
fn statement_rules_follow_rule_and_group_levels() {
    let mut constrainer = not_in_rules();
    constrainer.set_rule_level("not_in_nullable_subquery", Level::Deny);
    constrainer.set_group_level(LintGroup::Perf, Level::Allow);
    assert_eq!(
        statement_findings(
            &constrainer,
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b) AND team NOT IN (SELECT team FROM b)"
        ),
        [(
            "not_in_nullable_subquery",
            Level::Deny,
            "id NOT IN (SELECT a_id FROM b)".to_owned()
        )]
    );
}

#[test]
fn a_subquery_over_an_unresolvable_name_is_a_lookup_failure() {
    let constrainer: GenericConstrainer<ParserDB> = NotInNullableSubquery::default().into();
    assert!(matches!(
        constrainer.validate_statement(
            &schema(),
            &statement("SELECT id FROM a WHERE id NOT IN (SELECT x FROM a.b.c.missing)")
        ),
        Err(Error::Lookup(_))
    ));
}

#[test]
fn checking_a_statement_stops_when_the_sink_breaks() {
    let constrainer = not_in_rules();
    let mut seen = 0;
    let flow = constrainer.visit_statement(
        &schema(),
        &statement(
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b) AND team NOT IN (SELECT team FROM b)",
        ),
        &mut |_| {
            seen += 1;
            ControlFlow::Break(())
        },
    );
    assert_eq!((flow, seen), (ControlFlow::Break(()), 1));
}

#[test]
fn an_allowance_excuses_its_rule_on_the_same_statement_however_it_is_written() {
    let mut constrainer = not_in_rules();
    constrainer.allow_statement(
        "not_in_nullable_subquery",
        "select id from a where id not in (select a_id from b)",
    );
    assert_eq!(
        statement_findings(
            &constrainer,
            "SELECT id\n  FROM a WHERE id NOT IN (SELECT a_id FROM b)"
        ),
        []
    );
    assert_eq!(
        statement_findings(
            &constrainer,
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b) AND team > 0"
        ),
        [(
            "not_in_nullable_subquery",
            Level::Warn,
            "id NOT IN (SELECT a_id FROM b)".to_owned()
        )]
    );
    assert!(constrainer.validate_schema(&schema()).is_ok());
}

#[test]
fn an_allowance_for_another_rule_excuses_nothing() {
    let mut constrainer = not_in_rules();
    let sql = "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)";
    constrainer.allow_statement("not_in_subquery", sql);
    assert_eq!(
        statement_findings(&constrainer, sql),
        [(
            "not_in_nullable_subquery",
            Level::Warn,
            "id NOT IN (SELECT a_id FROM b)".to_owned()
        )]
    );
}

#[test]
fn an_allowance_whose_statement_no_longer_violates_its_rule_fails_validation() {
    let fixed = "select id from a where not exists (select 1 from b where b.a_id = a.id)";
    let normalized = "SELECT id FROM a WHERE NOT EXISTS (SELECT 1 FROM b WHERE b.a_id = a.id)";
    for (rule, sql, level, named) in [
        ("not_in_nullable_subquery", fixed, None, normalized),
        (
            "not_in_nullable_subquery",
            "SELECT FROM WHERE",
            None,
            "SELECT FROM WHERE",
        ),
        (
            "not_in_nullable_subquery",
            "SELECT 1; SELECT 2",
            None,
            "SELECT 1; SELECT 2",
        ),
        ("NoSuchRule", fixed, None, normalized),
        (
            "not_in_nullable_subquery",
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)",
            Some(Level::Allow),
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)",
        ),
    ] {
        let mut constrainer = not_in_rules();
        if let Some(level) = level {
            constrainer.set_rule_level(rule, level);
        }
        constrainer.allow_statement(rule, sql);
        let Err(error) = constrainer.validate_schema(&schema()) else {
            panic!("the allowance for {rule} on {sql} excuses nothing");
        };
        let Error::UnusedAllowance(Allowance::Statement(allowance)) = &error else {
            panic!("unexpected failure: {error}");
        };
        assert_eq!((allowance.rule(), allowance.statement()), (rule, named));
        let reported = error.to_string();
        assert!(
            reported.contains(rule) && reported.contains(named),
            "{reported}"
        );
    }
}

#[test]
fn an_allowance_whose_statement_cannot_be_resolved_reports_the_lookup_failure() {
    let mut constrainer = not_in_rules();
    constrainer.allow_statement(
        "not_in_nullable_subquery",
        "SELECT id FROM a WHERE id NOT IN (SELECT x FROM a.b.c.missing)",
    );
    let diagnostics = constrainer.diagnostics(&schema());
    assert!(
        matches!(diagnostics.as_slice(), [Error::Lookup(_)]),
        "{diagnostics:?}"
    );
}

#[test]
fn statement_allowances_are_checked_by_the_schema_and_not_by_statements() {
    let mut constrainer = not_in_rules();
    constrainer.allow_statement(
        "not_in_nullable_subquery",
        "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)",
    );
    assert_eq!(statement_findings(&constrainer, "SELECT id FROM a"), []);
}
