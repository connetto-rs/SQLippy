//! Rules checked against a single statement an application sends, observed
//! through the public constrainer API. The behaviour each rule cites was
//! measured on PostgreSQL 17.11 and 18.6.

use std::ops::ControlFlow;

use crate::rule_findings::{findings, statement};
use sql_rules::prelude::*;
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
                "NotInNullableSubquery",
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
            ("NotInSubquery", "team NOT IN (SELECT team FROM b)"),
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b WHERE a_id IS NOT NULL)",
            (
                "NotInSubquery",
                "id NOT IN (SELECT a_id FROM b WHERE a_id IS NOT NULL)",
            ),
        ),
        (
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)",
            ("NotInNullableSubquery", "id NOT IN (SELECT a_id FROM b)"),
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
        "NotInSubquery",
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
            "NotInSubquery",
            Level::Warn,
            "team NOT IN (SELECT team FROM b)".to_owned()
        )]
    );
    assert_eq!(statement_findings(&constrainer, "SELECT id FROM a"), []);
}

#[test]
fn statement_rules_follow_rule_and_group_levels() {
    let mut constrainer = not_in_rules();
    constrainer.set_rule_level("NotInNullableSubquery", Level::Deny);
    constrainer.set_group_level(LintGroup::Perf, Level::Allow);
    assert_eq!(
        statement_findings(
            &constrainer,
            "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b) AND team NOT IN (SELECT team FROM b)"
        ),
        [(
            "NotInNullableSubquery",
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
        "NotInNullableSubquery",
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
            "NotInNullableSubquery",
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
    constrainer.allow_statement("NotInSubquery", sql);
    assert_eq!(
        statement_findings(&constrainer, sql),
        [(
            "NotInNullableSubquery",
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
        ("NotInNullableSubquery", fixed, None, normalized),
        (
            "NotInNullableSubquery",
            "SELECT FROM WHERE",
            None,
            "SELECT FROM WHERE",
        ),
        (
            "NotInNullableSubquery",
            "SELECT 1; SELECT 2",
            None,
            "SELECT 1; SELECT 2",
        ),
        ("NoSuchRule", fixed, None, normalized),
        (
            "NotInNullableSubquery",
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
        "NotInNullableSubquery",
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
        "NotInNullableSubquery",
        "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)",
    );
    assert_eq!(statement_findings(&constrainer, "SELECT id FROM a"), []);
}
