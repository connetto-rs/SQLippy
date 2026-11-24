//! Redundant terms observed through the public constrainer API.

use crate::rule_findings::{findings, statement_findings};
use pg_diesel::PgDieselDatabase;
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// The term every finding of `redundant_term` on `sql` names.
fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = RedundantTerm::default().into();
    findings(&constrainer, "redundant_term", sql)
        .into_iter()
        .map(|(_, _, message)| {
            message
                .split('`')
                .nth(1)
                .expect("the message quotes the term")
                .to_owned()
        })
        .collect()
}

/// The object of every finding of `redundant_term` on the script statement
/// `sql` over the schema `schema`.
fn reported_in_statement(schema: &str, sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = RedundantTerm::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    statement_findings(&constrainer, &database, sql)
        .into_iter()
        .map(|(_, _, object)| object)
        .collect()
}

#[test]
fn a_weaker_term_of_a_domain_check_is_reported() {
    assert_eq!(
        reported("CREATE DOMAIN amount AS INT CHECK (VALUE > 5 AND VALUE > 3);"),
        ["VALUE > 3"]
    );
}

#[test]
fn a_domain_term_reads_under_its_base_domain() {
    assert_eq!(
        reported(
            "CREATE DOMAIN positive AS INT CHECK (VALUE > 5);
             CREATE DOMAIN amount AS positive CHECK (VALUE > 3 AND VALUE < 100);"
        ),
        ["VALUE > 3"]
    );
}

#[test]
fn a_domain_term_reads_under_the_domain_other_checks_but_not_its_own() {
    assert_eq!(
        reported("CREATE DOMAIN amount AS INT CHECK (VALUE > 3 AND VALUE < 100);"),
        Vec::<String>::new()
    );
    assert_eq!(
        reported(
            "CREATE DOMAIN amount AS INT CHECK (VALUE > 5) CHECK (VALUE > 3 AND VALUE < 100);"
        ),
        ["VALUE > 3"]
    );
}

#[test]
fn a_view_where_term_the_table_checks_guarantee_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE t (x INT NOT NULL, y INT, CHECK (x > 5));
             CREATE VIEW v AS SELECT y FROM t WHERE y = 1 AND x > 3;"
        ),
        ["x > 3"]
    );
}

#[test]
fn a_join_on_term_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE t (id INT, x INT);
             CREATE TABLE u (id INT);
             CREATE VIEW v AS SELECT u.id FROM u JOIN t ON t.id = u.id AND t.x > 5 AND t.x > 3;"
        ),
        ["t.x > 3"]
    );
}

#[test]
fn a_null_extended_side_guarantees_nothing() {
    let schema = "CREATE TABLE t (id INT, x INT NOT NULL, CHECK (x > 5)); CREATE TABLE u (id INT);";
    assert_eq!(
        reported(&format!(
            "{schema} CREATE VIEW v AS SELECT u.id FROM u JOIN t ON t.id = u.id WHERE u.id = 1 AND t.x > 3;"
        )),
        ["t.x > 3"]
    );
    assert_eq!(
        reported(&format!(
            "{schema} CREATE VIEW v AS SELECT u.id FROM u LEFT JOIN t ON t.id = u.id WHERE u.id = 1 AND t.x > 3;"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn two_readings_of_one_table_are_two_values() {
    assert_eq!(
        reported(
            "CREATE TABLE t (id INT, x INT);
             CREATE VIEW v AS SELECT a.id FROM t AS a JOIN t AS b ON a.id = b.id WHERE a.x > 5 AND b.x > 3;"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_materialized_view_is_read() {
    assert_eq!(
        reported(
            "CREATE TABLE t (x INT, y INT);
             CREATE MATERIALIZED VIEW v AS SELECT y FROM t WHERE x > 5 AND x > 3;"
        ),
        ["x > 3"]
    );
}

#[test]
fn a_subquery_of_a_view_is_read_in_its_own_scope() {
    assert_eq!(
        reported(
            "CREATE TABLE t (x INT NOT NULL, CHECK (x > 5));
             CREATE TABLE u (x INT NOT NULL, y INT);
             CREATE VIEW v AS SELECT 1 FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.y > 5 AND u.y > 3 AND x > 3);"
        ),
        ["u.y > 3"]
    );
}

#[test]
fn a_sql_function_body_is_read() {
    assert_eq!(
        reported(
            "CREATE TABLE t (x INT, y INT);
             CREATE FUNCTION f() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT y FROM t WHERE x > 5 AND x > 3 $$;"
        ),
        ["x > 3"]
    );
}

#[test]
fn a_plpgsql_parameter_carries_its_type() {
    assert_eq!(
        reported(
            "CREATE TABLE t (x INT, y INT);
             CREATE FUNCTION f(p INT) RETURNS SETOF INT LANGUAGE plpgsql AS $$
             BEGIN RETURN QUERY SELECT y FROM t WHERE p > 5 AND p > 3; END $$;"
        ),
        ["p > 3"]
    );
}

#[test]
fn a_script_query_is_read() {
    let schema = "CREATE TABLE t (x INT NOT NULL, y INT, CHECK (x > 5));";
    assert_eq!(
        reported_in_statement(schema, "SELECT y FROM t WHERE y = 1 AND x > 3"),
        ["x > 3"]
    );
    assert_eq!(
        reported_in_statement(schema, "UPDATE t SET y = 1 WHERE y = 2 AND x > 3"),
        ["x > 3"]
    );
    assert_eq!(
        reported_in_statement(schema, "DELETE FROM t WHERE y = 2 AND x > 3"),
        ["x > 3"]
    );
    assert_eq!(
        reported_in_statement(schema, "SELECT y FROM t WHERE y = 1 AND x > 7"),
        Vec::<String>::new()
    );
}

#[test]
fn a_weaker_term_of_a_check_conjunction_is_reported() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT, CHECK (x > 5 AND x > 3));"),
        ["x > 3"]
    );
}

#[test]
fn a_stronger_term_of_a_check_disjunction_is_reported() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT, CHECK (x > 5 OR x > 3));"),
        ["x > 5"]
    );
}

#[test]
fn a_stronger_term_of_a_policy_disjunction_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (x INT); CREATE POLICY large ON payments USING (x > 5 OR x > 3);"
        ),
        ["x > 5"]
    );
}

#[test]
fn a_check_admits_null_where_a_policy_does_not() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT, CHECK (x > 0 AND x IS NOT NULL));"),
        Vec::<String>::new()
    );
    assert_eq!(
        reported(
            "CREATE TABLE payments (x INT); CREATE POLICY positive ON payments USING (x > 0 AND x IS NOT NULL);"
        ),
        ["x IS NOT NULL"]
    );
}

#[test]
fn a_with_check_clause_is_read() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (x INT); CREATE POLICY positive ON payments FOR INSERT WITH CHECK (x > 5 AND x > 3);"
        ),
        ["x > 3"]
    );
}

#[test]
fn a_policy_term_the_table_checks_guarantee_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (x INT NOT NULL, owner TEXT, CHECK (x > 5));
             CREATE POLICY own ON payments USING (owner = current_user AND x > 3);"
        ),
        ["x > 3"]
    );
}

#[test]
fn unvalidated_checks_guarantee_nothing() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (x INT NOT NULL, owner TEXT);
             ALTER TABLE payments ADD CONSTRAINT large CHECK (x > 5) NOT VALID;
             CREATE POLICY own ON payments USING (owner = current_user AND x > 3);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_check_term_reads_under_the_other_checks_but_not_its_own() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT, y INT, CHECK (x > 3 AND y > 0));"),
        Vec::<String>::new()
    );
    assert_eq!(
        reported("CREATE TABLE payments (x INT, y INT, CHECK (x > 5), CHECK (x > 3 AND y > 0));"),
        ["x > 3"]
    );
}

#[test]
fn a_partial_index_predicate_is_read() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (id INT PRIMARY KEY, x INT);
             CREATE INDEX large ON payments (id) WHERE x > 5 AND x > 3;"
        ),
        ["x > 3"]
    );
}

#[test]
fn a_nested_term_keeping_the_inner_value_is_reported() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT, y INT, CHECK (y = 1 AND (x > 5 OR x > 3)));"),
        ["x > 5"]
    );
}

#[test]
fn a_term_under_not_is_reported() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT, CHECK (NOT (x > 5 AND x > 3)));"),
        ["x > 3"]
    );
}

#[test]
fn a_nested_term_changing_the_inner_value_is_kept() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (x INT, y INT);
             CREATE POLICY marked ON payments USING (y = 1 OR (x > 0 AND x IS NOT NULL));"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_subquery_is_not_read_over_the_policy_table() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (x INT NOT NULL, CHECK (x > 5));
             CREATE TABLE ledger (x INT NOT NULL, y INT);
             CREATE POLICY listed ON payments USING (EXISTS (SELECT 1 FROM ledger WHERE x > 3 AND y = 1));"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn of_equivalent_terms_only_the_later_is_reported() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT, CHECK (x > 5 AND 5 < x));"),
        ["5 < x"]
    );
}

#[test]
fn a_term_raising_on_admitted_rows_is_kept() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT NOT NULL, CHECK (x >= 0 AND (1 / x) IS NOT NULL));"),
        Vec::<String>::new()
    );
}

#[test]
fn expressions_admitting_no_row_are_left_to_other_rules() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT NOT NULL, CHECK (x > 5 AND x < 0 AND x > 3));"),
        Vec::<String>::new()
    );
}

#[test]
fn expressions_admitting_every_row_are_left_to_other_rules() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (x INT NOT NULL);
             CREATE POLICY everyone ON payments USING (x IS NOT NULL AND x = x);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn independent_terms_are_kept() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (x INT, y INT, CHECK (x > 0 AND y > 0));
             CREATE POLICY either ON payments USING (x > 0 OR y > 0);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn the_message_names_the_site() {
    let constrainer: GenericConstrainer<ParserDB> = RedundantTerm::default().into();
    let messages: Vec<String> = findings(
        &constrainer,
        "redundant_term",
        "CREATE TABLE payments (id INT PRIMARY KEY, x INT, CHECK (x > 5 AND x > 3));
         CREATE POLICY large ON payments USING (x > 5 OR x > 3);
         CREATE INDEX positive ON payments (id) WHERE x > 5 AND x > 3;",
    )
    .into_iter()
    .map(|(_, _, message)| message)
    .collect();
    assert_eq!(messages.len(), 3, "{messages:?}");
    assert!(
        messages
            .iter()
            .any(|message| message.contains("CHECK (x > 5 AND x > 3)"))
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("'large'") && message.contains("USING"))
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("'positive'"))
    );
}

#[test]
fn a_live_redundant_term_is_reported() {
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        "CREATE TABLE payments (x INT, CONSTRAINT positive CHECK (x > 5 AND x > 3));",
    );
    let constrainer: GenericConstrainer<PgDieselDatabase> = RedundantTerm::default().into();
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.to_string(),
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains("x > 3"), "{}", messages[0]);
}
