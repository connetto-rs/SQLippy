//! Policy subqueries correlated to the checked row, observed through the public
//! constrainer API.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const TABLES: &str = "
    CREATE TABLE test_table (id INT, team_id INT);
    CREATE TABLE team_user (team_id INT, user_id TEXT);
    ALTER TABLE test_table ENABLE ROW LEVEL SECURITY;";

/// Level, clause and subquery of every violation.
fn correlated(policy: &str) -> Vec<(Level, PolicyClause, String)> {
    let constrainer: GenericConstrainer<ParserDB> = CorrelatedPolicySubquery::default().into();
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{TABLES}{policy}")).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                let Location::Policies(sites) = violation.location() else {
                    panic!("a policy finding is located on policies");
                };
                let [site] = sites.as_slice() else {
                    panic!("one site per correlated subquery");
                };
                (
                    violation.level(),
                    site.clause(),
                    site.expression().to_owned(),
                )
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn a_subquery_joined_to_the_checked_row_is_reported() {
    assert_eq!(
        correlated(
            "CREATE POLICY rls_test_select ON test_table USING (
               current_user IN (SELECT user_id FROM team_user WHERE team_user.team_id = test_table.team_id));"
        ),
        [(
            Level::Warn,
            PolicyClause::Using,
            "SELECT user_id FROM team_user WHERE team_user.team_id = test_table.team_id".to_owned()
        )]
    );
}

#[test]
fn a_subquery_reading_only_the_caller_is_not_reported() {
    assert_eq!(
        correlated(
            "CREATE POLICY rls_test_select ON test_table USING (
               team_id IN (SELECT team_id FROM team_user WHERE user_id = current_user));"
        ),
        []
    );
}

#[test]
fn a_subquery_reading_the_policy_table_itself_is_not_correlated() {
    for policy in [
        "CREATE POLICY own ON test_table USING (EXISTS (SELECT 1 FROM test_table WHERE id = test_table.id));",
        "CREATE POLICY own ON test_table USING (EXISTS (SELECT 1 FROM team_user AS test_table WHERE test_table.team_id > 0));",
    ] {
        assert_eq!(correlated(policy), [], "{policy}");
    }
}

#[test]
fn a_subquery_whose_with_item_reads_the_checked_row_is_reported() {
    assert_eq!(
        correlated(
            "CREATE POLICY p ON test_table USING (EXISTS (
               WITH m AS (SELECT 1 FROM team_user WHERE team_user.team_id = test_table.team_id AND user_id = current_user)
               SELECT 1 FROM m));"
        ),
        [(
            Level::Warn,
            PolicyClause::Using,
            "WITH m AS (SELECT 1 FROM team_user WHERE team_user.team_id = test_table.team_id AND user_id = current_user) SELECT 1 FROM m".to_owned()
        )]
    );
}

#[test]
fn a_subquery_nesting_a_sublink_that_reads_the_checked_row_is_reported() {
    assert_eq!(
        correlated(
            "CREATE POLICY p ON test_table USING (EXISTS (
               SELECT 1 FROM team_user u WHERE u.user_id = current_user
                 AND EXISTS (SELECT 1 FROM team_user v WHERE v.team_id = test_table.team_id)));"
        )
        .len(),
        1
    );
}

#[test]
fn a_with_item_reading_only_the_caller_and_its_own_relations_is_not_correlated() {
    for policy in [
        "CREATE POLICY p ON test_table USING (team_id IN (
           WITH m AS (SELECT team_user.team_id FROM team_user WHERE team_user.user_id = current_user)
           SELECT m.team_id FROM m));",
        "CREATE POLICY p ON test_table USING (team_id IN (
           WITH m AS (SELECT team_id FROM team_user WHERE user_id = current_user),
                n AS (SELECT m.team_id FROM m WHERE m.team_id > 0)
           SELECT team_id FROM n));",
    ] {
        assert_eq!(correlated(policy), [], "{policy}");
    }
}

#[test]
fn ordering_local_with_outputs_does_not_correlate_a_policy() {
    for policy in [
        "CREATE POLICY p ON test_table USING (team_id IN (
           WITH members AS (SELECT team_id FROM team_user WHERE user_id = current_user)
           SELECT team_id FROM members ORDER BY team_id));",
        "CREATE POLICY p ON test_table USING (team_id IN (
           WITH members AS (SELECT team_id FROM team_user WHERE user_id = current_user ORDER BY team_id)
           SELECT team_id FROM members));",
    ] {
        assert_eq!(correlated(policy), [], "{policy}");
    }
}

#[test]
fn every_correlated_subquery_of_every_clause_is_reported() {
    let found = correlated(
        "CREATE POLICY team_rows ON test_table FOR ALL
           USING (EXISTS (SELECT 1 FROM team_user u WHERE u.team_id = test_table.team_id AND u.user_id = current_user)
                  OR EXISTS (SELECT 1 FROM team_user v WHERE v.team_id = team_id AND v.user_id = 'admin'))
           WITH CHECK (EXISTS (SELECT 1 FROM team_user w WHERE w.team_id = test_table.team_id));",
    );
    let clauses: Vec<PolicyClause> = found.iter().map(|(_, clause, _)| *clause).collect();
    assert_eq!(clauses, [PolicyClause::Using, PolicyClause::WithCheck]);
}

#[test]
fn the_default_constrainer_warns_about_correlated_policy_subqueries() {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{TABLES} CREATE POLICY p ON test_table USING (
           EXISTS (SELECT 1 FROM team_user u WHERE u.team_id = test_table.team_id));"
    ))
    .expect("schema parses");
    assert!(
        DefaultConstrainer::<ParserDB>::default()
            .diagnostics(&database)
            .iter()
            .any(|error| {
                matches!(
                    error,
                    Error::Violation(violation)
                        if violation.rule().name == "correlated_policy_subquery"
                            && violation.rule().group == LintGroup::Perf
                            && violation.level() == Level::Warn
                )
            })
    );
}
