//! Policies whose clause has the same value for every row, observed through
//! the public constrainer API. Every flagged and passing shape below was
//! measured on PostgreSQL 18.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const DOCS: &str = "
    CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT, is_public BOOL);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

/// Rule name and object of every violation `constrainer` raises on `policies`
/// declared on `docs`.
fn findings(constrainer: &GenericConstrainer<ParserDB>, policies: &str) -> Vec<(String, String)> {
    constrainer
        .diagnostics(
            &ParserDB::parse::<PostgreSqlDialect>(&format!("{DOCS} {policies}"))
                .expect("schema parses"),
        )
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.rule().name.to_owned(),
                violation.object().to_owned(),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn tautological(policies: &str) -> Vec<(String, String)> {
    let constrainer: GenericConstrainer<ParserDB> = TautologicalPolicy::default().into();
    findings(&constrainer, policies)
}

fn unsatisfiable(policies: &str) -> Vec<(String, String)> {
    let constrainer: GenericConstrainer<ParserDB> = UnsatisfiablePolicy::default().into();
    findings(&constrainer, policies)
}

fn finding(rule: &str, object: &str) -> (String, String) {
    (rule.to_owned(), object.to_owned())
}

const OWN: &str =
    "CREATE POLICY own ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));";

#[test]
fn a_permissive_condition_that_admits_every_row_is_reported() {
    for using in [
        "owner = current_setting('app.user_id', true) OR true",
        "(owner = current_setting('app.user_id', true)) OR (1 = 1)",
    ] {
        assert_eq!(
            tautological(&format!(
                "CREATE POLICY own ON docs FOR SELECT USING ({using});"
            )),
            [finding("tautological_policy", "docs.own")],
            "{using}"
        );
    }
}

#[test]
fn a_deliberate_public_read_is_not_reported() {
    for public in [
        "CREATE POLICY everyone ON docs FOR SELECT USING (true);",
        "CREATE POLICY everyone ON docs FOR SELECT USING ((true));",
    ] {
        assert_eq!(tautological(public), [], "{public}");
    }
    assert_eq!(tautological(OWN), []);
}

#[test]
fn a_restrictive_policy_that_restricts_nothing_is_reported() {
    for floor in [
        "CREATE POLICY floor ON docs AS RESTRICTIVE FOR SELECT USING (true);",
        "CREATE POLICY floor ON docs AS RESTRICTIVE FOR SELECT USING (owner IS NULL OR true);",
        "CREATE POLICY floor ON docs AS RESTRICTIVE FOR INSERT WITH CHECK (true);",
    ] {
        assert_eq!(
            tautological(&format!("{OWN} {floor}")),
            [finding("tautological_policy", "docs.floor")],
            "{floor}"
        );
    }
    assert_eq!(
        tautological(&format!(
            "{OWN} CREATE POLICY floor ON docs AS RESTRICTIVE FOR SELECT USING (is_public);"
        )),
        []
    );
}

#[test]
fn a_restrictive_policy_that_still_checks_writes_is_not_reported() {
    for floor in [
        "CREATE POLICY floor ON docs AS RESTRICTIVE USING (true) WITH CHECK (owner = current_user);",
        "CREATE POLICY floor ON docs AS RESTRICTIVE FOR UPDATE USING (true) WITH CHECK (owner = current_user);",
    ] {
        assert_eq!(tautological(&format!("{OWN} {floor}")), [], "{floor}");
    }
    assert_eq!(
        tautological(&format!(
            "{OWN} CREATE POLICY floor ON docs AS RESTRICTIVE USING (true) WITH CHECK (true);"
        )),
        [finding("tautological_policy", "docs.floor -> docs.floor")]
    );
}

#[test]
fn a_permissive_policy_that_admits_no_row_is_reported() {
    for policy in [
        "CREATE POLICY own ON docs FOR SELECT USING (false);",
        "CREATE POLICY own ON docs FOR SELECT USING (owner = current_setting('app.user_id', true) AND false);",
        "CREATE POLICY own ON docs FOR INSERT WITH CHECK (owner = current_setting('app.user_id', true) AND 1 = 0);",
    ] {
        assert_eq!(
            unsatisfiable(policy),
            [finding("unsatisfiable_policy", "docs.own")],
            "{policy}"
        );
    }
    assert_eq!(unsatisfiable(OWN), []);
}

#[test]
fn a_permissive_policy_that_still_grants_a_command_is_not_reported() {
    for policy in [
        "CREATE POLICY own ON docs USING (false) WITH CHECK (owner = current_user);",
        "CREATE POLICY own ON docs FOR UPDATE USING (owner = current_user) WITH CHECK (owner = current_user OR false);",
        "CREATE POLICY own ON docs FOR UPDATE USING (owner = current_user) WITH CHECK (false);",
    ] {
        assert_eq!(unsatisfiable(policy), [], "{policy}");
    }
    assert_eq!(
        unsatisfiable("CREATE POLICY own ON docs USING (false);"),
        [finding("unsatisfiable_policy", "docs.own")]
    );
    assert_eq!(
        unsatisfiable("CREATE POLICY own ON docs USING (false) WITH CHECK (false);"),
        [finding("unsatisfiable_policy", "docs.own -> docs.own")]
    );
}

#[test]
fn policies_whose_impossible_stages_complement_each_other_are_not_reported() {
    assert_eq!(
        unsatisfiable(
            "CREATE POLICY p1 ON docs FOR UPDATE USING (false) WITH CHECK (owner = current_user);
             CREATE POLICY p2 ON docs FOR UPDATE USING (owner = current_user) WITH CHECK (false);"
        ),
        []
    );
}

#[test]
fn a_restrictive_lockout_is_not_reported() {
    assert_eq!(
        unsatisfiable(&format!(
            "{OWN} CREATE POLICY no_delete ON docs AS RESTRICTIVE FOR DELETE USING (false);"
        )),
        []
    );
}
