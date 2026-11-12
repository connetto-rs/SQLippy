//! Policies trusting a claim or column the caller sets, observed through the
//! public constrainer API.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
    CREATE SCHEMA auth;
    CREATE TABLE auth.users (id TEXT, raw_user_meta_data JSONB, raw_app_meta_data JSONB);
    CREATE TABLE profiles (id TEXT, raw_user_meta_data JSONB, team TEXT);
    CREATE TABLE docs (team TEXT, owner TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

fn deployment() -> Deployment {
    Deployment::default()
        .with_self_asserted_claim("auth.jwt() -> 'user_metadata'")
        .expect("claim parses")
        .with_self_asserted_column("auth", "users", "raw_user_meta_data")
}

/// Every diagnostic of the rule as level, object and policy sites, or the
/// rendered failure.
fn outcomes<C: Constrainer<Database = ParserDB>>(constrainer: &C, sql: &str) -> Vec<String> {
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA}{sql}")).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation)
                if violation.rule().name == "self_asserted_claim_policy" =>
            {
                let Location::Policies(sites) = violation.location() else {
                    panic!("the rule reports policies");
                };
                let sites: Vec<String> = sites
                    .iter()
                    .map(|site| format!("{} {}", site.clause(), site.expression()))
                    .collect();
                Some(format!(
                    "{:?} {}: {}",
                    violation.level(),
                    violation.object(),
                    sites.join(" | ")
                ))
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => Some(other.to_string()),
        })
        .collect()
}

fn reported(sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = SelfAssertedClaimPolicy::default().into();
    constrainer.set_deployment(deployment());
    outcomes(&constrainer, sql)
}

#[test]
fn a_declared_claim_read_anywhere_in_a_policy_is_reported() {
    for (policy, site) in [
        (
            "CREATE POLICY p ON docs USING (team = auth.jwt() -> 'user_metadata' ->> 'team');",
            "USING auth.jwt() -> 'user_metadata'",
        ),
        (
            "CREATE POLICY p ON docs FOR INSERT WITH CHECK ((auth.jwt() -> 'user_metadata') ? 'admin');",
            "WITH CHECK auth.jwt() -> 'user_metadata'",
        ),
        (
            "CREATE POLICY p ON docs USING (team IN (
               SELECT p.team FROM profiles p WHERE (auth.jwt() -> 'user_metadata' ->> 'admin')::BOOL));",
            "USING auth.jwt() -> 'user_metadata'",
        ),
    ] {
        assert_eq!(reported(policy), [format!("Deny docs.p: {site}")], "{policy}");
    }
}

#[test]
fn a_declared_column_read_through_aliases_and_sublinks_is_reported() {
    for (policy, site) in [
        (
            "CREATE POLICY p ON docs USING (EXISTS (
               SELECT 1 FROM auth.users u WHERE u.id = docs.owner AND u.raw_user_meta_data ->> 'role' = 'admin'));",
            "u.raw_user_meta_data",
        ),
        (
            "CREATE POLICY p ON docs USING (owner IN (
               SELECT id FROM profiles WHERE id IN (
                 SELECT id FROM auth.users WHERE raw_user_meta_data ? 'admin')));",
            "raw_user_meta_data",
        ),
        (
            "CREATE POLICY p ON docs USING (owner IN (
               SELECT s.id FROM (SELECT id, raw_user_meta_data AS meta FROM auth.users) AS s
               WHERE s.meta ? 'admin'));",
            "raw_user_meta_data",
        ),
        (
            "ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON auth.users USING (raw_user_meta_data ? 'admin');",
            "raw_user_meta_data",
        ),
    ] {
        let object = if policy.contains("ON auth.users") { "users.p" } else { "docs.p" };
        assert_eq!(
            reported(policy),
            [format!("Deny {object}: USING {site}")],
            "{policy}"
        );
    }
}

#[test]
fn issued_claims_and_columns_of_the_same_name_elsewhere_pass() {
    for policy in [
        "CREATE POLICY p ON docs USING (team = auth.jwt() -> 'app_metadata' ->> 'team');",
        "CREATE POLICY p ON docs USING (team = auth.jwt() ->> 'user_metadata');",
        "CREATE POLICY p ON docs USING (EXISTS (
           SELECT 1 FROM auth.users u WHERE u.id = docs.owner AND u.raw_app_meta_data ? 'admin'));",
        "CREATE POLICY p ON docs USING (EXISTS (
           SELECT 1 FROM profiles WHERE id = docs.owner AND raw_user_meta_data ? 'admin'));",
        "CREATE POLICY p ON docs USING (owner IN (
           SELECT id FROM auth.users WHERE id IN (
             SELECT id FROM profiles WHERE raw_user_meta_data ? 'admin')));",
        "CREATE POLICY p ON docs USING (owner IN (
           SELECT id FROM auth.users UNION SELECT id FROM profiles));",
    ] {
        assert_eq!(reported(policy), Vec::<String>::new(), "{policy}");
    }
}

#[test]
fn a_finding_names_every_clause_reading_a_source() {
    assert_eq!(
        reported(
            "CREATE POLICY p ON docs FOR UPDATE
               USING (team = auth.jwt() -> 'user_metadata' ->> 'team')
               WITH CHECK (EXISTS (SELECT 1 FROM auth.users WHERE raw_user_meta_data ? 'admin'));"
        ),
        [
            "Deny docs.p -> docs.p: USING auth.jwt() -> 'user_metadata' | WITH CHECK raw_user_meta_data"
        ]
    );
}

#[test]
fn a_declared_column_of_a_table_outside_the_schema_fails_the_lookup() {
    let mut constrainer: GenericConstrainer<ParserDB> = SelfAssertedClaimPolicy::default().into();
    constrainer.set_deployment(Deployment::default().with_self_asserted_column(
        "auth",
        "identities",
        "identity_data",
    ));
    let outcome = outcomes(&constrainer, "");
    assert_eq!(outcome.len(), 1);
    assert!(outcome[0].contains("auth.identities"), "{outcome:?}");
}

#[test]
fn an_ambiguous_reference_fails_the_lookup() {
    for policy in [
        "CREATE POLICY p ON docs USING (EXISTS (SELECT 1 FROM auth.users, profiles WHERE id = 'x'));",
        "CREATE POLICY p ON docs USING (EXISTS (
           SELECT 1 FROM docs d WHERE EXISTS (SELECT 1 FROM auth.users, profiles WHERE id = 'x')));",
    ] {
        let outcome = reported(policy);
        assert_eq!(outcome.len(), 1, "{policy}");
        assert!(!outcome[0].starts_with("Deny"), "{outcome:?}");
    }
}

#[test]
fn the_rule_waits_for_a_declared_source_and_denies_by_default() {
    let sql = "CREATE POLICY p ON docs USING (team = auth.jwt() -> 'user_metadata' ->> 'team');";
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA}{sql}")).expect("schema parses");
    let inactive = DefaultConstrainer::<ParserDB>::default()
        .diagnostics(&database)
        .into_iter()
        .any(|error| {
            matches!(&error, Error::Inactive(rule)
                if rule.rule().name == "self_asserted_claim_policy"
                    && rule.missing() == Declaration::SelfAssertedSources)
        });
    assert!(inactive);
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    constrainer.set_deployment(deployment());
    assert_eq!(
        outcomes(&constrainer, sql),
        ["Deny docs.p: USING auth.jwt() -> 'user_metadata'"]
    );
    assert_eq!(
        Declaration::SelfAssertedSources.to_string(),
        "self-asserted claims or columns"
    );
}
