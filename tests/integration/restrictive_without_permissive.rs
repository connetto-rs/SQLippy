//! Restrictive policies on commands no permissive policy grants to their
//! roles, observed through the public constrainer API. Every flagged and
//! passing shape below was measured on PostgreSQL 18.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const DOCS: &str = "
    CREATE ROLE anon;
    CREATE ROLE authenticated;
    CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT, is_public BOOL);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

/// Objects of every violation the rule raises on `policies` declared on
/// `docs`.
fn findings(policies: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = RestrictiveWithoutPermissive::default().into();
    constrainer
        .diagnostics(
            &ParserDB::parse::<PostgreSqlDialect>(&format!("{DOCS} {policies}"))
                .expect("schema parses"),
        )
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().name, "restrictive_without_permissive");
                violation.object().to_owned()
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn a_restrictive_policy_alone_is_reported() {
    assert_eq!(
        findings("CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT USING (is_public);"),
        ["docs.pub"]
    );
}

#[test]
fn a_permissive_policy_on_another_command_does_not_help() {
    assert_eq!(
        findings(
            "CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT USING (is_public);
             CREATE POLICY del ON docs FOR DELETE USING (true);"
        ),
        ["docs.pub"]
    );
}

#[test]
fn a_permissive_policy_for_other_roles_does_not_help() {
    assert_eq!(
        findings(
            "CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT TO anon USING (is_public);
             CREATE POLICY signed ON docs FOR SELECT TO authenticated USING (true);"
        ),
        ["docs.pub"]
    );
}

#[test]
fn a_restrictive_policy_for_public_narrows_a_named_role() {
    assert_eq!(
        findings(
            "CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT USING (is_public);
             CREATE POLICY signed ON docs FOR SELECT TO authenticated USING (true);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_role_holding_both_targets_makes_the_restrictive_policy_take_effect() {
    assert_eq!(
        findings(
            "CREATE ROLE member;
             GRANT anon TO member;
             GRANT authenticated TO member;
             CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT TO anon USING (is_public);
             CREATE POLICY signed ON docs FOR SELECT TO authenticated USING (true);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_restrictive_policy_beside_a_permissive_one_is_not_reported() {
    for permissive in [
        "CREATE POLICY everyone ON docs FOR SELECT USING (true);",
        "CREATE POLICY everyone ON docs FOR ALL USING (true);",
        "CREATE POLICY everyone ON docs FOR SELECT TO anon USING (true);",
    ] {
        assert_eq!(
            findings(&format!(
                "CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT TO anon USING (is_public);
                 {permissive}"
            )),
            Vec::<String>::new(),
            "{permissive}"
        );
    }
}

#[test]
fn a_permissive_policy_inherited_through_membership_counts() {
    assert_eq!(
        findings(
            "GRANT authenticated TO anon;
             CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT TO anon USING (is_public);
             CREATE POLICY signed ON docs FOR SELECT TO authenticated USING (true);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_membership_without_inherit_does_not_count() {
    assert_eq!(
        findings(
            "CREATE ROLE noinh NOINHERIT;
             GRANT authenticated TO noinh;
             CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT TO noinh USING (is_public);
             CREATE POLICY signed ON docs FOR SELECT TO authenticated USING (true);"
        ),
        ["docs.pub"]
    );
}

#[test]
fn a_restrictive_floor_over_every_command_needs_one_permissive_command() {
    assert_eq!(
        findings(
            "CREATE POLICY floor ON docs AS RESTRICTIVE USING (is_public);
             CREATE POLICY everyone ON docs FOR SELECT USING (true);"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        findings("CREATE POLICY floor ON docs AS RESTRICTIVE USING (is_public);"),
        ["docs.floor"]
    );
}
