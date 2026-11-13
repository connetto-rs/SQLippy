//! Policies with the same definition under different names, observed through
//! the public constrainer API.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const DOCS: &str = "
    CREATE ROLE anon;
    CREATE ROLE authenticated;
    CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT, tenant INT, is_public BOOL);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

/// Objects of every violation the rule raises on `policies` declared on
/// `docs`.
fn findings(policies: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = DuplicatePolicy::default().into();
    constrainer
        .diagnostics(
            &ParserDB::parse::<PostgreSqlDialect>(&format!("{DOCS} {policies}"))
                .expect("schema parses"),
        )
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().name, "duplicate_policy");
                violation.object().to_owned()
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn a_restrictive_policy_repeated_under_another_name_is_reported() {
    assert_eq!(
        findings(
            "CREATE POLICY tenant_floor ON docs AS RESTRICTIVE USING (tenant = 1);
             CREATE POLICY tenant_guard ON docs AS RESTRICTIVE USING (tenant = 1);"
        ),
        ["docs.tenant_floor -> docs.tenant_guard"]
    );
}

#[test]
fn a_permissive_policy_repeated_under_another_name_is_reported() {
    assert_eq!(
        findings(
            "CREATE POLICY own ON docs FOR SELECT TO anon, authenticated USING ((owner = current_user));
             CREATE POLICY own_again ON docs FOR SELECT TO authenticated, anon USING (owner = current_user);"
        ),
        ["docs.own -> docs.own_again"]
    );
}

#[test]
fn policies_differing_in_any_part_of_their_definition_are_not_reported() {
    for second in [
        "CREATE POLICY b ON docs AS RESTRICTIVE FOR SELECT USING (owner = current_user);",
        "CREATE POLICY b ON docs FOR UPDATE USING (owner = current_user);",
        "CREATE POLICY b ON docs FOR SELECT TO anon USING (owner = current_user);",
        "CREATE POLICY b ON docs FOR SELECT USING (is_public);",
    ] {
        assert_eq!(
            findings(&format!(
                "CREATE POLICY a ON docs FOR SELECT USING (owner = current_user); {second}"
            )),
            Vec::<String>::new(),
            "{second}"
        );
    }
    assert_eq!(
        findings(
            "CREATE POLICY a ON docs FOR UPDATE USING (owner = current_user) WITH CHECK (is_public);
             CREATE POLICY b ON docs FOR UPDATE USING (owner = current_user);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn three_copies_are_reported_against_the_first() {
    assert_eq!(
        findings(
            "CREATE POLICY a ON docs FOR SELECT USING (is_public);
             CREATE POLICY b ON docs FOR SELECT USING (is_public);
             CREATE POLICY c ON docs FOR SELECT USING (is_public);"
        ),
        ["docs.a -> docs.b", "docs.a -> docs.c"]
    );
}
