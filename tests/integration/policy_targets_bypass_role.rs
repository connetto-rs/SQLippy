//! Policy targets with attributes that bypass row security.

use sql_traits::structs::{AccessResolution, ParseOptions};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Returns diagnostics for bypassing policy targets.
fn messages(roles: &str, policies: &str) -> Vec<String> {
    let database = ParseOptions::default()
        .with_access_resolution(AccessResolution::OpenWorld)
        .parse::<PostgreSqlDialect>(&format!(
            "{roles} CREATE TABLE docs (id INT PRIMARY KEY); \
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY; {policies}"
        ))
        .expect("schema parses");
    DefaultConstrainer::default()
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation)
                if violation.rule().name == "policy_targets_bypass_role" =>
            {
                Some(violation.message().to_owned())
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn declared_bypassing_policy_targets_are_reported() {
    for roles in [
        "CREATE ROLE byp BYPASSRLS;",
        "CREATE ROLE byp; ALTER ROLE byp BYPASSRLS;",
        "CREATE ROLE byp SUPERUSER;",
        "CREATE ROLE byp; ALTER ROLE byp SUPERUSER;",
        "CREATE ROLE byp BYPASSRLS; ALTER ROLE byp LOGIN;",
    ] {
        let found = messages(roles, "CREATE POLICY visible ON docs TO byp USING (true);");
        assert_eq!(found.len(), 1, "{roles}");
        for text in ["visible", "docs", "byp"] {
            assert!(found[0].contains(text), "{}", found[0]);
        }
    }
}

#[test]
fn each_policy_and_bypassing_target_is_reported() {
    let found = messages(
        "CREATE ROLE byp BYPASSRLS; CREATE ROLE root SUPERUSER; CREATE ROLE app;",
        "CREATE POLICY visible ON docs TO byp, app USING (true); \
         CREATE POLICY writable ON docs TO byp, root WITH CHECK (true);",
    );
    assert_eq!(found.len(), 3);
    assert_eq!(
        found
            .iter()
            .filter(|message| message.contains("visible"))
            .count(),
        1
    );
    assert_eq!(
        found
            .iter()
            .filter(|message| message.contains("byp"))
            .count(),
        2
    );
    assert_eq!(
        found
            .iter()
            .filter(|message| message.contains("root"))
            .count(),
        1
    );
}

#[test]
fn targets_without_final_bypass_attributes_are_not_reported() {
    for (roles, target) in [
        (
            "CREATE ROLE byp BYPASSRLS; CREATE ROLE app IN ROLE byp;",
            "app",
        ),
        (
            "CREATE ROLE byp SUPERUSER; CREATE ROLE app IN ROLE byp;",
            "app",
        ),
        (
            "CREATE ROLE byp BYPASSRLS; ALTER ROLE byp NOBYPASSRLS;",
            "byp",
        ),
        (
            "CREATE ROLE byp SUPERUSER; ALTER ROLE byp NOSUPERUSER;",
            "byp",
        ),
        ("CREATE ROLE byp BYPASSRLS;", "PUBLIC"),
        ("", "unknown_role"),
        ("", "CURRENT_USER"),
        ("", "CURRENT_ROLE"),
        ("", "SESSION_USER"),
    ] {
        assert!(
            messages(
                roles,
                &format!("CREATE POLICY visible ON docs TO {target} USING (true);")
            )
            .is_empty(),
            "{roles} {target}"
        );
    }
}

#[test]
fn quoted_role_names_preserve_case() {
    let found = messages(
        "CREATE ROLE \"Byp\" BYPASSRLS; CREATE ROLE byp;",
        "CREATE POLICY visible ON docs TO \"Byp\", byp USING (true);",
    );
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("Byp"));
}
