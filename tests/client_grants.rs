//! Grants that hand client roles operations row-level security does not
//! govern, observed through the public constrainer API.

mod common;

use common::{ROLES, finding, findings, parse, supabase};
use sql_rules::prelude::*;

#[test]
fn a_table_without_row_level_security_granted_to_a_client_role_is_reachable() {
    for grantee in ["PUBLIC", "anon", "authenticated"] {
        assert_eq!(
            findings(
                ReachableTableWithoutRowLevelSecurity::default(),
                supabase(),
                &format!("CREATE TABLE secrets (id INT); GRANT SELECT ON secrets TO {grantee};"),
            ),
            [finding(
                "ReachableTableWithoutRowLevelSecurity",
                Level::Warn,
                "secrets"
            )],
            "{grantee}"
        );
    }
}

#[test]
fn a_grant_to_a_role_a_client_role_inherits_reaches_the_client() {
    assert_eq!(
        findings(
            ReachableTableWithoutRowLevelSecurity::default(),
            Deployment::default().with_app_role("app_user"),
            "CREATE ROLE readers;
             CREATE ROLE app_user IN ROLE readers;
             CREATE TABLE secrets (id INT);
             GRANT SELECT ON secrets TO readers;",
        ),
        [finding(
            "ReachableTableWithoutRowLevelSecurity",
            Level::Warn,
            "secrets"
        )]
    );
}

#[test]
fn a_table_without_row_level_security_left_to_other_roles_is_not_reachable() {
    for sql in [
        "CREATE TABLE secrets (id INT); GRANT SELECT ON secrets TO reporting;",
        "CREATE TABLE secrets (id INT); GRANT SELECT ON secrets TO anon; REVOKE SELECT ON secrets FROM anon;",
        "CREATE TABLE secrets (id INT); ALTER TABLE secrets ENABLE ROW LEVEL SECURITY; GRANT SELECT ON secrets TO anon;",
    ] {
        assert_eq!(
            findings(
                ReachableTableWithoutRowLevelSecurity::default(),
                supabase(),
                sql
            ),
            [],
            "{sql}"
        );
    }
}

#[test]
fn a_table_without_row_level_security_in_an_exposed_schema_is_reachable_without_a_grant() {
    let sql =
        "CREATE SCHEMA api; CREATE TABLE api.secrets (id INT); CREATE TABLE internal (id INT);";
    assert_eq!(
        findings(
            ReachableTableWithoutRowLevelSecurity::default(),
            supabase().with_exposed_schema("api"),
            sql,
        ),
        [finding(
            "ReachableTableWithoutRowLevelSecurity",
            Level::Warn,
            "secrets"
        )]
    );
    assert_eq!(
        findings(
            ReachableTableWithoutRowLevelSecurity::default(),
            supabase(),
            sql
        ),
        []
    );
}

#[test]
fn an_unqualified_table_sits_in_the_public_schema() {
    assert_eq!(
        findings(
            ReachableTableWithoutRowLevelSecurity::default(),
            supabase().with_exposed_schema("public"),
            "CREATE TABLE secrets (id INT);",
        ),
        [finding(
            "ReachableTableWithoutRowLevelSecurity",
            Level::Warn,
            "secrets"
        )]
    );
}

const PROTECTED: &str = "
    CREATE TABLE docs (id INT PRIMARY KEY, email TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

#[test]
fn truncate_granted_to_an_anonymous_role_is_denied() {
    for grant in [
        "GRANT TRUNCATE ON docs TO PUBLIC;",
        "GRANT TRUNCATE ON docs TO anon;",
        "GRANT ALL ON docs TO anon;",
    ] {
        assert_eq!(
            findings(
                TruncateGrantedToAnonymousRole::default(),
                supabase(),
                &format!("{PROTECTED}{grant}"),
            ),
            [finding(
                "TruncateGrantedToAnonymousRole",
                Level::Deny,
                "docs"
            )],
            "{grant}"
        );
    }
}

#[test]
fn truncate_granted_to_an_app_role_warns_once_and_not_for_anonymous_grants() {
    assert_eq!(
        findings(
            TruncateGrantedToAppRole::default(),
            supabase(),
            &format!("{PROTECTED}GRANT TRUNCATE ON docs TO authenticated;"),
        ),
        [finding("TruncateGrantedToAppRole", Level::Warn, "docs")]
    );
    assert_eq!(
        findings(
            TruncateGrantedToAppRole::default(),
            supabase(),
            &format!("{PROTECTED}GRANT TRUNCATE ON docs TO PUBLIC;"),
        ),
        []
    );
}

#[test]
fn truncate_on_a_table_without_row_level_security_or_to_other_roles_is_not_reported() {
    for sql in [
        "CREATE TABLE docs (id INT); GRANT TRUNCATE ON docs TO anon, authenticated;",
        &format!("{PROTECTED}GRANT TRUNCATE ON docs TO reporting;"),
        &format!("{PROTECTED}GRANT DELETE ON docs TO anon, authenticated;"),
    ] {
        let mut constrainer: GenericConstrainer<ParserDB> =
            TruncateGrantedToAnonymousRole::default().into();
        constrainer.register_table_rule(Box::new(TruncateGrantedToAppRole::default()));
        assert_eq!(findings(constrainer, supabase(), sql), [], "{sql}");
    }
}

#[test]
fn references_granted_to_a_client_role_on_a_protected_table_is_reported() {
    for grant in [
        "GRANT REFERENCES ON docs TO anon;",
        "GRANT REFERENCES (email) ON docs TO authenticated;",
        "GRANT ALL PRIVILEGES ON docs TO PUBLIC;",
    ] {
        assert_eq!(
            findings(
                ReferencesGrantedToClientRole::default(),
                supabase(),
                &format!("{PROTECTED}{grant}"),
            ),
            [finding(
                "ReferencesGrantedToClientRole",
                Level::Warn,
                "docs"
            )],
            "{grant}"
        );
    }
}

#[test]
fn references_without_row_level_security_or_to_other_roles_is_not_reported() {
    for sql in [
        "CREATE TABLE docs (id INT PRIMARY KEY); GRANT REFERENCES ON docs TO anon;",
        &format!("{PROTECTED}GRANT REFERENCES ON docs TO reporting;"),
        &format!("{PROTECTED}GRANT SELECT (email) ON docs TO anon;"),
    ] {
        assert_eq!(
            findings(ReferencesGrantedToClientRole::default(), supabase(), sql),
            [],
            "{sql}"
        );
    }
}

#[test]
fn a_grant_option_handed_to_a_client_role_is_reported() {
    for grant in [
        "GRANT SELECT ON docs TO authenticated WITH GRANT OPTION;",
        "GRANT UPDATE (email) ON docs TO anon WITH GRANT OPTION;",
        "GRANT SELECT ON docs TO PUBLIC WITH GRANT OPTION;",
    ] {
        assert_eq!(
            findings(
                GrantOptionToClientRole::default(),
                supabase(),
                &format!("CREATE TABLE docs (id INT, email TEXT);{grant}"),
            ),
            [finding("GrantOptionToClientRole", Level::Warn, "docs")],
            "{grant}"
        );
    }
}

#[test]
fn a_grant_option_kept_from_client_roles_is_not_reported() {
    for grant in [
        "GRANT SELECT ON docs TO reporting WITH GRANT OPTION;",
        "GRANT SELECT ON docs TO authenticated;",
        "GRANT SELECT ON docs TO anon WITH GRANT OPTION; REVOKE GRANT OPTION FOR SELECT ON docs FROM anon;",
    ] {
        assert_eq!(
            findings(
                GrantOptionToClientRole::default(),
                supabase(),
                &format!("CREATE TABLE docs (id INT, email TEXT);{grant}"),
            ),
            [],
            "{grant}"
        );
    }
}

#[test]
fn a_rule_missing_its_declaration_is_listed_once_and_never_runs() {
    let mut constrainer: GenericConstrainer<ParserDB> = TruncateGrantedToAppRole::default().into();
    let database = parse(&format!(
        "{ROLES}{PROTECTED}GRANT TRUNCATE ON docs TO authenticated;"
    ));

    let diagnostics = constrainer.diagnostics(&database);
    assert_eq!(diagnostics.len(), 1);
    let Error::Inactive(inactive) = &diagnostics[0] else {
        panic!("expected an inactive rule, got {}", diagnostics[0]);
    };
    assert_eq!(
        (inactive.rule().name, inactive.missing()),
        ("TruncateGrantedToAppRole", Declaration::AppRoles)
    );
    let shown = diagnostics[0].to_string();
    assert!(
        shown.contains("TruncateGrantedToAppRole") && shown.contains("app roles"),
        "{shown}"
    );
    assert!(constrainer.validate_schema(&database).is_ok());

    constrainer.set_rule_level("TruncateGrantedToAppRole", Level::Allow);
    assert!(constrainer.inactive_rules().is_empty());
}

#[test]
fn the_default_constrainer_runs_the_grant_rules_at_their_group_levels() {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    assert_eq!(
        constrainer
            .inactive_rules()
            .iter()
            .map(|inactive| inactive.rule().name)
            .collect::<Vec<_>>(),
        [
            "TruncateGrantedToAppRole",
            "RoleKeyedPolicyWhenPooled",
            "ClientRoleBypassesRowLevelSecurity",
            "SettableMembershipInBypassingRole",
        ]
    );
    constrainer.set_deployment(supabase());
    assert_eq!(
        constrainer
            .inactive_rules()
            .iter()
            .map(|inactive| inactive.rule().name)
            .collect::<Vec<_>>(),
        ["RoleKeyedPolicyWhenPooled"]
    );
    let database = parse(&format!(
        "{ROLES}{PROTECTED}
         CREATE TABLE open_data (id INT PRIMARY KEY);
         GRANT TRUNCATE, REFERENCES ON docs TO anon WITH GRANT OPTION;
         GRANT SELECT ON open_data TO anon;"
    ));
    let mut raised: Vec<(String, Level)> = constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) => {
                Some((violation.rule().name.to_owned(), violation.level()))
            }
            _ => None,
        })
        .filter(|(rule, _)| {
            [
                "ReachableTableWithoutRowLevelSecurity",
                "TruncateGrantedToAnonymousRole",
                "ReferencesGrantedToClientRole",
                "GrantOptionToClientRole",
            ]
            .contains(&rule.as_str())
        })
        .collect();
    raised.sort();
    assert_eq!(
        raised,
        [
            ("GrantOptionToClientRole".to_owned(), Level::Warn),
            (
                "ReachableTableWithoutRowLevelSecurity".to_owned(),
                Level::Warn
            ),
            ("TruncateGrantedToAnonymousRole".to_owned(), Level::Deny),
        ]
    );
}
