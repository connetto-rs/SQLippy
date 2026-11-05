//! Role memberships granted with `GRANT role TO role`, and their `INHERIT`
//! and `SET` options, observed through the public constrainer API.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Rule name and object of every violation, failing on anything else.
fn findings(
    constrainer: impl Into<GenericConstrainer<ParserDB>>,
    deployment: Deployment,
    sql: &str,
) -> Vec<(String, String)> {
    let mut constrainer = constrainer.into();
    constrainer.set_deployment(deployment);
    constrainer
        .diagnostics(&ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses"))
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

fn app_user() -> Deployment {
    Deployment::default().with_app_role("app_user")
}

const BYPASSER: &str = "CREATE ROLE bypasser BYPASSRLS; CREATE ROLE app_user;";

#[test]
fn a_granted_membership_in_a_bypassing_role_is_settable_by_default() {
    for grant in [
        "GRANT bypasser TO app_user;",
        "GRANT bypasser TO app_user WITH INHERIT FALSE;",
        "CREATE ROLE staff; GRANT bypasser TO staff WITH INHERIT FALSE; GRANT staff TO app_user;",
    ] {
        assert_eq!(
            findings(
                SettableMembershipInBypassingRole::default(),
                app_user(),
                &format!("{BYPASSER}{grant}")
            ),
            [(
                "SettableMembershipInBypassingRole".to_owned(),
                "app_user".to_owned()
            )],
            "{grant}"
        );
    }
}

#[test]
fn a_membership_granted_with_set_false_cannot_reach_the_bypassing_role() {
    for grant in [
        "GRANT bypasser TO app_user WITH SET FALSE;",
        "CREATE ROLE staff; GRANT bypasser TO staff WITH SET FALSE; GRANT staff TO app_user;",
        "CREATE ROLE staff; GRANT bypasser TO staff; GRANT staff TO app_user WITH SET FALSE;",
    ] {
        assert_eq!(
            findings(
                SettableMembershipInBypassingRole::default(),
                app_user(),
                &format!("{BYPASSER}{grant}")
            ),
            [],
            "{grant}"
        );
    }
}

#[test]
fn a_grant_to_a_role_held_without_inherit_does_not_reach_the_client() {
    let schema = "CREATE ROLE readers; CREATE ROLE app_user;
                  CREATE TABLE secrets (id INT); GRANT SELECT ON secrets TO readers;";
    assert_eq!(
        findings(
            ReachableTableWithoutRowLevelSecurity::default(),
            app_user(),
            &format!("{schema} GRANT readers TO app_user;")
        ),
        [(
            "ReachableTableWithoutRowLevelSecurity".to_owned(),
            "secrets".to_owned()
        )]
    );
    assert_eq!(
        findings(
            ReachableTableWithoutRowLevelSecurity::default(),
            app_user(),
            &format!("{schema} GRANT readers TO app_user WITH INHERIT FALSE;")
        ),
        []
    );
}
