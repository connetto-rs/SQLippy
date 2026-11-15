//! Role changes a database-local schema makes to the cluster its bootstrap
//! provisions, observed through the public constrainer API.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const BOOTSTRAP: &str = "
    CREATE ROLE anon NOLOGIN;
    CREATE ROLE authenticated NOLOGIN;
    GRANT anon TO authenticated;
    ALTER ROLE authenticated SET statement_timeout = '5s';";

/// Parses `sql` under the open world, where a role the input never creates
/// may still be named, as in a schema checked without its bootstrap.
fn parse(sql: &str) -> ParserDB {
    ParseOptions::default()
        .with_access_resolution(AccessResolution::OpenWorld)
        .parse::<PostgreSqlDialect>(sql)
        .expect("schema parses")
}

/// Objects `RoleDefinedInSchema` reports on `schema` under a deployment
/// declaring [`BOOTSTRAP`], failing on anything else.
fn reported(schema: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = RoleDefinedInSchema::default().into();
    constrainer.set_rule_level("role_defined_in_schema", Level::Warn);
    constrainer.set_deployment(Deployment::default().with_cluster_bootstrap(&parse(BOOTSTRAP)));
    let mut objects: Vec<String> = constrainer
        .diagnostics(&parse(schema))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    objects.sort();
    objects
}

#[test]
fn the_bootstrap_followed_by_a_schema_that_leaves_roles_alone_is_clean() {
    assert_eq!(
        reported(&format!(
            "{BOOTSTRAP}
             CREATE TABLE documents (id INT PRIMARY KEY);
             GRANT SELECT ON documents TO authenticated;"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn a_schema_checked_without_the_bootstrap_is_reported_for_what_it_adds() {
    assert_eq!(
        reported(
            "CREATE TABLE documents (id INT PRIMARY KEY);
             GRANT SELECT ON documents TO authenticated;"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        reported(
            "GRANT anon TO reporting;
             ALTER ROLE anon SET statement_timeout = '1s';"
        ),
        ["anon SET statement_timeout", "anon TO reporting"]
    );
}

#[test]
fn every_cluster_wide_role_change_of_the_schema_is_reported() {
    assert_eq!(
        reported(&format!(
            "{BOOTSTRAP}
             CREATE ROLE reporting NOLOGIN;
             ALTER ROLE anon BYPASSRLS;
             GRANT authenticated TO reporting;
             ALTER ROLE anon SET statement_timeout = '1s';
             ALTER ROLE ALL SET lock_timeout = '1s';"
        )),
        [
            "ALL SET lock_timeout",
            "anon",
            "anon SET statement_timeout",
            "authenticated TO reporting",
            "reporting",
        ]
    );
}

#[test]
fn undoing_or_changing_what_the_bootstrap_set_is_reported() {
    assert_eq!(
        reported(&format!(
            "{BOOTSTRAP}
             REVOKE anon FROM authenticated;
             ALTER ROLE authenticated RESET statement_timeout;"
        )),
        ["authenticated", "authenticated"]
    );
    assert_eq!(
        reported(&format!(
            "{BOOTSTRAP}
             GRANT anon TO authenticated WITH ADMIN OPTION;
             ALTER ROLE authenticated SET statement_timeout = '9s';"
        )),
        [
            "anon TO authenticated",
            "authenticated SET statement_timeout"
        ]
    );
}

#[test]
fn the_rule_is_inactive_until_a_cluster_bootstrap_is_declared() {
    let mut constrainer: GenericConstrainer<ParserDB> = RoleDefinedInSchema::default().into();
    constrainer.set_rule_level("role_defined_in_schema", Level::Warn);
    let inactive = constrainer.inactive_rules();
    assert_eq!(inactive.len(), 1);
    assert_eq!(inactive[0].missing(), Declaration::ClusterBootstrap);
    assert!(
        constrainer
            .validate_schema(&parse("CREATE ROLE reporting;"))
            .is_ok()
    );
}
