//! Schema and constrainer helpers shared by the deployment-aware test suites.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

pub fn parse(sql: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses")
}

pub fn supabase() -> Deployment {
    Deployment::default()
        .with_anonymous_role("anon")
        .with_app_role("authenticated")
}

pub const ROLES: &str = "
    CREATE ROLE anon;
    CREATE ROLE authenticated;
    CREATE ROLE reporting;";

/// Rule name, level and object of every violation, failing on anything else.
pub fn findings(
    constrainer: impl Into<GenericConstrainer<ParserDB>>,
    deployment: Deployment,
    sql: &str,
) -> Vec<(String, Level, String)> {
    let mut constrainer = constrainer.into();
    constrainer.set_deployment(deployment);
    constrainer
        .diagnostics(&parse(&format!("{ROLES}{sql}")))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.rule().name.to_owned(),
                violation.level(),
                violation.object().to_owned(),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

pub fn finding(rule: &str, level: Level, object: &str) -> (String, Level, String) {
    (rule.to_owned(), level, object.to_owned())
}
