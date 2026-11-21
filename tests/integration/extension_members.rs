//! Functions an extension creates, whose definitions its install script owns
//! and whose privileges the schema still grants.

use sqlippy::prelude::*;

use super::common::{finding, findings, parse, supabase};

#[test]
fn no_rule_reports_the_definition_of_a_function_an_extension_creates() {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    for group in [LintGroup::Restriction, LintGroup::Pedantic] {
        constrainer.set_group_level(group, Level::Warn);
    }
    let violations: Vec<String> = constrainer
        .diagnostics(&parse("CREATE EXTENSION postgis VERSION '3.7.0';"))
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) => Some(violation.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(violations, Vec::<String>::new());
}

#[test]
fn a_function_the_schema_writes_beside_an_extension_is_reported() {
    assert_eq!(
        findings(
            FunctionWithoutSafeSearchPath::default(),
            Deployment::default(),
            r#"CREATE EXTENSION "uuid-ossp";
               CREATE FUNCTION mine() RETURNS UUID LANGUAGE sql AS 'SELECT uuid_generate_v4()';
               CREATE FUNCTION tied() RETURNS UUID LANGUAGE sql AS 'SELECT uuid_generate_v4()';
               ALTER FUNCTION tied() DEPENDS ON EXTENSION "uuid-ossp";"#
        ),
        [
            finding("function_without_safe_search_path", Level::Warn, "mine()"),
            finding("function_without_safe_search_path", Level::Warn, "tied()"),
        ]
    );
}

#[test]
fn a_grant_the_schema_makes_on_a_function_an_extension_creates_is_reported() {
    assert_eq!(
        findings(
            GrantOptionToClientRole::default(),
            supabase(),
            r#"CREATE EXTENSION "uuid-ossp";
               GRANT EXECUTE ON FUNCTION uuid_generate_v4() TO authenticated WITH GRANT OPTION;"#
        ),
        [finding(
            "grant_option_to_client_role",
            Level::Warn,
            "uuid_generate_v4()"
        )]
    );
}
