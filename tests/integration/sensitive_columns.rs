//! Client-reachable tables without row-level security holding columns named
//! for credentials or personal data.

use crate::common::{finding, findings, supabase};
use sqlippy::prelude::*;

#[test]
fn a_sensitive_column_of_a_client_reached_table_is_reported() {
    for sql in [
        "CREATE TABLE keys (id INT, api_key TEXT); GRANT SELECT ON keys TO anon;",
        "CREATE TABLE keys (id INT, \"API-Key\" TEXT); GRANT SELECT ON keys TO authenticated;",
        "CREATE TABLE keys (id INT, Password TEXT); GRANT SELECT ON keys TO PUBLIC;",
        "CREATE TABLE keys (id INT, iban TEXT); GRANT SELECT (iban) ON keys TO anon;",
    ] {
        assert_eq!(
            findings(SensitiveColumnsExposed::default(), supabase(), sql),
            [finding("sensitive_columns_exposed", Level::Warn, "keys")],
            "{sql}"
        );
    }
}

#[test]
fn an_exposed_schema_reaches_the_table_without_a_grant() {
    let sql = "CREATE TABLE keys (id INT, ssn TEXT);";
    assert_eq!(
        findings(
            SensitiveColumnsExposed::default(),
            supabase().with_exposed_schema("public"),
            sql
        ),
        [finding("sensitive_columns_exposed", Level::Warn, "keys")]
    );
    assert_eq!(
        findings(SensitiveColumnsExposed::default(), supabase(), sql),
        []
    );
}

#[test]
fn every_matched_column_is_named_once_in_one_finding() {
    let mut constrainer: GenericConstrainer<ParserDB> = SensitiveColumnsExposed::default().into();
    constrainer.set_deployment(supabase());
    let database = crate::common::parse(&format!(
        "{}CREATE TABLE keys (id INT, token TEXT, cvv TEXT, note TEXT); GRANT SELECT ON keys TO anon;",
        crate::common::ROLES
    ));
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("token, cvv"), "{}", messages[0]);
    assert!(!messages[0].contains("note"), "{}", messages[0]);
}

#[test]
fn protected_unreached_or_partially_named_tables_are_not_reported() {
    for sql in [
        "CREATE TABLE keys (id INT, api_key TEXT); ALTER TABLE keys ENABLE ROW LEVEL SECURITY; GRANT SELECT ON keys TO anon;",
        "CREATE TABLE keys (id INT, api_key TEXT); GRANT SELECT ON keys TO reporting;",
        "CREATE TABLE keys (id INT, api_key_hint TEXT, tokens INT); GRANT SELECT ON keys TO anon;",
    ] {
        assert_eq!(
            findings(SensitiveColumnsExposed::default(), supabase(), sql),
            [],
            "{sql}"
        );
    }
}
