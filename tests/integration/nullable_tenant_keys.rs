//! Declared tenant keys that allow `NULL`, observed through the public
//! constrainer API.

use crate::rule_findings::{findings, inactive_declarations};
use sqlippy::prelude::*;

fn constrainer() -> GenericConstrainer<ParserDB> {
    let mut constrainer: GenericConstrainer<ParserDB> = NullableTenantKey::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_tenant_key("public", "documents", "organization_id")
            .with_tenant_key("billing", "Invoices", "Org"),
    );
    constrainer
}

fn reported(sql: &str) -> Vec<String> {
    findings(&constrainer(), "nullable_tenant_key", sql)
        .into_iter()
        .map(|(_, object, _)| object)
        .collect()
}

#[test]
fn a_nullable_tenant_key_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE organizations (id INT PRIMARY KEY);
             CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT REFERENCES organizations (id));"
        ),
        ["documents"]
    );
}

#[test]
fn a_tenant_key_that_cannot_hold_null_is_clean() {
    for sql in [
        "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL);",
        "CREATE TABLE documents (organization_id INT, id INT, PRIMARY KEY (organization_id, id));",
        "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT);
         ALTER TABLE documents ALTER COLUMN organization_id SET NOT NULL;",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn only_the_declared_column_of_the_declared_table_counts() {
    assert_eq!(
        reported(
            "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL, owner_id INT);
             CREATE TABLE notes (id INT PRIMARY KEY, organization_id INT);
             CREATE SCHEMA other;
             CREATE TABLE other.documents (organization_id INT);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn the_declaration_is_matched_by_stored_names() {
    assert_eq!(
        reported(r#"CREATE SCHEMA billing; CREATE TABLE billing."Invoices" ("Org" INT);"#),
        ["Invoices"]
    );
    assert_eq!(
        reported("CREATE SCHEMA billing; CREATE TABLE billing.invoices (org INT);"),
        Vec::<String>::new()
    );
}

#[test]
fn the_rule_is_inactive_without_tenant_keys() {
    let constrainer: GenericConstrainer<ParserDB> = NullableTenantKey::default().into();
    assert_eq!(
        inactive_declarations(&constrainer),
        [("nullable_tenant_key", Declaration::TenantKeys)]
    );
}
