//! Extension hierarchies of foreign key columns, observed through
//! `incompatible_foreign_key`.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Message of every `incompatible_foreign_key` violation, failing on anything
/// else.
fn findings(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = IncompatibleForeignKey::default().into();
    constrainer
        .diagnostics(&ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses"))
        .into_iter()
        .filter(|error| !matches!(error, Error::Inactive(_)))
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn a_composite_key_column_takes_the_hierarchy_through_a_chain_of_composite_keys() {
    assert_eq!(
        findings(
            "CREATE TABLE organizations (id INTEGER PRIMARY KEY);
             CREATE TABLE resources (
                 id INTEGER PRIMARY KEY,
                 organization_id INTEGER NOT NULL REFERENCES organizations (id),
                 UNIQUE (organization_id, id)
             );
             CREATE TABLE grants (
                 id INTEGER PRIMARY KEY,
                 resource_id INTEGER NOT NULL,
                 organization_id INTEGER NOT NULL,
                 UNIQUE (organization_id, id),
                 FOREIGN KEY (organization_id, resource_id)
                     REFERENCES resources (organization_id, id)
             );
             CREATE TABLE grant_notes (
                 grant_id INTEGER PRIMARY KEY,
                 organization_id INTEGER NOT NULL REFERENCES organizations (id),
                 FOREIGN KEY (organization_id, grant_id)
                     REFERENCES grants (organization_id, id)
             );",
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_composite_key_column_whose_own_reference_contradicts_the_referenced_column_is_reported() {
    let raised = findings(
        "CREATE TABLE organizations (id INTEGER PRIMARY KEY);
         CREATE TABLE teams (id INTEGER PRIMARY KEY);
         CREATE TABLE resources (
             id INTEGER PRIMARY KEY,
             organization_id INTEGER NOT NULL REFERENCES organizations (id),
             UNIQUE (organization_id, id)
         );
         CREATE TABLE grants (
             resource_id INTEGER PRIMARY KEY,
             organization_id INTEGER NOT NULL REFERENCES teams (id),
             FOREIGN KEY (organization_id, resource_id)
                 REFERENCES resources (organization_id, id)
         );",
    );
    assert_eq!(raised.len(), 1, "{raised:?}");
    for named in ["`grants.organization_id`", "teams", "organizations"] {
        assert!(raised[0].contains(named), "{named} in {}", raised[0]);
    }
}

#[test]
fn a_column_referencing_two_unrelated_primary_keys_is_reported_once() {
    let raised = findings(
        "CREATE TABLE a (id INT PRIMARY KEY);
         CREATE TABLE b (id INT PRIMARY KEY);
         CREATE TABLE d (id INT PRIMARY KEY, x INT REFERENCES a (id), FOREIGN KEY (x) REFERENCES b (id));",
    );
    assert_eq!(raised.len(), 1, "{raised:?}");
    assert!(raised[0].contains("`d.x`"), "{}", raised[0]);
}

#[test]
fn a_composite_key_column_of_another_type_is_reported() {
    let raised = findings(
        "CREATE TABLE organizations (id INTEGER PRIMARY KEY);
         CREATE TABLE resources (
             id INTEGER PRIMARY KEY,
             organization_id INTEGER NOT NULL REFERENCES organizations (id),
             UNIQUE (organization_id, id)
         );
         CREATE TABLE grants (
             resource_id INTEGER PRIMARY KEY,
             organization_id BIGINT NOT NULL,
             FOREIGN KEY (organization_id, resource_id)
                 REFERENCES resources (organization_id, id)
         );",
    );
    assert_eq!(raised.len(), 1, "{raised:?}");
    assert!(raised[0].contains("data type"), "{}", raised[0]);
}
