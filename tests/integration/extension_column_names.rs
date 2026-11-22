//! Column names repeated across an extension hierarchy, observed through
//! `duplicate_column_name_in_extension_graph`.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Object of every `duplicate_column_name_in_extension_graph` violation,
/// failing on anything else.
fn findings(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> =
        DuplicateColumnNameInExtensionGraph::default().into();
    constrainer
        .diagnostics(&ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses"))
        .into_iter()
        .filter(|error| !matches!(error, Error::Inactive(_)))
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn a_tenant_column_a_composite_key_keeps_equal_to_the_parent_is_not_reported() {
    for (enforcement, expected) in [
        ("", Vec::<String>::new()),
        ("NOT ENFORCED", vec!["tubes.organization_id".to_owned()]),
    ] {
        assert_eq!(
            findings(&format!(
                "CREATE TABLE assets (
                 id INT PRIMARY KEY,
                 organization_id INT NOT NULL,
                 UNIQUE (organization_id, id)
             );
             CREATE TABLE tubes (
                 id INT PRIMARY KEY REFERENCES assets (id) ON DELETE CASCADE,
                 organization_id INT NOT NULL,
                 FOREIGN KEY (organization_id, id) REFERENCES assets (organization_id, id) {enforcement}
             );"
            )),
            expected,
            "{enforcement}"
        );
    }
}

#[test]
fn columns_each_keyed_to_the_root_are_not_reported_along_the_hierarchy() {
    assert_eq!(
        findings(
            "CREATE TABLE resources (
                 id INT PRIMARY KEY,
                 organization_id INT NOT NULL,
                 UNIQUE (organization_id, id)
             );
             CREATE TABLE assets (
                 id INT PRIMARY KEY REFERENCES resources (id),
                 organization_id INT NOT NULL,
                 UNIQUE (organization_id, id),
                 FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id)
             );
             CREATE TABLE tubes (
                 id INT PRIMARY KEY REFERENCES assets (id),
                 organization_id INT NOT NULL,
                 FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id)
             );",
        ),
        Vec::<String>::new()
    );
}

#[test]
fn columns_each_keyed_to_a_table_outside_the_hierarchy_are_not_reported() {
    assert_eq!(
        findings(
            "CREATE TABLE resources (
                 id INT PRIMARY KEY,
                 organization_id INT NOT NULL,
                 UNIQUE (organization_id, id)
             );
             CREATE TABLE ownables (
                 id INT PRIMARY KEY,
                 organization_id INT NOT NULL,
                 FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id)
             );
             CREATE TABLE assets (
                 id INT PRIMARY KEY REFERENCES ownables (id),
                 organization_id INT NOT NULL,
                 FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id)
             );",
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_column_keyed_to_a_parent_that_leaves_its_own_copy_unkeyed_is_reported() {
    assert_eq!(
        findings(
            "CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL);
             CREATE TABLE assets (
                 id INT PRIMARY KEY REFERENCES resources (id),
                 organization_id INT NOT NULL,
                 UNIQUE (organization_id, id)
             );
             CREATE TABLE tubes (
                 id INT PRIMARY KEY REFERENCES assets (id),
                 organization_id INT NOT NULL,
                 FOREIGN KEY (organization_id, id) REFERENCES assets (organization_id, id)
             );",
        ),
        ["assets.organization_id", "tubes.organization_id"]
    );
}

#[test]
fn a_column_keyed_to_one_of_two_parents_carrying_it_is_reported() {
    assert_eq!(
        findings(
            "CREATE TABLE assets (
                 id INT PRIMARY KEY,
                 organization_id INT NOT NULL,
                 UNIQUE (organization_id, id)
             );
             CREATE TABLE containers (id INT PRIMARY KEY, organization_id INT NOT NULL);
             CREATE TABLE tubes (
                 id INT PRIMARY KEY REFERENCES assets (id) REFERENCES containers (id),
                 organization_id INT NOT NULL,
                 FOREIGN KEY (organization_id, id) REFERENCES assets (organization_id, id)
             );",
        ),
        ["tubes.organization_id"]
    );
}

#[test]
fn a_nullable_column_a_simple_match_key_lets_escape_is_reported() {
    assert_eq!(
        findings(
            "CREATE TABLE assets (
                 id INT PRIMARY KEY,
                 organization_id INT,
                 UNIQUE (organization_id, id)
             );
             CREATE TABLE tubes (
                 id INT PRIMARY KEY REFERENCES assets (id),
                 organization_id INT,
                 FOREIGN KEY (organization_id, id) REFERENCES assets (organization_id, id)
             );",
        ),
        ["tubes.organization_id"]
    );
}

#[test]
fn a_column_keyed_beside_a_nullable_column_a_simple_match_key_skips_is_reported() {
    assert_eq!(
        findings(
            "CREATE TABLE procedures (
                 id INT PRIMARY KEY,
                 template_id INT,
                 status_id INT NOT NULL,
                 UNIQUE (id, template_id, status_id)
             );
             CREATE TABLE weighings (
                 id INT PRIMARY KEY REFERENCES procedures (id),
                 template_id INT,
                 status_id INT NOT NULL,
                 FOREIGN KEY (id, template_id, status_id)
                     REFERENCES procedures (id, template_id, status_id)
             );",
        ),
        ["weighings.template_id", "weighings.status_id"]
    );
}

#[test]
fn a_nullable_column_a_full_match_key_keeps_equal_is_not_reported() {
    assert_eq!(
        findings(
            "CREATE TABLE assets (
                 id INT PRIMARY KEY,
                 organization_id INT,
                 UNIQUE (organization_id, id)
             );
             CREATE TABLE tubes (
                 id INT PRIMARY KEY REFERENCES assets (id),
                 organization_id INT,
                 FOREIGN KEY (organization_id, id) REFERENCES assets (organization_id, id) MATCH FULL
             );",
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_column_keyed_to_another_column_of_the_parent_is_reported() {
    assert_eq!(
        findings(
            "CREATE TABLE assets (
                 id INT PRIMARY KEY,
                 organization_id INT NOT NULL,
                 owner_id INT NOT NULL,
                 UNIQUE (owner_id, id)
             );
             CREATE TABLE tubes (
                 id INT PRIMARY KEY REFERENCES assets (id),
                 organization_id INT NOT NULL,
                 FOREIGN KEY (organization_id, id) REFERENCES assets (owner_id, id)
             );",
        ),
        ["tubes.organization_id"]
    );
}

#[test]
fn a_column_keyed_to_the_parent_through_another_row_is_reported() {
    assert_eq!(
        findings(
            "CREATE TABLE assets (
                 id INT PRIMARY KEY,
                 organization_id INT NOT NULL,
                 UNIQUE (organization_id, id)
             );
             CREATE TABLE tubes (
                 id INT PRIMARY KEY REFERENCES assets (id),
                 rack_id INT NOT NULL,
                 organization_id INT NOT NULL,
                 FOREIGN KEY (organization_id, rack_id) REFERENCES assets (organization_id, id)
             );",
        ),
        ["tubes.organization_id"]
    );
}

#[test]
fn a_column_keyed_through_a_parent_column_outside_its_primary_key_is_reported() {
    assert_eq!(
        findings(
            "CREATE TABLE assets (
                 id INT PRIMARY KEY,
                 serial INT NOT NULL,
                 organization_id INT NOT NULL,
                 UNIQUE (organization_id, serial)
             );
             CREATE TABLE tubes (
                 id INT PRIMARY KEY REFERENCES assets (id),
                 organization_id INT NOT NULL,
                 FOREIGN KEY (organization_id, id) REFERENCES assets (organization_id, serial)
             );",
        ),
        ["tubes.organization_id"]
    );
}
