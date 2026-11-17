//! Foreign key host columns that must end in `id`, observed through
//! `reference_without_id_suffix`.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Message of every `reference_without_id_suffix` violation, failing on
/// anything else.
fn findings(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = ReferenceWithoutIdSuffix::default().into();
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
fn a_composite_key_column_mapped_to_a_non_key_column_is_not_a_reference() {
    assert_eq!(
        findings(
            "CREATE TABLE templates (
                 id INT PRIMARY KEY,
                 name TEXT NOT NULL,
                 previous_version_id INT,
                 UNIQUE (id, name),
                 FOREIGN KEY (previous_version_id, name) REFERENCES templates (id, name)
             );",
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_composite_key_reports_only_the_column_mapped_to_the_primary_key() {
    assert_eq!(
        findings(
            "CREATE TABLE templates (
                 id INT PRIMARY KEY,
                 name TEXT NOT NULL,
                 previous_version INT,
                 UNIQUE (id, name),
                 FOREIGN KEY (previous_version, name) REFERENCES templates (id, name)
             );",
        ),
        vec![
            "Foreign key host column 'templates.previous_version' references primary key column \
             'templates.id' but does not end with 'id'."
                .to_owned()
        ]
    );
}

#[test]
fn a_column_reaching_the_primary_key_through_a_foreign_key_names_both_columns() {
    assert_eq!(
        findings(
            "CREATE TABLE grandparent (id INT PRIMARY KEY);
             CREATE TABLE parent (gp_id INT UNIQUE, FOREIGN KEY (gp_id) REFERENCES grandparent (id));
             CREATE TABLE child (parent_key INT, FOREIGN KEY (parent_key) REFERENCES parent (gp_id));",
        ),
        vec![
            "Foreign key host column 'child.parent_key' references 'parent.gp_id', which references \
             primary key column 'grandparent.id', but does not end with 'id'."
                .to_owned()
        ]
    );
}
