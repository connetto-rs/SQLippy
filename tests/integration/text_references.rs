//! Text columns whose values a foreign key forces to equal a referenced
//! column's, so the referenced column's length bound and emptiness check
//! hold for them too.

use sqlippy::prelude::*;

use crate::common::{finding, findings};

const STATUSES: &str =
    "CREATE TABLE statuses (id TEXT PRIMARY KEY CHECK (id <> '' AND length(id) <= 63));";

/// Rule name, level and object of every finding of the two text rules, in
/// a stable order.
fn text_findings(sql: &str) -> Vec<(String, Level, String)> {
    let mut constrainer: GenericConstrainer<ParserDB> = UnboundedTextColumn::default().into();
    constrainer.register_column_rule(Box::new(EmptyTextAllowed::default()));
    let mut raised = findings(constrainer, Deployment::default(), sql);
    raised.sort();
    raised
}

fn unbounded(object: &str) -> (String, Level, String) {
    finding("unbounded_text_column", Level::Warn, object)
}

fn empty(object: &str) -> (String, Level, String) {
    finding("empty_text_allowed", Level::Warn, object)
}

#[test]
fn a_single_column_reference_inherits_the_referenced_checks() {
    let raised = text_findings(&format!(
        "{STATUSES}
         CREATE TABLE runs (id INT PRIMARY KEY, status_id TEXT REFERENCES statuses (id));"
    ));
    assert_eq!(raised, Vec::new());
}

#[test]
fn a_referenced_declared_length_bounds_the_reference_but_allows_the_empty_string() {
    let raised = text_findings(
        "CREATE TABLE statuses (id VARCHAR(63) PRIMARY KEY);
         CREATE TABLE runs (id INT PRIMARY KEY, status_id TEXT NOT NULL REFERENCES statuses (id));",
    );
    assert_eq!(raised, vec![empty("runs.status_id"), empty("statuses.id")]);
}

#[test]
fn a_chain_of_references_inherits_the_checks_at_its_end() {
    let raised = text_findings(&format!(
        "{STATUSES}
         CREATE TABLE runs (status_id TEXT PRIMARY KEY REFERENCES statuses (id));
         CREATE TABLE run_notes (id INT PRIMARY KEY, status_id TEXT REFERENCES runs (status_id));"
    ));
    assert_eq!(raised, Vec::new());
}

#[test]
fn a_composite_reference_inherits_when_no_other_key_column_can_be_null() {
    let raised = text_findings(&format!(
        "{STATUSES}
         CREATE TABLE tenant_statuses (
             tenant_id INT,
             status_id TEXT REFERENCES statuses (id),
             PRIMARY KEY (tenant_id, status_id)
         );
         CREATE TABLE required_tenant (
             id INT PRIMARY KEY,
             tenant_id INT NOT NULL,
             status_id TEXT,
             FOREIGN KEY (tenant_id, status_id) REFERENCES tenant_statuses (tenant_id, status_id)
         );
         CREATE TABLE full_match (
             id INT PRIMARY KEY,
             tenant_id INT,
             status_id TEXT,
             FOREIGN KEY (tenant_id, status_id) REFERENCES tenant_statuses (tenant_id, status_id) MATCH FULL
         );
         CREATE TABLE simple_match (
             id INT PRIMARY KEY,
             tenant_id INT,
             status_id TEXT NOT NULL,
             FOREIGN KEY (tenant_id, status_id) REFERENCES tenant_statuses (tenant_id, status_id)
         );"
    ));
    assert_eq!(
        raised,
        vec![
            empty("simple_match.status_id"),
            unbounded("simple_match.status_id"),
        ]
    );
}

#[test]
fn a_reference_to_an_unchecked_key_is_reported_even_in_a_cycle() {
    let raised = text_findings(
        "CREATE TABLE nodes (id TEXT PRIMARY KEY REFERENCES nodes (id), parent_id TEXT REFERENCES nodes (id));",
    );
    assert_eq!(
        raised,
        vec![
            empty("nodes.id"),
            empty("nodes.parent_id"),
            unbounded("nodes.id"),
            unbounded("nodes.parent_id"),
        ]
    );
}
