//! Binary replication selection, diagnostics and level overrides.

use sqlippy::prelude::*;

use super::common::parse;

const SCHEMA: &str = "
    CREATE DOMAIN grant_item AS aclitem;
    CREATE DOMAIN grant_items AS aclitem[];
    CREATE TYPE grant_set AS (items grant_items);
    CREATE TABLE grants (
        id INT PRIMARY KEY,
        item grant_item,
        items grant_items,
        bundle grant_set,
        shape box2d
    );
    CREATE SCHEMA archive;
    CREATE TABLE archive.grants (id INT PRIMARY KEY, old_items aclitem[]);
    CREATE TABLE archive.\"MixedCase\" (id INT PRIMARY KEY, shape box2d);";

fn binary_rule(name: &str) -> bool {
    matches!(name, "binary_send_failure" | "unknown_binary_send")
}

fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    database: &ParserDB,
) -> Vec<Violation<ParserDB>> {
    constrainer
        .diagnostics(database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if binary_rule(violation.rule().name) => Some(*violation),
            Error::Violation(_) => None,
            Error::Inactive(inactive) if !binary_rule(inactive.rule().name) => None,
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect()
}

fn configured(deployment: Deployment) -> DefaultConstrainer<ParserDB> {
    let mut constrainer = DefaultConstrainer::default();
    constrainer.set_deployment(deployment);
    constrainer
}

fn signatures(found: &[Violation<ParserDB>]) -> Vec<(&str, Level, &str)> {
    let mut signatures: Vec<_> = found
        .iter()
        .map(|violation| (violation.rule().name, violation.level(), violation.object()))
        .collect();
    signatures.sort_unstable();
    signatures
}

#[test]
fn selection_enables_both_rules_and_replacement_disables_them() {
    let database = parse(SCHEMA);
    let mut constrainer = DefaultConstrainer::default();
    assert!(findings(&constrainer, &database).is_empty());
    constrainer
        .set_deployment(Deployment::default().with_binary_replication_table("public", "grants"));
    let found = findings(&constrainer, &database);
    assert_eq!(
        signatures(&found),
        [
            ("binary_send_failure", Level::Deny, "grants.bundle"),
            ("binary_send_failure", Level::Deny, "grants.items"),
            ("unknown_binary_send", Level::Warn, "grants.shape"),
        ]
    );
    for violation in &found[..2] {
        assert!(violation.message().contains("aclitem"));
        assert!(violation.message().contains(violation.object()));
        let declared = if violation.object() == "grants.bundle" {
            "grant_set"
        } else {
            "grant_items"
        };
        assert!(violation.message().contains(declared));
    }
    constrainer.set_deployment(Deployment::default());
    assert!(findings(&constrainer, &database).is_empty());
}

#[test]
fn selection_matches_stored_schema_and_case_sensitive_table_names() {
    let database = parse(SCHEMA);
    let constrainer = configured(
        Deployment::default()
            .with_binary_replication_table("archive", "grants")
            .with_binary_replication_table("archive", "MixedCase"),
    );
    assert_eq!(
        signatures(&findings(&constrainer, &database)),
        [
            ("binary_send_failure", Level::Deny, "grants.old_items"),
            ("unknown_binary_send", Level::Warn, "MixedCase.shape"),
        ]
    );
    let missing =
        configured(Deployment::default().with_binary_replication_table("archive", "mixedcase"));
    assert!(findings(&missing, &database).is_empty());
}

#[test]
fn all_tables_includes_every_schema_and_combines_with_named_selection() {
    let database = parse(SCHEMA);
    for deployment in [
        Deployment::default()
            .with_binary_replication_table("public", "grants")
            .with_binary_replication_all_tables(),
        Deployment::default()
            .with_binary_replication_all_tables()
            .with_binary_replication_table("public", "grants"),
    ] {
        assert_eq!(
            signatures(&findings(&configured(deployment), &database)),
            [
                ("binary_send_failure", Level::Deny, "grants.bundle"),
                ("binary_send_failure", Level::Deny, "grants.items"),
                ("binary_send_failure", Level::Deny, "grants.old_items"),
                ("unknown_binary_send", Level::Warn, "MixedCase.shape"),
                ("unknown_binary_send", Level::Warn, "grants.shape"),
            ]
        );
    }
}

#[test]
fn binary_and_text_fallback_types_pass() {
    let database = parse(
        "CREATE DOMAIN grant_item AS aclitem;
         CREATE TYPE pair AS (a INT, b TEXT[]);
         CREATE TABLE entries (id INT PRIMARY KEY, item aclitem, wrapped grant_item,
             counts INT4[], spans INT4RANGE, fields pair);",
    );
    let constrainer = configured(Deployment::default().with_binary_replication_all_tables());
    assert!(findings(&constrainer, &database).is_empty());
}

#[test]
fn unknown_nested_type_warning_names_the_column_and_both_types() {
    let database = parse(
        "CREATE TYPE region AS (shape box2d);
         CREATE TABLE maps (id INT PRIMARY KEY, area region, shapes box2d[]);",
    );
    let constrainer = configured(Deployment::default().with_binary_replication_all_tables());
    let found = findings(&constrainer, &database);
    assert_eq!(
        signatures(&found),
        [
            ("unknown_binary_send", Level::Warn, "maps.area"),
            ("unknown_binary_send", Level::Warn, "maps.shapes"),
        ]
    );
    for violation in found {
        assert!(violation.message().contains(violation.object()));
        assert!(violation.message().contains("box2d"));
        let declared = if violation.object() == "maps.area" {
            "region"
        } else {
            "box2d[]"
        };
        assert!(violation.message().contains(declared));
    }
}

#[test]
fn rule_overrides_take_precedence_over_group_overrides_and_registration_floors() {
    let database = parse(SCHEMA);
    let mut constrainer =
        configured(Deployment::default().with_binary_replication_table("public", "grants"));
    constrainer.set_group_level(LintGroup::Restriction, Level::Deny);
    assert_eq!(
        signatures(&findings(&constrainer, &database)),
        [
            ("binary_send_failure", Level::Deny, "grants.bundle"),
            ("binary_send_failure", Level::Deny, "grants.items"),
            ("unknown_binary_send", Level::Deny, "grants.shape"),
        ]
    );
    constrainer.set_rule_level("unknown_binary_send", Level::Allow);
    constrainer.set_rule_level("binary_send_failure", Level::Warn);
    constrainer.set_group_level(LintGroup::Restriction, Level::Allow);
    assert_eq!(
        signatures(&findings(&constrainer, &database)),
        [
            ("binary_send_failure", Level::Warn, "grants.bundle"),
            ("binary_send_failure", Level::Warn, "grants.items"),
        ]
    );
    constrainer.set_rule_level("binary_send_failure", Level::Allow);
    assert!(findings(&constrainer, &database).is_empty());
}
