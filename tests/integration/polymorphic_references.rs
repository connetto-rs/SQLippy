//! Discriminator and identifier column pairs that no foreign key checks,
//! observed through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

const TARGETS: &str = "CREATE TABLE posts (id BIGINT PRIMARY KEY);
    CREATE TABLE photos (id BIGINT PRIMARY KEY);";

/// The object and message of every `polymorphic_reference` finding on the
/// targets and `sql`, checked with `constrainer`.
fn reported_by(constrainer: &GenericConstrainer<ParserDB>, sql: &str) -> Vec<(String, String)> {
    findings(
        constrainer,
        "polymorphic_reference",
        &format!("{TARGETS} {sql}"),
    )
    .into_iter()
    .map(|(_, object, message)| (object, message))
    .collect()
}

/// The tables reported on the targets and `sql` under English.
fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = PolymorphicReference::default().into();
    reported_by(&constrainer, sql)
        .into_iter()
        .map(|(object, _)| object)
        .collect()
}

#[test]
fn an_unchecked_discriminator_and_identifier_pair_is_reported() {
    let constrainer: GenericConstrainer<ParserDB> = PolymorphicReference::default().into();
    let findings = reported_by(
        &constrainer,
        "CREATE TABLE comments (
            id BIGINT PRIMARY KEY,
            target_type TEXT NOT NULL CHECK (target_type IN ('post', 'photo')),
            target_id BIGINT NOT NULL
        );",
    );
    assert_eq!(findings.len(), 1);
    let (object, message) = &findings[0];
    assert_eq!(object, "comments");
    assert!(
        message.contains("'target_type' and 'target_id'"),
        "the finding names the pair: {message}"
    );
}

#[test]
fn kind_discriminators_of_any_type_are_reported() {
    assert_eq!(
        reported(
            "CREATE TYPE target_kind AS ENUM ('post', 'photo');
             CREATE TABLE likes (id BIGINT PRIMARY KEY, target_kind target_kind NOT NULL, target_id BIGINT NOT NULL);
             CREATE TABLE tags (id BIGINT PRIMARY KEY, \"Subject_Kind\" TEXT, SUBJECT_ID BIGINT);"
        ),
        ["likes", "tags"]
    );
}

#[test]
fn every_unchecked_pair_of_a_table_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE links (
                id BIGINT PRIMARY KEY,
                source_type TEXT, source_id BIGINT,
                target_type TEXT, target_id BIGINT
            );"
        ),
        ["links", "links"]
    );
}

#[test]
fn a_foreign_key_on_the_identifier_accepts_the_pair() {
    assert_eq!(
        reported(
            "CREATE TABLE targets (id BIGINT PRIMARY KEY, kind TEXT NOT NULL, UNIQUE (id, kind));
             CREATE TABLE comments (
                 id BIGINT PRIMARY KEY,
                 target_type TEXT NOT NULL,
                 target_id BIGINT NOT NULL,
                 FOREIGN KEY (target_id, target_type) REFERENCES targets (id, kind)
             );
             CREATE TABLE likes (
                 id BIGINT PRIMARY KEY,
                 target_kind TEXT NOT NULL,
                 target_id BIGINT NOT NULL REFERENCES targets (id)
             );"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_pair_keying_its_own_row_passes() {
    assert_eq!(
        reported(
            "CREATE TABLE users (user_id BIGINT PRIMARY KEY, user_type TEXT NOT NULL);
             CREATE TABLE resources (
                 resource_id BIGINT,
                 resource_kind TEXT,
                 PRIMARY KEY (resource_id, resource_kind)
             );
             CREATE TABLE grantees (id BIGINT PRIMARY KEY, kind TEXT NOT NULL);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_pair_inside_a_wider_primary_key_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE comments (id BIGINT PRIMARY KEY);
             CREATE TABLE comment_targets (
                 comment_id BIGINT REFERENCES comments (id),
                 target_type TEXT,
                 target_id BIGINT,
                 PRIMARY KEY (comment_id, target_type, target_id)
             );"
        ),
        ["comment_targets"]
    );
}

#[test]
fn an_identifier_of_no_key_type_passes() {
    assert_eq!(
        reported(
            "CREATE TABLE webhooks (
                id BIGINT PRIMARY KEY,
                provider_kind TEXT NOT NULL,
                provider_id TEXT NOT NULL
            );"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn an_identifier_typed_like_a_unique_key_is_reported() {
    assert_eq!(
        reported(
            "CREATE TABLE accounts (id BIGINT PRIMARY KEY, handle TEXT UNIQUE);
             CREATE TABLE audit_log (
                 id BIGINT PRIMARY KEY,
                 entity_type TEXT NOT NULL,
                 entity_id TEXT NOT NULL
             );"
        ),
        ["audit_log"]
    );
}

#[test]
fn columns_of_different_stems_do_not_pair() {
    assert_eq!(
        reported(
            "CREATE TABLE comments (
                id BIGINT PRIMARY KEY,
                content_type TEXT,
                target_id BIGINT,
                kind TEXT
            );"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_selected_vocabulary_names_the_pair() {
    let mut constrainer: GenericConstrainer<ParserDB> = PolymorphicReference::default().into();
    constrainer.set_deployment(
        Deployment::default().with_vocabulary(
            Vocabulary::default()
                .with_discriminator_term("tipo")
                .with_identifier_term("codice"),
        ),
    );
    let objects: Vec<String> = reported_by(
        &constrainer,
        "CREATE TABLE commenti (
            id BIGINT PRIMARY KEY,
            bersaglio_tipo TEXT,
            bersaglio_codice BIGINT,
            target_type TEXT,
            target_id BIGINT
        );",
    )
    .into_iter()
    .map(|(object, _)| object)
    .collect();
    assert_eq!(objects, ["commenti"]);
}
