//! Btree and hash indexes keyed on array columns, which serve no element
//! lookup.

use sqlippy::prelude::*;

use crate::common::parse;

/// The object of every `equality_index_on_array` finding on `database`.
fn reported(database: &ParserDB) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = EqualityIndexOnArray::default().into();
    constrainer
        .diagnostics(database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

const POSTS: &str = "CREATE TABLE posts (id BIGINT PRIMARY KEY, tenant BIGINT NOT NULL, title TEXT, tags TEXT[] NOT NULL);";

#[test]
fn btree_and_hash_keys_on_an_array_are_reported() {
    let sql = format!(
        "{POSTS}
         CREATE INDEX posts_default ON posts (tags);
         CREATE INDEX posts_btree ON posts USING btree (tags);
         CREATE INDEX posts_hash ON posts USING hash (tags);
         CREATE INDEX posts_tenant_tags ON posts (tenant, tags DESC);
         CREATE INDEX posts_partial ON posts (tags) WHERE title IS NOT NULL;"
    );
    assert_eq!(
        reported(&parse(&sql)),
        [
            "posts.posts_default",
            "posts.posts_btree",
            "posts.posts_hash",
            "posts.posts_tenant_tags",
            "posts.posts_partial",
        ]
    );
}

#[test]
fn an_index_on_two_arrays_is_reported_once_naming_both() {
    let database = parse(
        "CREATE TABLE posts (id BIGINT PRIMARY KEY, title TEXT, tags TEXT[], readers BIGINT[]);
         CREATE INDEX posts_arrays ON posts (tags, title, readers);",
    );
    let constrainer: GenericConstrainer<ParserDB> = EqualityIndexOnArray::default().into();
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| error.to_string())
        .collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(
        messages[0].contains("keyed on array columns 'tags', 'readers'"),
        "{}",
        messages[0]
    );
}

#[test]
fn element_serving_methods_uniqueness_and_non_array_keys_are_not_reported() {
    let sql = format!(
        "{POSTS}
         CREATE INDEX posts_gin ON posts USING gin (tags);
         CREATE INDEX posts_gist ON posts USING gist (tags);
         CREATE UNIQUE INDEX posts_unique_tags ON posts (tags);
         CREATE INDEX posts_first_tag ON posts ((tags[1]));
         CREATE INDEX posts_tag_count ON posts ((cardinality(tags)));
         CREATE INDEX posts_title ON posts (title) INCLUDE (tags);
         CREATE TABLE labels (names TEXT[] PRIMARY KEY);
         CREATE TABLE sets (id BIGINT PRIMARY KEY, members INT[] UNIQUE);"
    );
    assert_eq!(reported(&parse(&sql)), [] as [&str; 0]);
}

#[test]
fn an_array_reached_through_domains_is_reported_and_a_scalar_domain_is_not() {
    let sql = "CREATE DOMAIN tag_list AS TEXT[];
         CREATE DOMAIN short_tag_list AS tag_list CHECK (cardinality(VALUE) <= 8);
         CREATE DOMAIN tag AS TEXT;
         CREATE TABLE posts (id BIGINT PRIMARY KEY, tags short_tag_list, main_tag tag);
         CREATE INDEX posts_tags ON posts (tags);
         CREATE INDEX posts_main_tag ON posts (main_tag);";
    assert_eq!(reported(&parse(sql)), ["posts.posts_tags"]);
}
