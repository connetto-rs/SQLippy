//! Jointly contradictory `CHECK` constraints.

use crate::rule_findings::findings;
use pg_diesel::PgDieselDatabase;
use sqlippy::prelude::*;

fn messages(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = ContradictoryChecks::default().into();
    findings(&constrainer, "contradictory_checks", sql)
        .into_iter()
        .map(|(_, _, message)| message)
        .collect()
}

#[test]
fn nullable_opposing_checks_name_both_expressions() {
    let messages = messages("CREATE TABLE measurements (y INT CHECK (y > 0) CHECK (y < 0));");
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("y > 0"));
    assert!(messages[0].contains("y < 0"));
    assert!(messages[0].contains("NULL"));
}

#[test]
fn non_null_opposing_checks_are_reported() {
    assert_eq!(
        messages("CREATE TABLE measurements (y INT NOT NULL CHECK (y > 0) CHECK (y < 0));").len(),
        1
    );
}

#[test]
fn shrinking_names_only_the_contradictory_subset() {
    let messages = messages(
        "CREATE TABLE measurements (y INT, z INT, CHECK (z > 5), CHECK (y > 0), CHECK (y < 0));",
    );
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("y > 0"));
    assert!(messages[0].contains("y < 0"));
    assert!(!messages[0].contains("z > 5"));
}

#[test]
fn nullable_guards_on_different_columns_are_reported() {
    assert_eq!(messages("CREATE TABLE measurements (a INT, b INT, c INT, CHECK (a IS NULL OR c > 0), CHECK (b IS NULL OR c < 0));").len(), 1);
}

#[test]
fn individually_impossible_and_null_only_checks_are_excluded() {
    for sql in [
        "CREATE TABLE measurements (y INT CHECK (false));",
        "CREATE TABLE measurements (y INT CHECK (y > 0 AND y < 0));",
        "CREATE TABLE measurements (b INT CHECK (b IS NULL) CHECK (b > 0));",
    ] {
        assert!(messages(sql).is_empty(), "{sql}");
    }
}

#[test]
fn compatible_checks_and_tables_without_checks_are_clean() {
    for sql in [
        "CREATE TABLE measurements (y INT CHECK (y > 0) CHECK (y < 10));",
        "CREATE TABLE measurements (y INT);",
        "CREATE TABLE measurements (y INT CHECK (y > 0));",
    ] {
        assert!(messages(sql).is_empty(), "{sql}");
    }
}

#[test]
fn unvalidated_checks_are_excluded() {
    assert_eq!(
        messages(
            "CREATE TABLE measurements (y INT CHECK (y > 0)); ALTER TABLE measurements ADD CONSTRAINT negative CHECK (y < 0) NOT VALID;"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn non_inherited_checks_are_excluded() {
    assert_eq!(
        messages("CREATE TABLE measurements (y INT, CHECK (y > 0), CHECK (y < 0) NO INHERIT);"),
        Vec::<String>::new()
    );
}

#[test]
fn quoted_mixed_case_columns_resolve() {
    assert_eq!(messages(r#"CREATE TABLE measurements ("MixedCase" INT CHECK ("MixedCase" > 0) CHECK ("MixedCase" < 0));"#).len(), 1);
}

#[test]
fn unquoted_mixed_case_columns_resolve() {
    assert_eq!(
        messages(
            "CREATE TABLE measurements (MixedCase INT CHECK (mixedcase > 0) CHECK (MIXEDCASE < 0));"
        )
        .len(),
        1
    );
}

#[test]
fn live_postgres_accepts_contradictory_checks_on_an_empty_table() {
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        "CREATE TABLE measurements (y INT CHECK (y > 0) CHECK (y < 0));",
    );
    let constrainer: GenericConstrainer<PgDieselDatabase> = ContradictoryChecks::default().into();
    let diagnostics = constrainer.diagnostics(&database);
    assert_eq!(diagnostics.len(), 1);
    match &diagnostics[0] {
        Error::Violation(violation) => assert_eq!(violation.object(), "measurements"),
        other => panic!("unexpected diagnostic {other}"),
    }
}
