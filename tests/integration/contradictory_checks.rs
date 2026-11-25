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
fn nullable_opposing_checks_name_both_expressions_and_the_forced_column() {
    let messages = messages("CREATE TABLE measurements (y INT CHECK (y > 0) CHECK (y < 0));");
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("y > 0"));
    assert!(messages[0].contains("y < 0"));
    assert!(messages[0].contains("'y'"));
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
fn checks_keeping_optional_columns_apart_are_clean() {
    for sql in [
        "CREATE TABLE parameters (value_kind TEXT NOT NULL CHECK (value_kind IN ('text', 'boolean')), default_text TEXT, default_boolean BOOLEAN, CHECK (default_text IS NULL OR value_kind = 'text'), CHECK (default_boolean IS NULL OR value_kind = 'boolean'));",
        "CREATE TABLE parameters (value_kind TEXT NOT NULL CHECK (value_kind IN ('text', 'number')), default_text TEXT CHECK (default_text <> ''), default_number DOUBLE PRECISION CHECK (default_number >= 0), CHECK (default_text IS NULL OR value_kind = 'text'), CHECK (default_number IS NULL OR value_kind = 'number'));",
        "CREATE TABLE parameters (value_kind TEXT NOT NULL CHECK (value_kind IN ('text', 'number')), default_text TEXT CHECK (default_text IS NULL OR default_text <> ''), default_number DOUBLE PRECISION CHECK (default_number IS NULL OR default_number >= 0), CHECK (default_text IS NULL OR value_kind = 'text'), CHECK (default_number IS NULL OR value_kind = 'number'));",
        "CREATE TABLE measurements (a INT, b INT, c INT, CHECK (a IS NULL OR c > 0), CHECK (b IS NULL OR c < 0));",
    ] {
        assert!(messages(sql).is_empty(), "{sql}");
    }
}

#[test]
fn guarded_checks_forcing_a_column_null_name_it() {
    let messages = messages(
        "CREATE TABLE measurements (y INT, CHECK (y IS NULL OR y > 0), CHECK (y IS NULL OR y < 0));",
    );
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("'y'"));
}

#[test]
fn columns_forced_by_the_same_checks_share_one_finding() {
    let messages = messages(
        "CREATE TABLE measurements (y INT, z INT, CHECK (y > 0 AND z > 0), CHECK (y < 0 AND z < 0));",
    );
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains("'y'"));
    assert!(messages[0].contains("'z'"));
}

#[test]
fn opposing_comparisons_between_columns_name_the_check_never_true() {
    let messages =
        messages("CREATE TABLE measurements (y INT, z INT, CHECK (y > z), CHECK (y < z));");
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("`CHECK (y > z)`, `CHECK (y < z)`"));
    assert!(messages[0].contains("under which `CHECK (y > z)` is never true"));
}

#[test]
fn a_forced_column_and_an_independent_contradiction_are_both_reported() {
    let messages = messages(
        "CREATE TABLE measurements (y INT, p INT, q INT, CHECK (y > 0), CHECK (y < 0), CHECK (p > q), CHECK (p < q));",
    );
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert!(
        messages
            .iter()
            .any(|message| message.contains("'y'") && !message.contains("p > q"))
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("p > q") && !message.contains("y > 0"))
    );
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
