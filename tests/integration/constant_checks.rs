//! `CHECK` constraints whose expression has the same value for every row,
//! observed through the public constrainer API. Every flagged and passing
//! shape below was measured on PostgreSQL 18.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// The objects `tautological_check` reports on a table holding two text
/// columns under different collations and `check`.
fn tautological(check: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = TautologicalCheck::default().into();
    constrainer
        .diagnostics(
            &ParserDB::parse::<PostgreSqlDialect>(&format!(
                "CREATE TABLE t (icu TEXT COLLATE \"und-x-icu\" NOT NULL, \
                 bytes TEXT COLLATE \"C\" NOT NULL, CHECK ({check}));"
            ))
            .expect("schema parses"),
        )
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn a_check_comparing_two_implicit_collations_is_not_a_tautology() {
    // PostgreSQL rejects every insert with "could not determine which
    // collation to use for string comparison".
    assert_eq!(
        tautological("(icu < bytes) IS NOT NULL"),
        Vec::<String>::new()
    );
}

#[test]
fn a_check_comparing_under_an_explicit_collation_is_a_tautology() {
    assert_eq!(
        tautological("(icu < bytes COLLATE \"C\") IS NOT NULL").len(),
        1
    );
}

#[test]
fn a_raising_comparison_folded_away_by_or_true_is_a_tautology() {
    // PostgreSQL folds the check to `true` before running the comparison.
    assert_eq!(tautological("icu < bytes OR true").len(), 1);
}
