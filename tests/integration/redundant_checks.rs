//! Redundant checks observed through the public constrainer API.

use crate::rule_findings::findings;
use pg_diesel::PgDieselDatabase;
use sql_traits::traits::{CheckConstraintLike, DatabaseLike, TableLike};
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = RedundantCheck::default().into();
    findings(&constrainer, "redundant_check", sql)
        .into_iter()
        .map(|(_, _, message)| message)
        .collect()
}

#[test]
fn a_weaker_check_is_reported() {
    let messages =
        reported("CREATE TABLE payments (amount INT, CHECK (amount > 0), CHECK (amount > -5));");
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("amount > -5"));
}

#[test]
fn only_the_conjunction_is_reported() {
    let messages = reported(
        "CREATE TABLE payments (x INT, y INT, CHECK (x > 0), CHECK (y > 0), CHECK (x > 0 AND y > 0));",
    );
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("x > 0 AND y > 0"));
}

#[test]
fn checks_on_other_columns_do_not_hide_a_weaker_check() {
    let messages = reported(
        "CREATE TABLE payments (
             amount INT,
             fee INT,
             CHECK (amount > 0),
             CHECK (fee > 0),
             CHECK (fee < 100),
             CHECK (amount > -5)
         );",
    );
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("amount > -5"));
}

#[test]
fn a_chain_of_shared_columns_links_checks() {
    let messages = reported(
        "CREATE TABLE ranges (
             w INT NOT NULL,
             x INT NOT NULL,
             y INT NOT NULL,
             z INT NOT NULL,
             CHECK (w < x),
             CHECK (x < y),
             CHECK (y < z),
             CHECK (w < z)
         );",
    );
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains("w < z"));
}

#[test]
fn a_generated_column_links_the_columns_it_reads() {
    let messages = reported(
        "CREATE TABLE payments (
             amount INT,
             doubled INT GENERATED ALWAYS AS (amount * 2) STORED,
             CHECK (amount > 0),
             CHECK (doubled > -5)
         );",
    );
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains("doubled > -5"));
}

#[test]
fn verbatim_duplicates_are_left_to_duplicate_check() {
    assert_eq!(
        reported("CREATE TABLE payments (amount INT, CHECK (amount > 0), CHECK (amount > 0));"),
        Vec::<String>::new()
    );
}

#[test]
fn tautologies_are_left_to_tautological_check() {
    assert_eq!(
        reported("CREATE TABLE payments (amount INT, CHECK (TRUE));"),
        Vec::<String>::new()
    );
}

#[test]
fn a_later_stronger_check_guarantees_an_earlier_check() {
    let messages =
        reported("CREATE TABLE payments (amount INT, CHECK (amount > -5), CHECK (amount > 0));");
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("amount > -5"));
}

#[test]
fn unvalidated_checks_neither_vouch_nor_are_reported() {
    for sql in [
        "CREATE TABLE payments (amount INT CHECK (amount > -5)); ALTER TABLE payments ADD CONSTRAINT positive CHECK (amount > 0) NOT VALID;",
        "CREATE TABLE payments (amount INT CHECK (amount > 0)); ALTER TABLE payments ADD CONSTRAINT weak CHECK (amount > -5) NOT VALID;",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn uninherited_and_unenforced_checks_neither_vouch_nor_are_reported() {
    for sql in [
        "CREATE TABLE payments (amount INT, CHECK (amount > -5), CHECK (amount > 0) NO INHERIT);",
        "CREATE TABLE payments (amount INT, CHECK (amount > 0), CHECK (amount > -5) NO INHERIT);",
        "CREATE TABLE payments (amount INT, CHECK (amount > -5), CHECK (amount > 0) NOT ENFORCED);",
        "CREATE TABLE payments (amount INT, CHECK (amount > 0), CHECK (amount > -5) NOT ENFORCED);",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn checks_admitting_no_row_report_nothing() {
    assert_eq!(
        reported(
            "CREATE TABLE payments (amount INT NOT NULL, CHECK (amount > 0), CHECK (amount < 0), CHECK (amount > -5));"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn not_null_checks_are_already_tautological() {
    let sql = "CREATE TABLE payments (amount INT NOT NULL, CHECK (amount IS NOT NULL));";
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).unwrap();
    let table = database.tables().next().unwrap();
    let check = table.check_constraints(&database).unwrap().next().unwrap();
    assert!(check.is_tautology(&database).unwrap());
    assert_eq!(reported(sql), Vec::<String>::new());
}

#[test]
fn the_message_names_the_expression_and_table() {
    let messages =
        reported("CREATE TABLE payments (amount INT, CHECK (amount > 0), CHECK (amount > -5));");
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("amount > -5"));
    assert!(messages[0].contains("payments"));
}

#[test]
fn independent_checks_are_kept() {
    assert_eq!(
        reported("CREATE TABLE payments (x INT, y INT, CHECK (x > 0), CHECK (y > 0));"),
        Vec::<String>::new()
    );
}

#[test]
fn a_live_weaker_check_is_reported() {
    let (_container, database) = crate::live_catalog::catalog(
        "public",
        "CREATE TABLE payments (amount INT, CONSTRAINT positive CHECK (amount > 0), CONSTRAINT weak CHECK (amount > -5));",
    );
    let table = database.tables().next().unwrap();
    let expression = table
        .check_constraints(&database)
        .unwrap()
        .map(|check| check.expression().to_string())
        .find(|expression| expression.contains("-5"))
        .expect("the weaker check");
    let constrainer: GenericConstrainer<PgDieselDatabase> = RedundantCheck::default().into();
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.to_string(),
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains(&expression), "{}", messages[0]);
}
