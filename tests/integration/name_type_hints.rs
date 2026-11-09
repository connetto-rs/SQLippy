//! Column names that imply a type the column does not have, observed through
//! the public constrainer API. The behaviour each rule cites was measured on
//! PostgreSQL 17.11 and 18.6.

use crate::common::{finding, findings, parse};
use sqlippy::prelude::*;

/// Objects `FloatingPointMoney` reports on `sql` under `deployment`.
fn money(deployment: Deployment, sql: &str) -> Vec<String> {
    findings(FloatingPointMoney::default(), deployment, sql)
        .into_iter()
        .map(|(_, _, object)| object)
        .collect()
}

#[test]
fn an_amount_of_money_in_a_floating_point_column_is_reported() {
    assert_eq!(
        money(
            Deployment::default(),
            "CREATE DOMAIN amount_t AS DOUBLE PRECISION;
             CREATE TABLE ledger (
                 price REAL,
                 total_price DOUBLE PRECISION,
                 expenses FLOAT8,
                 price_cents FLOAT,
                 prices DOUBLE PRECISION[],
                 cost amount_t
             );"
        ),
        [
            "ledger.price",
            "ledger.total_price",
            "ledger.expenses",
            "ledger.price_cents",
            "ledger.prices",
            "ledger.cost"
        ]
    );
}

#[test]
fn exact_types_rates_and_other_names_are_not_reported() {
    assert_eq!(
        money(
            Deployment::default(),
            "CREATE TABLE ledger (
                 price NUMERIC,
                 price_cents BIGINT,
                 tax_rate DOUBLE PRECISION,
                 discount_percent REAL,
                 priceless DOUBLE PRECISION,
                 weight DOUBLE PRECISION,
                 total_distance DOUBLE PRECISION,
                 subtotal_weight REAL,
                 costo DOUBLE PRECISION
             );"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_selected_vocabulary_replaces_the_english_default() {
    let italian = Vocabulary::default()
        .with_money_term("costo")
        .with_ratio_term("aliquota");
    let sql = "CREATE TABLE ledger (costo REAL, costo_aliquota REAL, price REAL);";
    assert_eq!(
        money(Deployment::default().with_vocabulary(italian.clone()), sql),
        ["ledger.costo"]
    );
    assert_eq!(
        money(
            Deployment::default()
                .with_vocabulary(Vocabulary::english())
                .with_vocabulary(italian),
            sql
        ),
        ["ledger.costo", "ledger.price"]
    );
}

#[test]
fn the_default_constrainer_warns_for_floating_point_money() {
    let raised = DefaultConstrainer::<ParserDB>::default()
        .diagnostics(&parse(
            "CREATE TABLE ledger (id INT PRIMARY KEY, amount REAL);",
        ))
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == "FloatingPointMoney" => Some((
                violation.rule().name.to_owned(),
                violation.level(),
                violation.object().to_owned(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        raised,
        [finding("FloatingPointMoney", Level::Warn, "ledger.amount")]
    );
}
