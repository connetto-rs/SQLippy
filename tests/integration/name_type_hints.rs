//! Column names that imply a type the column does not have, observed through
//! the public constrainer API. The behaviour each rule cites was measured on
//! PostgreSQL 17.11 and 18.6.

use crate::common::{finding, findings, parse};
use sqlippy::prelude::*;

/// Objects `FloatingPointMoney` reports on `sql` under `deployment`.
fn money(deployment: Deployment, sql: &str) -> Vec<String> {
    objects(FloatingPointMoney::default(), deployment, sql)
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

/// Objects `rule` reports on `sql` under `deployment`.
fn objects(
    rule: impl Into<GenericConstrainer<ParserDB>>,
    deployment: Deployment,
    sql: &str,
) -> Vec<String> {
    findings(rule, deployment, sql)
        .into_iter()
        .map(|(_, _, object)| object)
        .collect()
}

#[test]
fn a_yes_or_no_state_stored_as_a_number_or_text_is_reported() {
    assert_eq!(
        objects(
            FlagNotBoolean::default(),
            Deployment::default(),
            "CREATE DOMAIN flag_t AS SMALLINT;
             CREATE TABLE jobs (
                 is_active SMALLINT,
                 has_access INTEGER,
                 should_retry BIGINT,
                 can_edit TEXT,
                 was_sent CHAR(1),
                 is_done flag_t
             );"
        ),
        [
            "jobs.is_active",
            "jobs.has_access",
            "jobs.should_retry",
            "jobs.can_edit",
            "jobs.was_sent",
            "jobs.is_done"
        ]
    );
}

#[test]
fn booleans_and_names_not_opening_with_a_flag_word_are_not_reported() {
    assert_eq!(
        objects(
            FlagNotBoolean::default(),
            Deployment::default(),
            "CREATE TABLE jobs (
                 is_active BOOLEAN,
                 active INTEGER,
                 this_is_count INTEGER,
                 island TEXT,
                 is_ratio REAL
             );"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_uuid_stored_as_text_is_reported() {
    assert_eq!(
        objects(
            UuidStoredAsText::default(),
            Deployment::default(),
            "CREATE DOMAIN uuid_t AS TEXT;
             CREATE TABLE things (
                 uuid TEXT,
                 thing_uuid VARCHAR(36),
                 owner_uuid CHAR(36),
                 parent_uuid uuid_t
             );"
        ),
        [
            "things.uuid",
            "things.thing_uuid",
            "things.owner_uuid",
            "things.parent_uuid"
        ]
    );
}

#[test]
fn uuid_columns_and_names_not_ending_in_uuid_are_not_reported() {
    assert_eq!(
        objects(
            UuidStoredAsText::default(),
            Deployment::default(),
            "CREATE TABLE things (
                 thing_uuid UUID,
                 uuid_label TEXT,
                 uuid_count INTEGER
             );"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_selected_vocabulary_supplies_flag_and_uuid_words() {
    let german = Vocabulary::default()
        .with_flag_prefix("ist")
        .with_uuid_term("guid");
    let sql =
        "CREATE TABLE t (ist_aktiv INTEGER, is_active INTEGER, item_guid TEXT, item_uuid TEXT);";
    assert_eq!(
        objects(
            FlagNotBoolean::default(),
            Deployment::default().with_vocabulary(german.clone()),
            sql
        ),
        ["t.ist_aktiv"]
    );
    assert_eq!(
        objects(
            UuidStoredAsText::default(),
            Deployment::default().with_vocabulary(german),
            sql
        ),
        ["t.item_guid"]
    );
}

#[test]
fn the_default_constrainer_runs_the_name_hints_after_money_as_pedantic() {
    let database = parse(
        "CREATE TABLE t (
             id INT PRIMARY KEY,
             is_active INTEGER,
             item_uuid TEXT,
             created_at TEXT,
             client_ip TEXT,
             payload_json TEXT,
             item_count REAL
         );",
    );
    let hints = [
        "FlagNotBoolean",
        "UuidStoredAsText",
        "MomentStoredAsText",
        "AddressStoredAsText",
        "JsonStoredAsText",
        "FractionalCount",
    ];
    let raised = |constrainer: &DefaultConstrainer<ParserDB>| {
        constrainer
            .diagnostics(&database)
            .into_iter()
            .filter_map(|error| match error {
                Error::Violation(violation) if hints.contains(&violation.rule().name) => Some((
                    violation.rule().name.to_owned(),
                    violation.level(),
                    violation.object().to_owned(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    assert_eq!(raised(&constrainer), []);
    constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
    assert_eq!(
        raised(&constrainer),
        [
            finding("FlagNotBoolean", Level::Warn, "t.is_active"),
            finding("UuidStoredAsText", Level::Warn, "t.item_uuid"),
            finding("MomentStoredAsText", Level::Warn, "t.created_at"),
            finding("AddressStoredAsText", Level::Warn, "t.client_ip"),
            finding("JsonStoredAsText", Level::Warn, "t.payload_json"),
            finding("FractionalCount", Level::Warn, "t.item_count")
        ]
    );
}

#[test]
fn an_ip_address_or_network_stored_as_text_is_reported() {
    assert_eq!(
        objects(
            AddressStoredAsText::default(),
            Deployment::default(),
            "CREATE DOMAIN ip_t AS TEXT;
             CREATE TABLE hits (
                 client_ip TEXT,
                 ip TEXT,
                 allowed_cidr VARCHAR(43),
                 ip_address TEXT,
                 server_ip_address TEXT,
                 peer_ip ip_t
             );"
        ),
        [
            "hits.client_ip",
            "hits.ip",
            "hits.allowed_cidr",
            "hits.ip_address",
            "hits.server_ip_address",
            "hits.peer_ip"
        ]
    );
}

#[test]
fn typed_addresses_and_other_addresses_are_not_reported() {
    assert_eq!(
        objects(
            AddressStoredAsText::default(),
            Deployment::default(),
            "CREATE TABLE hits (
                 client_ip INET,
                 allowed_cidr CIDR,
                 ip_country TEXT,
                 email_address TEXT,
                 shipping_address TEXT,
                 tip TEXT
             );"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_json_document_stored_as_text_is_reported() {
    assert_eq!(
        objects(
            JsonStoredAsText::default(),
            Deployment::default(),
            "CREATE TABLE docs (
                 payload_json TEXT,
                 json TEXT,
                 settings_json VARCHAR(200),
                 meta_json JSONB,
                 json_path TEXT,
                 jsonish TEXT
             );"
        ),
        ["docs.payload_json", "docs.json", "docs.settings_json"]
    );
}

#[test]
fn a_selected_vocabulary_supplies_terms_of_several_words() {
    let italian = Vocabulary::default()
        .with_address_term("indirizzo_ip")
        .with_json_term("dati_json");
    let sql = "CREATE TABLE t (server_indirizzo_ip TEXT, indirizzo TEXT, client_ip TEXT, evento_dati_json TEXT, payload_json TEXT);";
    assert_eq!(
        objects(
            AddressStoredAsText::default(),
            Deployment::default().with_vocabulary(italian.clone()),
            sql
        ),
        ["t.server_indirizzo_ip"]
    );
    assert_eq!(
        objects(
            JsonStoredAsText::default(),
            Deployment::default().with_vocabulary(italian),
            sql
        ),
        ["t.evento_dati_json"]
    );
}

#[test]
fn a_moment_or_a_day_stored_as_text_is_reported() {
    assert_eq!(
        objects(
            MomentStoredAsText::default(),
            Deployment::default(),
            "CREATE DOMAIN stamp_t AS TEXT;
             CREATE TABLE events (
                 created_at TEXT,
                 published_on VARCHAR(10),
                 start_date CHAR(10),
                 event_time TEXT,
                 timestamp TEXT,
                 birthday TEXT,
                 deleted_at stamp_t
             );"
        ),
        [
            "events.created_at",
            "events.published_on",
            "events.start_date",
            "events.event_time",
            "events.timestamp",
            "events.birthday",
            "events.deleted_at"
        ]
    );
}

#[test]
fn typed_moments_and_names_not_ending_in_a_moment_word_are_not_reported() {
    assert_eq!(
        objects(
            MomentStoredAsText::default(),
            Deployment::default(),
            "CREATE TABLE events (
                 created_at TIMESTAMPTZ,
                 start_date DATE,
                 at_risk TEXT,
                 date_format TEXT,
                 attachment TEXT,
                 run_time INTEGER
             );"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn the_past_time_rule_leaves_a_text_moment_to_the_moment_hint() {
    let sql = "CREATE TABLE events (created_at TEXT, updated_at TIMESTAMPTZ);";
    assert_eq!(
        objects(PastTimeColumnRule::default(), Deployment::default(), sql),
        ["events.updated_at"]
    );
    let german = Vocabulary::default().with_moment_term("datum");
    assert_eq!(
        objects(
            PastTimeColumnRule::default(),
            Deployment::default().with_vocabulary(german.clone()),
            sql
        ),
        ["events.created_at", "events.updated_at"]
    );
    assert_eq!(
        objects(
            MomentStoredAsText::default(),
            Deployment::default().with_vocabulary(german),
            "CREATE TABLE events (geburts_datum TEXT, created_at TEXT);"
        ),
        ["events.geburts_datum"]
    );
}

#[test]
fn a_count_stored_as_a_float_or_numeric_is_reported() {
    assert_eq!(
        objects(
            FractionalCount::default(),
            Deployment::default(),
            "CREATE DOMAIN count_t AS NUMERIC;
             CREATE TABLE stock (
                 item_count DOUBLE PRECISION,
                 quantity REAL,
                 qty NUMERIC,
                 count FLOAT8,
                 visit_count count_t
             );"
        ),
        [
            "stock.item_count",
            "stock.quantity",
            "stock.qty",
            "stock.count",
            "stock.visit_count"
        ]
    );
}

#[test]
fn integer_counts_averages_and_other_names_are_not_reported() {
    assert_eq!(
        objects(
            FractionalCount::default(),
            Deployment::default(),
            "CREATE TABLE stock (
                 item_count INTEGER,
                 quantity BIGINT,
                 avg_count DOUBLE PRECISION,
                 mean_quantity REAL,
                 count_ratio REAL,
                 country REAL,
                 discount REAL
             );"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_selected_vocabulary_supplies_count_terms() {
    let italian = Vocabulary::default()
        .with_count_term("quantita")
        .with_average_term("media");
    assert_eq!(
        objects(
            FractionalCount::default(),
            Deployment::default().with_vocabulary(italian),
            "CREATE TABLE t (pezzi_quantita REAL, media_quantita REAL, item_count REAL);"
        ),
        ["t.pezzi_quantita"]
    );
}
