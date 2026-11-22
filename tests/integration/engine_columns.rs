use sqlippy::prelude::*;
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};

fn sqlite(sql: &str) -> ParserDB {
    ParseOptions::default()
        .with_identifier_case(IdentifierCase::Folded)
        .parse::<SQLiteDialect>(sql)
        .expect("schema parses")
}

fn resolution(constrainer: &GenericConstrainer<ParserDB>, database: &ParserDB) -> String {
    match constrainer.validate_schema(database) {
        Err(Error::Violation(violation)) => violation.resolution().to_owned(),
        other => panic!("expected a violation, got {other:?}"),
    }
}

macro_rules! postgres_only {
    ($test:ident, $rule:ident, $sql:expr) => {
        #[test]
        fn $test() {
            let mut constrainer: GenericConstrainer<ParserDB> = $rule::default().into();
            constrainer.set_deployment(Deployment::default().with_binary_replication_all_tables());
            let postgres = ParserDB::parse::<PostgreSqlDialect>($sql).expect("schema parses");
            assert!(matches!(
                constrainer.validate_schema(&postgres),
                Err(Error::Violation(_))
            ));
            assert!(constrainer.validate_schema(&sqlite($sql)).is_ok());
        }
    };
}

postgres_only!(
    narrow_keys,
    NarrowIntegerKey,
    "CREATE TABLE t (id INT PRIMARY KEY);"
);
postgres_only!(serial_columns, SerialColumn, "CREATE TABLE t (id SERIAL);");
postgres_only!(
    closed_sets,
    ClosedSetAsText,
    "CREATE TABLE t (state TEXT CHECK (state IN ('a', 'b')));"
);
postgres_only!(
    mixed_columns,
    MixedCaseColumnName,
    "CREATE TABLE t (\"MyColumn\" INT);"
);
postgres_only!(
    snake_columns,
    NonSnakeCaseColumnName,
    "CREATE TABLE t (my__column INT);"
);
postgres_only!(
    mixed_tables,
    MixedCaseTableName,
    "CREATE TABLE \"MyTable\" (id INT);"
);
postgres_only!(
    snake_tables,
    NonSnakeCaseTableName,
    "CREATE TABLE my__table (id INT);"
);
postgres_only!(
    unknown_binary,
    UnknownBinarySend,
    "CREATE TABLE t (value BOX2D);"
);

macro_rules! engine_advice {
    ($test:ident, $rule:ident, $sql:expr, $postgres:expr, $sqlite:expr) => {
        #[test]
        fn $test() {
            let constrainer: GenericConstrainer<ParserDB> = $rule::default().into();
            let postgres = ParserDB::parse::<PostgreSqlDialect>($sql).expect("schema parses");
            assert!(resolution(&constrainer, &postgres).contains($postgres));
            let advice = resolution(&constrainer, &sqlite($sql));
            assert!(advice.contains($sqlite), "{advice}");
            assert!(!advice.contains($postgres), "{advice}");
        }
    };
}

engine_advice!(
    money,
    FloatingPointMoney,
    "CREATE TABLE t (total_price REAL);",
    "Declare it `numeric`",
    "integer minor units"
);
engine_advice!(
    flags,
    FlagNotBoolean,
    "CREATE TABLE t (is_active INTEGER);",
    "Declare it `boolean`",
    "CHECK (col IN (0, 1))"
);
engine_advice!(
    uuids,
    UuidStoredAsText,
    "CREATE TABLE t (owner_uuid TEXT);",
    "Declare it `uuid`",
    "GLOB '*[^0-9a-f-]*'"
);
engine_advice!(
    moments,
    MomentStoredAsText,
    "CREATE TABLE t (start_date TEXT);",
    "Declare it `timestamptz`",
    "date(col)"
);
engine_advice!(
    documents,
    JsonStoredAsText,
    "CREATE TABLE t (payload_json TEXT);",
    "Declare it `jsonb`",
    "CHECK (json_valid(col))"
);
engine_advice!(
    counts,
    FractionalCount,
    "CREATE TABLE t (item_count REAL);",
    "rounds a fractional input",
    "typeof(col)"
);
engine_advice!(
    events,
    BooleanStateWithoutTime,
    "CREATE TABLE t (revoked BOOLEAN);",
    "`timestamptz`",
    "UTC"
);
postgres_only!(
    addresses,
    AddressStoredAsText,
    "CREATE TABLE t (client_ip TEXT);"
);
postgres_only!(
    client_times,
    ClientChosenTimestamp,
    "CREATE TABLE t (created_at TIMESTAMP);"
);

/// Every SQLite schema that follows its rule's advice, which the rule then
/// leaves unreported.
#[test]
fn following_sqlite_advice_clears_the_finding() {
    let followed: [(GenericConstrainer<ParserDB>, &str); 5] = [
        (
            FlagNotBoolean::default().into(),
            "CREATE TABLE t (is_active INTEGER CHECK (is_active IN (0, 1)));",
        ),
        (
            UuidStoredAsText::default().into(),
            "CREATE TABLE t (owner_uuid TEXT CHECK (length(owner_uuid) = 36 AND NOT (owner_uuid GLOB '*[^0-9a-f-]*')));",
        ),
        (
            MomentStoredAsText::default().into(),
            "CREATE TABLE t (start_date TEXT CHECK (date(start_date) IS start_date));",
        ),
        (
            JsonStoredAsText::default().into(),
            "CREATE TABLE t (payload_json TEXT CHECK (json_valid(payload_json)));",
        ),
        (
            FractionalCount::default().into(),
            "CREATE TABLE t (item_count INTEGER CHECK (typeof(item_count) IN ('integer', 'null')));",
        ),
    ];
    for (constrainer, schema) in followed {
        assert!(
            constrainer.diagnostics(&sqlite(schema)).is_empty(),
            "{schema}"
        );
    }
}

#[test]
fn sqlite_numeric_scale_does_not_make_counts_integral() {
    let constrainer: GenericConstrainer<ParserDB> = FractionalCount::default().into();
    let sql = "CREATE TABLE t (item_count NUMERIC(10, 0));";
    assert!(
        constrainer
            .validate_schema(&ParserDB::parse::<PostgreSqlDialect>(sql).unwrap())
            .is_ok()
    );
    assert!(resolution(&constrainer, &sqlite(sql)).contains("typeof(col)"));
}

#[test]
fn counter_key_advice_names_a_uuid_form_the_engine_has() {
    let mut constrainer: GenericConstrainer<ParserDB> = ClientWrittenCounterKey::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_client_written_table("main", "drafts")
            .with_client_written_table("public", "drafts"),
    );
    let sql = "CREATE TABLE drafts (id INTEGER PRIMARY KEY);";
    let advice = resolution(&constrainer, &sqlite(sql));
    assert!(advice.contains("CHECK (length(id) = 36)"), "{advice}");
    assert!(!advice.contains("gen_random_uuid"), "{advice}");
    let postgres = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    assert!(resolution(&constrainer, &postgres).contains("gen_random_uuid()"));
}

#[test]
fn a_fixed_column_under_an_inline_sqlite_before_trigger_is_reported() {
    let constrainer: GenericConstrainer<ParserDB> = ConstantColumnNotGenerated::default().into();
    let sql = "CREATE TABLE entries (id INTEGER PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'entry' CHECK (kind = 'entry'));
               CREATE TABLE audit (entry_id INTEGER);
               CREATE TRIGGER log_entry BEFORE INSERT ON entries FOR EACH ROW BEGIN INSERT INTO audit VALUES (NEW.id); END;";
    assert!(resolution(&constrainer, &sqlite(sql)).contains("GENERATED ALWAYS AS"));
}
