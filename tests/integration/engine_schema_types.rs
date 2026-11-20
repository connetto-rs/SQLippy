use sqlippy::prelude::*;
use sqlparser::{
    dialect::{PostgreSqlDialect, SQLiteDialect},
    parser::Parser,
};

fn sqlite(schema: &str) -> ParserDB {
    ParseOptions::default()
        .with_identifier_case(IdentifierCase::Folded)
        .parse::<SQLiteDialect>(schema)
        .expect("SQLite schema parses")
}

fn postgres_only(constrainer: &GenericConstrainer<ParserDB>, schema: &str) {
    let postgres = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    assert!(matches!(
        constrainer.validate_schema(&postgres),
        Err(Error::Violation(_))
    ));
    assert!(constrainer.diagnostics(&sqlite(schema)).is_empty());
}

macro_rules! type_engine_test {
    ($test:ident, $rule:ident, $data_type:literal) => {
        #[test]
        fn $test() {
            postgres_only(
                &$rule::default().into(),
                concat!("CREATE TABLE t (value ", $data_type, ");"),
            );
        }
    };
}

type_engine_test!(
    naive_timestamp_is_postgres_only,
    TimestampWithoutTimeZone,
    "TIMESTAMP"
);
type_engine_test!(zoned_time_is_postgres_only, TimeWithTimeZone, "TIMETZ");
type_engine_test!(
    rounded_timestamp_is_postgres_only,
    ZeroPrecisionTimestamp,
    "TIMESTAMP(0)"
);
type_engine_test!(
    padded_character_is_postgres_only,
    BlankPaddedCharacter,
    "CHAR(5)"
);
type_engine_test!(money_is_postgres_only, MoneyType, "MONEY");
type_engine_test!(json_type_is_postgres_only, JsonType, "JSON");
type_engine_test!(
    scaled_numeric_is_postgres_only,
    ScaledNumeric,
    "NUMERIC(10, 2)"
);
type_engine_test!(reg_column_is_postgres_only, RegColumnType, "REGNAMESPACE");

#[test]
fn client_scaled_numeric_is_postgres_only() {
    let mut constrainer: GenericConstrainer<ParserDB> =
        ClientWrittenScaledNumeric::default().into();
    constrainer.set_deployment(Deployment::default().with_client_written_table("public", "t"));
    postgres_only(&constrainer, "CREATE TABLE t (value NUMERIC(10, 2));");
}

#[test]
fn exposed_owner_rights_are_postgres_only() {
    let mut constrainer: GenericConstrainer<ParserDB> = OwnerRightsViewExposed::default().into();
    constrainer.set_deployment(Deployment::default().with_exposed_schema("public"));
    postgres_only(
        &constrainer,
        "CREATE TABLE t (value INT); CREATE VIEW v AS SELECT value FROM t;",
    );
}

#[test]
fn filtering_view_barriers_are_postgres_only() {
    let mut constrainer: GenericConstrainer<ParserDB> =
        SecurityBarrierMissingOnFilteringView::default().into();
    constrainer.set_deployment(Deployment::default().with_exposed_schema("public"));
    postgres_only(
        &constrainer,
        "CREATE TABLE t (value INT); CREATE VIEW v AS SELECT value FROM t WHERE value > 0;",
    );
}

#[test]
fn not_in_performance_advice_is_postgres_only() {
    let schema = "CREATE TABLE a (id INT); CREATE TABLE b (id INT NOT NULL);";
    let query = "SELECT id FROM a WHERE id NOT IN (SELECT id FROM b)";
    let constrainer: GenericConstrainer<ParserDB> = NotInSubquery::default().into();
    let postgres = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    let postgres_statement = Parser::parse_sql(&PostgreSqlDialect {}, query)
        .unwrap()
        .remove(0);
    assert!(
        !constrainer
            .statement_diagnostics(&postgres, &postgres_statement)
            .is_empty()
    );
    let sqlite_statement = Parser::parse_sql(&SQLiteDialect {}, query)
        .unwrap()
        .remove(0);
    assert!(
        constrainer
            .statement_diagnostics(&sqlite(schema), &sqlite_statement)
            .is_empty()
    );
    postgres_only(&constrainer, &format!("{schema} CREATE VIEW v AS {query};"));
}

#[test]
fn type_name_case_collisions_are_postgres_only() {
    let constrainer: GenericConstrainer<ParserDB> = TypeNameCaseCollision::default().into();
    let postgres = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE \"Mood\" (id INT); CREATE TABLE mood (id INT);",
    )
    .unwrap();
    assert!(matches!(
        constrainer.validate_schema(&postgres),
        Err(Error::Violation(_))
    ));
    assert!(
        constrainer
            .diagnostics(&sqlite("CREATE TABLE \"Mood\" (id INT);"))
            .is_empty()
    );
}

#[test]
fn reserved_identifiers_follow_the_engine() {
    let constrainer: GenericConstrainer<ParserDB> = ReservedKeywordIdentifier::default().into();
    let schema = "CREATE TABLE \"order\" (\"user\" INT);";
    let postgres = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    assert_eq!(constrainer.diagnostics(&postgres).len(), 2);
    let diagnostics = constrainer.diagnostics(&sqlite(schema));
    assert_eq!(diagnostics.len(), 1);
    match &diagnostics[0] {
        Error::Violation(violation) => assert_eq!(
            violation.resolution(),
            "Rename 'order' to a word SQLite does not reserve."
        ),
        other => panic!("unexpected failure {other}"),
    }
    assert!(
        constrainer
            .diagnostics(&sqlite("CREATE TABLE user (id INT);"))
            .is_empty()
    );
    assert_eq!(
        constrainer
            .diagnostics(&sqlite("CREATE TABLE t (current_timestamp INT);"))
            .len(),
        1
    );
}
