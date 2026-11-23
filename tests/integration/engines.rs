//! Rules read the engine a schema runs on from the dialect it was parsed in,
//! so a PostgreSQL limit is not reported on SQLite and advice names a form
//! the engine enforces.

use sqlippy::prelude::*;
use sqlparser::dialect::{GenericDialect, PostgreSqlDialect, SQLiteDialect};

const LONG_TABLE: &str = "organizations_organizations_id_kind_fkey_pg2sqlite_key_pg2sqlite_rows";

fn long_table_schema() -> String {
    format!("CREATE TABLE {LONG_TABLE} (id TEXT PRIMARY KEY CHECK (length(id) <= 36));")
}

fn sqlite(sql: &str) -> ParserDB {
    ParseOptions::default()
        .with_identifier_case(IdentifierCase::Folded)
        .parse::<SQLiteDialect>(sql)
        .expect("schema parses")
}

/// Every violation's rule name and object, failing on anything else.
fn violations(
    constrainer: &impl Constrainer<Database = ParserDB>,
    database: &ParserDB,
) -> Vec<(&'static str, String)> {
    constrainer
        .diagnostics(database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (violation.rule().name, violation.object().to_owned()),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn the_engine_is_sqlite_only_for_a_schema_parsed_as_sqlite() {
    assert_eq!(Engine::of(&sqlite("")), Engine::Sqlite);
    for database in [
        ParserDB::parse::<PostgreSqlDialect>("").expect("schema parses"),
        ParserDB::parse::<GenericDialect>("").expect("schema parses"),
    ] {
        assert_eq!(Engine::of(&database), Engine::PostgreSql);
    }
}

#[test]
fn a_long_identifier_is_reported_on_postgresql_and_not_on_sqlite() {
    let constrainer: GenericConstrainer<ParserDB> = TruncatedIdentifier::default().into();
    let schema = long_table_schema();
    assert_eq!(
        violations(
            &constrainer,
            &ParserDB::parse::<PostgreSqlDialect>(&schema).expect("schema parses")
        ),
        [("truncated_identifier", LONG_TABLE.to_owned())]
    );
    assert_eq!(violations(&constrainer, &sqlite(&schema)), []);
}

#[test]
fn an_allowance_for_a_rule_off_on_the_engine_excuses_nothing() {
    let mut constrainer: GenericConstrainer<ParserDB> = TruncatedIdentifier::default().into();
    constrainer.allow_table("truncated_identifier", TargetName::new(LONG_TABLE, false));
    let diagnostics = constrainer.diagnostics(&sqlite(&long_table_schema()));
    assert!(
        matches!(diagnostics.as_slice(), [Error::UnusedAllowance(_)]),
        "{diagnostics:?}"
    );
}

#[test]
fn the_rule_list_names_the_engines_each_rule_runs_on() {
    let rules = DefaultConstrainer::<ParserDB>::default().rules();
    let engines = |name: &str| {
        rules
            .iter()
            .find(|rule| rule.metadata().name == name)
            .unwrap_or_else(|| panic!("{name} is registered"))
            .engines()
    };
    assert_eq!(
        engines("truncated_identifier"),
        [Engine::PostgreSql].as_slice()
    );
    assert_eq!(engines("unbounded_text_column"), Engine::ALL.as_slice());
}

#[test]
fn a_rule_off_on_the_engine_is_not_listed_as_inactive() {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    for group in LintGroup::ALL {
        constrainer.set_group_level(group, Level::Warn);
    }
    let schema = "CREATE TABLE t (id INTEGER PRIMARY KEY);";
    let inactive = |database: &ParserDB| -> Vec<&'static str> {
        constrainer
            .diagnostics(database)
            .into_iter()
            .filter_map(|error| match error {
                Error::Inactive(inactive) => Some(inactive.rule().name),
                _ => None,
            })
            .collect()
    };
    assert!(inactive(&postgresql(schema)).contains(&"nullable_tenant_key"));
    assert_eq!(inactive(&sqlite(schema)), ["tenant_local_reference"]);
}

#[test]
fn a_rule_reading_roles_pooling_or_replication_runs_only_on_postgresql() {
    let postgresql_only = [
        Declaration::AppRoles,
        Declaration::ClientRoles,
        Declaration::Pooled,
        Declaration::BinaryReplicationTables,
        Declaration::ClusterBootstrap,
    ];
    for rule in DefaultConstrainer::<ParserDB>::default().rules() {
        if rule
            .requires()
            .iter()
            .any(|declaration| postgresql_only.contains(declaration))
        {
            assert_eq!(
                rule.engines(),
                [Engine::PostgreSql].as_slice(),
                "{}",
                rule.metadata().name
            );
        }
    }
}

/// The resolution of the one `unbounded_text_column` finding on `database`.
fn unbounded_text_resolution(database: &ParserDB) -> String {
    let constrainer: GenericConstrainer<ParserDB> = UnboundedTextColumn::default().into();
    match constrainer.validate_schema(database) {
        Err(Error::Violation(violation)) => violation.resolution().to_owned(),
        other => panic!("expected one violation, got {other:?}"),
    }
}

#[test]
fn unbounded_text_advice_names_only_a_length_check_on_sqlite() {
    let resolution = unbounded_text_resolution(&sqlite("CREATE TABLE users (name VARCHAR(3));"));
    assert!(!resolution.contains("VARCHAR"), "{resolution}");
    assert!(
        resolution.contains("CHECK (LENGTH(name) <= n)"),
        "{resolution}"
    );
}

#[test]
fn unbounded_text_advice_names_a_declared_length_on_postgresql() {
    let resolution = unbounded_text_resolution(
        &ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE users (name TEXT);")
            .expect("schema parses"),
    );
    assert!(resolution.contains("VARCHAR(n)"), "{resolution}");
    assert!(
        resolution.contains("CHECK (LENGTH(name) <= n)"),
        "{resolution}"
    );
}

fn postgresql(sql: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses")
}

#[test]
fn rules_on_postgresql_only_behaviour_report_on_postgresql_and_not_on_sqlite() {
    let cases: [(GenericConstrainer<ParserDB>, &str); 5] = [
        (
            WildcardView::default().into(),
            "CREATE TABLE entries (id INT, body TEXT); CREATE VIEW visible AS SELECT * FROM entries;",
        ),
        (
            ReachableTableWithoutRowLevelSecurity::default().into(),
            "CREATE TABLE notes (id INT PRIMARY KEY);",
        ),
        (
            SensitiveColumnsExposed::default().into(),
            "CREATE TABLE credentials (id INT PRIMARY KEY, token TEXT);",
        ),
        (
            ExtensionWithoutVersion::default().into(),
            "CREATE EXTENSION pgcrypto;",
        ),
        (
            UnstreamableReplicaIdentity::default().into(),
            "CREATE TABLE events (id INT);",
        ),
    ];
    for (constrainer, sql) in cases {
        let name = constrainer.rules()[0].metadata().name;
        let mut constrainer = constrainer;
        constrainer.set_deployment(Deployment::example());
        assert_eq!(
            violations(&constrainer, &postgresql(sql)).len(),
            1,
            "{name} on PostgreSQL"
        );
        assert_eq!(
            violations(&constrainer, &sqlite(sql)),
            [],
            "{name} on SQLite"
        );
    }
}

#[test]
fn an_inexact_key_names_only_what_the_engine_compares_inexactly() {
    let schema = "CREATE TABLE spans (span INTERVAL PRIMARY KEY, score REAL UNIQUE);";
    let messages = |database: &ParserDB| {
        let constrainer: GenericConstrainer<ParserDB> = KeyWithoutExactEquality::default().into();
        constrainer
            .diagnostics(database)
            .into_iter()
            .map(|error| match error {
                Error::Violation(violation) => (
                    violation.object().to_owned(),
                    violation.message().to_owned(),
                    violation.resolution().to_owned(),
                ),
                other => panic!("unexpected failure: {other}"),
            })
            .collect::<Vec<_>>()
    };
    let on_postgresql = messages(&postgresql(schema));
    assert_eq!(on_postgresql.len(), 2, "{on_postgresql:?}");
    let [(object, message, resolution)] = messages(&sqlite(schema))
        .try_into()
        .unwrap_or_else(|found: Vec<_>| panic!("one finding on SQLite, got {found:?}"));
    assert_eq!(object, "spans.score");
    assert!(!message.contains("double precision"), "{message}");
    assert!(!resolution.contains("uuid"), "{resolution}");
}

/// The message and resolution of every finding the query rules of
/// `constrainer` raise on `statement`.
fn statement_texts(
    constrainer: impl Into<GenericConstrainer<ParserDB>>,
    database: &ParserDB,
    statement: &sqlparser::ast::Statement,
) -> Vec<String> {
    let constrainer = constrainer.into();
    constrainer
        .statement_diagnostics(database, statement)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                format!("{} {}", violation.message(), violation.resolution())
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn query_findings_name_forms_the_engine_has() {
    use sqlparser::parser::Parser;

    const TABLE: &str = "CREATE TABLE t (id INT PRIMARY KEY, a INT, at TIMESTAMP);";
    let on = |sql: &str| {
        let postgresql_statement = Parser::parse_sql(&PostgreSqlDialect {}, sql).expect("parses");
        let sqlite_statement = Parser::parse_sql(&SQLiteDialect {}, sql).expect("parses");
        (postgresql_statement, sqlite_statement)
    };
    let (postgresql_database, sqlite_database) = (postgresql(TABLE), sqlite(TABLE));
    let both = |constrainer: fn() -> GenericConstrainer<ParserDB>, sql: &str| {
        let (postgresql_statement, sqlite_statement) = on(sql);
        (
            statement_texts(
                constrainer(),
                &postgresql_database,
                &postgresql_statement[0],
            ),
            statement_texts(constrainer(), &sqlite_database, &sqlite_statement[0]),
        )
    };

    let (postgresql_texts, sqlite_texts) =
        both(|| UnfilteredWrite::default().into(), "DELETE FROM t");
    assert!(
        postgresql_texts[0].contains("TRUNCATE"),
        "{postgresql_texts:?}"
    );
    assert!(!sqlite_texts[0].contains("TRUNCATE"), "{sqlite_texts:?}");

    let (postgresql_texts, sqlite_texts) = both(
        || DuplicateColumnAssignment::default().into(),
        "UPDATE t SET a = 1, a = 2",
    );
    assert!(
        postgresql_texts[0].contains("PostgreSQL rejects"),
        "{postgresql_texts:?}"
    );
    assert!(
        sqlite_texts[0].contains("SQLite keeps one"),
        "{sqlite_texts:?}"
    );

    let (postgresql_texts, sqlite_texts) = both(
        || RandomOrderLimit::default().into(),
        "SELECT id FROM t ORDER BY random() LIMIT 3",
    );
    assert!(
        postgresql_texts[0].contains("TABLESAMPLE"),
        "{postgresql_texts:?}"
    );
    assert!(!sqlite_texts[0].contains("TABLESAMPLE"), "{sqlite_texts:?}");

    let (postgresql_texts, sqlite_texts) = both(
        || SessionTimeZoneDependence::default().into(),
        "SELECT id FROM t WHERE at < CURRENT_TIMESTAMP",
    );
    assert_eq!(postgresql_texts.len(), 1, "{postgresql_texts:?}");
    assert_eq!(sqlite_texts, Vec::<String>::new());
}

#[test]
fn a_conditional_creation_is_reported_only_where_objects_have_owners() {
    use sqlparser::parser::Parser;

    let sql = "CREATE TABLE IF NOT EXISTS docs (id INT);";
    let constrainer: GenericConstrainer<ParserDB> =
        ConditionalCreationWithoutTrustedSchema::default().into();
    let postgresql_statements = Parser::parse_sql(&PostgreSqlDialect {}, sql).expect("parses");
    let sqlite_statements = Parser::parse_sql(&SQLiteDialect {}, sql).expect("parses");
    assert_eq!(
        constrainer
            .script_diagnostics(&postgresql(sql), &postgresql_statements)
            .len(),
        1
    );
    assert_eq!(
        constrainer
            .script_diagnostics(&sqlite(sql), &sqlite_statements)
            .len(),
        0
    );
}
