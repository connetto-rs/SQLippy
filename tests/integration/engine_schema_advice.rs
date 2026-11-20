use sqlippy::prelude::*;
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};

fn advice(constrainer: &GenericConstrainer<ParserDB>, schema: &str, engine: Engine) -> String {
    let database = match engine {
        Engine::PostgreSql => ParserDB::parse::<PostgreSqlDialect>(schema).unwrap(),
        Engine::Sqlite => ParseOptions::default()
            .with_identifier_case(IdentifierCase::Folded)
            .parse::<SQLiteDialect>(schema)
            .unwrap(),
    };
    let diagnostics = constrainer.diagnostics(&database);
    assert!(!diagnostics.is_empty());
    diagnostics
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                format!("{} {}", violation.message(), violation.resolution())
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn nullable_unique_advice_uses_supported_constraints() {
    let constrainer = NullableUniqueColumn::default().into();
    let schema = "CREATE TABLE users (email TEXT UNIQUE);";
    assert!(advice(&constrainer, schema, Engine::PostgreSql).contains("NULLS NOT DISTINCT"));
    let sqlite = advice(&constrainer, schema, Engine::Sqlite);
    assert!(sqlite.contains("NOT NULL"));
    assert!(!sqlite.contains("NULLS NOT DISTINCT"));
}

#[test]
fn nil_uuid_advice_uses_sqlite_null_tests() {
    let constrainer = NilUuidSentinel::default().into();
    let schema = "CREATE TABLE docs (id TEXT); CREATE VIEW absent AS SELECT id FROM docs WHERE id = '00000000-0000-0000-0000-000000000000';";
    assert!(advice(&constrainer, schema, Engine::PostgreSql).contains("current_setting"));
    let sqlite = advice(&constrainer, schema, Engine::Sqlite);
    assert!(sqlite.contains("IS NULL"));
    assert!(!sqlite.contains("current_setting"));
}

#[test]
fn unread_cte_message_names_its_engine() {
    let constrainer = UnusedCte::default().into();
    let schema = "CREATE VIEW unread AS WITH unused AS (SELECT 1 AS value) SELECT 2 AS value;";
    assert!(
        advice(&constrainer, schema, Engine::PostgreSql).contains("PostgreSQL never evaluates")
    );
    let sqlite = advice(&constrainer, schema, Engine::Sqlite);
    assert!(sqlite.contains("SQLite never evaluates"));
    assert!(!sqlite.contains("PostgreSQL"));
}

#[test]
fn catalog_name_advice_uses_explicit_migration_on_sqlite() {
    let constrainer = CatalogNameAsText::default().into();
    let schema = "CREATE TABLE documents (id INT); CREATE TABLE grants (relation_name TEXT); CREATE VIEW document_grants AS SELECT relation_name FROM grants WHERE relation_name = 'documents';";
    assert!(advice(&constrainer, schema, Engine::PostgreSql).contains("regclass"));
    let sqlite = advice(&constrainer, schema, Engine::Sqlite);
    assert!(sqlite.contains("migration"));
    assert!(!sqlite.contains("regclass"));
    assert!(!sqlite.contains("search_path"));
}

#[test]
fn email_advice_names_ascii_nocase_on_sqlite() {
    let constrainer = CaseSensitiveEmail::default().into();
    let schema = "CREATE TABLE invitations (email TEXT, request JSONB); CREATE VIEW invited AS SELECT email FROM invitations WHERE email = (request ->> 'email');";
    assert!(advice(&constrainer, schema, Engine::PostgreSql).contains("citext"));
    let sqlite = advice(&constrainer, schema, Engine::Sqlite);
    assert!(sqlite.contains("COLLATE NOCASE"));
    assert!(sqlite.contains("ASCII"));
    assert!(!sqlite.contains("citext"));
    let followed = ParseOptions::default()
        .with_identifier_case(IdentifierCase::Folded)
        .parse::<SQLiteDialect>(&schema.replace("email TEXT", "email TEXT COLLATE NOCASE"))
        .unwrap();
    assert!(constrainer.diagnostics(&followed).is_empty());
}

#[test]
fn ordered_set_advice_uses_ranks_on_sqlite() {
    let constrainer = OrderedSetAsDisjunction::default().into();
    let schema = "CREATE TABLE permissions (actual TEXT NOT NULL CHECK (actual IN ('read', 'write')), required TEXT NOT NULL CHECK (required IN ('read', 'write'))); CREATE VIEW sufficient AS SELECT actual FROM permissions WHERE actual = required OR (actual = 'write' AND required = 'read');";
    assert!(advice(&constrainer, schema, Engine::PostgreSql).contains("CREATE TYPE"));
    let sqlite = advice(&constrainer, schema, Engine::Sqlite);
    assert!(sqlite.contains("CASE"));
    assert!(!sqlite.contains("CREATE TYPE"));
}

#[test]
fn repeated_bound_advice_uses_a_constant_view_on_sqlite() {
    let constrainer = RepeatedRecursionBound::default().into();
    let walk = "WITH RECURSIVE walk(depth) AS (SELECT 0 UNION ALL SELECT depth + 1 FROM walk WHERE depth < 32) SELECT max(depth) FROM walk";
    let schema = format!("CREATE VIEW first_depth AS {walk}; CREATE VIEW second_depth AS {walk};");
    assert!(advice(&constrainer, &schema, Engine::PostgreSql).contains("IMMUTABLE"));
    let sqlite = advice(&constrainer, &schema, Engine::Sqlite);
    assert!(sqlite.contains("CREATE VIEW depth_limit"));
    assert!(!sqlite.contains("IMMUTABLE"));
}

#[test]
fn recursive_union_advice_does_not_promise_postgresql_plans_on_sqlite() {
    let constrainer = RecursiveStepOverUnion::default().into();
    let schema = "CREATE TABLE first_edges (parent_id INT, child_id INT); CREATE TABLE second_edges (parent_id INT, child_id INT); CREATE VIEW reachable_view AS WITH RECURSIVE reachable(id) AS (SELECT 1 UNION SELECT edge.child_id FROM reachable JOIN (SELECT * FROM first_edges UNION SELECT * FROM second_edges) edge ON edge.parent_id = reachable.id) SELECT id FROM reachable;";
    assert!(advice(&constrainer, schema, Engine::PostgreSql).contains("parameterized index scans"));
    let sqlite = advice(&constrainer, schema, Engine::Sqlite);
    assert!(sqlite.contains("UNION ALL"));
    assert!(!sqlite.contains("parameterized index scans"));
    assert!(!sqlite.contains("113.694"));
}

#[test]
fn sqlite_statement_advice_uses_sqlite_remedies() {
    let database = ParseOptions::default()
        .with_identifier_case(IdentifierCase::Folded)
        .parse::<SQLiteDialect>(
            "CREATE TABLE docs (id TEXT);
             CREATE TABLE first_edges (parent_id INT, child_id INT);
             CREATE TABLE second_edges (parent_id INT, child_id INT);",
        )
        .unwrap();
    let cases: [(GenericConstrainer<ParserDB>, &str, &str, &str); 3] = [
        (
            NilUuidSentinel::default().into(),
            "SELECT id FROM docs WHERE id = '00000000-0000-0000-0000-000000000000'",
            "IS NULL",
            "current_setting",
        ),
        (
            UnusedCte::default().into(),
            "WITH unused AS (SELECT 1) SELECT 2",
            "SQLite never evaluates",
            "PostgreSQL",
        ),
        (
            RecursiveStepOverUnion::default().into(),
            "WITH RECURSIVE reachable(id) AS (SELECT 1 UNION SELECT edge.child_id FROM reachable JOIN (SELECT * FROM first_edges UNION SELECT * FROM second_edges) edge ON edge.parent_id = reachable.id) SELECT id FROM reachable",
            "UNION ALL",
            "parameterized index scans",
        ),
    ];
    for (constrainer, query, expected, excluded) in cases {
        let statements = sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, query).unwrap();
        let diagnostics = constrainer.statement_diagnostics(&database, &statements[0]);
        assert!(!diagnostics.is_empty());
        for diagnostic in diagnostics {
            let Error::Violation(violation) = diagnostic else {
                panic!("unexpected failure: {diagnostic}");
            };
            let text = format!("{} {}", violation.message(), violation.resolution());
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains(excluded), "{text}");
        }
    }
}
