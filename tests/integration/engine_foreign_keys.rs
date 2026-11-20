use sqlippy::prelude::*;
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};

fn sqlite(sql: &str) -> ParserDB {
    ParseOptions::default()
        .with_identifier_case(IdentifierCase::Folded)
        .parse::<SQLiteDialect>(sql)
        .expect("schema parses")
}

#[test]
fn mixed_case_foreign_key_names_only_warn_on_postgresql() {
    let schema = "CREATE TABLE parents (id INT PRIMARY KEY); CREATE TABLE children (parent_id INT, CONSTRAINT \"ParentKey\" FOREIGN KEY (parent_id) REFERENCES parents(id));";
    let constrainer: GenericConstrainer<ParserDB> = MixedCaseForeignKeyName::default().into();
    assert!(matches!(
        constrainer.validate_schema(&ParserDB::parse::<PostgreSqlDialect>(schema).unwrap()),
        Err(Error::Violation(_))
    ));
    assert!(constrainer.validate_schema(&sqlite(schema)).is_ok());
}

#[test]
fn extension_cascade_advice_applies_to_both_engines() {
    let rule = ExtensionForeignKeyOnDeleteCascade::<ParserDB>::default();
    assert!(!rule.metadata().rationale.contains("PostgreSQL"));
    let constrainer: GenericConstrainer<ParserDB> = rule.into();
    let schema = "CREATE TABLE parents (id INT PRIMARY KEY); CREATE TABLE children (id INT PRIMARY KEY REFERENCES parents(id));";
    for database in [
        ParserDB::parse::<PostgreSqlDialect>(schema).unwrap(),
        sqlite(schema),
    ] {
        match constrainer.validate_schema(&database) {
            Err(Error::Violation(violation)) => {
                assert!(violation.resolution().contains("ON DELETE CASCADE"));
            }
            other => panic!("expected a cascade finding, got {other:?}"),
        }
    }
}

#[test]
fn nullable_composite_keys_require_enforced_nullness_on_sqlite() {
    let constrainer: GenericConstrainer<ParserDB> = NullableCompositeForeignKey::default().into();
    let schema = "CREATE TABLE parents (a INT, b INT, PRIMARY KEY (a,b)); CREATE TABLE children (a INT, b INT, FOREIGN KEY (a,b) REFERENCES parents(a,b)";
    for matching in ["", " MATCH FULL"] {
        let schema = format!("{schema}{matching});");
        match constrainer.validate_schema(&sqlite(&schema)) {
            Err(Error::Violation(violation)) => {
                assert!(!violation.resolution().contains("MATCH FULL"));
                assert!(violation.resolution().contains("NOT NULL"));
                assert!(violation.resolution().contains("(a IS NULL) = (b IS NULL)"));
            }
            other => panic!("expected a partial-key finding, got {other:?}"),
        }
        let database = ParserDB::parse::<PostgreSqlDialect>(&schema).unwrap();
        if matching.is_empty() {
            match constrainer.validate_schema(&database) {
                Err(Error::Violation(violation)) => {
                    assert!(violation.resolution().contains("MATCH FULL"));
                }
                other => panic!("expected a partial-key finding, got {other:?}"),
            }
        } else {
            assert!(constrainer.validate_schema(&database).is_ok());
        }
    }
    let checked = format!("{schema} MATCH FULL, CHECK ((a IS NULL) = (b IS NULL)));");
    assert!(constrainer.validate_schema(&sqlite(&checked)).is_ok());
}
