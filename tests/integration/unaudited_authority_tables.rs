//! Audit coverage of authority tables.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "CREATE TABLE memberships (user_id TEXT, doc_id INT);
CREATE TABLE docs (id INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY readable ON docs USING (EXISTS (SELECT 1 FROM memberships m WHERE m.doc_id = docs.id AND m.user_id = current_setting('app.user_id', true)));
CREATE FUNCTION record_authority() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;";

/// Counts authority audit findings through the public API.
fn findings(suffix: &str) -> usize {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA}{suffix}")).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnauditedAuthorityTable::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.set_rule_level("unaudited_authority_table", Level::Warn);
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(_) => 1,
            other => panic!("unexpected diagnostic {other}"),
        })
        .sum()
}

#[test]
fn authority_without_audit_is_reported() {
    assert_eq!(findings(""), 1);
}
#[test]
fn row_and_statement_audit_triggers_cover_declared_events() {
    for orientation in ["ROW", "STATEMENT"] {
        assert_eq!(
            findings(&format!(
                "CREATE TRIGGER audit_grants AFTER INSERT OR UPDATE OR DELETE ON memberships FOR EACH {orientation} EXECUTE FUNCTION record_authority();"
            )),
            0
        );
    }
}
#[test]
fn incomplete_or_before_audit_is_reported() {
    for trigger in [
        "AFTER INSERT OR UPDATE ON memberships FOR EACH ROW",
        "BEFORE INSERT OR UPDATE OR DELETE ON memberships FOR EACH ROW",
        "AFTER INSERT OR UPDATE OR DELETE ON docs FOR EACH ROW",
        "AFTER INSERT OR UPDATE OF doc_id OR DELETE ON memberships FOR EACH ROW",
    ] {
        assert_eq!(
            findings(&format!(
                "CREATE TRIGGER audit_grants {trigger} EXECUTE FUNCTION record_authority();"
            )),
            1
        );
    }
}

#[test]
fn undeclared_audit_function_does_not_exempt() {
    assert_eq!(findings("CREATE FUNCTION other_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
CREATE TRIGGER audit_grants AFTER INSERT OR UPDATE OR DELETE ON memberships FOR EACH ROW EXECUTE FUNCTION other_audit();"), 1);
}

#[test]
fn function_names_follow_postgresql_folding() {
    let schema = SCHEMA.replace("record_authority()", "PUBLIC.RECORD_AUTHORITY()");
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!("{schema}
CREATE TRIGGER audit_grants AFTER INSERT OR UPDATE OR DELETE ON memberships FOR EACH ROW EXECUTE FUNCTION PUBLIC.RECORD_AUTHORITY();")).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnauditedAuthorityTable::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.set_rule_level("unaudited_authority_table", Level::Deny);
    assert!(constrainer.validate_schema(&database).is_ok());
}

#[test]
fn authority_reached_through_sql_helper_is_reported() {
    let database = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE memberships (user_id TEXT, doc_id INT);
CREATE TABLE docs (id INT);
CREATE FUNCTION allowed_docs() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT doc_id FROM memberships WHERE user_id = current_setting('app.user_id', true) $$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY readable ON docs USING (id IN (SELECT allowed_docs()));").unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnauditedAuthorityTable::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.set_rule_level("unaudited_authority_table", Level::Deny);
    assert!(constrainer.validate_schema(&database).is_err());
}

#[test]
fn separate_triggers_cover_declared_events() {
    assert_eq!(findings(
        "CREATE TRIGGER audit_insert AFTER INSERT ON memberships EXECUTE FUNCTION record_authority();
         CREATE TRIGGER audit_update AFTER UPDATE ON memberships EXECUTE FUNCTION record_authority();
         CREATE TRIGGER audit_delete AFTER DELETE ON memberships EXECUTE FUNCTION record_authority();"
    ), 0);
}

#[test]
fn audit_function_uses_creation_search_path() {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE SCHEMA audit; SET search_path = audit; {SCHEMA}
         CREATE TRIGGER audit_grants AFTER INSERT OR UPDATE OR DELETE ON memberships EXECUTE FUNCTION record_authority();"
    )).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnauditedAuthorityTable::default().into();
    constrainer.set_deployment(Deployment::example().with_audit_function(
        "audit",
        "record_authority",
        [WriteEvent::Insert, WriteEvent::Update, WriteEvent::Delete],
    ));
    constrainer.set_rule_level("unaudited_authority_table", Level::Deny);
    assert!(constrainer.validate_schema(&database).is_ok());
}

#[test]
fn inline_trigger_does_not_execute_declared_audit_function() {
    let database = ParserDB::parse::<sqlparser::dialect::GenericDialect>(&format!("{SCHEMA} CREATE TRIGGER audit_grants AFTER INSERT OR UPDATE OR DELETE ON memberships FOR EACH ROW BEGIN SELECT 1; END;")).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnauditedAuthorityTable::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.set_rule_level("unaudited_authority_table", Level::Deny);
    assert!(matches!(
        constrainer.validate_schema(&database),
        Err(Error::Violation(_))
    ));
}

#[test]
fn missing_audit_declaration_identifies_inactive_rule() {
    let database = ParserDB::parse::<PostgreSqlDialect>(SCHEMA).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnauditedAuthorityTable::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_credential("current_setting('app.user_id', true)")
            .unwrap(),
    );
    let diagnostics = constrainer.diagnostics(&database);
    let [Error::Inactive(inactive)] = diagnostics.as_slice() else {
        panic!("expected inactive audit rule");
    };
    assert_eq!(inactive.rule().name, "unaudited_authority_table");
    assert_eq!(inactive.missing(), Declaration::AuditFunctions);
    assert!(diagnostics[0].to_string().contains("audit functions"));
}
