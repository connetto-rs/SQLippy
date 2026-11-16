//! Client updates of irreversible columns.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "CREATE ROLE authenticated;
CREATE TABLE tokens (id INT, revoked_at TIMESTAMPTZ, revoked BOOLEAN, label TEXT);
GRANT UPDATE ON tokens TO authenticated;";
const GUARD: &str = "CREATE FUNCTION preserve_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL THEN RAISE EXCEPTION 'revocation is permanent'; END IF; RETURN NEW; END $$;";

/// Counts irreversible-column findings through the public API.
fn findings(column: &str, suffix: &str) -> usize {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA}{suffix}")).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = MonotonicFlagReset::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_app_role("authenticated")
            .with_irreversible_column("public", "tokens", column),
    );
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
fn writable_irreversible_column_is_reported() {
    assert_eq!(findings("revoked_at", ""), 1);
    assert_eq!(
        findings(
            "revoked_at",
            "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE TO authenticated USING (true);"
        ),
        1
    );
}

#[test]
fn old_and_new_row_trigger_exempts_column() {
    assert_eq!(
        findings(
            "revoked_at",
            &format!(
                "{GUARD} CREATE TRIGGER preserve BEFORE UPDATE ON tokens FOR EACH ROW EXECUTE FUNCTION preserve_revocation();"
            )
        ),
        0
    );
}

#[test]
fn other_trigger_events_timing_and_orientation_do_not_exempt() {
    for shape in [
        "BEFORE INSERT ON tokens FOR EACH ROW",
        "AFTER UPDATE ON tokens FOR EACH ROW",
        "BEFORE UPDATE ON tokens FOR EACH STATEMENT",
    ] {
        assert_eq!(
            findings(
                "revoked_at",
                &format!(
                    "{GUARD} CREATE TRIGGER preserve {shape} EXECUTE FUNCTION preserve_revocation();"
                )
            ),
            1
        );
    }
}

#[test]
fn every_permissive_using_must_require_initial_state() {
    let guarded = "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE TO authenticated USING (revoked_at IS NULL);";
    assert_eq!(findings("revoked_at", guarded), 0);
    assert_eq!(
        findings(
            "revoked_at",
            &format!("{guarded} CREATE POLICY other ON tokens FOR UPDATE USING (true);")
        ),
        1
    );
    assert_eq!(
        findings(
            "revoked",
            "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE USING (NOT revoked);"
        ),
        0
    );
    assert_eq!(
        findings(
            "revoked_at",
            "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE USING (true) WITH CHECK (revoked_at IS NULL);"
        ),
        1
    );
}

#[test]
fn no_update_policy_or_withheld_column_is_safe() {
    assert_eq!(
        findings(
            "revoked_at",
            "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;"
        ),
        0
    );
    assert_eq!(
        findings(
            "revoked_at",
            "REVOKE UPDATE ON tokens FROM authenticated; GRANT UPDATE (label) ON tokens TO authenticated;"
        ),
        0
    );
}

#[test]
fn parenthesized_initial_state_is_safe() {
    assert_eq!(
        findings(
            "revoked_at",
            "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE USING ((tokens.revoked_at) IS NULL);"
        ),
        0
    );
    assert_eq!(
        findings(
            "revoked",
            "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE USING (NOT (revoked));"
        ),
        0
    );
}

#[test]
fn trigger_must_read_both_values_of_the_declared_column() {
    for guard in [
        "BEGIN IF NEW.revoked_at IS NULL THEN RAISE EXCEPTION 'missing'; END IF; RETURN NEW; END",
        "BEGIN IF OLD.revoked_at IS NULL THEN RAISE EXCEPTION 'missing'; END IF; RETURN NEW; END",
        "BEGIN IF OLD.revoked AND NOT NEW.revoked THEN RAISE EXCEPTION 'missing'; END IF; RETURN NEW; END",
    ] {
        assert_eq!(
            findings(
                "revoked_at",
                &format!(
                    "CREATE FUNCTION guard() RETURNS trigger LANGUAGE plpgsql AS $$ {guard} $$; CREATE TRIGGER preserve BEFORE UPDATE ON tokens FOR EACH ROW EXECUTE FUNCTION guard();"
                )
            ),
            1
        );
    }
    assert_eq!(
        findings(
            "revoked_at",
            &format!(
                "{GUARD} CREATE TRIGGER preserve BEFORE UPDATE OF label ON tokens FOR EACH ROW EXECUTE FUNCTION preserve_revocation();"
            )
        ),
        1
    );
    assert_eq!(
        findings(
            "revoked_at",
            &format!(
                "{GUARD} CREATE TRIGGER preserve BEFORE UPDATE OF revoked_at ON tokens FOR EACH ROW EXECUTE FUNCTION preserve_revocation();"
            )
        ),
        0
    );
}

#[test]
fn grants_and_policies_follow_inherited_roles_and_public() {
    for suffix in [
        "CREATE ROLE writers; GRANT writers TO authenticated; REVOKE UPDATE ON tokens FROM authenticated; GRANT UPDATE (revoked_at) ON tokens TO writers; ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE TO writers USING (true);",
        "REVOKE UPDATE ON tokens FROM authenticated; GRANT UPDATE (revoked_at) ON tokens TO PUBLIC;",
        "REVOKE UPDATE ON tokens FROM authenticated; GRANT UPDATE (revoked_at) ON tokens TO authenticated;",
    ] {
        assert_eq!(findings("revoked_at", suffix), 1);
    }
}

#[test]
fn unrelated_policies_do_not_open_updates() {
    for suffix in [
        "CREATE POLICY readable ON tokens FOR SELECT USING (true);",
        "CREATE POLICY restricted ON tokens AS RESTRICTIVE FOR UPDATE USING (true);",
        "CREATE ROLE other; CREATE POLICY writable ON tokens FOR UPDATE TO other USING (true);",
    ] {
        assert_eq!(
            findings(
                "revoked_at",
                &format!("ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; {suffix}")
            ),
            0
        );
    }
    assert_eq!(
        findings(
            "revoked_at",
            "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE USING (revoked_at IS NULL OR id = 1);"
        ),
        1
    );
}

#[test]
fn public_grants_reach_clients_without_role_declarations() {
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE tokens (id INT, revoked_at TIMESTAMPTZ); GRANT UPDATE ON tokens TO PUBLIC;",
    )
    .unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = MonotonicFlagReset::default().into();
    constrainer.set_deployment(Deployment::example());
    assert!(constrainer.validate_schema(&database).is_err());
}

#[test]
fn restrictive_initial_state_blocks_resets() {
    assert_eq!(findings("revoked_at",
        "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;
         CREATE POLICY own ON tokens FOR UPDATE TO authenticated USING (true);
         CREATE POLICY initial ON tokens AS RESTRICTIVE FOR UPDATE TO authenticated USING (revoked_at IS NULL);"), 0);
    for policy in [
        "CREATE POLICY initial ON tokens AS RESTRICTIVE FOR SELECT USING (revoked_at IS NULL);",
        "CREATE POLICY initial ON tokens AS RESTRICTIVE FOR UPDATE USING (true) WITH CHECK (revoked_at IS NULL);",
        "CREATE ROLE other; CREATE POLICY initial ON tokens AS RESTRICTIVE FOR UPDATE TO other USING (revoked_at IS NULL);",
    ] {
        assert_eq!(
            findings(
                "revoked_at",
                &format!(
                    "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;
             CREATE POLICY own ON tokens FOR UPDATE TO authenticated USING (true); {policy}"
                )
            ),
            1
        );
    }
}

#[test]
fn null_initial_state_applies_to_uuid_columns() {
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE ROLE authenticated; CREATE TABLE tokens (id INT, revoked_by UUID);
         GRANT UPDATE ON tokens TO authenticated; ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;
         CREATE POLICY initial ON tokens FOR UPDATE TO authenticated USING (revoked_by IS NULL);",
    )
    .unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = MonotonicFlagReset::default().into();
    constrainer.set_deployment(Deployment::example().with_irreversible_column(
        "public",
        "tokens",
        "revoked_by",
    ));
    assert!(constrainer.validate_schema(&database).is_ok());
}

#[test]
fn check_only_policy_does_not_protect_old_rows() {
    assert_eq!(
        findings(
            "revoked_at",
            "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE WITH CHECK (revoked_at IS NULL);"
        ),
        1
    );
    assert_eq!(
        findings(
            "revoked_at",
            "ALTER TABLE tokens ENABLE ROW LEVEL SECURITY; CREATE POLICY writable ON tokens FOR UPDATE USING (label IS NULL);"
        ),
        1
    );
}

#[test]
fn unrelated_record_does_not_guard_transitions() {
    assert_eq!(
        findings(
            "revoked_at",
            "CREATE FUNCTION guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF other.revoked_at IS NULL THEN RETURN NEW; END IF; RETURN NEW; END $$; CREATE TRIGGER preserve BEFORE UPDATE ON tokens FOR EACH ROW EXECUTE FUNCTION guard();"
        ),
        1
    );
}

#[test]
fn inline_trigger_without_transition_reads_does_not_guard_resets() {
    let database = ParserDB::parse::<sqlparser::dialect::GenericDialect>(&format!(
        "{SCHEMA} CREATE TRIGGER preserve BEFORE UPDATE ON tokens FOR EACH ROW BEGIN SELECT 1; END;"
    ))
    .unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = MonotonicFlagReset::default().into();
    constrainer.set_deployment(Deployment::example());
    assert!(matches!(
        constrainer.validate_schema(&database),
        Err(Error::Violation(_))
    ));
}

#[test]
fn missing_irreversible_declaration_identifies_inactive_rule() {
    let database = ParserDB::parse::<PostgreSqlDialect>(SCHEMA).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = MonotonicFlagReset::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("authenticated"));
    let diagnostics = constrainer.diagnostics(&database);
    let [Error::Inactive(inactive)] = diagnostics.as_slice() else {
        panic!("expected inactive irreversible column rule");
    };
    assert_eq!(inactive.rule().name, "monotonic_flag_reset");
    assert_eq!(inactive.missing(), Declaration::IrreversibleColumns);
    assert!(diagnostics[0].to_string().contains("irreversible columns"));
}
