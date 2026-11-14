//! Read policies that admit a caller because its credential is `NULL`,
//! observed through the public constrainer API. Every flagged and passing
//! shape below was measured on PostgreSQL 18 as an anonymous caller.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

fn parse(sql: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses")
}

fn supabase() -> Deployment {
    Deployment::default()
        .with_credential("auth.uid()")
        .expect("credential parses")
        .with_anonymous_role("anon")
        .with_app_role("authenticated")
}

fn connetto() -> Deployment {
    Deployment::default()
        .with_credential("current_setting('app.user_id', true)")
        .expect("credential parses")
}

const SUPABASE: &str = "
    CREATE ROLE anon;
    CREATE ROLE authenticated;
    CREATE SCHEMA auth;
    CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
        AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
    CREATE TABLE documents (id INT, owner uuid, archived BOOL, is_public BOOL);
    ALTER TABLE documents ENABLE ROW LEVEL SECURITY;";

/// Rule name, level and object of every violation, failing on anything else.
fn findings(deployment: Deployment, sql: &str) -> Vec<(String, Level, String)> {
    let mut constrainer: GenericConstrainer<ParserDB> = NullCredentialRead::default().into();
    constrainer.set_deployment(deployment);
    constrainer
        .diagnostics(&parse(sql))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.rule().name.to_owned(),
                violation.level(),
                violation.object().to_owned(),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn finding(object: &str) -> (String, Level, String) {
    (
        "null_credential_read".to_owned(),
        Level::Warn,
        object.to_owned(),
    )
}

/// Findings for `policies` declared on Supabase's `documents`.
fn on_documents(policies: &str) -> Vec<(String, Level, String)> {
    findings(supabase(), &format!("{SUPABASE} {policies}"))
}

#[test]
fn an_arm_admitting_a_missing_credential_is_reported() {
    for policy in [
        "CREATE POLICY doc_read ON documents FOR SELECT USING (auth.uid() IS NULL OR owner = auth.uid());",
        "CREATE POLICY doc_read ON documents FOR ALL USING (owner = auth.uid() OR auth.uid() IS NULL);",
        "CREATE POLICY doc_read ON documents FOR SELECT TO anon USING (owner = auth.uid() OR (SELECT auth.uid()) IS NULL);",
        "CREATE POLICY doc_read ON documents FOR SELECT USING (COALESCE(auth.uid(), owner) = owner);",
        "CREATE POLICY doc_read ON documents FOR SELECT USING (auth.uid() IS DISTINCT FROM owner);",
        "CREATE POLICY doc_read ON documents FOR SELECT USING (NOT (auth.uid() IS NOT NULL) OR owner = auth.uid());",
        "CREATE POLICY doc_read ON documents FOR SELECT USING ((auth.uid() IS NULL OR owner = auth.uid()) AND NOT archived);",
    ] {
        assert_eq!(
            on_documents(policy),
            [finding("documents.doc_read")],
            "{policy}"
        );
    }
}

#[test]
fn reads_that_need_no_credential_by_design_are_not_reported() {
    for policy in [
        "CREATE POLICY doc_read ON documents FOR SELECT TO anon, authenticated USING (true);",
        "CREATE POLICY doc_read ON documents FOR SELECT USING (owner = auth.uid() OR is_public);",
        "CREATE POLICY doc_read ON documents FOR SELECT USING (owner = (SELECT auth.uid()));",
        "CREATE POLICY doc_read ON documents FOR SELECT USING (auth.uid() IS NOT NULL AND owner = auth.uid());",
    ] {
        assert_eq!(on_documents(policy), [], "{policy}");
    }
}

#[test]
fn a_policy_no_anonymous_caller_reaches_is_not_reported() {
    assert_eq!(
        on_documents(
            "CREATE POLICY doc_read ON documents FOR SELECT TO authenticated
               USING (auth.uid() IS NULL OR owner = auth.uid());"
        ),
        []
    );
}

#[test]
fn a_clause_false_whenever_the_credential_is_null_is_not_reported() {
    for policy in [
        "CREATE POLICY doc_read ON documents FOR SELECT USING (auth.uid() IS DISTINCT FROM NULL);",
        "CREATE POLICY doc_read ON documents FOR SELECT USING ((auth.uid() IS NULL) AND false);",
        "CREATE POLICY doc_read ON documents FOR SELECT USING (auth.uid() IS NULL AND NULL);",
    ] {
        assert_eq!(on_documents(policy), [], "{policy}");
    }
}

/// Findings for `policies` on `documents` with `anon` and `guest` both
/// declared anonymous.
fn with_two_anonymous_roles(policies: &str) -> Vec<(String, Level, String)> {
    findings(
        supabase().with_anonymous_role("guest"),
        &format!("{SUPABASE} CREATE ROLE guest; {policies}"),
    )
}

#[test]
fn a_guard_for_one_anonymous_role_does_not_cover_another() {
    assert_eq!(
        with_two_anonymous_roles(
            "CREATE POLICY doc_read ON documents FOR SELECT TO guest USING (auth.uid() IS NULL OR owner = auth.uid());
             CREATE POLICY signed_in ON documents AS RESTRICTIVE FOR SELECT TO anon USING (auth.uid() IS NOT NULL);"
        ),
        [finding("documents.doc_read")]
    );
    assert_eq!(
        with_two_anonymous_roles(
            "CREATE POLICY doc_read ON documents FOR SELECT TO anon, guest USING (auth.uid() IS NULL OR owner = auth.uid());
             CREATE POLICY signed_in ON documents AS RESTRICTIVE FOR SELECT TO anon USING (auth.uid() IS NOT NULL);"
        ),
        [finding("documents.doc_read")]
    );
    assert_eq!(
        with_two_anonymous_roles(
            "CREATE POLICY doc_read ON documents FOR SELECT TO anon, guest USING (auth.uid() IS NULL OR owner = auth.uid());
             CREATE POLICY signed_in ON documents AS RESTRICTIVE FOR SELECT TO anon, guest USING (auth.uid() IS NOT NULL);"
        ),
        []
    );
}

#[test]
fn a_guard_for_a_named_role_does_not_cover_public() {
    assert_eq!(
        on_documents(
            "CREATE POLICY doc_read ON documents FOR SELECT USING (auth.uid() IS NULL OR owner = auth.uid());
             CREATE POLICY signed_in ON documents AS RESTRICTIVE FOR SELECT TO anon USING (auth.uid() IS NOT NULL);"
        ),
        [finding("documents.doc_read")]
    );
}

#[test]
fn a_restrictive_policy_requiring_a_credential_guards_the_read() {
    assert_eq!(
        on_documents(
            "CREATE POLICY doc_read ON documents FOR SELECT USING (auth.uid() IS NULL OR owner = auth.uid());
             CREATE POLICY signed_in ON documents AS RESTRICTIVE FOR SELECT USING (auth.uid() IS NOT NULL);"
        ),
        []
    );
}

#[test]
fn writes_are_left_to_credential_free_write() {
    assert_eq!(
        on_documents(
            "CREATE POLICY doc_delete ON documents FOR DELETE USING (auth.uid() IS NULL OR owner = auth.uid());"
        ),
        []
    );
}

#[test]
fn a_table_without_row_level_security_is_not_reported() {
    assert_eq!(
        findings(
            supabase(),
            &format!(
                "{SUPABASE}
                 CREATE TABLE notes (id INT, owner uuid);
                 CREATE POLICY note_read ON notes FOR SELECT USING (auth.uid() IS NULL OR owner = auth.uid());"
            )
        ),
        []
    );
}

#[test]
fn a_setting_credential_is_judged_the_same_way() {
    assert_eq!(
        findings(
            connetto(),
            "CREATE TABLE items (id INT, owner TEXT);
             ALTER TABLE items ENABLE ROW LEVEL SECURITY;
             CREATE POLICY items_read ON items FOR SELECT USING (
               current_setting('app.user_id', true) IS NULL
               OR owner = current_setting('app.user_id', true));"
        ),
        [finding("items.items_read")]
    );
}

#[test]
fn the_rule_is_inactive_until_a_credential_is_declared() {
    let constrainer: GenericConstrainer<ParserDB> = NullCredentialRead::default().into();
    let database = parse(&format!(
        "{SUPABASE} CREATE POLICY doc_read ON documents FOR SELECT USING (auth.uid() IS NULL OR owner = auth.uid());"
    ));
    let diagnostics = constrainer.diagnostics(&database);
    assert!(
        matches!(diagnostics.as_slice(), [Error::Inactive(inactive)] if inactive.rule().name == "null_credential_read"),
        "{diagnostics:?}"
    );
}
