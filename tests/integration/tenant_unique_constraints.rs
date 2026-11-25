//! Unique constraints that ignore the subject column of a row-level-security
//! table, observed through the public constrainer API. On PostgreSQL 17.11
//! and 18.6, a tenant that saw no row of another tenant's `users` got a
//! duplicate-key error inserting that tenant's email under a global unique
//! index, and stored it under one scoped to the tenant. A role holding no
//! `INSERT` got `permission denied` before any duplicate-key check, and one
//! holding only `UPDATE` of the predicate column of a partial unique index got
//! the duplicate-key error by moving its own row under the index.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
    CREATE TABLE users (id INT PRIMARY KEY, email TEXT, handle TEXT, tenant_id INT NOT NULL,
      UNIQUE (handle), UNIQUE (tenant_id, handle));
    ALTER TABLE users ENABLE ROW LEVEL SECURITY;
    CREATE POLICY users_rls ON users USING (tenant_id = current_setting('app.tenant', true)::int);
    CREATE TABLE notes (id INT PRIMARY KEY, slug TEXT UNIQUE);
    CREATE TABLE plain (id INT PRIMARY KEY, code TEXT UNIQUE, tenant_id INT);
    CREATE POLICY plain_rls ON plain USING (tenant_id = current_setting('app.tenant', true)::int);";

/// Level and message of every finding of the rule.
fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    sql: &str,
) -> Vec<(Level, String)> {
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA}{sql}")).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation)
                if violation.rule().name
                    == "unscoped_unique_constraint_on_row_level_security_table" =>
            {
                Some((violation.level(), violation.message().to_owned()))
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn deployment() -> Deployment {
    Deployment::default()
        .with_credential("current_setting('app.tenant', true)")
        .expect("credential parses")
}

#[test]
fn unique_constraints_leaving_out_the_subject_are_reported() {
    let mut constrainer: GenericConstrainer<ParserDB> =
        UnscopedUniqueConstraintOnRowLevelSecurityTable::default().into();
    constrainer.set_deployment(deployment());
    let found = findings(
        &constrainer,
        "CREATE UNIQUE INDEX users_email ON users (email);
         CREATE UNIQUE INDEX users_email_scoped ON users (tenant_id, lower(email));
         CREATE INDEX users_by_email ON users (email);",
    );
    let messages: Vec<&str> = found.iter().map(|(_, message)| message.as_str()).collect();
    assert_eq!(
        messages,
        [
            "Unique constraint 'users_handle_key' on 'users' leaves out 'tenant_id', so a duplicate-key error reveals values in rows the caller's policies hide.",
            "Unique constraint 'users_email' on 'users' leaves out 'tenant_id', so a duplicate-key error reveals values in rows the caller's policies hide.",
        ]
    );
    assert!(found.iter().all(|(level, _)| *level == Level::Warn));
}

#[test]
fn the_rule_waits_for_a_credential_and_warns_by_default() {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    assert!(
        constrainer
            .inactive_rules(Engine::PostgreSql)
            .iter()
            .any(|inactive| inactive.rule().name
                == "unscoped_unique_constraint_on_row_level_security_table")
    );
    constrainer.set_deployment(deployment());
    assert_eq!(findings(&constrainer, "").len(), 1);
}

/// Messages of the rule's findings with `app` declared as the app role and
/// `anon` as the anonymous role, both created and stripped of every privilege
/// on `users` before `sql` runs.
fn client_findings(sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> =
        UnscopedUniqueConstraintOnRowLevelSecurityTable::default().into();
    constrainer.set_deployment(
        deployment()
            .with_app_role("app")
            .with_anonymous_role("anon"),
    );
    findings(
        &constrainer,
        &format!(
            "CREATE ROLE app; CREATE ROLE anon;
             REVOKE ALL ON users FROM app; REVOKE ALL ON users FROM anon;
             CREATE UNIQUE INDEX users_email ON users (lower(email)) WHERE handle IS NOT NULL;
             {sql}"
        ),
    )
    .into_iter()
    .map(|(_, message)| message)
    .collect()
}

#[test]
fn unique_indices_no_client_role_can_write_are_not_reported() {
    assert_eq!(
        client_findings("GRANT SELECT ON users TO app, anon; GRANT UPDATE (id) ON users TO app;"),
        Vec::<String>::new()
    );
}

#[test]
fn a_client_role_inserting_or_updating_a_key_column_keeps_the_finding() {
    let email = "Unique constraint 'users_email' on 'users' leaves out 'tenant_id', so a duplicate-key error reveals values in rows the caller's policies hide.";
    let handle = "Unique constraint 'users_handle_key' on 'users' leaves out 'tenant_id', so a duplicate-key error reveals values in rows the caller's policies hide.";
    assert_eq!(
        client_findings("GRANT INSERT (id) ON users TO anon;"),
        [handle, email]
    );
    assert_eq!(
        client_findings("GRANT UPDATE (email) ON users TO app;"),
        [email]
    );
    assert_eq!(
        client_findings("GRANT UPDATE (handle) ON users TO app;"),
        [handle, email]
    );
    assert_eq!(
        client_findings("GRANT UPDATE ON users TO PUBLIC;"),
        [handle, email]
    );
}

#[test]
fn a_declared_client_role_the_schema_never_creates_keeps_the_finding() {
    let mut constrainer: GenericConstrainer<ParserDB> =
        UnscopedUniqueConstraintOnRowLevelSecurityTable::default().into();
    constrainer.set_deployment(deployment().with_app_role("app"));
    assert_eq!(
        findings(&constrainer, "REVOKE ALL ON users FROM PUBLIC;").len(),
        1
    );
}

#[test]
fn each_subject_column_is_named_once() {
    let mut constrainer: GenericConstrainer<ParserDB> =
        UnscopedUniqueConstraintOnRowLevelSecurityTable::default().into();
    constrainer.set_deployment(deployment());
    let found = findings(
        &constrainer,
        "CREATE POLICY users_read ON users FOR SELECT
           USING (tenant_id = current_setting('app.tenant', true)::int);",
    );
    assert_eq!(
        found
            .into_iter()
            .map(|(_, message)| message)
            .collect::<Vec<_>>(),
        [
            "Unique constraint 'users_handle_key' on 'users' leaves out 'tenant_id', so a duplicate-key error reveals values in rows the caller's policies hide."
        ]
    );
}

#[test]
fn a_credential_only_write_policies_compare_scopes_no_key() {
    let mut constrainer: GenericConstrainer<ParserDB> =
        UnscopedUniqueConstraintOnRowLevelSecurityTable::default().into();
    constrainer.set_deployment(deployment());
    let found = findings(
        &constrainer,
        "CREATE TABLE runs (id INT PRIMARY KEY, code TEXT UNIQUE, performed_by INT);
         ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY runs_read ON runs FOR SELECT USING (true);
         CREATE POLICY runs_insert ON runs FOR INSERT
           WITH CHECK (performed_by IS NULL OR performed_by = current_setting('app.tenant', true)::int);
         CREATE POLICY runs_update ON runs FOR UPDATE
           USING (performed_by = current_setting('app.tenant', true)::int);
         CREATE POLICY runs_delete ON runs FOR DELETE
           USING (performed_by = current_setting('app.tenant', true)::int);",
    );
    assert!(
        found
            .iter()
            .all(|(_, message)| !message.contains("on 'runs'")),
        "{found:?}"
    );
}
