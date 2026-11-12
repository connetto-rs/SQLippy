//! Unique constraints that ignore the subject column of a row-level-security
//! table, observed through the public constrainer API. On PostgreSQL 17.11
//! and 18.6, a tenant that saw no row of another tenant's `users` got a
//! duplicate-key error inserting that tenant's email under a global unique
//! index, and stored it under one scoped to the tenant.

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
            "Unique constraint 'handle' on 'users' leaves out 'tenant_id', so a duplicate-key error reveals values in rows the caller's policies hide.",
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
            .inactive_rules()
            .iter()
            .any(|inactive| inactive.rule().name
                == "unscoped_unique_constraint_on_row_level_security_table")
    );
    constrainer.set_deployment(deployment());
    assert_eq!(findings(&constrainer, "").len(), 1);
}
