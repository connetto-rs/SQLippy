//! Policies reading a custom setting in a way that raises when the session
//! never set it, observed through the public constrainer API. Every reported
//! and passing shape was measured on PostgreSQL 18.6 as a role the policy
//! applies to.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const DOCS: &str = "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT, is_public BOOL);
    CREATE TABLE members (member TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    CREATE FUNCTION me() RETURNS TEXT LANGUAGE sql STABLE
        AS $$ SELECT current_setting('app.user_id') $$;
    CREATE FUNCTION me_pl() RETURNS TEXT LANGUAGE plpgsql STABLE
        AS $$ BEGIN RETURN current_setting('app.user_id'); END $$;
    CREATE FUNCTION outer_me() RETURNS TEXT LANGUAGE sql STABLE AS $$ SELECT me_pl() $$;
    CREATE FUNCTION me_or_null() RETURNS TEXT LANGUAGE sql STABLE
        AS $$ SELECT current_setting('app.user_id', true) $$;
    CREATE FUNCTION me_atomic() RETURNS TEXT LANGUAGE sql STABLE
        BEGIN ATOMIC SELECT current_setting('app.user_id'); END;
    CREATE FUNCTION setting_of(name TEXT) RETURNS TEXT LANGUAGE sql STABLE
        AS $$ SELECT current_setting(name) $$;";

/// The clause and site of every finding the rule raises on `policies`.
fn reads(policies: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = RaisingSettingRead::default().into();
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{DOCS} {policies}")).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().name, "raising_setting_read");
                let Location::Policies(sites) = violation.location() else {
                    panic!("raising_setting_read reports policies");
                };
                sites
                    .iter()
                    .map(|site| format!("{:?} {}", site.clause(), site.expression()))
                    .collect::<Vec<_>>()
                    .join(" | ")
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn reads_that_raise_for_a_session_without_the_setting_are_reported() {
    for (policy, site) in [
        (
            "CREATE POLICY p ON docs USING (owner = current_setting('app.user_id'));",
            "Using current_setting('app.user_id')",
        ),
        (
            "CREATE POLICY p ON docs FOR INSERT WITH CHECK (owner = current_setting('app.user_id'));",
            "WithCheck current_setting('app.user_id')",
        ),
        (
            "CREATE POLICY p ON docs USING (owner = current_setting('app.user_id', false));",
            "Using current_setting('app.user_id', false)",
        ),
        (
            "CREATE POLICY p ON docs USING (is_public OR owner = current_setting('app.user_id'));",
            "Using current_setting('app.user_id')",
        ),
        (
            "CREATE POLICY p ON docs USING (owner = pg_catalog.current_setting('app.user_id'));",
            "Using pg_catalog.current_setting('app.user_id')",
        ),
        (
            "CREATE POLICY p ON docs USING (EXISTS (
               SELECT 1 FROM members WHERE member = current_setting('app.user_id')));",
            "Using current_setting('app.user_id')",
        ),
        (
            "CREATE POLICY p ON docs USING (owner = me());",
            "Using me()",
        ),
        (
            "CREATE POLICY p ON docs USING (owner = outer_me());",
            "Using outer_me()",
        ),
        (
            "CREATE POLICY p ON docs USING (owner = current_setting('app.user_id', is_public));",
            "Using current_setting('app.user_id', is_public)",
        ),
        (
            "CREATE POLICY p ON docs USING (owner = me_atomic());",
            "Using me_atomic()",
        ),
    ] {
        assert_eq!(reads(policy), [site], "{policy}");
    }
}

#[test]
fn each_clause_of_a_policy_is_reported() {
    assert_eq!(
        reads(
            "CREATE POLICY p ON docs FOR UPDATE
               USING (owner = current_setting('app.user_id'))
               WITH CHECK (owner = me());"
        ),
        ["Using current_setting('app.user_id')", "WithCheck me()"]
    );
}

#[test]
fn reads_that_tolerate_a_missing_setting_pass() {
    for policy in [
        "CREATE POLICY p ON docs USING (owner = current_setting('app.user_id', true));",
        "CREATE POLICY p ON docs USING (owner = me_or_null());",
        "CREATE POLICY p ON docs USING (owner = current_setting('role'));",
        "CREATE POLICY p ON docs USING (owner = current_setting('search_path'));",
        "CREATE POLICY p ON docs USING (owner = current_setting('search_path', false));",
        "CREATE POLICY p ON docs USING (is_public);",
    ] {
        assert_eq!(reads(policy), Vec::<String>::new(), "{policy}");
    }
}

#[test]
fn a_setting_named_by_an_expression_is_not_seen() {
    for policy in [
        "CREATE POLICY p ON docs USING (owner = current_setting(owner));",
        "CREATE POLICY p ON docs USING (owner = setting_of('app.user_id'));",
    ] {
        assert_eq!(reads(policy), Vec::<String>::new(), "{policy}");
    }
}
