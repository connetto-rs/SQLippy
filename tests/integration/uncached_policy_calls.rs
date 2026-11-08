//! Row-independent calls in policies observed through the public constrainer
//! API. The costs the rule cites were measured on PostgreSQL 16.8 over
//! 300,000 rows: `current_setting` 49 ms unwrapped against 16 ms wrapped, a
//! `STABLE` plpgsql helper 277 against 17, and a `VOLATILE` plpgsql helper
//! 347 against 1.8 ms with an index on the compared column. An
//! `ARRAY(SELECT call)` runs once per statement as an initPlan on PostgreSQL
//! 17.11 and 18.6.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
    CREATE SCHEMA auth;
    CREATE FUNCTION auth.uid() RETURNS TEXT LANGUAGE sql STABLE
      AS 'SELECT current_setting(''app.user_id'', true)';
    CREATE FUNCTION auth.uid_volatile() RETURNS TEXT LANGUAGE plpgsql
      AS 'BEGIN RETURN current_setting(''app.user_id'', true); END';
    CREATE FUNCTION auth.uid_inlined() RETURNS TEXT LANGUAGE sql
      AS 'SELECT current_setting(''app.user_id'', true)';
    CREATE FUNCTION can_read(o TEXT, u TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE AS 'SELECT o = u';
    CREATE TABLE members (team INT, member TEXT);
    CREATE TABLE docs (owner TEXT, team INT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

/// Level, reported call and whether the message names the volatility, for
/// every finding of the rule.
fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    policies: &str,
) -> Vec<(Level, String, bool)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA}{policies}"))
        .expect("schema parses");
    let mut found: Vec<_> = constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == "UncachedPolicyCall" => {
                let Location::Policies(sites) = violation.location() else {
                    panic!("a policy finding is located on policies");
                };
                Some((
                    violation.level(),
                    sites[0].expression().to_owned(),
                    violation.message().contains("VOLATILE"),
                ))
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    found.sort();
    found
}

fn calls(policies: &str) -> Vec<(String, bool)> {
    findings(
        &GenericConstrainer::from(UncachedPolicyCall::default()),
        policies,
    )
    .into_iter()
    .map(|(_, call, volatile)| (call, volatile))
    .collect()
}

#[test]
fn row_independent_calls_outside_sublinks_are_reported_once_each() {
    assert_eq!(
        calls(
            "CREATE POLICY setting ON docs USING (owner = current_setting('app.user_id', true));
             CREATE POLICY helper ON docs USING (owner = auth.uid());
             CREATE POLICY nested ON docs USING (owner = lower(current_setting('app.user_id', true)));
             CREATE POLICY argument ON docs USING (can_read(owner, auth.uid()));",
        ),
        [
            ("auth.uid()".to_owned(), false),
            ("auth.uid()".to_owned(), false),
            ("current_setting('app.user_id', true)".to_owned(), false),
            ("current_setting('app.user_id', true)".to_owned(), false),
        ]
    );
}

#[test]
fn only_a_volatile_call_postgresql_cannot_inline_is_said_to_block_an_index() {
    assert_eq!(
        calls(
            "CREATE POLICY volatile ON docs USING (owner = auth.uid_volatile());
             CREATE POLICY inlined ON docs USING (owner = auth.uid_inlined());",
        ),
        [
            ("auth.uid_inlined()".to_owned(), false),
            ("auth.uid_volatile()".to_owned(), true),
        ]
    );
}

#[test]
fn wrapped_row_dependent_constant_and_sublink_calls_pass() {
    assert_eq!(
        calls(
            "CREATE POLICY wrapped ON docs USING (owner = (SELECT auth.uid()));
             CREATE POLICY row ON docs USING (can_read(owner, owner));
             CREATE POLICY constant ON docs USING (owner = lower('ADMIN'));
             CREATE POLICY value_function ON docs USING (owner = current_user);
             CREATE POLICY sublink ON docs USING (
               team IN (SELECT team FROM members WHERE member = current_setting('app.user_id', true)));
             CREATE POLICY array_sublink ON docs USING (owner = ANY (ARRAY(SELECT auth.uid())));",
        ),
        Vec::<(String, bool)>::new()
    );
}

#[test]
fn a_call_beside_a_literal_without_a_known_stored_value_is_still_reported() {
    assert_eq!(
        calls(
            "CREATE TABLE exp (owner TEXT, expires TIMESTAMPTZ);
             ALTER TABLE exp ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON exp USING (owner = current_setting('app.user_id', true) AND expires > '2026-01-01 09:00');"
        ),
        [("current_setting('app.user_id', true)".to_owned(), false)]
    );
}

#[test]
fn the_default_constrainer_warns() {
    let found = findings(
        &DefaultConstrainer::<ParserDB>::default(),
        "CREATE POLICY p ON docs USING (owner = auth.uid());",
    );
    assert_eq!(found, [(Level::Warn, "auth.uid()".to_owned(), false)]);
}
