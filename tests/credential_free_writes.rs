//! Write policies a caller with no credential can pass, observed through the
//! public constrainer API. Every flagged and passing shape below was measured
//! on PostgreSQL 17.11 and 18.6 as an anonymous caller.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

fn parse(sql: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses")
}

fn connetto() -> Deployment {
    Deployment::default()
        .with_credential("current_setting('app.user_id', true)")
        .and_then(|deployment| deployment.with_credential("current_setting('app.subjects', true)"))
        .expect("credentials parse")
}

fn supabase() -> Deployment {
    Deployment::default()
        .with_credential("auth.uid()")
        .expect("credential parses")
        .with_anonymous_role("anon")
        .with_app_role("authenticated")
}

const SUPABASE: &str = "
    CREATE ROLE anon;
    CREATE ROLE authenticated;
    CREATE SCHEMA auth;
    CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
        AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;";

/// Rule name, level and object of every violation, failing on anything else.
fn findings(deployment: Deployment, sql: &str) -> Vec<(String, Level, String)> {
    let mut constrainer: GenericConstrainer<ParserDB> = CredentialFreeWrite::default().into();
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
        "CredentialFreeWrite".to_owned(),
        Level::Warn,
        object.to_owned(),
    )
}

/// Findings for one `DELETE` policy on `items` under the connetto deployment.
fn delete_policy(using: &str) -> Vec<(String, Level, String)> {
    findings(
        connetto(),
        &format!(
            "CREATE TABLE members (member TEXT, team INT);
             CREATE TABLE items (id INT, owner TEXT, team INT, is_public BOOL);
             ALTER TABLE items ENABLE ROW LEVEL SECURITY;
             CREATE FUNCTION not_(b BOOL) RETURNS BOOL LANGUAGE sql STRICT IMMUTABLE AS 'SELECT NOT b';
             CREATE POLICY d ON items FOR DELETE USING ({using});"
        ),
    )
}

#[test]
fn the_request_examples_are_judged_as_measured() {
    assert_eq!(
        findings(
            connetto(),
            "CREATE TABLE posts (id INT, owner TEXT, is_public BOOL);
             ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
             CREATE POLICY posts_delete ON posts FOR DELETE USING (
               owner = current_setting('app.user_id', true) OR is_public);"
        ),
        [finding("posts.posts_delete")]
    );
    assert_eq!(
        findings(
            supabase(),
            &format!(
                "{SUPABASE}
                 CREATE TABLE guestbook (id INT, body TEXT);
                 ALTER TABLE guestbook ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY guestbook_insert ON guestbook FOR INSERT TO anon WITH CHECK (true);"
            )
        ),
        [finding("guestbook.guestbook_insert")]
    );
    assert_eq!(
        findings(
            connetto(),
            "CREATE TABLE items (id INT, owner TEXT);
             ALTER TABLE items ENABLE ROW LEVEL SECURITY;
             CREATE POLICY items_p ON items FOR ALL USING (
               owner = current_setting('app.user_id', true)
               OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')));"
        ),
        []
    );
    assert_eq!(
        findings(
            connetto(),
            "CREATE TABLE notes (id INT, body TEXT, is_public BOOL);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY open_update ON notes FOR UPDATE USING (is_public);
             CREATE POLICY must_login ON notes AS RESTRICTIVE FOR UPDATE USING (
               current_setting('app.user_id', true) IS NOT NULL);"
        ),
        []
    );
    assert_eq!(
        findings(
            supabase(),
            &format!(
                "{SUPABASE}
                 CREATE TABLE notes (id INT, owner uuid);
                 ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY notes_update ON notes FOR UPDATE TO authenticated
                   USING (owner = (SELECT auth.uid()));"
            )
        ),
        []
    );
}

#[test]
fn a_platform_credential_the_schema_never_creates_still_counts() {
    let database = ParseOptions::default()
        .with_access_resolution(AccessResolution::OpenWorld)
        .parse::<PostgreSqlDialect>(
            "CREATE TABLE notes (id INT, owner uuid);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_delete ON notes FOR DELETE TO anon
               USING (owner = (SELECT auth.uid()));
             CREATE POLICY notes_open ON notes FOR UPDATE TO anon USING (owner IS NOT NULL);",
        )
        .expect("schema parses");
    let mut constrainer: GenericConstrainer<ParserDB> = CredentialFreeWrite::default().into();
    constrainer.set_deployment(supabase());
    let objects: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    assert_eq!(objects, ["notes.notes_open"]);
}

#[test]
fn a_restrictive_policy_without_a_credential_requirement_does_not_excuse() {
    assert_eq!(
        findings(
            connetto(),
            "CREATE TABLE notes (id INT, is_public BOOL, archived BOOL);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY open_update ON notes FOR UPDATE USING (is_public);
             CREATE POLICY live ON notes AS RESTRICTIVE FOR UPDATE USING (NOT archived);"
        ),
        [finding("notes.open_update")]
    );
}

#[test]
fn clauses_that_require_a_credential_pass() {
    for using in [
        "owner = current_setting('app.user_id', true)",
        "current_setting('app.user_id', true) IS NOT NULL",
        "owner = current_setting('app.user_id', true) AND is_public",
        "is_public AND current_setting('app.user_id', true) IS NOT NULL",
        "owner IN (current_setting('app.user_id', true), current_setting('app.subjects', true))",
        "NOT (owner <> current_setting('app.user_id', true))",
        "not_(owner = current_setting('app.user_id', true))",
        "upper(owner) = upper(current_setting('app.user_id', true))",
        "owner = (SELECT current_setting('app.user_id', true))",
        "EXISTS (SELECT 1 FROM members m WHERE m.team = items.team AND m.member = current_setting('app.user_id', true))",
        "team IN (SELECT team FROM members WHERE member = current_setting('app.user_id', true))",
        "EXISTS (SELECT 1 FROM members m JOIN members n ON n.member = current_setting('app.user_id', true))",
        "EXISTS (SELECT team, count(*) FROM members WHERE member = current_setting('app.user_id', true) GROUP BY team)",
        "EXISTS (SELECT count(*) OVER () FROM members WHERE member = current_setting('app.user_id', true))",
        "EXISTS (SELECT not_(team > 1) FROM members WHERE member = current_setting('app.user_id', true))",
        "EXISTS (SELECT * FROM members WHERE member = current_setting('app.user_id', true))",
        "EXISTS (SELECT (SELECT count(*) FROM members) FROM members WHERE member = current_setting('app.user_id', true))",
        "(current_setting('app.user_id', true) IS NOT NULL)",
        "owner LIKE current_setting('app.user_id', true)",
        "current_setting('app.user_id', true) = ANY(ARRAY['a', 'b'])",
    ] {
        assert_eq!(delete_policy(using), [], "{using}");
    }
}

#[test]
fn clauses_a_caller_without_a_credential_can_pass_are_reported() {
    for using in [
        "true",
        "is_public",
        "owner = current_setting('app.user_id', true) OR is_public",
        "current_setting('app.user_id', true) IS NULL",
        "coalesce(owner = current_setting('app.user_id', true), true)",
        "owner IS DISTINCT FROM current_setting('app.user_id', true)",
        "NOT (current_setting('app.user_id', true) IS NOT NULL)",
        "not_(current_setting('app.user_id', true) IS NOT NULL)",
        "owner = current_setting('app.other', true)",
        "team NOT IN (SELECT team FROM members WHERE member = current_setting('app.user_id', true))",
        "NOT EXISTS (SELECT 1 FROM members WHERE member = current_setting('app.user_id', true))",
        "EXISTS (SELECT count(*) FROM members WHERE member = current_setting('app.user_id', true))",
        "EXISTS (SELECT 1 FROM members t LEFT JOIN members m ON m.member = current_setting('app.user_id', true))",
        "EXISTS (SELECT unknown_tally(member) FROM members WHERE member = current_setting('app.user_id', true))",
        "owner IN (current_setting('app.user_id', true), 'x')",
        "lower(owner) = 'a'",
        "owner = current_user",
        "owner = (SELECT * FROM (SELECT member FROM members) AS s LIMIT 1)",
        "owner = (SELECT member FROM members UNION SELECT 'x' LIMIT 1)",
        "EXISTS (SELECT 1 FROM members WHERE member = current_setting('app.user_id', true) UNION SELECT 1)",
        "CASE WHEN current_setting('app.user_id', true) IS NULL THEN true ELSE false END",
    ] {
        assert_eq!(delete_policy(using), [finding("items.d")], "{using}");
    }
}

#[test]
fn each_command_judges_the_clause_postgres_applies() {
    let schema = "CREATE TABLE items (id INT, owner TEXT);
                  ALTER TABLE items ENABLE ROW LEVEL SECURITY;";
    assert_eq!(
        findings(
            connetto(),
            &format!(
                "{schema} CREATE POLICY w ON items FOR INSERT WITH CHECK (
                   owner = current_setting('app.user_id', true));"
            )
        ),
        []
    );
    assert_eq!(
        findings(
            connetto(),
            &format!(
                "{schema} CREATE POLICY w ON items FOR UPDATE USING (true)
                   WITH CHECK (owner = current_setting('app.user_id', true));"
            )
        ),
        [finding("items.w")]
    );
    assert_eq!(
        findings(
            connetto(),
            &format!(
                "{schema} CREATE POLICY w ON items FOR ALL USING (
                   owner = current_setting('app.user_id', true)) WITH CHECK (true);"
            )
        ),
        [finding("items.w")]
    );
    assert_eq!(
        findings(
            connetto(),
            &format!("{schema} CREATE POLICY r ON items FOR SELECT USING (true);")
        ),
        []
    );
}

#[test]
fn only_policies_reaching_an_anonymous_role_are_judged() {
    let schema = format!(
        "{SUPABASE}
         CREATE ROLE guests IN ROLE anon;
         CREATE ROLE visitor IN ROLE guests;
         CREATE ROLE web;
         GRANT web TO anon;
         CREATE ROLE muted;
         GRANT muted TO anon WITH INHERIT FALSE;
         CREATE TABLE items (id INT, owner uuid);
         ALTER TABLE items ENABLE ROW LEVEL SECURITY;"
    );
    for (to, expected) in [
        ("", 1),
        ("TO PUBLIC", 1),
        ("TO anon", 1),
        ("TO authenticated", 0),
        ("TO guests", 0),
        ("TO authenticated, anon", 1),
        ("TO web", 1),
        ("TO muted", 0),
    ] {
        assert_eq!(
            findings(
                supabase(),
                &format!("{schema} CREATE POLICY w ON items FOR DELETE {to} USING (true);")
            )
            .len(),
            expected,
            "{to}"
        );
    }
}

#[test]
fn a_declared_credential_wrapped_in_nullif_is_matched_as_written() {
    let deployment = Deployment::default()
        .with_credential("NULLIF(current_setting('app.user_id', true), '')")
        .expect("credential parses");
    let schema = "CREATE TABLE items (id INT, owner TEXT);
                  ALTER TABLE items ENABLE ROW LEVEL SECURITY;";
    assert_eq!(
        findings(
            deployment.clone(),
            &format!(
                "{schema} CREATE POLICY d ON items FOR DELETE USING (
                   owner = NULLIF(current_setting('app.user_id', true), ''));"
            )
        ),
        []
    );
    assert_eq!(
        findings(
            deployment,
            &format!(
                "{schema} CREATE POLICY d ON items FOR DELETE USING (
                   owner = current_setting('app.user_id', true));"
            )
        ),
        [finding("items.d")]
    );
}

#[test]
fn the_rule_waits_for_a_declared_credential() {
    let constrainer: GenericConstrainer<ParserDB> = CredentialFreeWrite::default().into();
    assert_eq!(
        constrainer
            .inactive_rules()
            .iter()
            .map(InactiveRule::missing)
            .collect::<Vec<_>>(),
        [Declaration::Credentials]
    );
    assert!(
        Deployment::default()
            .with_credential("current_setting(")
            .is_err()
    );
    let shown = constrainer.inactive_rules()[0].to_string();
    assert!(shown.contains("credential expressions"), "{shown}");
}

#[test]
fn the_finding_names_the_clause_and_the_arm_that_admits_the_caller() {
    let mut constrainer: GenericConstrainer<ParserDB> = CredentialFreeWrite::default().into();
    constrainer.set_deployment(connetto());
    let diagnostics = constrainer.diagnostics(&parse(
        "CREATE TABLE posts (id INT, owner TEXT, is_public BOOL);
         ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
         CREATE POLICY posts_delete ON posts FOR DELETE USING (
           owner = current_setting('app.user_id', true) OR is_public);",
    ));
    let [Error::Violation(violation)] = diagnostics.as_slice() else {
        panic!("expected one violation");
    };
    let Location::Policies(sites) = violation.location() else {
        panic!("expected policy sites");
    };
    assert_eq!(
        sites
            .iter()
            .map(|site| (site.clause(), site.expression()))
            .collect::<Vec<_>>(),
        [(PolicyClause::Using, "is_public")]
    );
    assert!(
        violation.message().contains("DELETE"),
        "{}",
        violation.message()
    );

    for (using, witness) in [
        (
            "(is_public OR owner = current_setting('app.user_id', true))",
            "is_public",
        ),
        ("archived OR is_public", "archived"),
    ] {
        let diagnostics = constrainer.diagnostics(&parse(&format!(
            "CREATE TABLE posts (id INT, owner TEXT, is_public BOOL, archived BOOL);
             ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
             CREATE POLICY posts_delete ON posts FOR DELETE USING ({using});"
        )));
        let [Error::Violation(violation)] = diagnostics.as_slice() else {
            panic!("expected one violation for {using}");
        };
        let Location::Policies(sites) = violation.location() else {
            panic!("expected policy sites");
        };
        assert_eq!(sites[0].expression(), witness, "{using}");
    }
}

#[test]
fn a_clause_shared_by_several_writes_is_named_once() {
    let mut constrainer: GenericConstrainer<ParserDB> = CredentialFreeWrite::default().into();
    constrainer.set_deployment(connetto());
    let diagnostics = constrainer.diagnostics(&parse(
        "CREATE TABLE items (id INT, owner TEXT);
         ALTER TABLE items ENABLE ROW LEVEL SECURITY;
         CREATE POLICY open ON items FOR ALL USING (true);",
    ));
    let [Error::Violation(violation)] = diagnostics.as_slice() else {
        panic!("expected one violation");
    };
    let Location::Policies(sites) = violation.location() else {
        panic!("expected policy sites");
    };
    assert_eq!(sites.len(), 1);
    assert!(
        violation.message().contains("INSERT, UPDATE, DELETE"),
        "{}",
        violation.message()
    );
}

#[test]
fn an_allowance_excuses_a_deliberate_anonymous_write() {
    let mut constrainer: GenericConstrainer<ParserDB> = CredentialFreeWrite::default().into();
    constrainer.set_deployment(supabase());
    constrainer.allow_policy(
        "CredentialFreeWrite",
        TargetName::new("guestbook", false),
        "guestbook_insert",
    );
    let database = parse(&format!(
        "{SUPABASE}
         CREATE TABLE guestbook (id INT, body TEXT);
         ALTER TABLE guestbook ENABLE ROW LEVEL SECURITY;
         CREATE POLICY guestbook_insert ON guestbook FOR INSERT TO anon WITH CHECK (true);"
    ));
    assert!(constrainer.diagnostics(&database).is_empty());
}
