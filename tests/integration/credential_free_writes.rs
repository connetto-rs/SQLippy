//! Write policies a caller with no credential can pass, observed through the
//! public constrainer API. Every flagged and passing shape below was measured
//! on PostgreSQL 17.11 and 18.6 as an anonymous caller.

use sqlippy::prelude::*;
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
        "credential_free_write".to_owned(),
        Level::Warn,
        object.to_owned(),
    )
}

/// Findings for one `DELETE` policy on `items` under the connetto deployment.
fn delete_policy(using: &str) -> Vec<(String, Level, String)> {
    delete_policy_after("", using)
}

/// Findings for one `DELETE` policy on `items` declared after `prelude`.
fn delete_policy_after(prelude: &str, using: &str) -> Vec<(String, Level, String)> {
    findings(
        connetto(),
        &format!(
            "CREATE TABLE members (member TEXT, team INT);
             CREATE TABLE items (id INT, owner TEXT, team INT, is_public BOOL);
             ALTER TABLE items ENABLE ROW LEVEL SECURITY;
             CREATE FUNCTION not_(b BOOL) RETURNS BOOL LANGUAGE sql STRICT IMMUTABLE AS 'SELECT NOT b';
             {prelude}
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
             CREATE POLICY notes_appended ON notes FOR DELETE TO anon
               USING (owner = ANY (ARRAY[owner] || auth.uid()));
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
    assert_eq!(objects, ["notes.notes_appended", "notes.notes_open"]);
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
        "owner LIKE current_setting('app.user_id', true) || '%'",
        "owner = 'u:' || current_setting('app.user_id', true)",
        "(owner || current_setting('app.user_id', true)) IS NOT NULL",
        "(jsonb_build_object('a', 1) || current_setting('app.user_id', true)::jsonb) IS NOT NULL",
        "(owner = current_setting('app.user_id', true)) IS TRUE",
        "team IN (SELECT team FROM members WHERE member = current_setting('app.user_id', true)) IS TRUE",
        "coalesce(owner = current_setting('app.user_id', true), false)",
        "owner = coalesce(current_setting('app.user_id', true), current_setting('app.subjects', true))",
        "CASE WHEN is_public THEN owner = current_setting('app.user_id', true)
           ELSE team IN (SELECT team FROM members WHERE member = current_setting('app.user_id', true)) END",
        "CASE WHEN is_public THEN owner = current_setting('app.user_id', true) END",
        "owner = nullif(current_setting('app.user_id', true), '')",
        "(team, owner) = (1, current_setting('app.user_id', true))",
        "owner = current_setting('app.user_id', true) COLLATE \"C\"",
        "owner = trim(current_setting('app.user_id', true))",
        "owner = trim(current_setting('app.user_id', true) FROM owner)",
        "owner = ANY (ARRAY[current_setting('app.user_id', true)])",
        "team IN (SELECT team FROM members WHERE member = ANY (ARRAY[current_setting('app.user_id', true)]))",
        "owner IN (SELECT current_setting('app.user_id', true))",
        "owner = ANY (SELECT current_setting('app.user_id', true) FROM members)",
        "CASE WHEN is_public
           THEN team IN (SELECT team FROM members WHERE member = current_setting('app.user_id', true)) END",
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
        "EXISTS (SELECT platform.unknown_tally(member) FROM members WHERE member = current_setting('app.user_id', true))",
        "owner IN (current_setting('app.user_id', true), 'x')",
        "lower(owner) = 'a'",
        "owner = current_user",
        "owner = (SELECT * FROM (SELECT member FROM members) AS s LIMIT 1)",
        "owner = (SELECT member FROM members UNION SELECT 'x' LIMIT 1)",
        "EXISTS (SELECT 1 FROM members WHERE member = current_setting('app.user_id', true) UNION SELECT 1)",
        "CASE WHEN current_setting('app.user_id', true) IS NULL THEN true ELSE false END",
        "CASE WHEN is_public THEN true ELSE owner = current_setting('app.user_id', true) END",
        "owner = coalesce(current_setting('app.user_id', true), 'anon')",
        "owner = nullif('x', current_setting('app.user_id', true))",
        "(owner = current_setting('app.user_id', true)) IS NOT FALSE",
        "team IN (SELECT team FROM members WHERE member = current_setting('app.user_id', true)) IS NOT TRUE",
        "(owner, team) <> (current_setting('app.user_id', true), 1)",
        "owner = ANY (ARRAY[current_setting('app.user_id', true), 'x'])",
        "owner = trim(owner) OR owner = current_setting('app.user_id', true)",
        "coalesce(items.*, current_setting('app.user_id', true)::items) IS NOT NULL",
    ] {
        assert_eq!(delete_policy(using), [finding("items.d")], "{using}");
    }
}

/// Helpers taking the credential as an argument.
const TAKING_THE_CREDENTIAL: &str = "
    CREATE FUNCTION teams_of(who TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
      AS 'SELECT team FROM members WHERE member = who';
    CREATE FUNCTION teams_named(who TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
      AS 'SELECT team FROM members WHERE member = teams_named.who';
    CREATE FUNCTION teams_by_position(TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
      AS 'SELECT team FROM members WHERE member = $1';
    CREATE FUNCTION strict_teams(who TEXT) RETURNS SETOF INT LANGUAGE sql STABLE STRICT
      AS 'SELECT team FROM members';
    CREATE FUNCTION teams_or_all(who TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
      AS 'SELECT team FROM members WHERE member = who OR who IS NULL';
    CREATE FUNCTION shadowed(member TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
      AS 'SELECT team FROM members WHERE member = member';
    CREATE FUNCTION kept_teams(who TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
      AS 'SELECT team FROM members WHERE team > 0 AND member = who';
    CREATE FUNCTION quoted_named(who TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
      AS 'SELECT team FROM members WHERE member = \"quoted_named\".who';";

#[test]
fn a_helper_requiring_the_credential_it_is_handed_passes() {
    for using in [
        "team IN (SELECT teams_of(current_setting('app.user_id', true)))",
        "team IN (SELECT t FROM teams_of(current_setting('app.user_id', true)) t)",
        "team IN (SELECT teams_named(current_setting('app.user_id', true)))",
        "team IN (SELECT teams_by_position(current_setting('app.user_id', true)))",
        "team IN (SELECT strict_teams(current_setting('app.user_id', true)))",
        "team IN (SELECT t FROM strict_teams(current_setting('app.user_id', true)) t)",
        "team IN (SELECT kept_teams(current_setting('app.user_id', true)))",
        "team IN (SELECT quoted_named(current_setting('app.user_id', true)))",
    ] {
        assert_eq!(
            delete_policy_after(TAKING_THE_CREDENTIAL, using),
            [],
            "{using}"
        );
    }
}

#[test]
fn a_helper_returning_rows_for_a_missing_credential_it_is_handed_is_reported() {
    for using in [
        "team IN (SELECT teams_or_all(current_setting('app.user_id', true)))",
        "team IN (SELECT t FROM teams_or_all(current_setting('app.user_id', true)) t)",
        "team IN (SELECT shadowed(current_setting('app.user_id', true)))",
        "team IN (SELECT teams_of('x'))",
    ] {
        assert_eq!(
            delete_policy_after(TAKING_THE_CREDENTIAL, using),
            [finding("items.d")],
            "{using}"
        );
    }
}

/// A helper and a view appending the credential to an array.
const APPENDING: &str = "
    CREATE FUNCTION appended_teams() RETURNS SETOF INT LANGUAGE sql STABLE AS $$
      SELECT team FROM members WHERE member = ANY (ARRAY['x'] || current_setting('app.user_id', true)) $$;
    CREATE VIEW appended_view AS
      SELECT team FROM members WHERE member = ANY (ARRAY['x'] || current_setting('app.user_id', true));";

#[test]
fn an_array_concatenated_with_a_missing_credential_keeps_its_elements() {
    for using in [
        "owner = ANY (ARRAY['x'] || current_setting('app.user_id', true))",
        "owner = ANY (current_setting('app.user_id', true) || ARRAY['x'])",
        "owner = ANY (string_to_array('x', ',') || current_setting('app.user_id', true))",
        "owner = ANY (ARRAY['x'] || string_to_array(current_setting('app.user_id', true), ','))",
        "team IN (WITH a AS (SELECT team FROM members
           WHERE member = ANY (ARRAY['x'] || current_setting('app.user_id', true))) SELECT team FROM a)",
        "team IN (SELECT team FROM members m
           WHERE m.member = ANY (ARRAY[m.member] || current_setting('app.user_id', true)))",
        "team IN (SELECT appended_teams())",
        "team IN (SELECT team FROM appended_view)",
    ] {
        assert_eq!(
            delete_policy_after(APPENDING, using),
            [finding("items.d")],
            "{using}"
        );
    }
}

/// A `members` query whose filter requires a credential, ending in `clause`.
fn grouped_members(clause: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM members WHERE member = current_setting('app.user_id', true) {clause})"
    )
}

#[test]
fn an_aggregation_over_the_empty_grouping_set_is_reported() {
    for clause in [
        "HAVING count(*) < 5",
        "HAVING true",
        "HAVING count(*) < 5 ORDER BY 1",
        "ORDER BY count(*)",
        "WINDOW w AS (ORDER BY count(*))",
        "GROUP BY ()",
        "GROUP BY (), ()",
        "GROUP BY ROLLUP (team)",
        "GROUP BY ROLLUP ((team, member))",
        "GROUP BY CUBE (team)",
        "GROUP BY ROLLUP (team), CUBE (member)",
        "GROUP BY GROUPING SETS (())",
        "GROUP BY GROUPING SETS ((team), ())",
        "GROUP BY GROUPING SETS (team, ())",
    ] {
        assert_eq!(
            delete_policy(&grouped_members(clause)),
            [finding("items.d")],
            "{clause}"
        );
    }
    assert_eq!(
        delete_policy(
            "EXISTS (SELECT DISTINCT ON (count(*)) 1 FROM members
               WHERE member = current_setting('app.user_id', true))"
        ),
        [finding("items.d")]
    );
}

#[test]
fn an_aggregation_without_the_empty_grouping_set_passes() {
    for clause in [
        "GROUP BY GROUPING SETS ((team))",
        "GROUP BY GROUPING SETS (team, member)",
        "GROUP BY team, ROLLUP (member)",
        "GROUP BY GROUPING SETS (team), ROLLUP (member)",
        "GROUP BY team HAVING true",
        "GROUP BY ROLLUP (team) HAVING false",
        "GROUP BY () HAVING max(member) = current_setting('app.user_id', true)",
    ] {
        assert_eq!(delete_policy(&grouped_members(clause)), [], "{clause}");
    }
}

const HELPERS: &str = "
    CREATE SCHEMA authz;
    CREATE TABLE grants (team INT, member TEXT);
    CREATE FUNCTION authz.mine() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
      AS $$ SELECT g.team FROM public.grants g WHERE g.member = current_setting('app.user_id', true) $$;
    CREATE FUNCTION authz.nested() RETURNS SETOF INT LANGUAGE sql STABLE AS $$
      SELECT g.team FROM public.grants g WHERE g.member = current_setting('app.user_id', true)
      UNION SELECT m.team FROM public.members m WHERE m.team IN (SELECT authz.mine()) $$;
    CREATE FUNCTION authz.either() RETURNS SETOF INT LANGUAGE sql STABLE
      AS $$ (SELECT authz.mine()) UNION (SELECT authz.nested() FROM public.members) $$;
    CREATE FUNCTION authz.everyone() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT team FROM public.members $$;
    CREATE FUNCTION authz.half() RETURNS SETOF INT LANGUAGE sql STABLE
      AS $$ SELECT authz.mine() UNION SELECT team FROM public.members $$;
    CREATE FUNCTION authz.tally() RETURNS INT LANGUAGE sql STABLE
      AS $$ SELECT count(*)::INT FROM public.grants WHERE member = current_setting('app.user_id', true) $$;
    CREATE FUNCTION authz.procedural() RETURNS SETOF INT LANGUAGE plpgsql STABLE AS $$
      BEGIN RETURN QUERY SELECT team FROM public.grants WHERE member = current_setting('app.user_id', true); END $$;
    CREATE FUNCTION authz.constant() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ VALUES (1) $$;
    CREATE FUNCTION authz.last() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1; SELECT 2 $$;
    CREATE FUNCTION authz.looping() RETURNS SETOF INT LANGUAGE sql STABLE
      AS $$ SELECT team FROM public.members WHERE team IN (SELECT authz.looping()) $$;";

#[test]
fn a_set_returning_sql_helper_whose_every_arm_requires_a_credential_passes() {
    for using in [
        "team = ANY (ARRAY(SELECT authz.mine()))",
        "team IN (SELECT authz.nested())",
        "team = ANY (ARRAY(SELECT authz.either()))",
    ] {
        assert_eq!(delete_policy_after(HELPERS, using), [], "{using}");
    }
}

#[test]
fn helpers_returning_a_row_without_a_credential_are_reported() {
    for using in [
        "team = ANY (ARRAY(SELECT authz.everyone()))",
        "team = ANY (ARRAY(SELECT authz.half()))",
        "team = ANY (ARRAY(SELECT authz.tally()))",
        "team IN (SELECT authz.constant())",
        "team IN (SELECT authz.last())",
        "team = ANY (ARRAY[1, 2])",
    ] {
        assert_eq!(
            delete_policy_after(HELPERS, using),
            [finding("items.d")],
            "{using}"
        );
    }
}

/// PostgreSQL deletes nothing through these, but the rule reads only
/// `LANGUAGE sql` bodies and reads each helper once per path.
#[test]
fn plpgsql_and_recursive_helpers_are_not_read() {
    for using in [
        "team IN (SELECT authz.procedural())",
        "team IN (SELECT authz.looping())",
    ] {
        assert_eq!(
            delete_policy_after(HELPERS, using),
            [finding("items.d")],
            "{using}"
        );
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
        "credential_free_write",
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

/// Findings for `policies` on `notes` with `anon` and `guest` both declared
/// anonymous.
fn notes_with_two_anonymous_roles(policies: &str) -> Vec<(String, Level, String)> {
    findings(
        supabase().with_anonymous_role("guest"),
        &format!(
            "{SUPABASE}
             CREATE ROLE guest;
             CREATE TABLE notes (id INT, owner uuid, is_public BOOL);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             {policies}"
        ),
    )
}

#[test]
fn a_guard_for_one_anonymous_role_does_not_cover_another() {
    assert_eq!(
        notes_with_two_anonymous_roles(
            "CREATE POLICY open_delete ON notes FOR DELETE TO guest USING (is_public);
             CREATE POLICY must_login ON notes AS RESTRICTIVE FOR DELETE TO anon USING (auth.uid() IS NOT NULL);"
        ),
        [finding("notes.open_delete")]
    );
    assert_eq!(
        notes_with_two_anonymous_roles(
            "CREATE POLICY open_delete ON notes FOR DELETE TO anon, guest USING (is_public);
             CREATE POLICY must_login ON notes AS RESTRICTIVE FOR DELETE TO anon, guest USING (auth.uid() IS NOT NULL);"
        ),
        []
    );
}

#[test]
fn a_guard_for_a_named_role_does_not_cover_public() {
    assert_eq!(
        notes_with_two_anonymous_roles(
            "CREATE POLICY open_delete ON notes FOR DELETE USING (is_public);
             CREATE POLICY must_login ON notes AS RESTRICTIVE FOR DELETE TO anon, guest USING (auth.uid() IS NOT NULL);"
        ),
        [finding("notes.open_delete")]
    );
}
