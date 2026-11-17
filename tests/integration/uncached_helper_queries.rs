//! Policy helpers that recompute work independent of their arguments for
//! every row, observed through the public constrainer API. On PostgreSQL 18.6
//! with 200 teams, 20 of them the caller's, and 20,000 docs, a `SECURITY
//! DEFINER` helper testing `doc_team IN (SELECT authz.member_teams())` plans
//! as `Filter: authz.can_read(team_id)` and takes 988 ms, its invoker
//! `LANGUAGE sql STABLE` twin 368 ms, and `team_id IN (SELECT
//! authz.member_teams())` written in the policy 1.5 ms.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
    CREATE SCHEMA authz;
    CREATE TABLE teams (id UUID PRIMARY KEY);
    CREATE TABLE team_members (team_id UUID NOT NULL REFERENCES teams (id), user_id UUID NOT NULL, PRIMARY KEY (team_id, user_id));
    CREATE TABLE docs (id UUID PRIMARY KEY, team_id UUID NOT NULL REFERENCES teams (id), archived BOOLEAN NOT NULL DEFAULT FALSE);
    CREATE FUNCTION authz.caller_id() RETURNS UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
      AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;
    CREATE FUNCTION authz.member_teams() RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
      SELECT member.team_id FROM public.team_members member WHERE member.user_id = authz.caller_id()
    $$;
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

/// The messages of the rule on the schema followed by `helpers`.
fn messages(helpers: &str) -> Vec<String> {
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA}{helpers}")).expect("schema parses");
    let mut messages: Vec<String> = GenericConstrainer::from(UncachedHelperQuery::default())
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    messages.sort();
    messages
}

/// The message reporting `call` in the `USING` clause of `policy`, which
/// runs `function` and recomputes `part`.
fn reported(policy: &str, call: &str, function: &str, part: &str) -> String {
    format!(
        "Policy '{policy}' on 'docs' calls `{call}` in its USING clause, and PostgreSQL runs '{function}' for each row it checks, recomputing `{part}` although it does not depend on the arguments."
    )
}

#[test]
fn helpers_recomputing_a_set_per_row_are_reported_and_argument_filtered_ones_are_not() {
    assert_eq!(
        messages(
            "CREATE FUNCTION authz.can_read(doc_team UUID) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT doc_team IN (SELECT authz.member_teams())
             $$;
             CREATE FUNCTION authz.can_edit(doc_team UUID) RETURNS BOOLEAN LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = '' AS $$
             BEGIN
               RETURN doc_team = ANY (ARRAY(SELECT authz.member_teams()));
             END
             $$;
             CREATE FUNCTION authz.is_archived(doc UUID) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT EXISTS (SELECT 1 FROM public.docs archived WHERE archived.id = doc AND archived.archived)
             $$;
             CREATE POLICY docs_select ON docs FOR SELECT USING (authz.can_read(team_id));
             CREATE POLICY docs_update ON docs FOR UPDATE USING (authz.can_edit(team_id))
               WITH CHECK (team_id = ANY (ARRAY(SELECT authz.member_teams())));
             CREATE POLICY docs_delete ON docs FOR DELETE
               USING (team_id = ANY (ARRAY(SELECT authz.member_teams())) AND NOT authz.is_archived(id));"
        ),
        [
            reported(
                "docs_select",
                "authz.can_read(team_id)",
                "can_read(UUID)",
                "SELECT authz.member_teams()"
            ),
            reported(
                "docs_update",
                "authz.can_edit(team_id)",
                "can_edit(UUID)",
                "SELECT authz.member_teams()"
            ),
        ]
    );
}

#[test]
fn invoker_helpers_with_a_sublink_are_not_inlined_and_are_reported() {
    assert_eq!(
        messages(
            "CREATE FUNCTION authz.can_read(doc_team UUID) RETURNS BOOLEAN LANGUAGE sql STABLE
               AS $$ SELECT doc_team IN (SELECT authz.member_teams()) $$;
             CREATE FUNCTION authz.can_list(doc_team UUID) RETURNS BOOLEAN LANGUAGE sql STABLE
               RETURN doc_team IN (SELECT authz.member_teams());
             CREATE POLICY reading ON docs USING (authz.can_read(team_id));
             CREATE POLICY listing ON docs USING (authz.can_list(team_id));"
        ),
        [
            reported(
                "listing",
                "authz.can_list(team_id)",
                "can_list(UUID)",
                "SELECT authz.member_teams()"
            ),
            reported(
                "reading",
                "authz.can_read(team_id)",
                "can_read(UUID)",
                "SELECT authz.member_teams()"
            ),
        ]
    );
}

#[test]
fn plpgsql_variables_carry_dependence_on_the_arguments() {
    assert_eq!(
        messages(
            "CREATE FUNCTION authz.by_setting(doc_team UUID) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$
             DECLARE me UUID := current_setting('app.user_id')::uuid;
             BEGIN
               RETURN doc_team IN (SELECT team_id FROM team_members WHERE user_id = me);
             END $$;
             CREATE FUNCTION authz.by_argument(doc_team UUID) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$
             DECLARE wanted UUID := doc_team;
             BEGIN
               RETURN EXISTS (SELECT 1 FROM team_members m WHERE m.team_id = wanted);
             END $$;
             CREATE POLICY by_setting ON docs USING (authz.by_setting(team_id));
             CREATE POLICY by_argument ON docs USING (authz.by_argument(team_id));"
        ),
        [reported(
            "by_setting",
            "authz.by_setting(team_id)",
            "by_setting(UUID)",
            "SELECT team_id FROM team_members WHERE user_id = me"
        )]
    );
}

#[test]
fn parts_reading_no_relation_are_not_reported() {
    assert_eq!(
        messages(
            "CREATE FUNCTION authz.in_setting(doc_team UUID) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
               AS $$ SELECT doc_team = (SELECT authz.caller_id()) $$;
             CREATE POLICY p ON docs USING (authz.in_setting(team_id));"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn inlined_helpers_and_calls_reading_nothing_from_the_row_are_not_reported() {
    assert_eq!(
        messages(
            "CREATE FUNCTION authz.team_array() RETURNS UUID[] LANGUAGE sql STABLE SECURITY DEFINER
               AS $$ SELECT ARRAY(SELECT authz.member_teams()) $$;
             CREATE FUNCTION authz.teams_of(doc_team UUID) RETURNS UUID[] LANGUAGE sql STABLE
               AS $$ SELECT authz.team_array() $$;
             CREATE FUNCTION authz.strict_teams_of(doc_team UUID) RETURNS UUID[] LANGUAGE sql STABLE STRICT
               AS $$ SELECT authz.team_array() $$;
             CREATE FUNCTION authz.can_read(doc_team UUID) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
               AS $$ SELECT doc_team IN (SELECT authz.member_teams()) $$;
             CREATE POLICY inlined ON docs USING (team_id = ANY (authz.teams_of(team_id)));
             CREATE POLICY strict ON docs USING (team_id = ANY (authz.strict_teams_of(team_id)));
             CREATE POLICY constant ON docs USING (authz.can_read('00000000-0000-0000-0000-000000000001'::uuid));
             CREATE POLICY nested ON docs USING (EXISTS (SELECT 1 FROM teams t WHERE t.id = team_id AND authz.can_read(t.id)));"
        ),
        [reported(
            "strict",
            "authz.strict_teams_of(team_id)",
            "strict_teams_of(UUID)",
            "SELECT authz.team_array()"
        )]
    );
}

#[test]
fn set_returning_calls_in_from_are_reported_unless_postgresql_inlines_them() {
    assert_eq!(
        messages(
            "CREATE FUNCTION authz.member_teams_inlined() RETURNS SETOF UUID LANGUAGE sql STABLE AS $$
               SELECT member.team_id FROM public.team_members member WHERE member.user_id = authz.caller_id()
             $$;
             CREATE FUNCTION authz.can_read(doc_team UUID) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
               AS $$ SELECT EXISTS (SELECT 1 FROM authz.member_teams() m WHERE m = doc_team) $$;
             CREATE FUNCTION authz.can_list(doc_team UUID) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
               AS $$ SELECT EXISTS (SELECT 1 FROM authz.member_teams_inlined() m WHERE m = doc_team) $$;
             CREATE POLICY reading ON docs USING (authz.can_read(team_id));
             CREATE POLICY listing ON docs USING (authz.can_list(team_id));"
        ),
        [reported(
            "reading",
            "authz.can_read(team_id)",
            "can_read(UUID)",
            "authz.member_teams()"
        )]
    );
}
