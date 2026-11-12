//! Writes to authority tables that let the writer choose the scope policies
//! grant on, observed through the public constrainer API. Every flagged and
//! passing shape below was measured on PostgreSQL 17.11 and 18.6.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const CREDENTIAL: &str = "current_setting('app.user_id', true)";

const SCHEMA: &str = "
    CREATE TABLE teams (id INT PRIMARY KEY, owner TEXT);
    CREATE TABLE members (team_id INT REFERENCES teams (id), member TEXT, role TEXT,
      parent INT, PRIMARY KEY (team_id, member));
    CREATE TABLE invitations (team_id INT, invitee TEXT);
    CREATE TABLE docs (id INT, team_id INT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE members ENABLE ROW LEVEL SECURITY;
    ALTER TABLE teams ENABLE ROW LEVEL SECURITY;";

/// Level and object of every finding of the rule.
fn findings<C: Constrainer<Database = ParserDB>>(constrainer: &C, sql: &str) -> Vec<String> {
    let sql = format!("{SCHEMA}{sql}").replace("CRED", CREDENTIAL);
    let database = ParserDB::parse::<PostgreSqlDialect>(&sql).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == "self_granting_write" => {
                Some(format!("{:?} {}", violation.level(), violation.object()))
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn deployment() -> Deployment {
    Deployment::default()
        .with_credential(CREDENTIAL)
        .expect("credential parses")
}

fn reported(sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = SelfGrantingWrite::default().into();
    constrainer.set_deployment(deployment());
    findings(&constrainer, sql)
}

/// Docs readable through a membership in their team.
const READ_BY_SUBLINK: &str = "CREATE POLICY docs_read ON docs FOR SELECT USING (
    team_id IN (SELECT team_id FROM members WHERE member = CRED));";

#[test]
fn a_write_choosing_a_scope_freely_is_reported() {
    for write in [
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);",
        "CREATE POLICY w ON members FOR UPDATE USING (member = CRED);",
        "CREATE POLICY w ON members FOR ALL USING (member = CRED);",
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (
           member = CRED OR team_id IN (SELECT team_id FROM invitations WHERE invitee = CRED));",
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (
           team_id IN (SELECT team_id FROM invitations));",
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (
           parent IN (SELECT team_id FROM invitations WHERE invitee = CRED));",
    ] {
        assert_eq!(
            reported(&format!("{READ_BY_SUBLINK} {write}")),
            ["Warn members.w"],
            "{write}"
        );
    }
}

#[test]
fn a_scope_constrained_by_a_credential_passes() {
    for write in [
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (
           member = CRED AND team_id IN (SELECT team_id FROM invitations WHERE invitee = CRED));",
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (
           EXISTS (SELECT 1 FROM invitations i WHERE i.team_id = members.team_id AND i.invitee = CRED));",
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (
           (team_id IN (SELECT team_id FROM invitations WHERE invitee = CRED))
           OR team_id IN (SELECT id FROM teams WHERE owner = CRED));",
        "CREATE POLICY w ON members FOR UPDATE USING (member = CRED)
           WITH CHECK (team_id IN (SELECT id FROM teams WHERE owner = CRED));",
        "CREATE POLICY w ON members FOR DELETE USING (member = CRED);",
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);
         CREATE POLICY g ON members AS RESTRICTIVE FOR INSERT WITH CHECK (
           team_id IN (SELECT team_id FROM invitations WHERE invitee = CRED));",
        "CREATE POLICY t ON teams FOR INSERT WITH CHECK (owner = CRED);",
    ] {
        assert_eq!(
            reported(&format!("{READ_BY_SUBLINK} {write}")),
            Vec::<String>::new(),
            "{write}"
        );
    }
}

#[test]
fn a_restrictive_guard_for_other_roles_or_commands_does_not_close_the_gap() {
    for guard in [
        "CREATE POLICY g ON members AS RESTRICTIVE FOR INSERT TO reviewers WITH CHECK (
           team_id IN (SELECT team_id FROM invitations WHERE invitee = CRED));",
        "CREATE POLICY g ON members AS RESTRICTIVE FOR DELETE USING (
           team_id IN (SELECT team_id FROM invitations WHERE invitee = CRED));",
        "CREATE POLICY g ON members AS RESTRICTIVE FOR INSERT WITH CHECK (member = CRED);",
    ] {
        assert_eq!(
            reported(&format!(
                "CREATE ROLE reviewers; {READ_BY_SUBLINK}
                 CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED); {guard}"
            )),
            ["Warn members.w"],
            "{guard}"
        );
    }
}

#[test]
fn only_scope_columns_of_authority_tables_count() {
    for sql in [
        "CREATE POLICY docs_read ON docs FOR SELECT USING (
           team_id IN (SELECT team_id FROM members));
         CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);",
        "CREATE POLICY docs_read ON docs FOR SELECT USING (
           EXISTS (SELECT 1 FROM members m WHERE m.member = CRED AND m.role = 'admin'));
         CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);",
        "CREATE POLICY docs_read ON docs FOR SELECT USING (
           id IN (SELECT team_id FROM teams JOIN members ON members.team_id = teams.id
                  WHERE teams.owner = CRED));
         CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);",
        "CREATE POLICY docs_read ON docs FOR SELECT USING (
           EXISTS (SELECT 1 FROM members m WHERE m.member = CRED AND m.team_id = m.parent));
         CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);",
        "CREATE POLICY docs_read ON docs FOR SELECT USING (EXISTS (
           SELECT 1 FROM teams t LEFT JOIN members m ON m.member = CRED
           WHERE m.team_id = docs.team_id));
         CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);",
        "CREATE POLICY docs_read ON docs FOR SELECT USING (
           team_id IN (VALUES (1)) OR team_id = ANY (ARRAY[1, 2]) OR CRED = current_user);
         CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn scopes_found_through_correlation_joins_and_helpers_are_reported() {
    for read in [
        "CREATE POLICY docs_read ON docs FOR SELECT USING (EXISTS (
           SELECT 1 FROM members m WHERE m.team_id = docs.team_id AND m.member = CRED));",
        "CREATE POLICY docs_read ON docs FOR SELECT USING (EXISTS (
           SELECT 1 FROM teams t JOIN members m ON m.member = (SELECT CRED)
           WHERE m.team_id = docs.team_id));",
        "CREATE POLICY docs_read ON docs FOR SELECT USING (team_id IN (
           SELECT t.id FROM teams t WHERE t.id IN (
             SELECT team_id FROM members WHERE (member = CRED))));",
        "CREATE FUNCTION my_teams() RETURNS SETOF INT LANGUAGE sql STABLE
           AS $$ (SELECT team_id FROM public.members WHERE member = (current_setting('app.user_id', true)))
                 UNION (SELECT id FROM public.teams WHERE owner = current_setting('app.user_id', true)) $$;
         CREATE FUNCTION via() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT my_teams() $$;
         CREATE POLICY docs_read ON docs FOR SELECT USING (team_id = ANY (ARRAY(SELECT via())));
         CREATE POLICY docs_other ON docs FOR SELECT USING (team_id IN (SELECT my_teams()));",
    ] {
        assert_eq!(
            reported(&format!(
                "{read} CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);"
            )),
            ["Warn members.w"],
            "{read}"
        );
    }
}

#[test]
fn a_whole_primary_key_or_a_self_reference_names_no_other_scope() {
    assert_eq!(
        reported(
            "CREATE TABLE nodes (id INT PRIMARY KEY, parent INT REFERENCES nodes (id), owner TEXT);
             ALTER TABLE nodes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_read ON docs FOR SELECT USING (
               team_id IN (SELECT id FROM nodes WHERE owner = CRED)
               OR id IN (SELECT parent FROM nodes WHERE owner = CRED));
             CREATE POLICY w ON nodes FOR INSERT WITH CHECK (owner = CRED);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn the_rule_waits_for_a_credential_and_warns_by_default() {
    let sql = format!(
        "{READ_BY_SUBLINK} CREATE POLICY w ON members FOR INSERT WITH CHECK (member = CRED);"
    );
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    assert!(
        constrainer
            .inactive_rules()
            .iter()
            .any(|inactive| inactive.rule().name == "self_granting_write")
    );
    constrainer.set_deployment(deployment());
    assert_eq!(findings(&constrainer, &sql), ["Warn members.w"]);
}
