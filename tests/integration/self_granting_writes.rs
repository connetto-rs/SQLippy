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
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (
           NOT (team_id = ANY (SELECT team_id FROM invitations WHERE invitee = CRED)));",
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
        "CREATE TABLE people (id TEXT PRIMARY KEY, active BOOL);
         CREATE FUNCTION in_team(t INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
           SELECT EXISTS (SELECT 1 FROM members m JOIN people p ON p.id = m.member
             WHERE m.team_id = t AND m.member = current_setting('app.user_id', true) AND p.active) $$;
         CREATE POLICY docs_read ON docs FOR SELECT USING (in_team(team_id));",
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
fn a_join_partner_inside_the_read_is_not_the_outer_row() {
    for read in [
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (team_id IN (
           SELECT m.team_id FROM members m JOIN people p ON p.id = m.member
           WHERE m.member = CRED AND m.role = 'admin' AND p.active));",
        "CREATE POLICY w ON members FOR INSERT WITH CHECK (team_id IN (
           SELECT m.team_id FROM (members m CROSS JOIN people p)
           WHERE p.id = m.member AND m.member = CRED AND m.role = 'admin' AND p.active));",
        "CREATE FUNCTION administered() RETURNS SETOF INT LANGUAGE sql STABLE AS $$
           SELECT m.team_id FROM members m JOIN people p ON p.id = m.member
           WHERE m.member = current_setting('app.user_id', true) AND m.role = 'admin' AND p.active $$;
         CREATE POLICY w ON members FOR INSERT WITH CHECK (team_id IN (SELECT administered()));",
    ] {
        assert_eq!(
            reported(&format!(
                "CREATE TABLE people (id TEXT PRIMARY KEY, active BOOL);
                 ALTER TABLE members ADD FOREIGN KEY (member) REFERENCES people (id);
                 {READ_BY_SUBLINK} {read}"
            )),
            Vec::<String>::new(),
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

/// A write scoped by a helper whose body reads `WITH` items.
fn scoped_by_helper(body: &str) -> String {
    format!(
        "{READ_BY_SUBLINK}
         CREATE FUNCTION administered() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ {body} $$;
         CREATE POLICY w ON members FOR INSERT WITH CHECK (team_id IN (SELECT administered()));"
    )
}

#[test]
fn a_helper_reading_with_items_that_require_a_credential_passes() {
    for body in [
        "WITH mine AS (SELECT m.team_id FROM members m WHERE m.member = CRED AND m.role = 'admin')
         SELECT team_id FROM mine",
        "WITH mine AS (SELECT team_id FROM members WHERE member = CRED),
              chosen AS (SELECT team_id FROM mine)
         SELECT t.id FROM teams t JOIN chosen c ON c.team_id = t.id",
        "WITH mine AS (SELECT team_id FROM members WHERE member = CRED)
         SELECT t.id FROM teams t, mine WHERE mine.team_id = t.id",
        "WITH mine AS (SELECT team_id FROM members WHERE member = CRED)
         SELECT id FROM teams WHERE id IN (SELECT team_id FROM mine)",
        "WITH mine AS (SELECT team_id FROM members WHERE member = CRED)
         SELECT id FROM teams WHERE id = (SELECT team_id FROM mine LIMIT 1)",
        "WITH mine AS (SELECT team_id FROM members WHERE member = CRED)
         SELECT t.id FROM teams t RIGHT JOIN mine ON mine.team_id = t.id",
        "WITH mine AS (SELECT team_id FROM members WHERE member = CRED)
         SELECT d.id FROM (SELECT id FROM teams) d JOIN mine ON mine.team_id = d.id",
        "WITH RECURSIVE tree (id) AS (
           SELECT team_id FROM members WHERE member = CRED
           UNION SELECT m.parent FROM members m JOIN tree ON m.team_id = tree.id)
         SELECT id FROM tree",
    ] {
        assert_eq!(
            reported(&scoped_by_helper(body)),
            Vec::<String>::new(),
            "{body}"
        );
    }
}

#[test]
fn a_helper_reading_with_items_that_return_rows_without_a_credential_is_reported() {
    for body in [
        "WITH everyone AS (SELECT team_id FROM members) SELECT team_id FROM everyone",
        "WITH mine AS (SELECT team_id FROM members WHERE member = CRED)
         SELECT t.id FROM teams t LEFT JOIN mine ON mine.team_id = t.id",
        "WITH mine AS (SELECT team_id FROM members WHERE member = CRED)
         SELECT i.team_id FROM mine JOIN teams t ON mine.team_id = t.id FULL JOIN invitations i ON true",
        "WITH chosen AS (SELECT team_id FROM invitations),
              invitations AS (SELECT team_id FROM members WHERE member = CRED)
         SELECT team_id FROM chosen",
        "WITH members AS (SELECT team_id FROM public.members WHERE member = CRED)
         SELECT team_id FROM public.members",
        "WITH RECURSIVE tree (id) AS (
           SELECT team_id FROM members
           UNION SELECT m.parent FROM members m JOIN tree ON m.team_id = tree.id WHERE m.member = CRED)
         SELECT id FROM tree",
    ] {
        assert_eq!(
            reported(&scoped_by_helper(body)),
            ["Warn members.w"],
            "{body}"
        );
    }
}

/// Helpers and views returning the caller's teams, and every team.
const RELATIONS: &str = "
    CREATE FUNCTION my_teams() RETURNS SETOF INT LANGUAGE sql STABLE
      AS $$ SELECT team_id FROM members WHERE member = current_setting('app.user_id', true) $$;
    CREATE FUNCTION my_teams_again() RETURNS SETOF INT LANGUAGE sql STABLE
      AS $$ SELECT t FROM my_teams() t $$;
    CREATE FUNCTION all_teams() RETURNS SETOF INT LANGUAGE sql STABLE
      AS $$ SELECT team_id FROM members $$;
    CREATE VIEW my_memberships AS SELECT team_id FROM members WHERE member = CRED;
    CREATE VIEW my_team_ids AS SELECT my_teams() AS team_id;
    CREATE VIEW from_my_teams AS SELECT t AS team_id FROM my_teams() t;
    CREATE VIEW all_memberships AS SELECT team_id FROM members;";

/// A write scoped by the set `scope` returns.
fn scoped_by(scope: &str) -> String {
    format!(
        "{READ_BY_SUBLINK} {RELATIONS}
         CREATE POLICY w ON members FOR INSERT WITH CHECK (team_id IN ({scope}));"
    )
}

#[test]
fn a_set_reading_a_relation_that_requires_a_credential_passes() {
    for scope in [
        "SELECT d.team_id FROM (SELECT team_id FROM members WHERE member = CRED) d",
        "SELECT t.id FROM teams t JOIN (SELECT team_id FROM members WHERE member = CRED) d
           ON d.team_id = t.id",
        "SELECT team_id FROM my_memberships",
        "SELECT team_id FROM my_team_ids",
        "SELECT t FROM my_teams() t",
        "SELECT t.id FROM teams t, LATERAL my_teams() m WHERE m = t.id",
        "SELECT team_id FROM from_my_teams",
        "SELECT my_teams_again()",
        "SELECT t.id FROM (teams t JOIN my_memberships m ON m.team_id = t.id)",
        "SELECT team_id FROM members WHERE member = CRED
         INTERSECT SELECT team_id FROM invitations",
        "SELECT team_id FROM invitations
         INTERSECT SELECT team_id FROM members WHERE member = CRED",
        "SELECT team_id FROM members WHERE member = CRED
         EXCEPT SELECT team_id FROM invitations",
    ] {
        assert_eq!(reported(&scoped_by(scope)), Vec::<String>::new(), "{scope}");
    }
}

#[test]
fn a_set_compared_with_any_that_requires_a_credential_passes() {
    for scope in [
        "SELECT team_id FROM members WHERE member = CRED
         UNION SELECT id FROM teams WHERE owner = CRED",
        "SELECT my_teams()",
    ] {
        assert_eq!(
            reported(&format!(
                "{READ_BY_SUBLINK} {RELATIONS}
                 CREATE POLICY w ON members FOR INSERT WITH CHECK (team_id = ANY ({scope}));"
            )),
            Vec::<String>::new(),
            "{scope}"
        );
    }
}

#[test]
fn a_set_reading_a_relation_that_returns_rows_without_a_credential_is_reported() {
    for scope in [
        "SELECT d.team_id FROM (SELECT team_id FROM members) d",
        "SELECT t.id FROM teams t LEFT JOIN (SELECT team_id FROM members WHERE member = CRED) d
           ON d.team_id = t.id",
        "SELECT t FROM all_teams() t",
        "SELECT u FROM unnest(ARRAY[1, 2]) u",
        "SELECT t.id FROM teams t LEFT JOIN LATERAL my_teams() m ON m = t.id",
        "SELECT team_id FROM all_memberships",
        "SELECT team_id FROM invitations
         EXCEPT SELECT team_id FROM members WHERE member = CRED",
    ] {
        assert_eq!(reported(&scoped_by(scope)), ["Warn members.w"], "{scope}");
    }
}

/// Seats scoped by squad and organization, each bound through a composite
/// key to a pass or a squad, under the given `MATCH` of the pass key.
fn keyed(pass_match: &str) -> String {
    format!(
        "CREATE TABLE orgs (id INT PRIMARY KEY);
         CREATE TABLE admins (org_id INT NOT NULL REFERENCES orgs (id), person TEXT NOT NULL,
           PRIMARY KEY (org_id, person));
         CREATE TABLE squads (id INT PRIMARY KEY, org_id INT NOT NULL REFERENCES orgs (id),
           UNIQUE (org_id, id));
         CREATE TABLE passes (id INT PRIMARY KEY, squad_id INT NOT NULL REFERENCES squads (id),
           invitee TEXT NOT NULL, UNIQUE (squad_id, id));
         CREATE TABLE seats (org_id INT NOT NULL, squad_id INT NOT NULL, person TEXT NOT NULL,
           pass_id INT, PRIMARY KEY (squad_id, person),
           FOREIGN KEY (org_id, squad_id) REFERENCES squads (org_id, id),
           FOREIGN KEY (squad_id, pass_id) REFERENCES passes (squad_id, id) {pass_match});
         ALTER TABLE seats ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_squad ON docs FOR SELECT USING (
           team_id IN (SELECT squad_id FROM seats WHERE person = CRED));
         CREATE POLICY docs_org ON docs FOR SELECT USING (
           id IN (SELECT org_id FROM seats WHERE person = CRED));"
    )
}

/// Seats a caller may take with a pass addressed to them.
const BY_PASS: &str = "pass_id IN (SELECT id FROM passes WHERE invitee = CRED)";

/// Seats an organization admin may hand out.
const BY_ADMIN: &str = "org_id IN (SELECT org_id FROM admins WHERE person = CRED)";

/// Seats on a squad the caller holds a pass for.
const BY_SQUAD_PASS: &str = "squad_id IN (SELECT squad_id FROM passes WHERE invitee = CRED)";

#[test]
fn a_composite_key_binds_its_columns_to_a_constrained_one() {
    for check in [
        format!("person = CRED AND {BY_PASS}"),
        BY_ADMIN.to_owned(),
        format!("({BY_ADMIN}) OR ({BY_SQUAD_PASS})"),
        format!("({BY_ADMIN} AND pass_id IS NULL) OR (person = CRED AND {BY_PASS})"),
        "person = CRED AND pass_id = ANY (ARRAY(SELECT id FROM passes WHERE invitee = CRED))"
            .to_owned(),
        "(squad_id, pass_id) IN (SELECT squad_id, id FROM passes WHERE invitee = CRED)".to_owned(),
    ] {
        let sql = format!(
            "{} CREATE POLICY w ON seats FOR INSERT WITH CHECK ({check});",
            keyed("")
        );
        assert_eq!(reported(&sql), Vec::<String>::new(), "{check}");
    }
    let guarded = format!(
        "{} CREATE POLICY w ON seats FOR INSERT WITH CHECK (person = CRED);
         CREATE POLICY g ON seats AS RESTRICTIVE FOR INSERT WITH CHECK ({BY_PASS});",
        keyed("")
    );
    assert_eq!(reported(&guarded), Vec::<String>::new());
}

#[test]
fn a_composite_key_binds_nothing_without_a_constrained_checked_column() {
    let nullable_pass =
        "person = CRED AND coalesce(pass_id, 0) IN (SELECT id FROM passes WHERE invitee = CRED)";
    for check in [
        "person = CRED".to_owned(),
        nullable_pass.to_owned(),
        format!("person = CRED OR {BY_PASS}"),
    ] {
        let sql = format!(
            "{} CREATE POLICY w ON seats FOR INSERT WITH CHECK ({check});",
            keyed("")
        );
        assert_eq!(reported(&sql), ["Warn seats.w"], "{check}");
    }
    let full = format!(
        "{} CREATE POLICY w ON seats FOR INSERT WITH CHECK ({nullable_pass});",
        keyed("MATCH FULL")
    );
    assert_eq!(reported(&full), Vec::<String>::new());
    let filtered = format!(
        "{} CREATE POLICY w ON seats FOR UPDATE USING (person = CRED) WITH CHECK (person = CRED);
         CREATE POLICY g ON seats AS RESTRICTIVE FOR UPDATE USING ({BY_PASS})
           WITH CHECK (person = CRED);",
        keyed("")
    );
    assert_eq!(reported(&filtered), ["Warn seats.w"]);
}

/// Takes every privilege on `members` from `app` and grants back reads and
/// writes of columns other than `team_id`.
const WITHHELD: &str = "CREATE ROLE app; REVOKE ALL ON members FROM app;
    GRANT SELECT, INSERT (member, role), UPDATE (role) ON members TO app;";

#[test]
fn a_scope_the_writers_cannot_write_is_not_reported() {
    for write in [
        "CREATE POLICY w ON members FOR INSERT TO app WITH CHECK (member = CRED);",
        "CREATE POLICY w ON members FOR UPDATE TO app USING (member = CRED)
           WITH CHECK (member = CRED);",
        "CREATE POLICY w ON members FOR ALL TO app USING (member = CRED);",
    ] {
        assert_eq!(
            reported(&format!("{READ_BY_SUBLINK} {WITHHELD} {write}")),
            Vec::<String>::new(),
            "{write}"
        );
    }
}

#[test]
fn a_scope_left_writable_by_a_writer_keeps_the_finding() {
    for (write, grants) in [
        (
            "CREATE POLICY w ON members FOR UPDATE TO app USING (member = CRED);",
            "GRANT UPDATE (team_id) ON members TO app;",
        ),
        (
            "CREATE POLICY w ON members FOR ALL TO app USING (member = CRED);",
            "GRANT INSERT ON members TO app;",
        ),
        (
            "CREATE POLICY w ON members FOR UPDATE TO app, other USING (member = CRED);",
            "CREATE ROLE other; GRANT SELECT, UPDATE ON members TO other;",
        ),
        (
            "CREATE POLICY w ON members FOR UPDATE USING (member = CRED);",
            "CREATE ROLE other; GRANT SELECT, UPDATE ON members TO other;",
        ),
    ] {
        assert_eq!(
            reported(&format!("{READ_BY_SUBLINK} {WITHHELD} {grants} {write}")),
            ["Warn members.w"],
            "{write} {grants}"
        );
    }
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
