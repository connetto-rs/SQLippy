//! Policies deciding on tables that the roles they restrict may rewrite.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
    CREATE ROLE app;
    CREATE ROLE admin BYPASSRLS;
    CREATE TABLE docs (id INT, team INT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    CREATE TABLE members (uid TEXT, team INT);
    CREATE TABLE blocked (uid TEXT);";

/// Object and message of every finding on `sql` appended to the schema.
fn reported(sql: &str) -> Vec<(String, String)> {
    let constrainer: GenericConstrainer<ParserDB> = PolicyReadsUnprotectedTable::default().into();
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA}{sql}")).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.object().to_owned(),
                violation.message().to_owned(),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

/// Objects of every finding on `sql`.
fn objects(sql: &str) -> Vec<String> {
    reported(sql)
        .into_iter()
        .map(|(object, _)| object)
        .collect()
}

const MEMBERSHIP: &str = "CREATE POLICY p ON docs TO app USING (team IN (SELECT team FROM members WHERE uid = current_user));";

const DENY_LIST: &str = "CREATE POLICY open ON docs TO app USING (true);
    CREATE POLICY not_blocked ON docs AS RESTRICTIVE TO app
      USING (NOT EXISTS (SELECT 1 FROM blocked WHERE uid = current_user));";

#[test]
fn a_membership_table_its_roles_may_insert_into_is_reported() {
    let found = reported(MEMBERSHIP);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "docs.p");
    assert!(found[0].1.contains("'members'"), "{}", found[0].1);
    assert!(found[0].1.contains("'app'"), "{}", found[0].1);
}

#[test]
fn a_positive_read_needs_a_way_to_add_rows() {
    for silenced in [
        "REVOKE INSERT, UPDATE ON members FROM app;",
        "ALTER TABLE members ENABLE ROW LEVEL SECURITY;",
    ] {
        assert_eq!(
            objects(&format!("{MEMBERSHIP}{silenced}")),
            Vec::<String>::new(),
            "{silenced}"
        );
    }
    assert_eq!(
        objects(&format!("{MEMBERSHIP} REVOKE INSERT ON members FROM app;")),
        ["docs.p"],
        "a column UPDATE still rewrites a member to the caller"
    );
}

#[test]
fn a_negated_read_needs_a_way_to_remove_rows() {
    assert_eq!(objects(DENY_LIST), ["docs.not_blocked"]);
    assert_eq!(
        objects(&format!(
            "{DENY_LIST} REVOKE DELETE, UPDATE, TRUNCATE ON blocked FROM app;"
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        objects(&format!(
            "{DENY_LIST} REVOKE DELETE, UPDATE ON blocked FROM app;"
        )),
        ["docs.not_blocked"],
        "TRUNCATE empties the table"
    );
}

#[test]
fn truncate_reaches_past_the_read_tables_own_row_security() {
    let protected = format!("{DENY_LIST} ALTER TABLE blocked ENABLE ROW LEVEL SECURITY;");
    assert_eq!(objects(&protected), ["docs.not_blocked"]);
    assert_eq!(
        objects(&format!("{protected} REVOKE TRUNCATE ON blocked FROM app;")),
        Vec::<String>::new()
    );
    assert_eq!(
        objects(&format!(
            "{MEMBERSHIP} ALTER TABLE members ENABLE ROW LEVEL SECURITY; REVOKE INSERT, UPDATE ON members FROM app;"
        )),
        Vec::<String>::new(),
        "emptying a membership table only takes rows away"
    );
}

#[test]
fn reads_whose_outcome_rows_can_move_either_way_need_any_write() {
    let revoked = "REVOKE INSERT, UPDATE ON members, blocked FROM app;";
    for policy in [
        "CREATE POLICY p ON docs TO app USING ((SELECT count(*) FROM members WHERE uid = current_user) < 3);",
        "CREATE POLICY p ON docs TO app USING (EXISTS (
           SELECT 1 FROM members m LEFT JOIN blocked b ON b.uid = m.uid WHERE b.uid IS NULL));
         REVOKE DELETE, TRUNCATE ON members FROM app;",
        "CREATE POLICY p ON docs TO app USING (EXISTS (
           SELECT 1 FROM members GROUP BY team HAVING count(*) > 1));",
        "CREATE VIEW busy AS SELECT team FROM members GROUP BY team HAVING count(*) > 1;
         CREATE POLICY p ON docs TO app USING (team IN (SELECT team FROM busy));",
        "CREATE POLICY p ON docs TO app USING (team IN (SELECT 0 EXCEPT SELECT team FROM members));",
        "CREATE POLICY p ON docs TO app USING (EXISTS (
           SELECT 1 FROM members WHERE team IN (SELECT team FROM members WHERE uid = current_user)));",
        "CREATE POLICY p ON docs TO app USING (team IN (SELECT row_number() OVER () FROM members));",
        "CREATE POLICY p ON docs TO app USING (team IN (SELECT max(team) FROM members));",
    ] {
        assert_eq!(
            objects(&format!("{policy}{revoked}")),
            ["docs.p"],
            "{policy}"
        );
    }
}

#[test]
fn reads_in_both_clauses_are_one_finding_with_their_combined_needs() {
    let policy = "CREATE POLICY p ON docs TO app
        USING ((team IN (SELECT team FROM members WHERE uid = current_user)))
        WITH CHECK (team IN (SELECT team FROM members WHERE uid = current_user)
                    OR team IN (SELECT team FROM members WHERE uid = current_user));";
    assert_eq!(objects(policy), ["docs.p"]);
    assert_eq!(
        objects(&format!(
            "{policy} REVOKE INSERT, UPDATE ON members FROM app;"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn a_check_clause_view_or_called_function_reading_the_table_is_reported() {
    for policy in [
        "CREATE POLICY p ON docs TO app WITH CHECK (team IN (SELECT team FROM members WHERE uid = current_user));",
        "CREATE VIEW teams AS SELECT uid, team FROM members;
         CREATE POLICY p ON docs TO app USING (team IN (SELECT team FROM teams WHERE uid = current_user));",
        "CREATE FUNCTION my_teams() RETURNS SETOF INT LANGUAGE sql STABLE
           AS 'SELECT team FROM public.members WHERE uid = current_user';
         CREATE POLICY p ON docs TO app USING (team IN (SELECT my_teams()));",
        "CREATE FUNCTION in_team(t INT) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
           AS 'SELECT EXISTS (SELECT 1 FROM public.members WHERE team = t AND uid = current_user)';
         ALTER FUNCTION in_team(INT) OWNER TO admin;
         CREATE POLICY p ON docs TO app USING (in_team(team));",
    ] {
        assert_eq!(objects(policy), ["docs.p"], "{policy}");
    }
}

#[test]
fn roles_the_policy_does_not_restrict_are_no_writers() {
    for policy in [
        "CREATE POLICY p ON docs TO admin USING (team IN (SELECT team FROM members WHERE uid = current_user));",
        "ALTER TABLE docs OWNER TO app;
         CREATE POLICY p ON docs TO app USING (team IN (SELECT team FROM members WHERE uid = current_user));",
        "CREATE POLICY p ON docs USING (team IN (SELECT team FROM docs));",
        "ALTER TABLE docs DISABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON docs TO app USING (team IN (SELECT team FROM members WHERE uid = current_user));",
    ] {
        assert_eq!(objects(policy), Vec::<String>::new(), "{policy}");
    }
    let public = reported(
        "CREATE POLICY p ON docs USING (team IN (SELECT team FROM members WHERE uid = current_user));",
    );
    assert_eq!(public.len(), 1, "{public:?}");
    assert!(public[0].1.contains("PUBLIC"), "{}", public[0].1);
    assert!(!public[0].1.contains("'admin'"), "{}", public[0].1);
}

#[test]
fn an_owner_writes_its_own_table_past_its_row_security() {
    assert_eq!(
        objects(&format!(
            "{MEMBERSHIP} ALTER TABLE members ENABLE ROW LEVEL SECURITY; ALTER TABLE members OWNER TO app;"
        )),
        ["docs.p"]
    );
    assert_eq!(
        objects(&format!(
            "{MEMBERSHIP} ALTER TABLE members ENABLE ROW LEVEL SECURITY;
             ALTER TABLE members FORCE ROW LEVEL SECURITY; ALTER TABLE members OWNER TO app;"
        )),
        Vec::<String>::new()
    );
}
