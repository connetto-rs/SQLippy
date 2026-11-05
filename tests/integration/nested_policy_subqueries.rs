//! Policy subqueries reading tables whose own policies hold subqueries,
//! observed through the public constrainer API.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
    CREATE ROLE readers;
    CREATE ROLE admins_role;
    CREATE TABLE docs (team INT);
    CREATE TABLE members (team INT, member TEXT);
    CREATE TABLE admins (member TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    CREATE FUNCTION my_teams() RETURNS SETOF INT LANGUAGE sql STABLE
      AS 'SELECT team FROM public.members';
    CREATE VIEW member_teams AS SELECT team, member FROM members;";

const DOCS: &str = "CREATE POLICY docs_p ON docs TO readers USING (
    team IN (SELECT team FROM members WHERE member = current_user));";

/// Level and site of every finding of the rule.
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
            Error::Violation(violation) if violation.rule().name == "NestedPolicySubquery" => {
                Some((violation.level(), violation.object().to_owned()))
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn reported(sql: &str) -> Vec<String> {
    findings(
        &GenericConstrainer::from(NestedPolicySubquery::default()),
        sql,
    )
    .into_iter()
    .map(|(_, site)| site)
    .collect()
}

#[test]
fn a_subquery_reading_a_table_whose_select_policy_holds_a_subquery_is_reported() {
    for members in [
        "CREATE POLICY members_p ON members USING (member IN (SELECT member FROM admins));",
        "CREATE POLICY members_p ON members FOR SELECT TO readers
           USING (EXISTS (SELECT 1 FROM admins WHERE admins.member = members.member));",
    ] {
        assert_eq!(
            reported(&format!(
                "ALTER TABLE members ENABLE ROW LEVEL SECURITY; {members} {DOCS}"
            )),
            ["docs.docs_p"],
            "{members}"
        );
    }
    assert_eq!(
        reported(
            "ALTER TABLE members ENABLE ROW LEVEL SECURITY;
             CREATE POLICY members_p ON members USING (member IN (SELECT member FROM admins));
             CREATE POLICY docs_p ON docs USING (
               team IN (SELECT team FROM members WHERE member IN (SELECT member FROM admins)));"
        ),
        ["docs.docs_p"]
    );
}

#[test]
fn flat_policies_writes_other_roles_unprotected_tables_and_calls_pass() {
    let cases = [
        "ALTER TABLE members ENABLE ROW LEVEL SECURITY;
         CREATE POLICY members_p ON members USING (member = current_user);",
        "ALTER TABLE members ENABLE ROW LEVEL SECURITY;
         CREATE POLICY members_p ON members FOR INSERT WITH CHECK (member IN (SELECT member FROM admins));",
        "ALTER TABLE members ENABLE ROW LEVEL SECURITY;
         CREATE POLICY members_p ON members TO admins_role USING (member IN (SELECT member FROM admins));",
        "CREATE POLICY members_p ON members USING (member IN (SELECT member FROM admins));",
    ];
    for members in cases {
        assert_eq!(
            reported(&format!("{members} {DOCS}")),
            Vec::<String>::new(),
            "{members}"
        );
    }
    for docs in [
        "team IN (SELECT my_teams())",
        "team IN (SELECT team FROM member_teams)",
    ] {
        assert_eq!(
            reported(&format!(
                "ALTER TABLE members ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY members_p ON members USING (member IN (SELECT member FROM admins));
                 CREATE POLICY docs_p ON docs USING ({docs});"
            )),
            Vec::<String>::new(),
            "{docs}"
        );
    }
}

#[test]
fn the_default_constrainer_warns() {
    assert_eq!(
        findings(
            &DefaultConstrainer::<ParserDB>::default(),
            &format!(
                "ALTER TABLE members ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY members_p ON members USING (member IN (SELECT member FROM admins));
                 {DOCS}"
            ),
        ),
        [(Level::Warn, "docs.docs_p".to_owned())]
    );
}
