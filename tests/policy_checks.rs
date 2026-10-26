//! Dead permissive policies, tautological write checks and unforced row-level
//! security observed through the public constrainer API.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

fn parse(sql: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses")
}

/// Rule name, level and listed objects of every violation.
fn findings(constrainer: &GenericConstrainer<ParserDB>, sql: &str) -> Vec<(String, Level, String)> {
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

fn dead(sql: &str) -> Vec<(String, Level, String)> {
    findings(
        &DeadPermissivePolicy::default().into(),
        &format!("{DOCS}{sql}"),
    )
}

const DOCS: &str = "
    CREATE ROLE admin;
    CREATE ROLE staff;
    CREATE ROLE lead IN ROLE staff;
    CREATE TABLE docs (id INT, owner TEXT, team INT);
    CREATE TABLE members (team INT, member TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

#[test]
fn a_permissive_tautology_kills_a_narrower_policy_for_the_same_command_and_roles() {
    assert_eq!(
        dead(
            "CREATE POLICY everyone ON docs FOR SELECT USING (true);
             CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);"
        ),
        [(
            "DeadPermissivePolicy".to_owned(),
            Level::Deny,
            "docs.own -> docs.everyone".to_owned()
        )]
    );
}

#[test]
fn a_policy_still_deciding_other_commands_is_not_dead() {
    assert_eq!(
        dead(
            "CREATE POLICY everyone ON docs FOR SELECT USING (true);
             CREATE POLICY own ON docs FOR ALL USING (owner = current_user);"
        ),
        []
    );
}

#[test]
fn a_tautology_for_a_narrower_role_leaves_other_roles_decided() {
    assert_eq!(
        dead(
            "CREATE POLICY admins ON docs FOR SELECT TO admin USING (true);
             CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);"
        ),
        []
    );
}

#[test]
fn a_tautology_for_everyone_kills_a_role_specific_policy() {
    assert_eq!(
        dead(
            "CREATE POLICY everyone ON docs FOR SELECT USING (true);
         CREATE POLICY own ON docs FOR SELECT TO admin USING (owner = current_user);"
        )
        .len(),
        1
    );
}

#[test]
fn a_tautology_for_an_inherited_role_kills_the_inheriting_role_policy() {
    assert_eq!(
        dead(
            "CREATE POLICY staff_all ON docs FOR SELECT TO staff USING (true);
         CREATE POLICY lead_own ON docs FOR SELECT TO lead USING (owner = current_user);"
        )
        .len(),
        1
    );
}

#[test]
fn a_restrictive_tautology_kills_nothing() {
    assert_eq!(
        dead(
            "CREATE POLICY everyone ON docs AS RESTRICTIVE FOR SELECT USING (true);
             CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);"
        ),
        []
    );
}

#[test]
fn an_all_command_tautology_kills_an_all_command_policy() {
    assert_eq!(
        dead(
            "CREATE POLICY everyone ON docs FOR ALL USING (true);
         CREATE POLICY own ON docs FOR ALL USING (owner = current_user);"
        )
        .len(),
        1
    );
}

#[test]
fn a_restricted_write_check_keeps_an_insert_policy_alive() {
    assert_eq!(
        dead(
            "CREATE POLICY everyone ON docs FOR ALL USING (true) WITH CHECK (owner = current_user);
             CREATE POLICY own_insert ON docs FOR INSERT WITH CHECK (team = 1);"
        ),
        []
    );
}

#[test]
fn a_lone_tautology_is_not_dead() {
    assert_eq!(
        dead("CREATE POLICY everyone ON docs FOR SELECT USING (true);"),
        []
    );
}

fn write_checks(sql: &str) -> Vec<(String, Level, String)> {
    findings(
        &TautologicalWithCheck::default().into(),
        &format!("{DOCS}{sql}"),
    )
}

#[test]
fn a_true_write_check_beside_a_row_reading_filter_is_suspicious() {
    assert_eq!(
        write_checks(
            "CREATE POLICY own ON docs FOR UPDATE USING (owner = current_user) WITH CHECK (true);"
        ),
        [(
            "TautologicalWithCheck".to_owned(),
            Level::Warn,
            "docs.own".to_owned()
        )]
    );
}

#[test]
fn a_true_write_check_beside_a_correlated_membership_filter_is_suspicious() {
    assert_eq!(
        write_checks(
            "CREATE POLICY team_rows ON docs FOR ALL USING (
               EXISTS (SELECT 1 FROM members m WHERE m.team = docs.team AND m.member = current_user)
             ) WITH CHECK (true);"
        )
        .len(),
        1
    );
}

#[test]
fn a_true_write_check_beside_a_row_independent_filter_is_consistent() {
    for using in [
        "current_setting('app.role', true) = 'admin'",
        "EXISTS (SELECT 1 FROM members m WHERE m.member = current_user)",
        "EXISTS (SELECT 1 FROM members WHERE team IS NOT NULL AND member = current_user)",
    ] {
        assert_eq!(
            write_checks(&format!(
                "CREATE POLICY admins ON docs FOR ALL USING ({using}) WITH CHECK (true);"
            )),
            [],
            "{using}"
        );
    }
}

#[test]
fn a_missing_write_check_reuses_the_filter() {
    assert_eq!(
        write_checks("CREATE POLICY own ON docs FOR ALL USING (owner = current_user);"),
        []
    );
}

fn unforced(sql: &str) -> Vec<(String, Level, String)> {
    findings(&UnforcedRowLevelSecurity::default().into(), sql)
}

#[test]
fn row_level_security_without_force_lets_the_owner_bypass_it() {
    assert_eq!(
        unforced(
            "CREATE TABLE docs (id INT);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON docs USING (id > 0);"
        ),
        [(
            "UnforcedRowLevelSecurity".to_owned(),
            Level::Warn,
            "docs".to_owned()
        )]
    );
}

#[test]
fn forced_or_policy_free_tables_are_not_reported() {
    for sql in [
        "CREATE TABLE docs (id INT);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         ALTER TABLE docs FORCE ROW LEVEL SECURITY;
         CREATE POLICY p ON docs USING (id > 0);",
        "CREATE TABLE docs (id INT); ALTER TABLE docs ENABLE ROW LEVEL SECURITY;",
        "CREATE TABLE docs (id INT); CREATE POLICY p ON docs USING (id > 0);",
    ] {
        assert_eq!(unforced(sql), [], "{sql}");
    }
}

#[test]
fn the_default_constrainer_registers_the_policy_checks_at_their_group_defaults() {
    let database = parse(&format!(
        "{DOCS}
         CREATE POLICY everyone ON docs FOR SELECT USING (true);
         CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);
         CREATE POLICY edit ON docs FOR UPDATE USING (owner = current_user) WITH CHECK (true);"
    ));
    let raised: Vec<(String, Level)> = DefaultConstrainer::<ParserDB>::default()
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) => {
                Some((violation.rule().name.to_owned(), violation.level()))
            }
            _ => None,
        })
        .collect();
    for expected in [
        ("DeadPermissivePolicy", Level::Deny),
        ("TautologicalWithCheck", Level::Warn),
        ("UnforcedRowLevelSecurity", Level::Warn),
    ] {
        assert!(
            raised
                .iter()
                .any(|(rule, level)| (rule.as_str(), *level) == expected),
            "{expected:?}"
        );
    }
}

#[test]
fn a_tautology_for_a_declared_role_leaves_a_creating_role_policy_decided() {
    assert_eq!(
        dead(
            "CREATE POLICY admins ON docs FOR SELECT TO admin USING (true);
             CREATE POLICY mine ON docs FOR SELECT TO CURRENT_USER USING (owner = current_user);"
        ),
        []
    );
}

#[test]
fn row_independent_filters_include_nested_subqueries_and_session_values() {
    for using in [
        "current_user = 'admin'",
        "no_such_column = 1",
        "EXISTS (SELECT 1 FROM members m WHERE m.team IN (SELECT team FROM members WHERE member = current_user))",
    ] {
        assert_eq!(
            write_checks(&format!(
                "CREATE POLICY admins ON docs FOR ALL USING ({using}) WITH CHECK (true);"
            )),
            [],
            "{using}"
        );
    }
}

#[test]
fn an_unresolvable_filter_is_a_lookup_failure() {
    for using in [
        "EXISTS (SELECT 1 FROM members a, members b WHERE team = docs.team)",
        "EXISTS (SELECT 1 FROM a.b.c.members)",
    ] {
        let constrainer: GenericConstrainer<ParserDB> = TautologicalWithCheck::default().into();
        let database = parse(&format!(
            "{DOCS} CREATE POLICY team_rows ON docs FOR ALL USING ({using}) WITH CHECK (true);"
        ));
        assert!(
            matches!(
                constrainer.validate_schema(&database),
                Err(Error::Lookup(_))
            ),
            "{using}"
        );
    }
}
