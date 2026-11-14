//! Statement rules that read the statement's shape and the catalogue's
//! columns and function bodies, observed through the public constrainer API.
//! The behaviour each rule cites was measured on PostgreSQL 17.11 and 18.6.

use crate::{
    common::parse,
    rule_findings::{
        inactive_declarations, query_rule, statement, statement_findings, statement_levels,
        statement_objects,
    },
};
use sqlippy::prelude::*;

const NOTES: &str = "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT);
    CREATE TABLE users (id INT PRIMARY KEY, name TEXT);";

/// Objects `rule` reports on each statement, in order.
fn reported(
    constrainer: &GenericConstrainer<ParserDB>,
    database: &ParserDB,
    statements: &[&str],
) -> Vec<Vec<String>> {
    statements
        .iter()
        .map(|sql| statement_objects(constrainer, database, sql))
        .collect()
}

#[test]
fn random_order_with_a_limit_is_reported() {
    let constrainer = query_rule(RandomOrderLimit::default());
    let database = parse(NOTES);
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &[
                "SELECT id FROM notes ORDER BY random() LIMIT 10",
                "SELECT id FROM notes ORDER BY random() FETCH FIRST 5 ROWS ONLY",
                "SELECT * FROM (SELECT id FROM notes ORDER BY owner, random() LIMIT 3) AS picked",
                "SELECT id FROM notes ORDER BY random()",
                "SELECT id FROM notes ORDER BY id LIMIT 10",
            ]
        ),
        [
            vec!["ORDER BY random() LIMIT 10".to_owned()],
            vec!["ORDER BY random() FETCH FIRST 5 ROWS ONLY".to_owned()],
            vec!["ORDER BY owner, random() LIMIT 3".to_owned()],
            vec![],
            vec![],
        ]
    );
}

#[test]
fn offset_paging_is_reported_except_the_zero_offset_fence() {
    let constrainer = query_rule(OffsetPaging::default());
    let database = parse(NOTES);
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &[
                "SELECT id FROM notes ORDER BY id LIMIT 10 OFFSET 90000",
                "SELECT id FROM notes ORDER BY id LIMIT 10 OFFSET $1",
                "SELECT id FROM (SELECT id FROM notes OFFSET 0) AS fenced",
                "SELECT id FROM notes WHERE id > $1 ORDER BY id LIMIT 10",
            ]
        ),
        [
            vec!["OFFSET 90000".to_owned()],
            vec!["OFFSET $1".to_owned()],
            vec![],
            vec![],
        ]
    );
}

#[test]
fn writes_without_a_where_are_reported() {
    let constrainer = query_rule(UnfilteredWrite::default());
    let database = parse(NOTES);
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &[
                "UPDATE notes SET body = 'x'",
                "DELETE FROM notes",
                "DELETE FROM notes USING users",
                "WITH gone AS (DELETE FROM notes RETURNING id) SELECT count(*) FROM gone",
                "UPDATE notes SET body = 'x' WHERE true",
                "DELETE FROM notes WHERE id = $1",
                "TRUNCATE notes",
                "SELECT body FROM notes",
            ]
        ),
        [
            vec!["UPDATE notes SET body = 'x'".to_owned()],
            vec!["DELETE FROM notes".to_owned()],
            vec!["DELETE FROM notes USING users".to_owned()],
            vec!["DELETE FROM notes RETURNING id".to_owned()],
            vec![],
            vec![],
            vec![],
            vec![],
        ]
    );
}

#[test]
fn writes_whose_where_reads_no_column_are_reported() {
    let constrainer = query_rule(UnfilteredWrite::default());
    let database = parse(NOTES);
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &[
                "DELETE FROM notes WHERE 1 = 1",
                "UPDATE notes SET body = 'x' WHERE 1 = 0",
                "DELETE FROM notes WHERE $1",
                "DELETE FROM notes WHERE now() > '2020-01-01'",
                "DELETE FROM notes WHERE (true)",
                "DELETE FROM notes WHERE owner = $1",
                "DELETE FROM notes WHERE EXISTS (SELECT 1 FROM users WHERE users.name = notes.owner)",
                "DELETE FROM notes USING users WHERE users.id = notes.id",
                "DELETE FROM notes WHERE random() < 0.5",
                "DELETE FROM notes WHERE nextval('note_ids') % 2 = 0",
                "UPDATE notes SET body = 'x' WHERE clock_timestamp() > '2020-01-01'",
                "DELETE FROM notes WHERE undeclared_flag()",
                "DELETE FROM notes WHERE upper('a') = 'A'",
            ]
        ),
        [
            vec!["DELETE FROM notes WHERE 1 = 1".to_owned()],
            vec!["UPDATE notes SET body = 'x' WHERE 1 = 0".to_owned()],
            vec!["DELETE FROM notes WHERE $1".to_owned()],
            vec!["DELETE FROM notes WHERE now() > '2020-01-01'".to_owned()],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec!["DELETE FROM notes WHERE upper('a') = 'A'".to_owned()],
        ]
    );
}

#[test]
fn a_where_whose_operator_runs_a_volatile_function_is_not_reported() {
    let constrainer = query_rule(UnfilteredWrite::default());
    let database = parse(&format!(
        "{NOTES}
         CREATE SCHEMA app;
         CREATE FUNCTION app.coinflip(a INT, b INT) RETURNS BOOL LANGUAGE sql VOLATILE
             AS 'SELECT random() < 0.5';
         CREATE OPERATOR app.<?> (LEFTARG = INT, RIGHTARG = INT, FUNCTION = app.coinflip);
         CREATE OPERATOR ~~ (LEFTARG = INT, RIGHTARG = INT, FUNCTION = app.coinflip);
         CREATE OPERATOR !~~ (LEFTARG = INT, RIGHTARG = INT, FUNCTION = app.coinflip);
         CREATE OPERATOR ~~* (LEFTARG = INT, RIGHTARG = INT, FUNCTION = app.coinflip);
         CREATE OPERATOR !~~* (LEFTARG = INT, RIGHTARG = INT, FUNCTION = app.coinflip);
         CREATE TYPE mood AS ENUM ('a', 'b');
         CREATE FUNCTION app.moodflip(a mood, b mood) RETURNS BOOL LANGUAGE sql VOLATILE
             AS 'SELECT random() < 0.5';
         CREATE OPERATOR = (LEFTARG = mood, RIGHTARG = mood, FUNCTION = app.moodflip);
         CREATE OPERATOR <> (LEFTARG = mood, RIGHTARG = mood, FUNCTION = app.moodflip);
         CREATE OPERATOR >= (LEFTARG = mood, RIGHTARG = mood, FUNCTION = app.moodflip);
         CREATE OPERATOR <= (LEFTARG = mood, RIGHTARG = mood, FUNCTION = app.moodflip);
         CREATE OPERATOR < (LEFTARG = mood, RIGHTARG = mood, FUNCTION = app.moodflip);
         CREATE OPERATOR > (LEFTARG = mood, RIGHTARG = mood, FUNCTION = app.moodflip);"
    ));
    let volatile = [
        "DELETE FROM notes WHERE 1 OPERATOR(app.<?>) 1",
        "DELETE FROM notes WHERE 1 OPERATOR(app.<%>) 1",
        "DELETE FROM notes WHERE 1 ~~ ANY (ARRAY[1])",
        "DELETE FROM notes WHERE 1 ~~ ALL (ARRAY[1])",
        "DELETE FROM notes WHERE 1 LIKE 1",
        "DELETE FROM notes WHERE 1 NOT LIKE 1",
        "DELETE FROM notes WHERE 1 ILIKE 1",
        "DELETE FROM notes WHERE 1 NOT ILIKE 1",
        "DELETE FROM notes WHERE 'a'::mood IN ('a'::mood)",
        "DELETE FROM notes WHERE 'a'::mood NOT IN ('a'::mood)",
        "DELETE FROM notes WHERE 'a'::mood IN (SELECT 'a'::mood)",
        "DELETE FROM notes WHERE 'a'::mood BETWEEN 'a'::mood AND 'a'::mood",
        "DELETE FROM notes WHERE 'a'::mood NOT BETWEEN 'a'::mood AND 'a'::mood",
        "DELETE FROM notes WHERE 'a'::mood IS DISTINCT FROM 'a'::mood",
        "DELETE FROM notes WHERE 'a'::mood IS NOT DISTINCT FROM 'a'::mood",
        "DELETE FROM notes WHERE CASE 'a'::mood WHEN 'a'::mood THEN true ELSE false END",
    ];
    assert_eq!(
        reported(&constrainer, &database, &volatile),
        vec![Vec::<String>::new(); volatile.len()]
    );
    let constant = [
        "DELETE FROM notes WHERE 1 + 1 = 2",
        "DELETE FROM notes WHERE 1 IN (1, 2)",
        "DELETE FROM notes WHERE 1 BETWEEN 0 AND 2",
        "DELETE FROM notes WHERE 'a' LIKE 'a'",
    ];
    assert_eq!(
        reported(&constrainer, &parse(NOTES), &constant),
        constant.map(|statement| vec![statement.to_owned()])
    );
}

#[test]
fn a_where_casting_through_a_volatile_function_is_not_reported() {
    let constrainer = query_rule(UnfilteredWrite::default());
    let app = |name| TargetName::new(name, false).with_schema("app", false);
    let database = ParseOptions::default()
        .with_postgres_catalog(PostgresCatalog::default().with_cast(
            PostgresCatalogCast::through_function(
                app("coin"),
                TargetName::new("bool", false).with_schema("pg_catalog", false),
                CastContext::Explicit,
                app("toss"),
                [app("coin")],
            ),
        ))
        .parse::<sqlparser::dialect::PostgreSqlDialect>(&format!(
            "{NOTES}
             CREATE SCHEMA app;
             CREATE TYPE app.coin AS (v INT);
             CREATE FUNCTION app.toss(app.coin) RETURNS BOOL LANGUAGE sql VOLATILE
                 AS 'SELECT random() < 0.5';"
        ))
        .expect("schema parses");
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &[
                "DELETE FROM notes WHERE '(1)'::app.coin::BOOL",
                "DELETE FROM notes WHERE CAST(CAST('(1)' AS app.coin) AS BOOLEAN)",
                "DELETE FROM notes WHERE (ARRAY['(1)'::app.coin]::BOOL[])[1]",
                "DELETE FROM notes WHERE (ARRAY[ARRAY['(1)'::app.coin]]::BOOL[][])[1][1]",
                "DELETE FROM notes WHERE (CAST(ARRAY['(1)'::app.coin] AS BOOLEAN ARRAY))[1]",
                "DELETE FROM notes WHERE 1::BIGINT = 1",
                "DELETE FROM notes WHERE '1'::INT = 1",
                "DELETE FROM notes WHERE (ARRAY[1]::BIGINT[])[1] = 1",
            ]
        ),
        [
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec!["DELETE FROM notes WHERE 1::BIGINT = 1".to_owned()],
            vec!["DELETE FROM notes WHERE '1'::INT = 1".to_owned()],
            vec!["DELETE FROM notes WHERE (ARRAY[1]::BIGINT[])[1] = 1".to_owned()],
        ]
    );
}

const LOGINS: &str = "
    CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT);
    CREATE FUNCTION login(who TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN PERFORM set_config('app.user_id', who, false); END $$;
    CREATE FUNCTION sql_login(who TEXT) RETURNS TEXT LANGUAGE sql
      AS $$ SELECT set_config('app.user_id', who, false) $$;
    CREATE FUNCTION outer_login(who TEXT) RETURNS VOID LANGUAGE sql
      AS $$ SELECT login(who) $$;
    CREATE FUNCTION set_theme(theme TEXT) RETURNS TEXT LANGUAGE sql
      AS $$ SELECT set_config('app.theme', theme, false) $$;
    CREATE FUNCTION spin() RETURNS INT LANGUAGE sql AS $$ SELECT spin() $$;
    CREATE FUNCTION commented() RETURNS INT LANGUAGE plpgsql AS $$
      BEGIN -- PERFORM set_config('app.user_id', 'x', false);
      RETURN 1; END $$;
    CREATE FUNCTION keyed(key_name TEXT, who TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN PERFORM set_config(key_name, who, false); END $$;
    CREATE FUNCTION forget() RETURNS VOID LANGUAGE plpgsql AS $$ BEGIN RESET ALL; END $$;
    CREATE FUNCTION returned_login(who TEXT) RETURNS TEXT LANGUAGE sql
      RETURN set_config('app.user_id', who, false);
    CREATE FUNCTION touch() RETURNS VOID LANGUAGE sql
      AS $$ UPDATE notes SET body = 'x' WHERE id = 1 $$;
    CREATE FUNCTION atomic_login(who TEXT) RETURNS TEXT LANGUAGE sql
      BEGIN ATOMIC SELECT 1; SELECT set_config('app.user_id', who, false); END;
    CREATE FUNCTION atomic_theme(theme TEXT) RETURNS TEXT LANGUAGE sql
      BEGIN ATOMIC SELECT set_config('app.theme', theme, false); END;
    CREATE SCHEMA app;
    CREATE FUNCTION app.become_admin() RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN SET LOCAL app.user_id = 'admin'; END $$;
    CREATE FUNCTION app.sign_in() RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN PERFORM app.become_admin(); END $$;";

fn credential_rule() -> GenericConstrainer<ParserDB> {
    let mut constrainer = query_rule(CredentialSettingWrite::default());
    constrainer.set_deployment(
        Deployment::default()
            .with_credential("current_setting('app.user_id', true)")
            .expect("credential parses"),
    );
    constrainer
}

#[test]
fn statements_writing_a_credential_setting_are_reported() {
    let constrainer = credential_rule();
    let database = parse(LOGINS);
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &[
                "SELECT set_config('app.user_id', 'alice', false)",
                "SELECT id FROM notes WHERE set_config('APP.USER_ID', 'alice', false) IS NOT NULL",
                "SELECT set_config($1, $2, false)",
                "SELECT pg_catalog.set_config('app.' || 'user_id', 'alice', true)",
                "SET app.user_id = 'alice'",
                "SET LOCAL app.user_id TO 'alice'",
                "RESET app.user_id",
                "RESET ALL",
                "DISCARD ALL",
                "SELECT login('alice')",
                "SELECT sql_login($1)",
                "SELECT outer_login($1)",
                "SELECT keyed($1, $2)",
                "SELECT forget()",
                "SELECT returned_login($1)",
                "SELECT app.sign_in()",
                "SELECT atomic_login($1)",
                "SELECT public.sql_login($1)",
            ]
        ),
        [
            vec!["set_config('app.user_id', 'alice', false)".to_owned()],
            vec!["set_config('APP.USER_ID', 'alice', false)".to_owned()],
            vec!["set_config($1, $2, false)".to_owned()],
            vec!["pg_catalog.set_config('app.' || 'user_id', 'alice', true)".to_owned()],
            vec!["SET app.user_id = 'alice'".to_owned()],
            vec!["SET LOCAL app.user_id = 'alice'".to_owned()],
            vec!["RESET app.user_id".to_owned()],
            vec!["RESET ALL".to_owned()],
            vec!["DISCARD ALL".to_owned()],
            vec!["login('alice')".to_owned()],
            vec!["sql_login($1)".to_owned()],
            vec!["outer_login($1)".to_owned()],
            vec!["keyed($1, $2)".to_owned()],
            vec!["forget()".to_owned()],
            vec!["returned_login($1)".to_owned()],
            vec!["app.sign_in()".to_owned()],
            vec!["atomic_login($1)".to_owned()],
            vec!["public.sql_login($1)".to_owned()],
        ]
    );
}

#[test]
fn statements_reading_credentials_or_writing_other_settings_pass() {
    let constrainer = credential_rule();
    let database = parse(LOGINS);
    for sql in [
        "SELECT set_config('app.theme', 'dark', false)",
        "SET app.theme = 'dark'",
        "RESET app.theme",
        "DISCARD PLANS",
        "SELECT current_setting('app.user_id', true)",
        "SELECT set_theme('dark')",
        "SELECT spin()",
        "SELECT commented()",
        "SELECT touch()",
        "SELECT atomic_theme('dark')",
        "SELECT app.sql_login($1)",
        "SELECT body FROM notes WHERE owner = current_setting('app.user_id', true)",
    ] {
        assert_eq!(
            statement_findings(&constrainer, &database, sql),
            [],
            "{sql}"
        );
    }
}

#[test]
fn credential_bodies_written_as_an_expression_a_select_or_a_block_are_read() {
    let constrainer = credential_rule();
    for database in [
        ParserDB::parse::<sqlparser::dialect::BigQueryDialect>(
            "CREATE FUNCTION login() AS (set_config('app.user_id', 'alice', false));",
        ),
        ParserDB::parse::<sqlparser::dialect::MsSqlDialect>(
            "CREATE FUNCTION login() RETURNS TABLE AS RETURN SELECT set_config('app.user_id', 'alice', false) AS c;",
        ),
        ParserDB::parse::<sqlparser::dialect::MsSqlDialect>(
            "CREATE FUNCTION login() RETURNS INT AS BEGIN RETURN set_config('app.user_id', 'alice', false); END;",
        ),
    ] {
        let database = database.expect("schema parses");
        assert_eq!(
            reported(&constrainer, &database, &["SELECT login()"]),
            [vec!["login()".to_owned()]]
        );
    }
}

#[test]
fn the_credential_rule_is_inactive_without_declared_credentials() {
    let constrainer = query_rule(CredentialSettingWrite::default());
    let database = parse(LOGINS);
    assert_eq!(
        inactive_declarations(&constrainer),
        [("credential_setting_write", Declaration::Credentials)]
    );
    assert_eq!(
        statement_findings(&constrainer, &database, "SET app.user_id = 'alice'"),
        []
    );
}

const SCHEMAS: &str = "
    CREATE TABLE notes (id INT PRIMARY KEY);
    CREATE SCHEMA app;
    CREATE FUNCTION greet(who TEXT) RETURNS VOID LANGUAGE plpgsql AS $$ BEGIN PERFORM 1; END $$;
    CREATE FUNCTION app.greet(who TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN PERFORM set_config('app.user_id', who, false); END $$;
    CREATE FUNCTION sign() RETURNS INT LANGUAGE sql AS $$ SELECT 1 $$;
    CREATE FUNCTION sign(who TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN PERFORM set_config('app.user_id', who, false); END $$;
    CREATE FUNCTION plain_sign() RETURNS INT LANGUAGE plpgsql AS $$ BEGIN RETURN sign(); END $$;
    CREATE FUNCTION nested_sign() RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN PERFORM sign(lower('A')); END $$;
    CREATE FUNCTION quoted_admin() RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN SET \"app\".user_id = 'admin'; END $$;
    CREATE FUNCTION pair(a TEXT, b TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN PERFORM set_config('app.user_id', a || b, false); END $$;
    CREATE FUNCTION relay() RETURNS VOID LANGUAGE plpgsql AS $$
      BEGIN PERFORM pair('x', 'y'); END $$;";

#[test]
fn a_call_reaches_the_overload_and_schema_postgresql_picks() {
    let constrainer = credential_rule();
    let database = parse(SCHEMAS);
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &[
                "SELECT greet('bob'), app.greet('alice')",
                "SELECT app.greet('alice'), greet('bob')",
                "SELECT sign()",
                "SELECT sign('alice')",
                "SELECT plain_sign()",
                "SELECT nested_sign()",
                "SELECT relay()",
                "SELECT CURRENT_TIMESTAMP",
            ]
        ),
        [
            vec!["app.greet('alice')".to_owned()],
            vec!["app.greet('alice')".to_owned()],
            vec![],
            vec!["sign('alice')".to_owned()],
            vec![],
            vec!["nested_sign()".to_owned()],
            vec!["relay()".to_owned()],
            vec![],
        ]
    );
}

#[test]
fn quoted_parts_of_a_credential_setting_name_still_name_it() {
    let constrainer = credential_rule();
    let database = parse(SCHEMAS);
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &["SET \"app\".user_id = 'alice'", "SELECT quoted_admin()"]
        ),
        [
            vec!["SET \"app\".user_id = 'alice'".to_owned()],
            vec!["quoted_admin()".to_owned()],
        ]
    );
}

const TEAMS: &str = "CREATE TABLE teams (id INT PRIMARY KEY, name TEXT);
    CREATE TABLE banned (team_id INT);
    CREATE TABLE members (user_id INT, team_id INT);";

#[test]
fn an_unqualified_name_resolving_outside_its_subquery_is_reported() {
    let constrainer = query_rule(OuterColumnCapture::default());
    let database = parse(TEAMS);
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &[
                "SELECT id FROM teams WHERE id IN (SELECT id FROM banned)",
                "SELECT id FROM teams WHERE EXISTS (SELECT 1 FROM banned WHERE team_id = id)",
                "SELECT id FROM teams WHERE id = ANY (SELECT id FROM banned)",
                "SELECT id, (SELECT max(name) FROM banned) FROM teams",
                "DELETE FROM teams WHERE id IN (SELECT id FROM banned)",
                "UPDATE teams SET name = 'x' WHERE id IN (SELECT id FROM banned)",
                "INSERT INTO members (user_id, team_id) SELECT 1, id FROM teams WHERE id NOT IN (SELECT id FROM banned)",
                "SELECT id FROM teams WHERE EXISTS (SELECT 1 FROM members WHERE members.team_id IN (SELECT name FROM banned))",
                "UPDATE teams SET name = 'x' FROM members WHERE members.team_id = teams.id AND teams.id IN (SELECT id FROM banned)",
                "SELECT id FROM teams WHERE id IN ((SELECT id FROM banned) UNION (SELECT team_id FROM members))",
                "SELECT team_id FROM banned JOIN members USING (team_id) WHERE team_id IN (SELECT team_id FROM teams)",
            ]
        ),
        [
            vec!["SELECT id FROM banned".to_owned()],
            vec!["SELECT 1 FROM banned WHERE team_id = id".to_owned()],
            vec!["SELECT id FROM banned".to_owned()],
            vec!["SELECT max(name) FROM banned".to_owned()],
            vec!["SELECT id FROM banned".to_owned()],
            vec!["SELECT id FROM banned".to_owned()],
            vec!["SELECT id FROM banned".to_owned()],
            vec!["SELECT name FROM banned".to_owned()],
            vec!["SELECT id FROM banned".to_owned()],
            vec!["(SELECT id FROM banned) UNION (SELECT team_id FROM members)".to_owned()],
            vec!["SELECT team_id FROM teams".to_owned()],
        ]
    );
}

#[test]
fn captures_under_a_with_clause_are_reported() {
    let constrainer = query_rule(OuterColumnCapture::default());
    let database = parse(TEAMS);
    assert_eq!(
        reported(
            &constrainer,
            &database,
            &[
                "WITH x AS (SELECT 1 AS one) DELETE FROM teams WHERE id IN (SELECT id FROM banned)",
                "WITH x AS (SELECT 1 AS one) UPDATE teams SET name = 'x' WHERE id IN (SELECT id FROM banned)",
                "WITH x AS (SELECT 1 AS one) INSERT INTO members (user_id, team_id) SELECT 1, id FROM teams WHERE id NOT IN (SELECT id FROM banned)",
                "WITH listed AS (SELECT team_id FROM banned) SELECT id FROM teams WHERE id IN (SELECT id FROM listed)",
                "WITH listed AS (SELECT team_id FROM banned) DELETE FROM teams WHERE id IN (SELECT team_id FROM listed)",
            ]
        ),
        [
            vec!["SELECT id FROM banned".to_owned()],
            vec!["SELECT id FROM banned".to_owned()],
            vec!["SELECT id FROM banned".to_owned()],
            vec!["SELECT id FROM listed".to_owned()],
            vec![],
        ]
    );
}

#[test]
fn a_captured_name_is_named_with_the_outer_relation() {
    let constrainer = query_rule(OuterColumnCapture::default());
    let Err(Error::Violation(violation)) = constrainer.validate_statement(
        &parse(TEAMS),
        &statement("SELECT id FROM teams AS t WHERE id IN (SELECT id FROM banned)"),
    ) else {
        panic!("the capture is reported");
    };
    assert!(violation.message().contains("'t.id'"), "{violation}");
    assert_eq!(violation.level(), Level::Deny);
}

#[test]
fn names_the_subquery_resolves_or_that_resolve_nowhere_pass() {
    let constrainer = query_rule(OuterColumnCapture::default());
    let database = parse(TEAMS);
    for sql in [
        "SELECT id FROM teams WHERE id IN (SELECT team_id FROM banned)",
        "SELECT id FROM teams WHERE EXISTS (SELECT 1 FROM banned AS b WHERE b.team_id = teams.id)",
        "SELECT id FROM teams WHERE id IN (SELECT missing FROM banned)",
        "SELECT id FROM teams WHERE id IN (SELECT g FROM generate_series(1, 3) AS g)",
        "SELECT id FROM teams WHERE id IN (SELECT team_id FROM banned UNION SELECT team_id FROM members)",
        "SELECT id FROM teams WHERE id IN (VALUES (1), (2))",
        "WITH listed AS (SELECT team_id FROM banned) SELECT id FROM teams WHERE id IN (SELECT team_id FROM listed)",
        "SELECT id FROM teams",
        "SET app.user_id = 'alice'",
    ] {
        assert_eq!(
            statement_findings(&constrainer, &database, sql),
            [],
            "{sql}"
        );
    }
}

#[test]
fn a_name_the_schema_cannot_resolve_is_a_lookup_failure() {
    let constrainer = query_rule(OuterColumnCapture::default());
    let database = parse(TEAMS);
    for sql in [
        "SELECT id FROM teams WHERE id IN (SELECT team_id FROM banned, members)",
        "SELECT id FROM a.b.c.teams",
    ] {
        assert!(
            matches!(
                constrainer.validate_statement(&database, &statement(sql)),
                Err(Error::Lookup(_))
            ),
            "{sql}"
        );
    }
}

#[test]
fn the_default_constrainer_runs_shape_rules_at_their_group_levels() {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    constrainer.set_deployment(
        Deployment::default()
            .with_credential("current_setting('app.user_id', true)")
            .expect("credential parses"),
    );
    let database = parse(&format!("{TEAMS} CREATE TABLE notes (id INT, body TEXT);"));
    let rules = |constrainer: &DefaultConstrainer<ParserDB>, sql: &str| {
        statement_levels(constrainer, &database, sql)
    };
    assert_eq!(
        rules(&constrainer, "DELETE FROM notes"),
        [("unfiltered_write", Level::Warn)]
    );
    assert_eq!(
        rules(&constrainer, "SET app.user_id = 'alice'"),
        [("credential_setting_write", Level::Deny)]
    );
    assert_eq!(
        rules(
            &constrainer,
            "SELECT id FROM teams WHERE id IN (SELECT id FROM banned)"
        ),
        [("outer_column_capture", Level::Deny)]
    );
    let paging = "SELECT id FROM notes ORDER BY random() LIMIT 5 OFFSET 5";
    assert_eq!(rules(&constrainer, paging), []);
    constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
    assert_eq!(
        rules(&constrainer, paging),
        [
            ("random_order_limit", Level::Warn),
            ("offset_paging", Level::Warn)
        ]
    );
}
