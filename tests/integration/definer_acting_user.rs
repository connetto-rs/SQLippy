//! Definer functions taking the acting user as an argument, observed through
//! the public constrainer API. On PostgreSQL 17.11 and 18.6 a caller acting
//! as bob read alice's row through a parameter compared by name or as `$1`,
//! deleted it through a writing definer, and got nothing from a definer that
//! also compared the parameter with the credential.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
    CREATE ROLE anon; CREATE ROLE app;
    CREATE TABLE docs (owner TEXT, body TEXT, team INT);
    CREATE TABLE members (team INT, member TEXT);
    CREATE TABLE notes (owner TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    CREATE POLICY own ON docs USING (owner = current_setting('app.user_id', true)
      OR team IN (SELECT team FROM members WHERE member = (current_setting('app.user_id', true))));";

fn deployment() -> Deployment {
    Deployment::default()
        .with_credential("current_setting('app.user_id', true)")
        .expect("credential parses")
        .with_anonymous_role("anon")
        .with_app_role("app")
}

/// Every finding of the rule with its message.
fn findings<C: Constrainer<Database = ParserDB>>(constrainer: &C, sql: &str) -> Vec<String> {
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA}{sql}")).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == "DefinerTakesActingUser" => {
                Some(format!(
                    "{:?} {}: {}",
                    violation.level(),
                    violation.object(),
                    violation.message()
                ))
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn reported(sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = DefinerTakesActingUser::default().into();
    constrainer.set_deployment(deployment());
    findings(&constrainer, sql)
}

fn definer(signature: &str, body: &str) -> String {
    format!(
        "CREATE FUNCTION {signature} LANGUAGE sql SECURITY DEFINER SET search_path = ''
           AS $$ {body} $$;"
    )
}

#[test]
fn a_definer_taking_the_acting_user_is_reported() {
    for (function, compared) in [
        (
            definer(
                "user_docs(who TEXT) RETURNS SETOF TEXT",
                "SELECT body FROM public.docs WHERE owner = who",
            ),
            "owner = who",
        ),
        (
            definer(
                "by_position(TEXT) RETURNS SETOF TEXT",
                "SELECT body FROM public.docs d WHERE $1 = d.owner",
            ),
            "$1 = d.owner",
        ),
        (
            definer(
                "wipe(who TEXT) RETURNS VOID",
                "DELETE FROM public.docs WHERE owner = who",
            ),
            "owner = who",
        ),
        (
            definer(
                "teams_of(who TEXT) RETURNS SETOF INT",
                "SELECT team FROM public.members WHERE member = who",
            ),
            "member = who",
        ),
    ] {
        let found = reported(&function);
        assert_eq!(found.len(), 1, "{function}");
        assert!(
            found[0].contains(&format!("`{compared}`"))
                && found[0].contains("executable by PUBLIC"),
            "{found:?}"
        );
    }
}

#[test]
fn definers_reading_the_credential_or_other_columns_or_invokers_pass() {
    for function in [
        definer(
            "mine(who TEXT) RETURNS SETOF TEXT",
            "SELECT body FROM public.docs WHERE owner = who AND who = current_setting('app.user_id', true)",
        ),
        definer(
            "by_body(text_in TEXT) RETURNS SETOF TEXT",
            "SELECT owner FROM public.docs WHERE body = text_in",
        ),
        definer(
            "other_owner(who TEXT) RETURNS SETOF TEXT",
            "SELECT owner FROM public.notes WHERE owner = who",
        ),
        definer(
            "constant(who TEXT) RETURNS SETOF TEXT",
            "SELECT body FROM public.docs WHERE owner = 'admin' AND 'admin' = who",
        ),
        "CREATE FUNCTION invoker(who TEXT) RETURNS SETOF TEXT LANGUAGE sql
           AS $$ SELECT body FROM public.docs WHERE owner = who $$;"
            .to_owned(),
        "CREATE FUNCTION procedural(who TEXT) RETURNS SETOF TEXT LANGUAGE plpgsql SECURITY DEFINER
           AS $$ BEGIN RETURN QUERY SELECT body FROM public.docs WHERE owner = who; END $$;"
            .to_owned(),
        "CREATE FUNCTION unreadable(who TEXT) RETURNS SETOF TEXT LANGUAGE sql SECURITY DEFINER
           AS $$ SELEC body FROM public.docs WHERE owner = who $$;"
            .to_owned(),
        format!(
            "{} REVOKE EXECUTE ON FUNCTION user_docs(TEXT) FROM PUBLIC;",
            definer(
                "user_docs(who TEXT) RETURNS SETOF TEXT",
                "SELECT body FROM public.docs WHERE owner = who",
            )
        ),
    ] {
        assert_eq!(reported(&function), Vec::<String>::new(), "{function}");
    }
}

#[test]
fn a_client_role_granted_execute_is_named() {
    let function = format!(
        "{} REVOKE EXECUTE ON FUNCTION user_docs(TEXT) FROM PUBLIC;
         GRANT EXECUTE ON FUNCTION user_docs(TEXT) TO app;",
        definer(
            "user_docs(who TEXT) RETURNS SETOF TEXT",
            "SELECT body FROM public.docs WHERE owner = who",
        )
    );
    let found = reported(&function);
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("executable by 'app'"), "{found:?}");
}

#[test]
fn a_return_body_is_read() {
    let found = reported(
        "CREATE FUNCTION owns(who TEXT) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER
           SET search_path = ''
           RETURN EXISTS (SELECT 1 FROM public.docs WHERE owner = who);",
    );
    assert_eq!(found.len(), 1, "{found:?}");
}

#[test]
fn the_rule_is_pedantic_and_waits_for_a_credential() {
    let function = definer(
        "user_docs(who TEXT) RETURNS SETOF TEXT",
        "SELECT body FROM public.docs WHERE owner = who",
    );
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    assert!(
        constrainer
            .inactive_rules()
            .iter()
            .all(|inactive| inactive.rule().name != "DefinerTakesActingUser")
    );
    constrainer.set_deployment(deployment());
    assert_eq!(findings(&constrainer, &function), Vec::<String>::new());
    constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
    assert_eq!(findings(&constrainer, &function).len(), 1);
    constrainer.set_deployment(Deployment::default());
    assert!(
        constrainer
            .inactive_rules()
            .iter()
            .any(|inactive| inactive.rule().name == "DefinerTakesActingUser")
    );
}
