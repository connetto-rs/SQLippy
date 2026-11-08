//! `SECURITY DEFINER` function rules observed through the public constrainer
//! API. The search path shapes were measured on PostgreSQL 17 and 18 with a
//! caller holding a temporary `docs` table over a three-row `public.docs`.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Rule, level and function of every finding, failing on any error other than
/// a rule the deployment leaves inactive.
fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    sql: &str,
) -> Vec<(String, Level, String)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let mut found: Vec<_> = constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) => Some((
                violation.rule().name.to_owned(),
                violation.level(),
                violation.object().to_owned(),
            )),
            Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    found.sort();
    found
}

/// Functions the rule reports.
fn reported(rule: impl Into<GenericConstrainer<ParserDB>>, sql: &str) -> Vec<String> {
    findings(&rule.into(), sql)
        .into_iter()
        .map(|(_, _, function)| function)
        .collect()
}

const DOCS: &str = "CREATE TABLE docs (id INT);";

#[test]
fn a_definer_body_resolved_at_call_time_without_its_own_path_is_denied() {
    assert_eq!(
        reported(
            DefinerWithoutSearchPath::default(),
            &format!(
                "{DOCS}
                 CREATE FUNCTION string_body() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION plpgsql_body() RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER
                   AS $$ BEGIN RETURN (SELECT count(*) FROM docs); END $$;
                 CREATE FUNCTION reset_later(n INT) RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = '' AS 'SELECT count(*) FROM public.docs';
                 ALTER FUNCTION reset_later(INT) RESET search_path;"
            ),
        ),
        ["plpgsql_body()", "reset_later(INT)", "string_body()"]
    );
}

#[test]
fn bound_bodies_pinned_paths_and_invoker_functions_pass() {
    assert_eq!(
        reported(
            DefinerWithoutSearchPath::default(),
            &format!(
                "{DOCS}
                 CREATE FUNCTION returned() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   RETURN (SELECT count(*) FROM docs);
                 CREATE FUNCTION atomic() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   BEGIN ATOMIC SELECT count(*) FROM docs; END;
                 CREATE FUNCTION emptied() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = '' AS 'SELECT count(*) FROM public.docs';
                 CREATE FUNCTION captured() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path FROM CURRENT AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION pinned_later() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   AS 'SELECT count(*) FROM public.docs';
                 ALTER FUNCTION pinned_later() SET search_path = '';
                 CREATE FUNCTION invoker() RETURNS BIGINT LANGUAGE sql
                   AS 'SELECT count(*) FROM docs';"
            ),
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_definer_path_leaving_the_temporary_schema_implicit_or_early_is_reported() {
    assert_eq!(
        reported(
            DefinerTemporarySchemaNotLast::default(),
            &format!(
                "{DOCS}
                 CREATE FUNCTION implicit() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = public AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION early() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = pg_temp, public AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION last() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = public, pg_temp AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION emptied() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = '' AS 'SELECT count(*) FROM public.docs';
                 CREATE FUNCTION unpinned() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   AS 'SELECT count(*) FROM docs';"
            ),
        ),
        ["early()", "implicit()"]
    );
}

const PROTECTED: &str = "
    CREATE ROLE anon;
    CREATE TABLE docs (id INT, owner TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    CREATE TABLE open_notes (id INT);";

fn exposed(deployment: Deployment, sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> =
        ExposedDefinerOverProtectedTable::default().into();
    constrainer.set_deployment(deployment);
    findings(&constrainer, &format!("{PROTECTED}{sql}"))
        .into_iter()
        .map(|(_, _, function)| function)
        .collect()
}

#[test]
fn a_definer_over_a_protected_table_that_public_can_execute_is_reported() {
    assert_eq!(
        exposed(
            Deployment::default(),
            "CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               SET search_path = '' AS 'SELECT count(*) FROM public.docs';
             CREATE FUNCTION wipe_docs() RETURNS VOID LANGUAGE sql SECURITY DEFINER
               SET search_path = '' AS 'DELETE FROM public.docs';
             CREATE FUNCTION note_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               SET search_path = '' AS 'SELECT count(*) FROM public.open_notes';
             CREATE FUNCTION invoker_count() RETURNS BIGINT LANGUAGE sql
               SET search_path = '' AS 'SELECT count(*) FROM public.docs';",
        ),
        ["doc_count()", "wipe_docs()"]
    );
}

#[test]
fn revoking_from_public_clears_it_unless_an_anonymous_role_still_executes() {
    let revoked = "CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                     SET search_path = '' AS 'SELECT count(*) FROM public.docs';
                   REVOKE EXECUTE ON FUNCTION doc_count() FROM PUBLIC;";
    assert_eq!(
        exposed(Deployment::default(), revoked),
        Vec::<String>::new()
    );
    let anon = || Deployment::default().with_anonymous_role("anon");
    assert_eq!(exposed(anon(), revoked), Vec::<String>::new());
    assert_eq!(
        exposed(
            anon(),
            &format!("{revoked} GRANT EXECUTE ON FUNCTION doc_count() TO anon;")
        ),
        ["doc_count()"]
    );
    assert_eq!(
        exposed(
            anon(),
            &format!("ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO anon; {revoked}")
        ),
        ["doc_count()"]
    );
}

#[test]
fn a_plpgsql_definer_is_reported_only_when_its_body_touches_a_protected_table() {
    assert_eq!(
        exposed(
            Deployment::default(),
            "CREATE FUNCTION set_state(p_id INT) RETURNS INT LANGUAGE plpgsql SECURITY DEFINER
               SET search_path TO '' AS $$ BEGIN UPDATE public.docs SET owner = 'x' WHERE id = p_id; RETURN p_id; END; $$;
             CREATE FUNCTION count_notes() RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER
               SET search_path TO '' AS $$ BEGIN RETURN (SELECT count(*) FROM public.open_notes); END; $$;",
        ),
        ["set_state(INT)"]
    );
}

#[test]
fn a_definer_body_whose_tables_cannot_be_read_is_reported() {
    assert_eq!(
        exposed(
            Deployment::default(),
            "CREATE FUNCTION wipe(t TEXT) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
               SET search_path TO '' AS $$ BEGIN EXECUTE 'DELETE FROM public.' || quote_ident(t); END; $$;
             CREATE FUNCTION native() RETURNS INT LANGUAGE c SECURITY DEFINER
               AS 'library', 'symbol';",
        ),
        ["native()", "wipe(TEXT)"]
    );
}

#[test]
fn the_default_constrainer_runs_the_function_rules_at_their_group_levels() {
    let found = findings(
        &DefaultConstrainer::<ParserDB>::default(),
        &format!(
            "{PROTECTED}
             CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               SET search_path = public AS 'SELECT count(*) FROM docs';
             CREATE FUNCTION unpinned() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               AS 'SELECT 1';"
        ),
    );
    let function_rules: Vec<_> = found
        .into_iter()
        .filter(|(rule, _, _)| {
            rule.starts_with("Definer") || rule == "ExposedDefinerOverProtectedTable"
        })
        .collect();
    assert_eq!(
        function_rules,
        [
            (
                "DefinerTemporarySchemaNotLast".to_owned(),
                Level::Deny,
                "doc_count()".to_owned()
            ),
            (
                "DefinerWithoutSearchPath".to_owned(),
                Level::Deny,
                "unpinned()".to_owned()
            ),
            (
                "ExposedDefinerOverProtectedTable".to_owned(),
                Level::Warn,
                "doc_count()".to_owned()
            ),
        ]
    );
}
