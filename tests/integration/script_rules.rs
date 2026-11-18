//! Rules reading a script's statements in the order they run: the session's
//! `search_path` and which schemas and objects earlier statements created.

use sqlippy::prelude::*;
use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};

/// The object of every violation `rule` raises on `sql` read as a script.
fn script_findings(rule: impl Into<GenericConstrainer<ParserDB>>, sql: &str) -> Vec<String> {
    let constrainer = rule.into();
    let database = crate::common::parse(sql);
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql).expect("script parses");
    constrainer
        .script_diagnostics(&database, &statements)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn unqualified(sql: &str) -> Vec<String> {
    script_findings(UnqualifiedNameUnderUnsafeSearchPath::default(), sql)
}

const DOCS: &str = "CREATE TABLE public.docs (id INT, title TEXT);";

#[test]
fn unqualified_names_under_the_default_path_are_listed_once_per_statement() {
    assert_eq!(
        unqualified(&format!(
            "{DOCS} SELECT lower(title), id + 1, title::text, -1, id::integer FROM docs WHERE id IN (1, 2);"
        )),
        ["lower, +, TEXT, docs, = in IN"]
    );
}

#[test]
fn a_trusted_path_excuses_the_statements_after_it() {
    let trusted = "SET search_path = pg_catalog, pg_temp;";
    let select = "SELECT lower(title) FROM docs;";
    assert_eq!(
        unqualified(&format!("{DOCS} {trusted} {select}")),
        Vec::<String>::new()
    );
    for untrusted in [
        "SET search_path = public;",
        "SET search_path = pg_catalog;",
        "SET search_path = pg_temp, pg_catalog;",
        "SET search_path = pg_catalog, app, pg_temp;",
        "SET search_path = DEFAULT;",
    ] {
        assert_eq!(
            unqualified(&format!("{DOCS} {trusted} {untrusted} {select}")),
            ["lower, docs"],
            "{untrusted}"
        );
    }
    assert_eq!(
        unqualified(&format!("{DOCS} {trusted} RESET search_path; {select}")),
        ["lower, docs"]
    );
}

#[test]
fn a_schema_the_script_created_may_stand_in_the_trusted_path() {
    let select = "SET search_path = pg_catalog, app, pg_temp; SELECT 1 OPERATOR(pg_catalog.+) 1;";
    assert_eq!(
        unqualified(&format!("CREATE SCHEMA app; {select} SELECT lower('a');")),
        Vec::<String>::new()
    );
    assert_eq!(
        unqualified(&format!(
            "CREATE SCHEMA IF NOT EXISTS app; {select} SELECT lower('a');"
        )),
        ["lower"]
    );
}

#[test]
fn a_local_path_lasts_until_the_transaction_ends() {
    let sql = "BEGIN; SET LOCAL search_path = pg_catalog, pg_temp; SELECT lower('a'); COMMIT;
               SELECT upper('a');";
    assert_eq!(unqualified(sql), ["upper"]);
    let configured = "SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', false);
                      SELECT lower('a');";
    assert_eq!(unqualified(configured), Vec::<String>::new());
}

#[test]
fn a_rollback_undoes_the_paths_set_since_its_transaction_or_savepoint() {
    let trusted = "SET search_path = pg_catalog, pg_temp;";
    assert_eq!(
        unqualified(&format!("BEGIN; {trusted} ROLLBACK; SELECT lower('a');")),
        ["lower"]
    );
    assert_eq!(
        unqualified(&format!("BEGIN; {trusted} COMMIT; SELECT lower('a');")),
        Vec::<String>::new()
    );
    assert_eq!(
        unqualified(
            "BEGIN; SAVEPOINT s; SET LOCAL search_path = pg_catalog, pg_temp; \
             ROLLBACK TO SAVEPOINT s; SELECT lower('a');"
        ),
        ["lower"]
    );
    assert_eq!(
        unqualified(&format!(
            "BEGIN; SAVEPOINT s; {trusted} RELEASE SAVEPOINT s; SELECT lower('a'); ROLLBACK; SELECT upper('a');"
        )),
        ["upper"]
    );
    assert_eq!(
        unqualified(&format!(
            "SET LOCAL search_path = pg_catalog, pg_temp; SELECT lower('a'); \
             BEGIN; SET LOCAL search_path = public; {trusted} COMMIT AND CHAIN; SELECT upper('a');"
        )),
        ["lower"]
    );
}

#[test]
fn only_a_set_config_the_statement_runs_changes_the_path() {
    assert_eq!(
        unqualified(
            "CREATE VIEW public.v AS SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', false);
             SELECT lower('a');"
        ),
        ["lower"]
    );
    assert_eq!(
        unqualified(
            "CREATE TABLE public.t AS SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', false);
             SELECT lower('a');"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn local_bindings_and_qualified_names_are_not_reported() {
    assert_eq!(
        unqualified(&format!(
            "{DOCS} WITH recent AS (SELECT id FROM public.docs) SELECT pg_catalog.count(*), \
             coalesce(id, 0), CURRENT_USER FROM recent;"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn a_table_function_is_reported_as_a_function() {
    assert_eq!(
        unqualified("SELECT * FROM generate_series(1, 3);"),
        ["generate_series"]
    );
}

#[test]
fn grammar_constructs_shaped_like_calls_are_not_reported() {
    assert_eq!(
        unqualified(
            "SELECT ARRAY(SELECT 1), ROW(1, 2), pg_catalog.count(*) FROM pg_catalog.pg_class \
             GROUP BY ROLLUP (relkind) HAVING GROUPING(relkind) OPERATOR(pg_catalog.=) 0;"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_string_body_follows_the_functions_own_path() {
    let body = "LANGUAGE sql AS $$ SELECT lower(x) $$;";
    let trusted = format!(
        "SET search_path = pg_catalog, pg_temp;
         CREATE FUNCTION public.f(x TEXT) RETURNS TEXT SET search_path = pg_catalog, pg_temp {body}"
    );
    assert_eq!(unqualified(&trusted), Vec::<String>::new());
    let callers = format!(
        "SET search_path = pg_catalog, pg_temp; CREATE FUNCTION public.f(x TEXT) RETURNS TEXT {body}"
    );
    assert_eq!(unqualified(&callers), ["lower"]);
    let current = format!(
        "SET search_path = pg_catalog, pg_temp;
         CREATE FUNCTION public.f(x TEXT) RETURNS TEXT SET search_path FROM CURRENT {body}"
    );
    assert_eq!(unqualified(&current), Vec::<String>::new());
    assert_eq!(
        unqualified(&format!(
            "CREATE FUNCTION public.f(x TEXT) RETURNS TEXT SET search_path FROM CURRENT {body}"
        )),
        ["lower"]
    );
    assert_eq!(
        unqualified(
            "SET search_path = pg_catalog, pg_temp;
             CREATE PROCEDURE public.p() LANGUAGE sql AS $$ SELECT lower('a') $$;"
        ),
        ["lower"]
    );
}

#[test]
fn simple_case_under_an_untrusted_path_is_reported() {
    let case = "SELECT CASE 1 WHEN 1 THEN 'one' END;";
    let findings = |sql: &str| script_findings(SimpleCaseUnderUnsafeSearchPath::default(), sql);
    assert_eq!(findings(case), ["CASE 1 WHEN 1 THEN 'one' END"]);
    assert_eq!(
        findings(&format!("SET search_path = pg_catalog, pg_temp; {case}")),
        Vec::<String>::new()
    );
    assert_eq!(
        findings("SELECT CASE WHEN 1 = 1 THEN 'one' END;"),
        Vec::<String>::new()
    );
}

fn replacement(sql: &str) -> Vec<String> {
    script_findings(ReplacementWithoutTrustedCreation::default(), sql)
}

#[test]
fn a_replacement_is_excused_by_an_earlier_unconditional_creation() {
    let function =
        "CREATE OR REPLACE FUNCTION public.f(x INT) RETURNS INT LANGUAGE sql AS 'SELECT 1';";
    assert_eq!(replacement(function), ["function public.f(integer)"]);
    assert_eq!(
        replacement(&format!(
            "CREATE FUNCTION public.f(x pg_catalog.int4) RETURNS INT LANGUAGE sql AS 'SELECT 2'; {function}"
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        replacement(&format!(
            "CREATE FUNCTION public.f(x TEXT) RETURNS INT LANGUAGE sql AS 'SELECT 2'; {function}"
        )),
        ["function public.f(integer)"]
    );
    assert_eq!(
        replacement(
            "CREATE SCHEMA app; CREATE OR REPLACE VIEW app.v AS SELECT 1 AS one;
             CREATE TABLE public.t (id INT);
             CREATE FUNCTION public.g() RETURNS TRIGGER LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
             CREATE OR REPLACE TRIGGER tr BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION public.g();"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        replacement(
            "CREATE OR REPLACE VIEW public.v AS SELECT 1 AS one; CREATE VIEW public.w AS SELECT 1 AS one;"
        ),
        ["view public.v"]
    );
    assert_eq!(
        replacement(
            "CREATE FUNCTION public.h(x CHARACTER VARYING(10), y NUMERIC(10, 2)) RETURNS INT LANGUAGE sql AS 'SELECT 1';
             CREATE OR REPLACE FUNCTION public.h(x VARCHAR, y DECIMAL) RETURNS INT LANGUAGE sql AS 'SELECT 2';"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        replacement(
            "CREATE OR REPLACE TEMP VIEW v AS SELECT 1 AS one;
             CREATE TEMP VIEW w AS SELECT 1 AS one; CREATE OR REPLACE VIEW w AS SELECT 2 AS one;"
        ),
        ["view w"]
    );
}

fn conditional(sql: &str) -> Vec<String> {
    script_findings(ConditionalCreationWithoutTrustedSchema::default(), sql)
}

#[test]
fn guarded_creation_outside_a_created_schema_is_reported() {
    assert_eq!(
        conditional(
            "CREATE SCHEMA IF NOT EXISTS app;
             CREATE TABLE IF NOT EXISTS app.t (id INT);
             CREATE SEQUENCE IF NOT EXISTS public.s;
             CREATE INDEX IF NOT EXISTS t_id ON app.t (id);
             CREATE TABLE IF NOT EXISTS public.snapshot AS SELECT 1 AS one;"
        ),
        [
            "schema app",
            "table app.t",
            "sequence public.s",
            "index t_id on app.t",
            "table public.snapshot"
        ]
    );
    assert_eq!(
        conditional(
            "CREATE SCHEMA app; CREATE SCHEMA IF NOT EXISTS app;
             CREATE TABLE IF NOT EXISTS app.t (id INT);
             CREATE INDEX IF NOT EXISTS t_id ON app.t (id);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_guarded_server_is_reported_whatever_its_schema() {
    assert_eq!(
        conditional(
            "CREATE SCHEMA app; CREATE FOREIGN DATA WRAPPER w NO HANDLER;
             CREATE SERVER IF NOT EXISTS s FOREIGN DATA WRAPPER w;"
        ),
        ["server s"]
    );
}

#[test]
fn guarded_foreign_tables_and_collations_are_reported() {
    assert_eq!(
        conditional(
            "CREATE FOREIGN DATA WRAPPER w NO HANDLER; CREATE SERVER s FOREIGN DATA WRAPPER w;
             CREATE FOREIGN TABLE IF NOT EXISTS public.ft (id INT) SERVER s;
             CREATE COLLATION IF NOT EXISTS public.c (provider = icu, locale = 'und');"
        ),
        ["foreign table public.ft", "collation public.c"]
    );
}

#[test]
fn a_misquoted_path_is_reported_where_it_is_set() {
    let findings = |sql: &str| script_findings(MisquotedSearchPath::default(), sql);
    for sql in [
        "SET search_path = \"pg_catalog, pg_temp\";",
        "SET search_path = 'pg_catalog, pg_temp';",
        "CREATE FUNCTION f() RETURNS INT LANGUAGE sql SET search_path = \"pg_catalog, pg_temp\" AS 'SELECT 1';",
        "CREATE ROLE r; ALTER ROLE r SET search_path = \"pg_catalog, pg_temp\";",
    ] {
        assert_eq!(findings(sql), ["\"pg_catalog, pg_temp\""], "{sql}");
    }
    assert_eq!(
        findings("SET search_path = \"app\", pg_temp;"),
        Vec::<String>::new()
    );
}

#[test]
fn only_a_repeated_function_path_is_reported() {
    let findings = |sql: &str| script_findings(RepeatedFunctionSearchPath::default(), sql);
    assert_eq!(
        findings(
            "CREATE FUNCTION f() RETURNS INT LANGUAGE sql SET search_path = pg_catalog, pg_temp
             SET work_mem = '64MB' SET search_path = public AS 'SELECT 1';"
        ),
        ["SET search_path = pg_catalog, pg_temp SET search_path = public"]
    );
    assert_eq!(
        findings(
            "CREATE FUNCTION f() RETURNS INT LANGUAGE sql SET search_path = pg_catalog, pg_temp
             SET work_mem = '64MB' AS 'SELECT 1';"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_statement_allowance_excuses_a_script_finding_and_goes_stale_once_fixed() {
    let mut constrainer: GenericConstrainer<ParserDB> = MisquotedSearchPath::default().into();
    constrainer.allow_statement("misquoted_search_path", "SET search_path = \"a, b\"");
    let check = |sql: &str| {
        let database = crate::common::parse(sql);
        let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap();
        (
            constrainer.script_diagnostics(&database, &statements).len(),
            constrainer.diagnostics(&database).len(),
        )
    };
    assert_eq!(check("SET search_path = \"a, b\";"), (0, 0));
    let mut stale: GenericConstrainer<ParserDB> = MisquotedSearchPath::default().into();
    stale.allow_statement("misquoted_search_path", "SET search_path = a, b");
    let database = crate::common::parse("SELECT 1;");
    assert!(matches!(
        stale.diagnostics(&database).as_slice(),
        [Error::UnusedAllowance(_)]
    ));
}
