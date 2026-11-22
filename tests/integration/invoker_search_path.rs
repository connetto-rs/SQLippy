//! Invoker functions reached by stored schema expressions.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const FUNCTION: &str = "CREATE TABLE allowed (v INT);
CREATE FUNCTION ok(x INT) RETURNS BOOLEAN LANGUAGE sql IMMUTABLE
AS 'SELECT EXISTS (SELECT FROM allowed WHERE v = x)';";

/// Functions reported through the public constrainer API.
fn reported(sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = InvokerWithoutSearchPath::default().into();
    let mut found: Vec<_> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    found.sort();
    found
}

#[test]
fn each_stored_expression_reaches_the_invoker() {
    for site in [
        "CREATE TABLE docs (v INT); CREATE POLICY p ON docs USING (ok(v));",
        "CREATE TABLE docs (v INT); CREATE POLICY p ON docs WITH CHECK (ok(v));",
        "CREATE TABLE docs (v INT, CHECK (ok(v)));",
        "CREATE TABLE docs (v INT CHECK (ok(v)));",
        "CREATE DOMAIN checked AS INT CHECK (ok(VALUE));",
        "CREATE TABLE docs (v BOOLEAN DEFAULT ok(1));",
        "CREATE TABLE docs (v INT, valid BOOLEAN GENERATED ALWAYS AS (ok(v)) STORED);",
        "CREATE TABLE docs (v INT); CREATE INDEX idx ON docs (ok(v));",
        "CREATE TABLE docs (v INT); CREATE INDEX idx ON docs (v) WHERE ok(v);",
    ] {
        assert_eq!(
            reported(&format!("{FUNCTION} {site}")),
            ["ok(INT)"],
            "{site}"
        );
    }
}

#[test]
fn transitive_calls_and_multiple_sites_report_the_function_once() {
    assert_eq!(
        reported(&format!(
            "{FUNCTION}
        CREATE FUNCTION wrapper(x INT) RETURNS BOOLEAN LANGUAGE sql
          AS 'SELECT public.ok(x)';
        CREATE TABLE docs (v INT CHECK (wrapper(v)), valid BOOLEAN DEFAULT ok(1));
        CREATE POLICY p ON docs USING (wrapper(v));"
        )),
        ["ok(INT)"]
    );
}

#[test]
fn unqualified_function_calls_are_reported() {
    assert_eq!(
        reported(
            "CREATE FUNCTION helper(x INT) RETURNS INT LANGUAGE sql IMMUTABLE AS 'SELECT x';
        CREATE FUNCTION norm(x INT) RETURNS INT LANGUAGE sql IMMUTABLE AS 'SELECT helper(x)';
        CREATE TABLE docs (v INT); CREATE INDEX idx ON docs (norm(v));"
        ),
        ["norm(INT)"]
    );
}

#[test]
fn pinned_bound_definer_and_qualified_bodies_are_excluded() {
    for body in [
        "LANGUAGE sql AS 'SELECT EXISTS (SELECT FROM public.allowed WHERE v = x)'",
        "LANGUAGE sql SET search_path = public, pg_temp AS 'SELECT EXISTS (SELECT FROM allowed WHERE v = x)'",
        "LANGUAGE sql SET search_path FROM CURRENT AS 'SELECT EXISTS (SELECT FROM allowed WHERE v = x)'",
        "LANGUAGE sql RETURN EXISTS (SELECT FROM allowed WHERE v = x)",
        "LANGUAGE sql BEGIN ATOMIC SELECT EXISTS (SELECT FROM allowed WHERE v = x); END",
        "LANGUAGE sql SECURITY DEFINER AS 'SELECT EXISTS (SELECT FROM allowed WHERE v = x)'",
    ] {
        assert!(
            reported(&format!(
                "CREATE TABLE allowed (v INT);
            CREATE FUNCTION ok(x INT) RETURNS BOOLEAN {body};
            CREATE TABLE docs (v INT CHECK (ok(v)));"
            ))
            .is_empty(),
            "{body}"
        );
    }
}

#[test]
fn views_and_unused_functions_are_excluded() {
    for site in [
        "CREATE VIEW visible AS SELECT v FROM allowed WHERE ok(v);",
        "CREATE MATERIALIZED VIEW visible AS SELECT v FROM allowed WHERE ok(v);",
        "CREATE TABLE docs (v INT);",
        "CREATE TABLE docs (v INT CHECK (ok(v)) NOT ENFORCED);",
    ] {
        assert!(reported(&format!("{FUNCTION} {site}")).is_empty(), "{site}");
    }
}

#[test]
fn plpgsql_relations_are_reported_but_qualified_bodies_are_not() {
    for (relation, expected) in [("allowed", vec!["ok(INT)"]), ("public.allowed", vec![])] {
        assert_eq!(
            reported(&format!(
                "CREATE TABLE allowed (v INT);
            CREATE FUNCTION ok(x INT) RETURNS BOOLEAN LANGUAGE plpgsql
              AS $$ BEGIN RETURN EXISTS (SELECT FROM {relation} WHERE v = x); END $$;
            CREATE TABLE docs (v INT CHECK (ok(v)));"
            )),
            expected
        );
    }
}

#[test]
fn cte_names_and_sql_syntax_are_not_unqualified_objects() {
    assert_eq!(
        reported(
            "CREATE FUNCTION ok(x INT) RETURNS BOOLEAN LANGUAGE sql
        AS 'WITH local AS (SELECT x AS v) SELECT EXISTS (SELECT FROM local WHERE v = x)';
        CREATE TABLE docs (v INT CHECK (ok(v)));"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn stored_calls_keep_their_creation_schema() {
    for site in [
        "CREATE TABLE docs (v INT CHECK (ok(v)));",
        "CREATE DOMAIN checked AS INT CHECK (ok(VALUE));",
        "CREATE TABLE docs (v BOOLEAN DEFAULT ok(1));",
        "CREATE TABLE docs (v INT, valid BOOLEAN GENERATED ALWAYS AS (ok(v)) STORED);",
        "CREATE TABLE docs (v INT); CREATE POLICY p ON docs USING (ok(v));",
        "CREATE TABLE docs (v INT); CREATE INDEX idx ON docs (ok(v));",
        "CREATE TABLE docs (v INT); CREATE INDEX idx ON docs (v) WHERE ok(v);",
    ] {
        assert_eq!(
            reported(&format!(
                "CREATE SCHEMA earlier; CREATE SCHEMA later;
            CREATE TABLE public.allowed (v INT);
            CREATE FUNCTION earlier.ok(x INT) RETURNS BOOLEAN LANGUAGE sql IMMUTABLE
              AS 'SELECT EXISTS (SELECT FROM allowed WHERE v = x)';
            CREATE FUNCTION later.ok(x INT) RETURNS BOOLEAN LANGUAGE sql IMMUTABLE AS 'SELECT true';
            SET search_path = earlier, public; {site}
            SET search_path = later, public;"
            )),
            ["ok(INT)"],
            "{site}"
        );
    }
}

#[test]
fn bound_wrappers_keep_the_function_they_called_at_creation() {
    assert_eq!(
        reported(
            "CREATE SCHEMA earlier; CREATE SCHEMA later;
        CREATE TABLE public.allowed(v INT);
        CREATE FUNCTION earlier.ok(x INT) RETURNS BOOLEAN LANGUAGE sql
          AS 'SELECT EXISTS (SELECT FROM allowed WHERE v = x)';
        CREATE FUNCTION later.ok(x INT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT true';
        SET search_path = earlier, public;
        CREATE FUNCTION public.wrapper(x INT) RETURNS BOOLEAN LANGUAGE sql RETURN ok(x);
        CREATE TABLE public.docs(v INT CHECK (public.wrapper(v)));
        SET search_path = later, public;"
        ),
        ["ok(INT)"]
    );
}

#[test]
fn default_registry_reports_the_function_at_correctness_level() {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{FUNCTION} CREATE TABLE docs (v INT CHECK (ok(v)));"
    ))
    .unwrap();
    assert!(DefaultConstrainer::<ParserDB>::default().diagnostics(&database).iter().any(|error| {
        matches!(error, Error::Violation(violation)
            if violation.rule().name == "invoker_without_search_path" && violation.level() == Level::Deny)
    }));
}

#[test]
fn builtins_are_path_sensitive_but_qualified_calls_and_expression_forms_are_not() {
    for (body, expected) in [
        ("SELECT abs(x)", vec!["norm(INT)"]),
        ("SELECT pg_catalog.abs(x)", vec![]),
        ("SELECT coalesce(x, 0)", vec![]),
    ] {
        assert_eq!(reported(&format!(
            "CREATE FUNCTION norm(x INT) RETURNS INT LANGUAGE sql IMMUTABLE SECURITY INVOKER AS '{body}';
             CREATE TABLE docs (v INT); CREATE INDEX idx ON docs (norm(v));"
        )), expected);
    }
}

#[test]
fn procedural_locals_ctes_and_parameters_are_not_schema_names() {
    assert_eq!(
        reported(
            "CREATE FUNCTION local_only(x INT) RETURNS INT LANGUAGE plpgsql AS $$
         DECLARE local_value integer := x;
         BEGIN
           WITH local_rows AS (SELECT x AS v)
           SELECT coalesce(v, 0) INTO local_value FROM local_rows;
           RETURN local_value;
         END $$;
         CREATE TABLE docs(v INT DEFAULT local_only(1));"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn cycles_do_not_hide_reachable_functions_or_report_unreachable_ones() {
    assert_eq!(
        reported(&format!(
            "{FUNCTION}
         CREATE FUNCTION first_call(x INT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT true';
         CREATE FUNCTION second_call(x INT) RETURNS BOOLEAN LANGUAGE sql
           AS 'SELECT public.first_call(x) OR public.ok(x)';
         CREATE OR REPLACE FUNCTION first_call(x INT) RETURNS BOOLEAN LANGUAGE sql
           AS 'SELECT public.second_call(x)';
         CREATE FUNCTION unused(x INT) RETURNS INT LANGUAGE sql AS 'SELECT abs(x)';
         CREATE TABLE docs(v INT CHECK (first_call(v)));"
        )),
        ["ok(INT)"]
    );
}

#[test]
fn transitive_procedural_calls_reach_unpinned_bodies() {
    assert_eq!(
        reported(&format!(
            "{FUNCTION}
         CREATE FUNCTION wrapper(x INT) RETURNS BOOLEAN LANGUAGE plpgsql
           AS $$ BEGIN RETURN public.ok(x); END $$;
         CREATE TABLE docs(v INT CHECK (wrapper(v)));"
        )),
        ["ok(INT)"]
    );
}
