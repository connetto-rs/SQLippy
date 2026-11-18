//! Functions without a fixed, trusted `search_path`.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Functions `rule` reports, through the public constrainer API.
fn reported(rule: impl Into<GenericConstrainer<ParserDB>>, sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = rule.into();
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

/// Functions `FunctionWithoutSafeSearchPath` reports.
fn unsafe_paths(sql: &str) -> Vec<String> {
    reported(FunctionWithoutSafeSearchPath::default(), sql)
}

#[test]
fn every_kind_of_body_without_a_path_is_reported() {
    for function in [
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE sql AS 'SELECT lower(x)';",
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE sql AS 'SELECT pg_catalog.lower(x)';",
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE sql RETURN lower(x);",
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE plpgsql AS $$ BEGIN RETURN lower(x); END $$;",
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER RETURN lower(x);",
    ] {
        assert_eq!(unsafe_paths(function).len(), 1, "{function}");
    }
}

#[test]
fn a_trusted_fixed_path_is_not_reported() {
    for function in [
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE sql SET search_path = '' AS 'SELECT pg_catalog.lower(x)';",
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE sql SET search_path = pg_catalog, pg_temp AS 'SELECT lower(x)';",
        "CREATE SCHEMA app; CREATE FUNCTION app.f(x TEXT) RETURNS TEXT LANGUAGE sql SET search_path = app, pg_temp AS 'SELECT lower(x)';",
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE sql AS 'SELECT lower(x)'; ALTER FUNCTION f(TEXT) SET search_path = pg_catalog, pg_temp;",
    ] {
        assert_eq!(unsafe_paths(function), Vec::<String>::new(), "{function}");
    }
}

#[test]
fn a_path_searching_the_temporary_schema_before_its_end_is_reported() {
    for path in ["pg_temp, pg_catalog", "pg_catalog", "app"] {
        assert_eq!(
            unsafe_paths(&format!(
                "CREATE SCHEMA app;
                 CREATE FUNCTION app.f(x TEXT) RETURNS TEXT LANGUAGE sql
                   SET search_path = {path} AS 'SELECT lower(x)';"
            )),
            ["f(TEXT)"],
            "{path}"
        );
    }
}

#[test]
fn a_path_searching_a_schema_another_role_creates_in_is_reported() {
    let function = "CREATE FUNCTION app.f(x TEXT) RETURNS TEXT LANGUAGE sql
                      SET search_path = app, pg_temp AS 'SELECT lower(x)';";
    assert_eq!(
        unsafe_paths(&format!(
            "CREATE ROLE mallory; CREATE SCHEMA app; GRANT CREATE ON SCHEMA app TO mallory; {function}"
        )),
        ["f(TEXT)"]
    );
    assert_eq!(
        unsafe_paths(&format!(
            "CREATE ROLE mallory; CREATE SCHEMA app; GRANT USAGE ON SCHEMA app TO mallory;
             CREATE TABLE app.t (id INT); GRANT INSERT ON app.t TO mallory; {function}"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn the_path_of_a_function_in_another_language_is_not_judged() {
    assert_eq!(
        unsafe_paths(
            "CREATE ROLE mallory; CREATE SCHEMA app; GRANT CREATE ON SCHEMA app TO mallory;
             CREATE FUNCTION app.f(x TEXT) RETURNS TEXT LANGUAGE plperl
               SET search_path = app AS 'return lc($_[0]);';"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn findings_the_default_rules_already_raise_are_left_to_them() {
    for sql in [
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER AS 'SELECT lower(x)';",
        "CREATE FUNCTION f(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER SET search_path = pg_temp, pg_catalog AS 'SELECT lower(x)';",
        "CREATE ROLE mallory; CREATE SCHEMA app; GRANT CREATE ON SCHEMA app TO mallory;
         CREATE FUNCTION app.f(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER SET search_path = app, pg_temp AS 'SELECT lower(x)';",
        "CREATE TABLE allowed (v INT);
         CREATE FUNCTION ok(x INT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT EXISTS (SELECT FROM allowed WHERE v = x)';
         CREATE TABLE docs (v INT CHECK (ok(v)));",
    ] {
        assert_eq!(unsafe_paths(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn an_aggregate_is_not_reported() {
    assert_eq!(
        unsafe_paths(
            "CREATE AGGREGATE total(INT) (SFUNC = pg_catalog.int4pl, STYPE = INT, INITCOND = '0');"
        ),
        Vec::<String>::new()
    );
}
