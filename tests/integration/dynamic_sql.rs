//! PL/pgSQL commands built from unescaped string values.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const TABLE: &str = "CREATE TABLE items (name TEXT, n INT);";

/// Functions reported through the public constrainer API.
fn reported(sql: &str) -> Vec<String> {
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{TABLE} {sql}")).expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = DynamicSqlInjection::default().into();
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

/// A PL/pgSQL function of `arguments` whose body is `body`.
fn function(arguments: &str, body: &str) -> String {
    format!("CREATE FUNCTION f({arguments}) RETURNS BIGINT LANGUAGE plpgsql AS $$ {body} $$;")
}

#[test]
fn string_values_built_into_a_command_are_reported() {
    for (arguments, body) in [
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = ''' || p || '''' INTO r; RETURN r; END",
        ),
        (
            "p VARCHAR",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = ''' || p || '''' INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE q TEXT := p; r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM ' || q INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE format('SELECT count(*) FROM %s', p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE format('SELECT %2$s FROM %1$s', 'items', p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE concat('SELECT count(*) FROM ', p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM ' || lower(p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM ' || p::VARCHAR INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "BEGIN RETURN QUERY EXECUTE 'SELECT count(*) FROM ' || p; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT := 0; c RECORD; BEGIN FOR c IN EXECUTE 'SELECT n FROM ' || p LOOP r := r + 1; END LOOP; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; c REFCURSOR; BEGIN OPEN c FOR EXECUTE 'SELECT count(*) FROM ' || p; FETCH c INTO r; RETURN r; END",
        ),
    ] {
        assert_eq!(
            reported(&function(arguments, body)),
            [format!("f({})", arguments.trim_start_matches("p ")).as_str()],
            "{body}"
        );
    }
}

#[test]
fn a_string_domain_is_a_string() {
    assert_eq!(
        reported(&format!(
            "CREATE DOMAIN label AS TEXT; {}",
            function(
                "p label",
                "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM ' || p INTO r; RETURN r; END",
            )
        )),
        ["f(label)"]
    );
}

#[test]
fn a_user_function_named_like_a_quoting_function_does_not_escape() {
    assert_eq!(
        reported(&format!(
            "CREATE FUNCTION public.quote_literal(v TEXT) RETURNS TEXT LANGUAGE sql AS 'SELECT v';
            {}",
            function(
                "p TEXT",
                "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = ' || public.quote_literal(p) INTO r; RETURN r; END",
            )
        )),
        ["f(TEXT)"]
    );
}

#[test]
fn escaped_bound_and_non_string_values_are_not_reported() {
    for (arguments, body) in [
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = $1' INTO r USING p; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = ' || quote_literal(p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = ' || quote_nullable(p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM ' || quote_ident(p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE format('SELECT count(*) FROM items WHERE name = %L', p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE format('SELECT count(*) FROM %I', p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE format('SELECT ''%%s'' FROM %1$I', p) INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE format('SELECT %s FROM %I', 'n', p) INTO r; RETURN r; END",
        ),
        (
            "p INT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE n = ' || p INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE n = ' || p::INT INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items' INTO r; RETURN r; END",
        ),
        (
            "p TEXT",
            "DECLARE r BIGINT; BEGIN DECLARE p INT := 1; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE n = ' || p INTO r; END; RETURN r; END",
        ),
    ] {
        assert!(reported(&function(arguments, body)).is_empty(), "{body}");
    }
}

#[test]
fn sql_functions_have_no_dynamic_commands() {
    let found = reported(
        "CREATE FUNCTION g(p TEXT) RETURNS BIGINT LANGUAGE sql
        AS 'SELECT count(*) FROM items WHERE name = p';",
    );
    assert_eq!(found, Vec::<String>::new());
}
