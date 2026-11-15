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
            "TEXT",
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = ''' || $1 || '''' INTO r; RETURN r; END",
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

/// A trigger function splicing `NEW.name` into its command, run by `triggers`.
fn trigger_function(triggers: &str) -> String {
    format!(
        "CREATE FUNCTION audit() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE r BIGINT;
        BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = ''' || NEW.name || '''' INTO r; RETURN NEW; END $$;
        {triggers}"
    )
}

#[test]
fn a_trigger_row_field_is_a_string_when_any_table_makes_it_one() {
    for triggers in [
        "CREATE TRIGGER on_items BEFORE INSERT ON items FOR EACH ROW EXECUTE FUNCTION audit();",
        "CREATE TABLE counted (name INT);
        CREATE TRIGGER on_counted BEFORE INSERT ON counted FOR EACH ROW EXECUTE FUNCTION audit();
        CREATE TRIGGER on_items BEFORE INSERT ON items FOR EACH STATEMENT EXECUTE FUNCTION audit();",
    ] {
        assert_eq!(reported(&trigger_function(triggers)), ["audit()"], "{triggers}");
    }
}

#[test]
fn a_trigger_row_field_of_no_string_table_is_not_reported() {
    for triggers in [
        "",
        "CREATE TABLE counted (name INT);
        CREATE TRIGGER on_counted BEFORE INSERT ON counted FOR EACH ROW EXECUTE FUNCTION audit();",
        "CREATE TABLE nameless (id INT);
        CREATE TRIGGER on_nameless BEFORE INSERT ON nameless FOR EACH ROW EXECUTE FUNCTION audit();",
    ] {
        assert_eq!(reported(&trigger_function(triggers)), Vec::<String>::new(), "{triggers}");
    }
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
fn sql_functions_without_sql_text_calls_have_no_dynamic_commands() {
    let found = reported(
        "CREATE FUNCTION g(p TEXT) RETURNS BIGINT LANGUAGE sql
        AS 'SELECT count(*) FROM items WHERE name = p';",
    );
    assert_eq!(found, Vec::<String>::new());
}

#[test]
fn catalog_functions_running_sql_text_are_reported() {
    for sql in [
        "CREATE FUNCTION g(p TEXT) RETURNS xml LANGUAGE plpgsql AS $$ BEGIN
        RETURN query_to_xml('SELECT * FROM items WHERE name = ''' || p || '''', false, false, ''); END $$;",
        "CREATE FUNCTION g(p TEXT) RETURNS xml LANGUAGE plpgsql AS $$ DECLARE x xml; BEGIN
        x := query_to_xmlschema('SELECT * FROM items WHERE name = ''' || p || '''', false, false, ''); RETURN x; END $$;",
        "CREATE FUNCTION g(p TEXT) RETURNS xml LANGUAGE sql
        AS $$ SELECT query_to_xml_and_xmlschema('SELECT * FROM items WHERE name = ''' || p || '''', false, false, '') $$;",
        "CREATE FUNCTION g(p TEXT) RETURNS BIGINT LANGUAGE sql
        AS $$ SELECT count(*) FROM ts_stat('SELECT to_tsvector(name) FROM items WHERE name = ''' || p || '''') $$;",
        "CREATE FUNCTION g(p TEXT) RETURNS tsquery LANGUAGE sql
        AS $$ SELECT ts_rewrite('a'::tsquery, 'SELECT ''a''::tsquery, ''b''::tsquery FROM items WHERE name = ''' || p || '''') $$;",
    ] {
        assert_eq!(reported(sql), ["g(TEXT)"], "{sql}");
    }
    assert_eq!(
        reported(
            "CREATE FUNCTION g() RETURNS SETOF xml LANGUAGE sql
            AS $$ SELECT query_to_xml('SELECT ' || name, false, false, '') FROM items $$;"
        ),
        ["g()"]
    );
}

#[test]
fn quoted_values_and_text_that_is_no_sql_are_not_reported() {
    for sql in [
        "CREATE FUNCTION g(p TEXT) RETURNS xml LANGUAGE sql
        AS $$ SELECT query_to_xml(format('SELECT * FROM items WHERE name = %L', p), false, false, '') $$;",
        "CREATE FUNCTION g(p TEXT) RETURNS tsquery LANGUAGE sql
        AS $$ SELECT ts_rewrite(('a' || p)::tsquery, 'SELECT ''a''::tsquery, ''b''::tsquery') $$;",
        "CREATE FUNCTION public.query_to_xml(t TEXT, a BOOLEAN, b BOOLEAN, c TEXT) RETURNS xml LANGUAGE sql AS 'SELECT NULL::xml';
        CREATE FUNCTION g(p TEXT) RETURNS xml LANGUAGE sql
        AS $$ SELECT public.query_to_xml('SELECT ' || p, false, false, '') $$;",
        "CREATE FUNCTION g(n TEXT) RETURNS SETOF xml LANGUAGE sql
        AS $$ SELECT query_to_xml('SELECT ' || n, false, false, '') FROM items $$;",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn cursor_loop_fields_and_scalar_subqueries_take_their_query_types() {
    for (body, expected) in [
        (
            "DECLARE source CURSOR FOR SELECT name FROM items; r BIGINT; BEGIN FOR row_value IN source LOOP EXECUTE 'SELECT count(*) FROM ' || row_value.name INTO r; END LOOP; RETURN r; END",
            vec!["f()"],
        ),
        (
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM ' || (SELECT name FROM items LIMIT 1) INTO r; RETURN r; END",
            vec!["f()"],
        ),
        (
            "DECLARE source CURSOR FOR SELECT n FROM items; r BIGINT; BEGIN FOR row_value IN source LOOP EXECUTE 'SELECT count(*) FROM items WHERE n = ' || row_value.n INTO r; END LOOP; RETURN r; END",
            vec![],
        ),
        (
            "DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE n = ' || (SELECT n FROM items LIMIT 1) INTO r; RETURN r; END",
            vec![],
        ),
    ] {
        assert_eq!(reported(&function("", body)), expected, "{body}");
    }
}
