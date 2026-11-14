//! `SECURITY DEFINER` functions whose `search_path` names a schema other
//! roles may create objects in. Measured on PostgreSQL 18: a role holding
//! `CREATE` on `app` took over `lower` and `upper` inside such a function,
//! with `app` before or after `pg_catalog`.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const ROLES: &str = "CREATE ROLE admin; CREATE ROLE mallory; CREATE ROLE app_user;";

/// Messages of the findings for `sql` after the roles.
fn messages(sql: &str) -> Vec<String> {
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{ROLES}{sql}")).expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = DefinerPathCreatableSchema::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

/// A definer function in `app` running `lower` under `path`.
fn definer(path: &str) -> String {
    format!(
        "CREATE FUNCTION app.norm(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER
           SET search_path = {path} AS 'SELECT lower(x)';"
    )
}

#[test]
fn a_creating_grant_names_the_schema_and_its_creators() {
    for (setup, creators) in [
        ("GRANT CREATE ON SCHEMA app TO mallory;", "role 'mallory'"),
        (
            "GRANT USAGE, CREATE ON SCHEMA app TO mallory;",
            "role 'mallory'",
        ),
        ("GRANT ALL ON SCHEMA app TO mallory;", "role 'mallory'"),
        ("GRANT CREATE ON SCHEMA app TO PUBLIC;", "PUBLIC"),
        (
            "GRANT CREATE ON SCHEMA app TO mallory, app_user;",
            "role 'mallory', role 'app_user'",
        ),
    ] {
        assert_eq!(
            messages(&format!(
                "CREATE SCHEMA app; {setup} {}",
                definer("app, pg_catalog")
            )),
            [format!(
                "`SECURITY DEFINER` function 'norm(TEXT)' searches schema 'app', where {creators} can create objects, so a function or operator created there runs with the owner's rights."
            )],
            "{setup}"
        );
    }
}

#[test]
fn the_position_of_the_schema_in_the_path_does_not_matter() {
    for path in [
        "app, pg_catalog",
        "pg_catalog, app",
        "pg_catalog, public, app, pg_temp",
    ] {
        assert_eq!(
            messages(&format!(
                "CREATE SCHEMA app; GRANT CREATE ON SCHEMA app TO mallory; {}",
                definer(path)
            ))
            .len(),
            1,
            "{path}"
        );
    }
}

#[test]
fn a_schema_owned_by_another_role_is_reported() {
    for (setup, owner) in [
        ("CREATE SCHEMA app AUTHORIZATION app_user;", "app_user"),
        (
            "CREATE SCHEMA app AUTHORIZATION app_user; SET ROLE admin;",
            "app_user",
        ),
        (
            "SET ROLE app_user; CREATE SCHEMA app; SET ROLE admin;",
            "app_user",
        ),
    ] {
        assert_eq!(
            messages(&format!("{setup} {}", definer("app, pg_catalog"))),
            [format!(
                "`SECURITY DEFINER` function 'norm(TEXT)' searches schema 'app', where its owner '{owner}' can create objects, so a function or operator created there runs with the owner's rights."
            )],
            "{setup}"
        );
    }
}

#[test]
fn schemas_only_the_function_owner_creates_in_are_not_reported() {
    for sql in [
        format!("CREATE SCHEMA app; {}", definer("app, pg_catalog")),
        format!(
            "CREATE SCHEMA app; GRANT USAGE ON SCHEMA app TO mallory; {}",
            definer("app, pg_catalog")
        ),
        format!(
            "CREATE SCHEMA app AUTHORIZATION admin; GRANT CREATE ON SCHEMA app TO admin;
             SET ROLE admin; {}",
            definer("app, pg_catalog")
        ),
        format!(
            "CREATE SCHEMA app AUTHORIZATION app_user; {}
             ALTER FUNCTION app.norm(TEXT) OWNER TO app_user;",
            definer("app, pg_catalog")
        ),
        format!(
            "CREATE SCHEMA app; GRANT CREATE ON SCHEMA app TO mallory;
             REVOKE CREATE ON SCHEMA app FROM mallory; {}",
            definer("app, pg_catalog")
        ),
        format!("CREATE SCHEMA app; {}", definer("public, pg_catalog")),
        format!(
            "CREATE SCHEMA app; GRANT CREATE ON SCHEMA app TO mallory; {}",
            definer("\"$user\", pg_catalog, pg_temp")
        ),
        format!(
            "CREATE SCHEMA app; GRANT CREATE ON SCHEMA app TO mallory; {}",
            definer("''")
        ),
    ] {
        assert_eq!(messages(&sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn functions_resolving_names_otherwise_are_not_reported() {
    for function in [
        "CREATE FUNCTION app.norm(x TEXT) RETURNS TEXT LANGUAGE sql
           SET search_path = app, pg_catalog AS 'SELECT lower(x)';",
        "CREATE FUNCTION app.norm(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER
           SET search_path = app, pg_catalog RETURN lower(x);",
        "CREATE FUNCTION app.norm(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER
           SET search_path = app, pg_catalog BEGIN ATOMIC SELECT lower(x); END;",
    ] {
        assert_eq!(
            messages(&format!(
                "CREATE SCHEMA app; GRANT CREATE ON SCHEMA app TO mallory; {function}"
            )),
            Vec::<String>::new(),
            "{function}"
        );
    }
}
