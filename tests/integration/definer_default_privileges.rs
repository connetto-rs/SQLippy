//! `SECURITY DEFINER` functions whose creator's default privileges still
//! give `PUBLIC` `EXECUTE` on the next function, observed through the public
//! constrainer API.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const DEFINER: &str =
    "LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 42 $$";

/// Functions `DefinerSchemaWithoutDefaultRevoke` reports on `sql`.
fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> =
        DefinerSchemaWithoutDefaultRevoke::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let mut functions: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    functions.sort();
    functions
}

#[test]
fn revoking_each_function_leaves_the_next_one_executable_by_public() {
    assert_eq!(
        reported(&format!(
            "CREATE SCHEMA private;
             CREATE FUNCTION private.answer() RETURNS integer {DEFINER};
             REVOKE EXECUTE ON FUNCTION private.answer() FROM PUBLIC;
             CREATE FUNCTION private.question() RETURNS integer {DEFINER};
             REVOKE EXECUTE ON FUNCTION private.question() FROM PUBLIC;"
        )),
        ["answer()"]
    );
}

#[test]
fn a_global_default_revoke_of_the_creating_role_is_clean_whenever_it_runs() {
    let function = format!("CREATE FUNCTION private.answer() RETURNS integer {DEFINER};");
    let revoke = "ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;";
    assert_eq!(
        reported(&format!("{revoke} CREATE SCHEMA private; {function}")),
        Vec::<String>::new()
    );
    assert_eq!(
        reported(&format!("CREATE SCHEMA private; {function} {revoke}")),
        Vec::<String>::new()
    );
}

#[test]
fn a_schema_local_revoke_or_a_later_grant_back_is_reported() {
    let function = format!("CREATE FUNCTION private.answer() RETURNS integer {DEFINER};");
    assert_eq!(
        reported(&format!(
            "CREATE SCHEMA private;
             ALTER DEFAULT PRIVILEGES IN SCHEMA private REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
             {function}"
        )),
        ["answer()"]
    );
    assert_eq!(
        reported(&format!(
            "ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
             CREATE SCHEMA private;
             {function}
             ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO PUBLIC;"
        )),
        ["answer()"]
    );
}

#[test]
fn the_default_read_is_the_one_of_the_role_owning_the_function() {
    let schema = "CREATE ROLE migrator; CREATE SCHEMA private;";
    let function = format!("CREATE FUNCTION private.answer() RETURNS integer {DEFINER};");
    assert_eq!(
        reported(&format!(
            "{schema}
             ALTER DEFAULT PRIVILEGES FOR ROLE migrator REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
             SET ROLE migrator;
             {function}"
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        reported(&format!(
            "{schema}
             ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
             SET ROLE migrator;
             {function}"
        )),
        ["answer()"]
    );
}

#[test]
fn invoker_functions_are_not_reported() {
    assert_eq!(
        reported(
            "CREATE SCHEMA api;
             CREATE FUNCTION api.answer() RETURNS integer LANGUAGE sql AS $$ SELECT 42 $$;"
        ),
        Vec::<String>::new()
    );
}
