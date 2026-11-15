//! User functions marked `LEAKPROOF`.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Functions reported through the public constrainer API.
fn reported(sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = LeakproofUserFunction::default().into();
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
fn each_leakproof_overload_is_reported() {
    assert_eq!(
        reported(
            "CREATE FUNCTION same(a INT, b INT) RETURNS BOOLEAN LANGUAGE sql LEAKPROOF AS 'SELECT a = b';
            CREATE FUNCTION same(a TEXT, b TEXT) RETURNS BOOLEAN LANGUAGE sql LEAKPROOF AS 'SELECT a = b';
            CREATE FUNCTION same(a UUID, b UUID) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT a = b';"
        ),
        ["same(INT, INT)", "same(TEXT, TEXT)"]
    );
}

#[test]
fn the_last_leakproof_declaration_decides() {
    for (statements, expected) in [
        (
            "CREATE FUNCTION f(v TEXT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT true';
            ALTER FUNCTION f(TEXT) LEAKPROOF;",
            &["f(TEXT)"][..],
        ),
        (
            "CREATE FUNCTION f(v TEXT) RETURNS BOOLEAN LANGUAGE sql LEAKPROOF AS 'SELECT true';
            ALTER FUNCTION f(TEXT) NOT LEAKPROOF;",
            &[],
        ),
        (
            "CREATE FUNCTION f(v TEXT) RETURNS BOOLEAN LANGUAGE sql LEAKPROOF AS 'SELECT true';
            CREATE OR REPLACE FUNCTION f(v TEXT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT true';",
            &[],
        ),
    ] {
        assert_eq!(reported(statements), expected, "{statements}");
    }
}

#[test]
fn leakproof_builtins_used_by_policies_are_not_reported() {
    let found = reported(
        "CREATE TABLE secrets (owner TEXT, secret TEXT);
        ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
        CREATE POLICY own ON secrets USING (owner = current_user AND texteq(secret, secret));",
    );
    assert_eq!(found, Vec::<String>::new());
}
