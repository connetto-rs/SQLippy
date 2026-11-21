//! Standing default privileges granting table or sequence privileges to
//! `PUBLIC`, observed through the public constrainer API.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Defaults `PublicDefaultPrivilege` reports on `sql`.
fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = PublicDefaultPrivilege::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let mut objects: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    objects.sort();
    objects
}

#[test]
fn table_and_sequence_defaults_for_public_are_reported() {
    assert_eq!(
        reported(
            "CREATE ROLE owner;
             CREATE SCHEMA api;
             ALTER DEFAULT PRIVILEGES IN SCHEMA api GRANT SELECT, INSERT ON TABLES TO PUBLIC;
             ALTER DEFAULT PRIVILEGES FOR ROLE owner GRANT UPDATE ON TABLES TO PUBLIC;
             ALTER DEFAULT PRIVILEGES IN SCHEMA api GRANT USAGE ON SEQUENCES TO PUBLIC;"
        ),
        [
            "DEFAULT PRIVILEGES FOR ROLE owner ON TABLES",
            "DEFAULT PRIVILEGES IN SCHEMA api ON SEQUENCES",
            "DEFAULT PRIVILEGES IN SCHEMA api ON TABLES",
        ]
    );
}

#[test]
fn defaults_leaving_public_out_are_not_reported() {
    for sql in [
        "CREATE ROLE app; ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO app;",
        "ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO PUBLIC;",
        "ALTER DEFAULT PRIVILEGES GRANT USAGE ON TYPES TO PUBLIC;",
        "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC;
         ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM PUBLIC;",
        "CREATE TABLE notes (id INT PRIMARY KEY); GRANT SELECT ON notes TO PUBLIC;",
    ] {
        assert_eq!(reported(sql), Vec::<String>::new(), "{sql}");
    }
}
