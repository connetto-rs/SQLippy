//! Statements non-volatile function bodies cannot run.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

fn findings(function: &str) -> Vec<String> {
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("CREATE TABLE audit (n INT); {function}"))
            .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = WritingNonVolatileFunction::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Correctness);
                violation.to_string()
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn sql_and_plpgsql_writes_are_reported_once() {
    for volatility in ["STABLE", "IMMUTABLE"] {
        for (language, body, kind) in [
            ("sql", "INSERT INTO audit VALUES (5)", "INSERT"),
            (
                "sql",
                "WITH d AS (INSERT INTO audit VALUES (5) RETURNING n) SELECT count(*) FROM d",
                "INSERT",
            ),
            (
                "sql",
                "WITH d AS (DELETE FROM audit RETURNING n) SELECT 1::bigint",
                "DELETE",
            ),
            (
                "plpgsql",
                "BEGIN INSERT INTO audit VALUES (6); END",
                "INSERT",
            ),
            (
                "plpgsql",
                "DECLARE x INT; BEGIN WITH d AS (INSERT INTO audit VALUES (5) RETURNING n) SELECT n INTO x FROM d; END",
                "INSERT",
            ),
            ("sql", "UPDATE audit SET n = 7", "UPDATE"),
            ("sql", "DELETE FROM audit", "DELETE"),
            (
                "sql",
                "MERGE INTO audit USING (SELECT 1 AS n) AS source ON audit.n = source.n WHEN MATCHED THEN DELETE",
                "MERGE",
            ),
            (
                "sql",
                "WITH d AS (UPDATE audit SET n = 7 RETURNING n) SELECT n FROM d",
                "UPDATE",
            ),
            (
                "sql",
                "WITH d AS (MERGE INTO audit USING (SELECT 1 AS n) AS source ON audit.n = source.n WHEN MATCHED THEN DELETE RETURNING audit.n) SELECT n FROM d",
                "MERGE",
            ),
            (
                "sql",
                "INSERT INTO audit VALUES (5); DELETE FROM audit",
                "INSERT",
            ),
        ] {
            let function = format!(
                "CREATE FUNCTION f() RETURNS BIGINT LANGUAGE {language} {volatility} AS $body${body}$body$;"
            );
            let found = findings(&function);
            assert_eq!(found.len(), 1, "{function}");
            assert!(
                found[0].contains(&format!(
                    "Function 'f()' is declared {volatility} but runs {kind}"
                )),
                "{}",
                found[0]
            );
        }
    }
}

#[test]
fn atomic_writes_are_reported() {
    let found = findings(
        "CREATE FUNCTION f() RETURNS VOID LANGUAGE sql STABLE BEGIN ATOMIC INSERT INTO audit VALUES (5); END;",
    );
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("runs INSERT"));
}

#[test]
fn sql_locking_reads_are_reported() {
    // PostgreSQL 18 rejects calls with either locking strength in a non-volatile SQL body.
    for volatility in ["STABLE", "IMMUTABLE"] {
        for strength in ["UPDATE", "SHARE"] {
            let function = format!(
                "CREATE FUNCTION f() RETURNS INT LANGUAGE sql {volatility} AS 'SELECT n FROM audit FOR {strength}';"
            );
            let found = findings(&function);
            assert_eq!(found.len(), 1, "{function}");
            assert!(found[0].contains(&format!("runs SELECT FOR {strength}")));
        }
    }
}

#[test]
fn strongest_lock_names_the_statement() {
    // PostgreSQL 18 names `SELECT FOR UPDATE` when the same table has both strengths.
    let found = findings(
        "CREATE FUNCTION f() RETURNS INT LANGUAGE sql STABLE AS 'SELECT n FROM audit FOR SHARE FOR UPDATE';",
    );
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("runs SELECT FOR UPDATE"));
}

#[test]
fn atomic_locking_reads_are_reported() {
    // PostgreSQL 18 rejects locking reads when calling a non-volatile atomic body.
    for volatility in ["STABLE", "IMMUTABLE"] {
        for strength in ["UPDATE", "SHARE"] {
            let function = format!(
                "CREATE FUNCTION f() RETURNS INT LANGUAGE sql {volatility} BEGIN ATOMIC SELECT n FROM audit FOR {strength}; END;"
            );
            let found = findings(&function);
            assert_eq!(found.len(), 1, "{function}");
            assert!(found[0].contains(&format!("runs SELECT FOR {strength}")));
        }
    }
}

#[test]
fn plpgsql_locking_reads_are_reported() {
    // PostgreSQL 18 rejects `SELECT INTO` with row locks when the statement is reached.
    for volatility in ["STABLE", "IMMUTABLE"] {
        for strength in ["UPDATE", "SHARE"] {
            let function = format!(
                "CREATE FUNCTION f() RETURNS INT LANGUAGE plpgsql {volatility} AS $$ DECLARE selected INT; BEGIN SELECT n INTO selected FROM audit FOR {strength}; RETURN selected; END $$;"
            );
            let found = findings(&function);
            assert_eq!(found.len(), 1, "{function}");
            assert!(found[0].contains(&format!("runs SELECT FOR {strength}")));
        }
    }
}

#[test]
fn truncate_is_reported() {
    // PostgreSQL 18 rejects `TRUNCATE TABLE` when a non-volatile SQL or PL/pgSQL body reaches it.
    for volatility in ["STABLE", "IMMUTABLE"] {
        for (language, body) in [
            ("sql", "TRUNCATE audit"),
            ("plpgsql", "BEGIN TRUNCATE audit; END"),
        ] {
            let function = format!(
                "CREATE FUNCTION f() RETURNS VOID LANGUAGE {language} {volatility} AS $body${body}$body$;"
            );
            let found = findings(&function);
            assert_eq!(found.len(), 1, "{function}");
            assert!(found[0].contains("runs TRUNCATE TABLE"));
        }
    }
}

#[test]
fn utility_statements_are_reported() {
    // PostgreSQL 18 refuses each call with `<command> is not allowed in a non-volatile function`.
    for volatility in ["STABLE", "IMMUTABLE"] {
        for (language, body, quoted) in [
            ("sql", "SET LOCAL work_mem = '8MB'; SELECT 1", "SET"),
            ("sql", "NOTIFY ch; SELECT 1", "NOTIFY"),
            ("sql", "LOCK TABLE audit; SELECT 1", "LOCK"),
            (
                "sql",
                "CREATE TEMPORARY TABLE x (n INT); SELECT 1",
                "CREATE",
            ),
            ("sql", "CALL noop(); SELECT 1", "CALL"),
            (
                "plpgsql",
                "BEGIN SET LOCAL work_mem = '8MB'; RETURN 1; END",
                "SET",
            ),
            ("plpgsql", "BEGIN NOTIFY ch; RETURN 1; END", "NOTIFY"),
            ("plpgsql", "BEGIN LOCK TABLE audit; RETURN 1; END", "LOCK"),
            (
                "plpgsql",
                "BEGIN CREATE TEMPORARY TABLE x (n INT); RETURN 1; END",
                "CREATE",
            ),
            ("plpgsql", "BEGIN CALL noop(); RETURN 1; END", "CALL"),
            ("plpgsql", "BEGIN SHOW work_mem; RETURN 1; END", "SHOW"),
        ] {
            let function = format!(
                "CREATE FUNCTION f() RETURNS INT LANGUAGE {language} {volatility} AS $body${body}$body$;"
            );
            let found = findings(&function);
            assert_eq!(found.len(), 1, "{function}");
            assert!(
                found[0].contains(&format!("runs `{quoted}")),
                "{}",
                found[0]
            );
        }
    }
}

#[test]
fn select_into_a_table_is_reported() {
    // PostgreSQL 18 refuses the call with `SELECT INTO is not allowed in a non-volatile function`.
    let found = findings(
        "CREATE FUNCTION f() RETURNS INT LANGUAGE sql STABLE AS 'SELECT 1 AS n INTO TEMPORARY made; SELECT 1';",
    );
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("runs SELECT INTO"));
}

#[test]
fn plain_selects_are_permitted() {
    for volatility in ["STABLE", "IMMUTABLE"] {
        for body in [
            format!("LANGUAGE sql {volatility} AS 'SELECT n FROM audit'"),
            format!("LANGUAGE sql {volatility} BEGIN ATOMIC SELECT n FROM audit; END"),
            format!(
                "LANGUAGE plpgsql {volatility} AS $$ DECLARE selected INT; BEGIN SELECT n INTO selected FROM audit; RETURN selected; END $$"
            ),
            format!(
                "LANGUAGE plpgsql {volatility} AS $$ BEGIN PERFORM set_config('work_mem', '8MB', true); RETURN 1; END $$"
            ),
        ] {
            assert!(
                findings(&format!("CREATE FUNCTION f() RETURNS INT {body};")).is_empty(),
                "{body}"
            );
        }
    }
}

#[test]
fn permitted_and_unreadable_bodies_are_skipped() {
    for function in [
        "CREATE FUNCTION f() RETURNS VOID LANGUAGE sql VOLATILE AS 'INSERT INTO audit VALUES (5)';",
        "CREATE FUNCTION f() RETURNS INT LANGUAGE sql STABLE AS 'SELECT n FROM audit';",
        "CREATE FUNCTION f() RETURNS VOID LANGUAGE sql STABLE AS 'not valid sql';",
        "CREATE FUNCTION f() RETURNS VOID LANGUAGE plpgsql STABLE AS 'not valid plpgsql';",
        "CREATE FUNCTION pg_catalog.f() RETURNS VOID LANGUAGE sql STABLE AS 'INSERT INTO audit VALUES (5)';",
    ] {
        assert!(findings(function).is_empty(), "{function}");
    }
}

#[test]
fn default_constrainer_reports_non_volatile_writes() {
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE audit (n INT); CREATE FUNCTION f() RETURNS VOID LANGUAGE sql STABLE AS 'INSERT INTO audit VALUES (5)';",
    ).expect("schema parses");
    assert!(DefaultConstrainer::<ParserDB>::default().diagnostics(&database).iter().any(|error| matches!(error, Error::Violation(violation) if violation.rule().name == "writing_non_volatile_function" && violation.rule().group == LintGroup::Correctness)));
}
