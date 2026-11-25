//! PL/pgSQL `LOOP` and `WHILE` loops a path enters and no path leaves.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for the PL/pgSQL `body` of a function taking
/// `x INT` and returning `INT`.
fn findings(body: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE FUNCTION spin(x INT) RETURNS INT LANGUAGE plpgsql AS $$ {body} $$;"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = UnendingLoop::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Suspicious);
                violation.message().to_owned()
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn a_loop_nothing_leaves_is_reported() {
    for (body, described) in [
        ("BEGIN LOOP PERFORM pg_sleep(1); END LOOP; END", "the LOOP"),
        (
            "BEGIN <<waiting>> LOOP PERFORM pg_sleep(1); END LOOP; END",
            "the LOOP labelled `waiting`",
        ),
        (
            "DECLARE n INT := 0; BEGIN WHILE n < 10 LOOP EXIT WHEN n > 3; END LOOP; RETURN n; END",
            "the WHILE loop on `n < 10`",
        ),
        (
            "BEGIN LOOP BEGIN RAISE EXCEPTION 'retry'; EXCEPTION WHEN OTHERS THEN NULL; END; END LOOP; END",
            "the LOOP",
        ),
    ] {
        assert_eq!(
            findings(body),
            [format!(
                "In function 'spin(INT)', {described} never ends once the body enters it."
            )],
            "{body}"
        );
    }
}

#[test]
fn a_loop_some_path_leaves_is_not_reported() {
    for body in [
        "DECLARE r RECORD; BEGIN WHILE true LOOP SELECT 1 INTO r; EXIT WHEN FOUND; END LOOP; RETURN 0; END",
        "DECLARE i INT := 0; BEGIN WHILE i < 10 LOOP i := i + 1; END LOOP; RETURN i; END",
        "BEGIN LOOP RAISE EXCEPTION 'stop'; END LOOP; END",
        "BEGIN LOOP IF x > 0 THEN RETURN x; END IF; END LOOP; END",
        "BEGIN <<outer>> LOOP LOOP EXIT outer; END LOOP; END LOOP; RETURN 0; END",
        "BEGIN FOR i IN 1..10 LOOP PERFORM pg_sleep(1); END LOOP; RETURN 0; END",
        "BEGIN RETURN 0; LOOP PERFORM pg_sleep(1); END LOOP; END",
    ] {
        assert_eq!(findings(body), Vec::<String>::new(), "{body}");
    }
}

#[test]
fn a_loop_inside_a_loop_nothing_leaves_is_reported_alone() {
    assert_eq!(
        findings(
            "BEGIN <<outer>> LOOP EXIT outer WHEN x > 0; <<inner>> LOOP PERFORM pg_sleep(1); END LOOP; END LOOP; RETURN 0; END"
        ),
        ["In function 'spin(INT)', the LOOP labelled `inner` never ends once the body enters it."]
    );
}
