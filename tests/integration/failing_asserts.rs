//! PL/pgSQL `ASSERT`s whose condition is never true where the body tests
//! it.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for the PL/pgSQL `body` of a function taking
/// `x INT` and returning `INT`.
fn findings(body: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE FUNCTION pick(x INT) RETURNS INT LANGUAGE plpgsql AS $$ {body} $$;"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = FailingAssert::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Correctness);
                violation.message().to_owned()
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn an_assert_never_true_where_it_runs_is_reported() {
    for (body, condition) in [
        (
            "DECLARE n INT := 3; BEGIN ASSERT n > 5; RETURN n; END",
            "n > 5",
        ),
        (
            "DECLARE v INT; BEGIN ASSERT v IS NOT NULL, 'v unset'; RETURN v; END",
            "v IS NOT NULL",
        ),
        (
            "BEGIN IF x > 0 THEN ASSERT x < 0; END IF; RETURN x; END",
            "x < 0",
        ),
    ] {
        assert_eq!(
            findings(body),
            [format!(
                "In function 'pick(INT)', the ASSERT condition `{condition}` is never true where the body tests it, so the ASSERT fails every time the body reaches it."
            )],
            "{body}"
        );
    }
}

#[test]
fn an_assert_some_path_makes_true_is_not_reported() {
    for body in [
        "BEGIN ASSERT x > 0; RETURN x; END",
        "DECLARE v INT; BEGIN IF x > 0 THEN v := x; END IF; ASSERT v IS NOT NULL; RETURN v; END",
        "DECLARE n INT := 3; BEGIN RETURN n; ASSERT n > 5; END",
        "DECLARE d INT := 0; BEGIN ASSERT 5 / d = 1; RETURN 0; END",
    ] {
        assert_eq!(findings(body), Vec::<String>::new(), "{body}");
    }
}
