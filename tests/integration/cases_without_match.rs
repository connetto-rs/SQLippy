//! PL/pgSQL `CASE` statements without `ELSE` that a path ends with no
//! `WHEN` matched.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for the PL/pgSQL `body` of a function taking
/// `x INT` and returning `INT`.
fn findings(body: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE FUNCTION pick(x INT) RETURNS INT LANGUAGE plpgsql AS $$ {body} $$;"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = CaseWithoutMatch::default().into();
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
fn a_case_some_path_ends_unmatched_is_reported() {
    for (body, opening) in [
        (
            "BEGIN CASE x WHEN 1 THEN RETURN 1; WHEN 2 THEN RETURN 2; END CASE; END",
            "CASE x",
        ),
        (
            "BEGIN CASE WHEN x > 0 THEN RETURN 1; WHEN x <= 0 THEN RETURN 0; END CASE; END",
            "CASE WHEN x > 0",
        ),
        (
            "DECLARE n INT := 3; BEGIN CASE n WHEN 1 THEN RETURN 1; WHEN 2 THEN RETURN 2; END CASE; END",
            "CASE n",
        ),
    ] {
        assert_eq!(
            findings(body),
            [format!(
                "In function 'pick(INT)', a path reaches the end of the CASE statement `{opening}` with no WHEN matched, where PostgreSQL raises case_not_found."
            )],
            "{body}"
        );
    }
}

#[test]
fn a_case_every_path_matches_is_not_reported() {
    for body in [
        "BEGIN CASE x WHEN 1 THEN RETURN 1; ELSE RETURN 0; END CASE; END",
        "DECLARE n INT := 1; BEGIN CASE n WHEN 1 THEN RETURN 1; WHEN 2 THEN RETURN 2; END CASE; END",
        "BEGIN IF x IS NULL THEN RETURN 0; END IF; CASE WHEN x > 0 THEN RETURN 1; WHEN x <= 0 THEN RETURN 0; END CASE; END",
        "BEGIN RETURN 0; CASE x WHEN 1 THEN RETURN 1; END CASE; END",
    ] {
        assert_eq!(findings(body), Vec::<String>::new(), "{body}");
    }
}
