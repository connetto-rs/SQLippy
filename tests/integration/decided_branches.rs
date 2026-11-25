//! PL/pgSQL conditions always true where the body tests them, ahead of
//! branches that then never run.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for the PL/pgSQL `body` of a function taking
/// `x INT` and returning `INT`.
fn findings(body: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE FUNCTION pick(x INT) RETURNS INT LANGUAGE plpgsql AS $$ {body} $$;"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = DecidedBranch::default().into();
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
fn a_condition_always_true_ahead_of_another_branch_is_reported() {
    for (body, condition) in [
        (
            "DECLARE n INT := 3; BEGIN IF n > 1 THEN RETURN 1; ELSE RETURN 0; END IF; END",
            "the IF condition `n > 1`",
        ),
        (
            "BEGIN IF x IS NULL THEN RETURN 0; ELSIF x IS NOT NULL THEN RETURN 1; ELSE RETURN 2; END IF; END",
            "the ELSIF condition `x IS NOT NULL`",
        ),
        (
            "BEGIN CASE WHEN x > 0 THEN RETURN 1; WHEN x <= 0 OR x IS NULL THEN RETURN 0; WHEN x = 7 THEN RETURN 7; END CASE; END",
            "the WHEN condition `x <= 0 OR x IS NULL`",
        ),
    ] {
        assert_eq!(
            findings(body),
            [format!(
                "In function 'pick(INT)', {condition} is always true where the body tests it, so the branches after it never run."
            )],
            "{body}"
        );
    }
}

#[test]
fn a_condition_some_path_makes_false_or_last_is_not_reported() {
    for body in [
        "BEGIN IF x > 1 THEN RETURN 1; ELSE RETURN 0; END IF; END",
        "DECLARE n INT := 3; BEGIN IF n > 1 THEN RETURN 1; END IF; RETURN 0; END",
        "BEGIN IF x IS NULL THEN RETURN 0; ELSIF x IS NOT NULL THEN RETURN 1; END IF; RETURN 2; END",
        "DECLARE n INT := 3; BEGIN IF x > 0 THEN n := 0; END IF; IF n > 1 THEN RETURN 1; ELSE RETURN 0; END IF; END",
    ] {
        assert_eq!(findings(body), Vec::<String>::new(), "{body}");
    }
}
