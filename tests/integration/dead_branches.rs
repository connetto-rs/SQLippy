//! PL/pgSQL branches whose condition is never true where the body tests it.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for the PL/pgSQL `body` of a function taking
/// `x INT` and returning `INT`.
fn findings(body: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE FUNCTION pick(x INT) RETURNS INT LANGUAGE plpgsql AS $$ {body} $$;"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = DeadBranch::default().into();
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
fn a_condition_never_true_where_it_is_tested_is_reported() {
    for (body, condition) in [
        (
            "DECLARE n INT := 3; BEGIN IF n > 5 THEN RETURN 1; END IF; RETURN 0; END",
            "the IF condition `n > 5`",
        ),
        (
            "BEGIN IF x > 0 THEN RETURN 1; ELSIF x > 5 THEN RETURN 2; END IF; RETURN 0; END",
            "the ELSIF condition `x > 5`",
        ),
        (
            "BEGIN CASE WHEN x IS NULL THEN RETURN 0; WHEN x IS NULL THEN RETURN 1; ELSE RETURN 2; END CASE; END",
            "the WHEN condition `x IS NULL`",
        ),
        (
            "DECLARE flag BOOLEAN; BEGIN IF flag THEN RETURN 1; END IF; RETURN 0; END",
            "the IF condition `flag`",
        ),
    ] {
        assert_eq!(
            findings(body),
            [format!(
                "In function 'pick(INT)', {condition} is never true where the body tests it, so the branch it guards never runs."
            )],
            "{body}"
        );
    }
}

#[test]
fn a_condition_some_path_makes_true_is_not_reported() {
    for body in [
        "BEGIN IF x > 5 THEN RETURN 1; END IF; RETURN 0; END",
        "DECLARE n INT := 3; BEGIN IF x > 0 THEN n := 9; END IF; IF n > 5 THEN RETURN 1; END IF; RETURN 0; END",
        "DECLARE i INT := 0; BEGIN WHILE i < 10 LOOP IF i = 5 THEN RETURN i; END IF; i := i + 1; END LOOP; RETURN 0; END",
        "BEGIN CASE x WHEN 1 THEN RETURN 1; WHEN 1 THEN RETURN 2; ELSE RETURN 0; END CASE; END",
    ] {
        assert_eq!(findings(body), Vec::<String>::new(), "{body}");
    }
}

#[test]
fn only_the_outermost_dead_condition_is_reported() {
    assert_eq!(
        findings(
            "DECLARE n INT := 3; BEGIN IF n > 5 THEN IF x > 0 THEN RETURN 1; END IF; END IF; RETURN 0; END"
        ),
        [
            "In function 'pick(INT)', the IF condition `n > 5` is never true where the body tests it, so the branch it guards never runs."
        ]
    );
}

#[test]
fn a_condition_raising_on_every_path_is_left_to_always_raising_expression() {
    assert_eq!(
        findings("BEGIN IF 1 / 0 > x THEN RETURN 1; END IF; RETURN 0; END"),
        Vec::<String>::new()
    );
}
