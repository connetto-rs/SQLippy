//! Floating-point and `numeric` columns whose checks admit `'NaN'`,
//! `'Infinity'` or `'-Infinity'`.

use sqlippy::prelude::*;
use sqlparser::dialect::SQLiteDialect;

use crate::common::parse;

/// Object and admitted values of every finding, in a stable order.
fn admitted(sql: &str) -> Vec<(String, String)> {
    let constrainer: GenericConstrainer<ParserDB> = NonFiniteNumberAllowed::default().into();
    let mut raised: Vec<(String, String)> = constrainer
        .diagnostics(&parse(sql))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                let message = violation.message();
                let values = message
                    .split_once(" admits ")
                    .map(|(_, values)| values.trim_end_matches('.'))
                    .expect("the message names the admitted values");
                (violation.object().to_owned(), values.to_owned())
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    raised.sort();
    raised
}

fn found(object: &str, values: &str) -> (String, String) {
    (object.to_owned(), values.to_owned())
}

#[test]
fn a_lower_bound_admits_nan_and_infinity_and_no_check_admits_all_three() {
    let raised = admitted(
        "CREATE TABLE containers (
             id UUID PRIMARY KEY,
             volume_l DOUBLE PRECISION NOT NULL CHECK (volume_l > 0.0),
             mass_kg DOUBLE PRECISION
         );",
    );
    assert_eq!(
        raised,
        vec![
            found("containers.mass_kg", "'NaN', 'Infinity' and '-Infinity'"),
            found("containers.volume_l", "'NaN' and 'Infinity'"),
        ]
    );
}

#[test]
fn an_upper_bound_admits_only_negative_infinity() {
    assert_eq!(
        admitted("CREATE TABLE t (ratio REAL CHECK (ratio <= 1));"),
        vec![found("t.ratio", "'-Infinity'")]
    );
}

#[test]
fn an_inclusive_bound_at_infinity_admits_infinity() {
    assert_eq!(
        admitted(
            "CREATE TABLE t (x DOUBLE PRECISION CHECK (x >= 0 AND x <= 'Infinity'::double precision));"
        ),
        vec![found("t.x", "'Infinity'")]
    );
}

#[test]
fn the_portable_bounds_refuse_every_non_finite_value() {
    let raised = admitted(
        "CREATE TABLE t (
             mass_kg DOUBLE PRECISION CHECK (mass_kg >= 0.0 AND mass_kg < 'Infinity'::double precision),
             offset_m DOUBLE PRECISION CHECK (offset_m > '-Infinity'::double precision AND offset_m < 'Infinity'::double precision),
             printed DOUBLE PRECISION CHECK (((printed > (0)::double precision) AND (printed < 'Infinity'::double precision))),
             reversed REAL CHECK ('-inf' < reversed AND 1e3 > reversed),
             split_m DOUBLE PRECISION CHECK (split_m >= -1.5),
             CHECK (split_m < 2.5)
         );",
    );
    assert_eq!(raised, Vec::new());
}

#[test]
fn between_in_lists_and_any_over_finite_literals_refuse_every_non_finite_value() {
    let raised = admitted(
        "CREATE TABLE t (
             fraction DOUBLE PRECISION CHECK (fraction BETWEEN 0 AND 1),
             step DOUBLE PRECISION CHECK (step IN (0.5, 1.0, 2.0)),
             level DOUBLE PRECISION CHECK (level = ANY (ARRAY[(1)::double precision, (2)::double precision])),
             outside DOUBLE PRECISION CHECK (outside NOT BETWEEN 0 AND 1)
         );",
    );
    assert_eq!(
        raised,
        vec![found("t.outside", "'NaN', 'Infinity' and '-Infinity'")]
    );
}

#[test]
fn a_nullable_column_is_judged_on_its_values() {
    assert_eq!(
        admitted("CREATE TABLE t (x DOUBLE PRECISION CHECK (x IS NULL OR x < 'Infinity'));"),
        vec![found("t.x", "'-Infinity'")]
    );
}

#[test]
fn a_check_the_rule_cannot_read_refuses_nothing() {
    let raised = admitted(
        "CREATE TABLE ranges (
             low_m DOUBLE PRECISION NOT NULL CHECK (low_m >= 0),
             high_m DOUBLE PRECISION NOT NULL,
             CHECK (low_m < high_m)
         );",
    );
    assert_eq!(
        raised,
        vec![
            found("ranges.high_m", "'NaN', 'Infinity' and '-Infinity'"),
            found("ranges.low_m", "'NaN' and 'Infinity'"),
        ]
    );
}

#[test]
fn a_check_refusing_nan_by_name_is_read() {
    assert_eq!(
        admitted(
            "CREATE TABLE t (x DOUBLE PRECISION CHECK (x <> 'NaN' AND NOT (x = '-Infinity') AND x IS DISTINCT FROM 'Infinity'));"
        ),
        Vec::new()
    );
}

#[test]
fn numeric_admits_nan_and_admits_the_infinities_only_without_a_precision() {
    let raised = admitted(
        "CREATE TABLE amounts (
             open NUMERIC CHECK (open > 0),
             scaled NUMERIC(10, 2),
             whole NUMERIC(10) CHECK (whole < 100),
             charged MONEY,
             counted INTEGER,
             samples DOUBLE PRECISION[]
         );",
    );
    assert_eq!(
        raised,
        vec![
            found("amounts.open", "'NaN' and 'Infinity'"),
            found("amounts.scaled", "'NaN'"),
        ]
    );
}

#[test]
fn the_checks_of_every_domain_a_column_goes_through_count() {
    let raised = admitted(
        "CREATE DOMAIN span AS DOUBLE PRECISION CHECK (VALUE > '-Infinity');
         CREATE DOMAIN positive_span AS span CHECK (VALUE > 0 AND VALUE < 'Infinity'::double precision);
         CREATE DOMAIN other_span AS span CHECK (VALUE < 5);
         CREATE TABLE t (took positive_span, waited span, idle other_span);",
    );
    assert_eq!(raised, vec![found("t.waited", "'NaN' and 'Infinity'")]);
}

#[test]
fn a_reference_takes_the_checks_of_the_column_it_must_equal() {
    let raised = admitted(
        "CREATE TABLE grades (score DOUBLE PRECISION PRIMARY KEY CHECK (score BETWEEN 0 AND 10));
         CREATE TABLE marks (id INT PRIMARY KEY, score DOUBLE PRECISION NOT NULL REFERENCES grades (score));",
    );
    assert_eq!(raised, Vec::new());
}

#[test]
fn the_fix_spells_the_bound_the_column_misses() {
    let constrainer: GenericConstrainer<ParserDB> = NonFiniteNumberAllowed::default().into();
    let resolutions: Vec<String> = constrainer
        .diagnostics(&parse(
            "CREATE TABLE t (
                 a DOUBLE PRECISION CHECK (a > 0.0),
                 b REAL,
                 c NUMERIC CHECK (c < 1)
             );",
        ))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.resolution().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    let fixes: Vec<&str> = resolutions
        .iter()
        .map(|resolution| {
            resolution
                .split_once("add `")
                .and_then(|(_, rest)| rest.split_once('`'))
                .map(|(fix, _)| fix)
                .expect("the resolution spells a check")
        })
        .collect();
    assert_eq!(
        fixes,
        [
            "CHECK (a < 'Infinity'::double precision)",
            "CHECK (b > '-Infinity'::real AND b < 'Infinity'::real)",
            "CHECK (c > '-Infinity'::numeric)",
        ]
    );
}

#[test]
fn a_sqlite_schema_is_not_checked() {
    let constrainer: GenericConstrainer<ParserDB> = NonFiniteNumberAllowed::default().into();
    let database = ParserDB::parse::<SQLiteDialect>("CREATE TABLE t (x REAL CHECK (x > 0));")
        .expect("schema parses");
    assert!(constrainer.diagnostics(&database).is_empty());
}
