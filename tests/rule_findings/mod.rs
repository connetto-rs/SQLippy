//! Findings of one rule, shared by the suites that check rules by name.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Level, object and message of every finding of `rule`, failing on anything
/// other than a violation or an inactive rule.
pub fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    rule: &str,
    sql: &str,
) -> Vec<(Level, String, String)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == rule => Some((
                violation.level(),
                violation.object().to_owned(),
                violation.message().to_owned(),
            )),
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}
