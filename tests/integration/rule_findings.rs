//! Findings of one rule, shared by the suites that check rules by name.

use sql_rules::prelude::*;
use sqlparser::{ast::Statement, dialect::PostgreSqlDialect, parser::Parser};

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

/// The single PostgreSQL statement `sql` holds.
pub fn statement(sql: &str) -> Statement {
    let [statement] = Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .expect("statement parses")
        .try_into()
        .expect("one statement");
    statement
}

/// Rule, level and object of every violation `sql` raises against
/// `database`, failing on anything else.
pub fn statement_findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    database: &ParserDB,
    sql: &str,
) -> Vec<(&'static str, Level, String)> {
    constrainer
        .statement_diagnostics(database, &statement(sql))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.rule().name,
                violation.level(),
                violation.object().to_owned(),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

/// A constrainer running `rule` alone.
pub fn query_rule<R: QueryRule<Database = ParserDB> + 'static>(
    rule: R,
) -> GenericConstrainer<ParserDB> {
    let mut constrainer = GenericConstrainer::default();
    constrainer.register_query_rule(Box::new(rule));
    constrainer
}

/// Object of every violation `sql` raises against `database`, in order.
pub fn statement_objects<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    database: &ParserDB,
    sql: &str,
) -> Vec<String> {
    statement_findings(constrainer, database, sql)
        .into_iter()
        .map(|(_, _, object)| object)
        .collect()
}

/// Rule and level of every violation `sql` raises against `database`, in
/// order.
pub fn statement_levels<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    database: &ParserDB,
    sql: &str,
) -> Vec<(&'static str, Level)> {
    statement_findings(constrainer, database, sql)
        .into_iter()
        .map(|(rule, level, _)| (rule, level))
        .collect()
}

/// Name and missing declaration of every rule `constrainer` holds inactive.
pub fn inactive_declarations<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
) -> Vec<(&'static str, Declaration)> {
    constrainer
        .inactive_rules()
        .iter()
        .map(|inactive| (inactive.rule().name, inactive.missing()))
        .collect()
}
