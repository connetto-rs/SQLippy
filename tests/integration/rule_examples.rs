//! Every registered rule's example, checked under the example deployment.

use sqlippy::prelude::*;
use sqlparser::{ast::Statement, dialect::PostgreSqlDialect, parser::Parser};

/// Whether a statement is one an application sends rather than schema DDL.
fn is_application_statement(statement: &Statement) -> bool {
    matches!(
        statement,
        Statement::Query(_)
            | Statement::Insert(_)
            | Statement::Update(_)
            | Statement::Delete(_)
            | Statement::Merge(_)
    )
}

/// Every rule at `warn` or above, under the example deployment.
fn constrainer() -> DefaultConstrainer<ParserDB> {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    for group in LintGroup::ALL {
        if group.default_level() == Level::Allow {
            constrainer.set_group_level(group, Level::Warn);
        }
    }
    constrainer.set_deployment(Deployment::example());
    constrainer
}

/// How many times `rule` reports `sql`, recording into `failures` why `sql`
/// could not be checked.
fn reports(
    constrainer: &DefaultConstrainer<ParserDB>,
    rule: &str,
    side: &str,
    sql: &str,
    failures: &mut Vec<String>,
) -> usize {
    let statements = match Parser::parse_sql(&PostgreSqlDialect {}, sql) {
        Ok(statements) => statements,
        Err(error) => {
            failures.push(format!(
                "{rule}: the {side} example does not parse: {error}"
            ));
            return 0;
        }
    };
    let database = match ParserDB::parse::<PostgreSqlDialect>(sql) {
        Ok(database) => database,
        Err(error) => {
            failures.push(format!(
                "{rule}: the {side} example is not a schema: {error}"
            ));
            return 0;
        }
    };
    let mut errors = constrainer.diagnostics(&database);
    for statement in statements
        .iter()
        .filter(|statement| is_application_statement(statement))
    {
        errors.extend(constrainer.statement_diagnostics(&database, statement));
    }
    let mut count = 0;
    for error in errors {
        match error {
            Error::Violation(violation) if violation.rule().name == rule => count += 1,
            Error::Lookup(lookup) => {
                failures.push(format!(
                    "{rule}: the {side} example fails a lookup: {lookup}"
                ));
            }
            _ => {}
        }
    }
    count
}

#[test]
fn every_rule_reports_its_bad_example_and_not_its_good_one() {
    let constrainer = constrainer();
    let mut checked: Vec<&'static str> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for rule in constrainer.rules() {
        let metadata = rule.metadata();
        if checked.contains(&metadata.name) {
            continue;
        }
        checked.push(metadata.name);
        let RuleExample { bad, good } = metadata.example;
        if bad.trim().is_empty() || good.trim().is_empty() {
            failures.push(format!("{}: has no example", metadata.name));
            continue;
        }
        if reports(&constrainer, metadata.name, "bad", bad, &mut failures) == 0 {
            failures.push(format!(
                "{}: does not report its bad example",
                metadata.name
            ));
        }
        if reports(&constrainer, metadata.name, "good", good, &mut failures) > 0 {
            failures.push(format!("{}: reports its good example", metadata.name));
        }
    }
    assert!(
        failures.is_empty(),
        "{} example failures across {} rules:\n{}",
        failures.len(),
        checked.len(),
        failures.join("\n")
    );
}
