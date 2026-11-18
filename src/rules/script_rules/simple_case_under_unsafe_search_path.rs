//! Submodule providing the `SimpleCaseUnderUnsafeSearchPath` rule.

use std::ops::ControlFlow;

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::{Expr, Statement, Visitor};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        script_support::{Untrusted, untrusted},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, ScriptRule},
};

rule_definition!(
    /// Struct defining a rule that reports a simple `CASE operand WHEN value`
    /// resolved under a `search_path` the script has not established as
    /// trusted.
    ///
    /// The comparison of the operand with each value calls an `=` operator
    /// found through the path, and no syntax qualifies it. The path is
    /// tracked as `unqualified_name_under_unsafe_search_path` tracks it, in
    /// statements and in string function bodies.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     SimpleCaseUnderUnsafeSearchPath::default().into();
    /// let case = "SELECT CASE 1 WHEN 1 THEN 'one' END;";
    /// for (sql, findings) in [
    ///     (format!("SET search_path = public; {case}"), 1),
    ///     (format!("SET search_path = pg_catalog, pg_temp; {case}"), 0),
    /// ] {
    ///     let database = ParserDB::parse::<PostgreSqlDialect>(&sql).unwrap();
    ///     let statements = Parser::parse_sql(&PostgreSqlDialect {}, &sql).unwrap();
    ///     assert_eq!(constrainer.script_diagnostics(&database, &statements).len(), findings);
    /// }
    /// ```
    SimpleCaseUnderUnsafeSearchPath,
    register_script_rule,
    LintGroup::Restriction,
    "A simple `CASE` compares with an `=` operator found through the search_path, so a role creating in a searched schema can supply an operator that runs its own code.",
    Some("https://github.com/timescale/pgspot/blob/main/src/pgspot/visitors.py"),
    RuleExample {
        bad: "SET search_path = public;\n\
SELECT CASE 1 WHEN 1 THEN 'matched' ELSE 'other' END;",
        good: "SET search_path = pg_catalog, pg_temp;\n\
SELECT CASE 1 WHEN 1 THEN 'matched' ELSE 'other' END;",
    }
);

/// Collects every simple `CASE` a statement evaluates.
#[derive(Default)]
struct SimpleCases(Vec<String>);

impl Visitor for SimpleCases {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if let Expr::Case {
            operand: Some(_), ..
        } = expression
        {
            self.0.push(expression.to_string());
        }
        ControlFlow::Continue(())
    }
}

/// The simple `CASE` expressions `statements` evaluate.
fn simple_cases(statements: &[Statement]) -> Vec<String> {
    let mut visitor = SimpleCases::default();
    for statement in statements {
        let _ = walk(statement, &mut visitor);
    }
    visitor.0
}

impl<DB: DatabaseLike> ScriptRule for SimpleCaseUnderUnsafeSearchPath<DB> {
    type Database = DB;

    fn check_script(
        &self,
        _database: &Self::Database,
        statements: &[Statement],
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        untrusted(statements, |site| {
            let (statement, cases, place) = match site {
                Untrusted::Session(statement) => (
                    statement,
                    simple_cases(std::slice::from_ref(statement)),
                    "the session's search_path".to_owned(),
                ),
                Untrusted::Body {
                    statement,
                    kind,
                    name,
                    body,
                } => (
                    statement,
                    simple_cases(&body),
                    format!("the search_path a call of the {kind} '{name}' runs with"),
                ),
            };
            for case in cases {
                let message = format!(
                    "{case} compares its operand with an = operator found through {place}, which this script has not set to pg_catalog, schemas it created and pg_temp last."
                );
                reporter.statement(
                    statement,
                    case,
                    message,
                    "SET search_path = pg_catalog, pg_temp before it, or write a searched CASE WHEN operand OPERATOR(pg_catalog.=) value.".to_owned(),
                )?;
            }
            Ok(())
        })
    }
}
