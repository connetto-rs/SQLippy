//! Submodule providing the `UnfilteredWrite` rule.

use std::ops::ControlFlow;

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::{Delete, Expr, Statement, Update, Value, Visitor};

use crate::rules::{
    policy_support::is_column_reference, volatility_support::runs_volatile, walk_support::walk,
};
use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// Finds a column reference.
struct ColumnReference;

impl Visitor for ColumnReference {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if is_column_reference(expression) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Whether the expression is the literal `true`, parenthesised or not.
fn is_literal_true(expression: &Expr) -> bool {
    match expression {
        Expr::Nested(inner) => is_literal_true(inner),
        Expr::Value(literal) => matches!(literal.value, Value::Boolean(true)),
        _ => false,
    }
}

/// The `UPDATE` and `DELETE` statements without a filter on their rows, each
/// with whether it has a `WHERE` at all.
struct Unfiltered<'a, DB>(&'a DB, Vec<(String, bool)>);

impl<DB: DatabaseLike> Visitor for Unfiltered<'_, DB> {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        if let Statement::Update(Update { selection, .. })
        | Statement::Delete(Delete { selection, .. }) = statement
        {
            match selection {
                None => self.1.push((statement.to_string(), false)),
                Some(selection)
                    if !is_literal_true(selection)
                        && walk(selection, &mut ColumnReference).is_continue()
                        && !runs_volatile(self.0, selection) =>
                {
                    self.1.push((statement.to_string(), true));
                }
                Some(_) => {}
            }
        }
        ControlFlow::Continue(())
    }
}

query_rule!(
    /// Struct defining a rule that reports an `UPDATE` or `DELETE` that does
    /// not filter its rows, which rewrites or removes every row the
    /// statement reaches.
    ///
    /// Measured on PostgreSQL 17.11 and 18.6, `UPDATE plain_notes SET body
    /// = 'x'` rewrote all three notes and `DELETE FROM plain_notes` left none.
    /// A `WHERE` reading no column and running no `VOLATILE` function, such
    /// as the query-builder `WHERE 1 = 1`, `WHERE now() > '2020-01-01'` or
    /// `WHERE $1`, has one value for every row, so on PostgreSQL 18 it
    /// deleted all of a thousand notes or none. A `VOLATILE` function is
    /// evaluated per row and does select a subset, `WHERE random() < 0.5`
    /// deleting 514 of them, an operator implemented by one 511 and an
    /// explicit cast through one 4938 of ten thousand, so none is reported,
    /// nor is a function or `OPERATOR(...)` the schema does not declare.
    /// Row-level security narrows the write to the rows the policy lets the
    /// caller reach, which is still every one of them. A deliberate full
    /// rewrite is written `WHERE true` or `TRUNCATE`, which are not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnfilteredWrite::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT);").unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("DELETE FROM t").is_err());
    /// assert!(check("DELETE FROM t WHERE 1 = 1").is_err());
    /// assert!(check("DELETE FROM t WHERE id = $1").is_ok());
    /// ```
    UnfilteredWrite,
    LintGroup::Suspicious,
    "An UPDATE or DELETE whose WHERE is missing or reads no column rewrites or removes every row it reaches, which is rarely what a forgotten filter meant.",
    Some("https://dev.mysql.com/doc/refman/8.4/en/mysql-tips.html"),
    RuleExample {
        bad: "CREATE TABLE notes (id INT PRIMARY KEY);\n\
DELETE FROM notes;",
        good: "CREATE TABLE notes (id INT PRIMARY KEY);\n\
DELETE FROM notes WHERE id = 1;",
    }
);

impl<DB: DatabaseLike> QueryRule for UnfilteredWrite<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut unfiltered = Unfiltered(database, Vec::new());
        let _ = walk(statement, &mut unfiltered);
        for (found, filtered) in unfiltered.1 {
            let message = if filtered {
                format!(
                    "`{found}` has a WHERE whose value is the same for every row, so it writes every row it reaches or none."
                )
            } else {
                format!("`{found}` has no WHERE, so it writes every row it reaches.")
            };
            reporter.statement(
                statement,
                found,
                message,
                "Add the WHERE that selects the rows meant, or write WHERE true or TRUNCATE for a deliberate full rewrite.".to_owned(),
            )?;
        }
        Ok(())
    }
}
