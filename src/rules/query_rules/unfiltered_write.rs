//! Submodule providing the `UnfilteredWrite` rule.

use std::ops::ControlFlow;

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::{Delete, Statement, Update, Visit, Visitor};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// Collects the `UPDATE` and `DELETE` statements without a `WHERE`.
struct Unfiltered(Vec<String>);

impl Visitor for Unfiltered {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        // Expression evaluator: only a missing `WHERE` is reported. The
        // evaluator decides whether a `WHERE` is always true, so a
        // query-builder `WHERE 1 = 1` is reported too while the literal
        // `WHERE true` stays the stated intent.
        if let Statement::Update(Update {
            selection: None, ..
        })
        | Statement::Delete(Delete {
            selection: None, ..
        }) = statement
        {
            self.0.push(statement.to_string());
        }
        ControlFlow::Continue(())
    }
}

query_rule!(
    /// Struct defining a rule that reports an `UPDATE` or `DELETE` without a
    /// `WHERE`, which rewrites or removes every row the statement reaches.
    ///
    /// Measured on PostgreSQL 17.11 and 18.6, `UPDATE plain_notes SET body
    /// = 'x'` rewrote all three notes and `DELETE FROM plain_notes` left none.
    /// Row-level security narrows it to the rows the policy lets the caller
    /// reach, which is still every one of them. A deliberate full rewrite is
    /// written `WHERE true` or `TRUNCATE`, which are not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnfilteredWrite::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT);").unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("DELETE FROM t").is_err());
    /// assert!(check("DELETE FROM t WHERE id = $1").is_ok());
    /// ```
    UnfilteredWrite,
    LintGroup::Suspicious,
    "An UPDATE or DELETE without a WHERE rewrites or removes every row it reaches, which is rarely what a forgotten filter meant.",
    Some("https://dev.mysql.com/doc/refman/8.4/en/mysql-tips.html")
);

impl<DB: DatabaseLike> QueryRule for UnfilteredWrite<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        _database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut unfiltered = Unfiltered(Vec::new());
        let _ = statement.visit(&mut unfiltered);
        for found in unfiltered.0 {
            reporter.statement(
                statement,
                found.clone(),
                format!("`{found}` has no WHERE, so it writes every row it reaches."),
                "Add the WHERE that selects the rows meant, or write WHERE true or TRUNCATE for a deliberate full rewrite.".to_owned(),
            )?;
        }
        Ok(())
    }
}
