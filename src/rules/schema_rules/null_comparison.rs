//! Submodule providing the `NullComparison` rule.

use std::{convert::Infallible, ops::ControlFlow};

use sql_traits::{errors::LookupError, traits::DatabaseLike};
use sqlparser::ast::{BinaryOperator, Expr, Statement, Value, Visit, Visitor};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Struct defining a rule that reports a comparison operator with a `NULL`
/// literal on either side.
///
/// `x = NULL`, `x <> NULL` and the ordering comparisons are `NULL` whatever
/// `x` holds, so a filter written with one keeps no row and a `CHECK`
/// written with one rejects no row. A cast or parentheses around the `NULL`
/// change nothing. The rule reads views, materialized views, policies, table
/// check constraints, SQL function bodies and, as a query rule, statements.
/// `IS NULL`, `IS NOT NULL` and `IS DISTINCT FROM` are the forms that test
/// for `NULL`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NullComparison::default().into();
/// let compared = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (id INT, x INT); CREATE VIEW v AS SELECT id FROM t WHERE x = NULL;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&compared).is_err());
/// let tested = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (id INT, x INT); CREATE VIEW v AS SELECT id FROM t WHERE x IS NULL;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&tested).is_ok());
/// ```
pub struct NullComparison<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NullComparison<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NullComparison<DB>> for GenericConstrainer<DB> {
    fn from(rule: NullComparison<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(NullComparison::default()));
        constrainer
    }
}

impl<DB> Rule for NullComparison<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NullComparison),
            group: LintGroup::Correctness,
            rationale: "A comparison with NULL is NULL whatever the other side holds, so a filter written with one keeps no row and a check written with one rejects none.",
            source: Some("https://www.postgresql.org/docs/current/functions-comparison.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE t (id INT, x INT);\n\
SELECT id FROM t WHERE x = NULL;",
                good: "CREATE TABLE t (id INT, x INT);\n\
SELECT id FROM t WHERE x IS NULL;",
            },
        };
        &METADATA
    }
}

/// Whether `expression`, under casts and parentheses, is the `NULL` literal.
fn is_null_literal(mut expression: &Expr) -> bool {
    loop {
        match expression {
            Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => expression = inner,
            Expr::Value(literal) => return matches!(literal.value, Value::Null),
            _ => return false,
        }
    }
}

/// Collects the comparisons with a `NULL` literal.
#[derive(Default)]
struct NullComparisons(Vec<String>);

impl Visitor for NullComparisons {
    type Break = Infallible;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Infallible> {
        if let Expr::BinaryOp {
            left,
            op:
                BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::Lt
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::GtEq,
            right,
        } = expression
            && (is_null_literal(left) || is_null_literal(right))
        {
            self.0.push(expression.to_string());
        }
        ControlFlow::Continue(())
    }
}

/// Finds and explains comparisons with `NULL`.
struct Finder;

impl ExpressionFinder for Finder {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        _database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let mut comparisons = NullComparisons::default();
        let ControlFlow::Continue(()) = walk(node, &mut comparisons);
        Ok(comparisons
            .0
            .into_iter()
            .map(|comparison| (format!("`{comparison}`"), comparison))
            .collect())
    }

    fn problem(&self) -> &'static str {
        "which is NULL whatever the other side holds, so a filter keeps no row and a check rejects none"
    }

    fn resolution(&self) -> &'static str {
        "Use IS NULL or IS NOT NULL, or IS DISTINCT FROM to compare with a value that may be NULL."
    }
}

impl<DB: DatabaseLike> SchemaRule for NullComparison<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&Finder, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for NullComparison<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&Finder, database, statement, reporter)
    }
}
