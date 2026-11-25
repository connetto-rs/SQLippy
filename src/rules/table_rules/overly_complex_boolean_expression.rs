//! Submodule providing the `OverlyComplexBooleanExpression` rule.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::Statement;

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::boolean_form_support::{report_schema, report_statement, report_table},
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule, TableRule},
};

/// Struct defining a rule that reports a boolean expression whose minimal
/// form reads fewer of its terms, the case clippy's
/// `overly_complex_bool_expr` reports in Rust.
///
/// The minimal form comes from Quine–McCluskey over the expression's terms,
/// each a maximal subexpression that is not `AND`, `OR` or `NOT`, and is
/// kept only when it agrees with the expression on every combination of
/// true, false and `NULL` its terms may take, as the site reads the result.
/// A `CHECK` or a domain check admits a `NULL` result as it admits true, a
/// policy clause, a partial index predicate, a `WHERE`, an `ON` and a
/// PL/pgSQL condition reject it as they reject false, and a column default,
/// a generated column, a select-list value and a PL/pgSQL value keep it
/// apart from both. A term that may raise or calls a `VOLATILE` function is
/// never dropped.
///
/// Each term is read where the expression sits, under the column types,
/// `NOT NULL` and validated checks of a table, the query's bindings, and in
/// a PL/pgSQL body what each variable may hold there, so a term proved never
/// `NULL` takes only true and false. An expression in which
/// `redundant_term` reports a term is left to it, and one whose minimal form
/// is a constant is left to the tautology and contradiction rules.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> =
///     OverlyComplexBooleanExpression::default().into();
/// let invalid = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE orders (paid BOOLEAN, amount INT,
///          CHECK ((paid AND amount > 0) OR (paid AND amount <= 0)));"
/// ).unwrap();
/// assert!(constrainer.validate_schema(&invalid).is_err());
/// let valid = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE orders (paid BOOLEAN, amount INT, CHECK (paid));"
/// ).unwrap();
/// assert!(constrainer.validate_schema(&valid).is_ok());
/// ```
pub struct OverlyComplexBooleanExpression<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for OverlyComplexBooleanExpression<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<OverlyComplexBooleanExpression<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: OverlyComplexBooleanExpression<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer.register_schema_rule(Box::new(OverlyComplexBooleanExpression::default()));
        constrainer.register_query_rule(Box::new(OverlyComplexBooleanExpression::default()));
        constrainer
    }
}

impl<DB> Rule for OverlyComplexBooleanExpression<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(OverlyComplexBooleanExpression),
            group: LintGroup::Complexity,
            rationale: "A boolean expression that means the same without some of its terms evaluates those terms for nothing, and hides the condition it actually tests.",
            source: Some(
                "https://rust-lang.github.io/rust-clippy/master/index.html#overly_complex_bool_expr",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE orders (paid BOOLEAN, amount INT, CHECK ((paid AND amount > 0) OR (paid AND amount <= 0)));",
                good: "CREATE TABLE orders (paid BOOLEAN, amount INT, CHECK (paid));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for OverlyComplexBooleanExpression<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report_table(database, table, reporter)
    }
}

impl<DB: DatabaseLike> SchemaRule for OverlyComplexBooleanExpression<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report_schema(database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for OverlyComplexBooleanExpression<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report_statement(database, statement, reporter)
    }
}
