//! Submodule providing the `AlwaysRaisingExpression` rule.

use sql_traits::{
    structs::{IdentifierCase, Raising},
    traits::{CheckConstraintLike, ColumnLike, DatabaseLike, IndexLike, PolicyLike, TableLike},
};
use sqlparser::ast::Expr;

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a schema expression raising an error
/// on every row, such as a division by zero or an integer overflow.
///
/// It reads every `CHECK` on its own, and every column default, generation
/// expression, index key, partial-index predicate and policy clause under the
/// table's guarantees. PostgreSQL accepts a raising `CHECK` or default at
/// `CREATE` and then fails every write that evaluates it. A `CHECK` that
/// always raises admits no row, and `unsatisfiable_check` leaves it to this
/// rule.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = AlwaysRaisingExpression::default().into();
/// let broken = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (amount INT CHECK (1 / 0 = 1));",
/// ).unwrap();
/// assert!(constrainer.validate_schema(&broken).is_err());
/// let valid = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (amount INT CHECK (10 / amount > 0));",
/// ).unwrap();
/// assert!(constrainer.validate_schema(&valid).is_ok());
/// ```
pub struct AlwaysRaisingExpression<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for AlwaysRaisingExpression<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<AlwaysRaisingExpression<DB>> for GenericConstrainer<DB> {
    fn from(rule: AlwaysRaisingExpression<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for AlwaysRaisingExpression<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(AlwaysRaisingExpression),
            group: LintGroup::Correctness,
            rationale: "A schema expression that always raises an error prevents every operation that evaluates it.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-expressions.html#SYNTAX-EXPRESS-EVAL",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE payments (amount INT CHECK (1 / 0 = 1));",
                good: "CREATE TABLE payments (amount INT CHECK (amount > 0));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for AlwaysRaisingExpression<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table_name = table.table_name();
        let resolution = "Rewrite or remove the expression.";
        for check in table.check_constraints(database)? {
            if check.truth_under(database, &[])?.raising == Raising::Always {
                let expression = check.expression(database);
                reporter.table(
                    table,
                    format!("The CHECK expression `{expression}` on table '{table_name}' raises an error on every row."),
                    resolution.to_owned(),
                )?;
            }
        }
        for column in table.columns(database)? {
            for (kind, expression) in [
                ("default", column.default_expression()),
                ("generation", column.generation_expression()),
            ] {
                if let Some(expression) = expression
                    && table
                        .expression_truth(database, expression, IdentifierCase::AsWritten)?
                        .raising
                        == Raising::Always
                {
                    let column_name = column.column_name();
                    reporter.column(
                        column,
                        format!("The {kind} expression `{expression}` on column '{table_name}.{column_name}' raises an error on every row."),
                        resolution.to_owned(),
                    )?;
                }
            }
        }
        for index in table.indices(database)? {
            for (kind, expression) in index
                .keys(database)?
                .map(|key| ("key", key.expression()))
                .chain(index.predicate().map(|predicate| ("predicate", predicate)))
            {
                let mut inner = expression;
                while let Expr::Nested(nested) = inner {
                    inner = nested;
                }
                if (kind == "key"
                    && matches!(inner, Expr::Identifier(_) | Expr::CompoundIdentifier(_)))
                    || table
                        .expression_truth(database, expression, IdentifierCase::AsWritten)?
                        .raising
                        != Raising::Always
                {
                    continue;
                }
                let index_name = index.name().unwrap_or("unnamed index");
                reporter.index(
                    index,
                    format!("The {kind} expression `{expression}` on index '{table_name}.{index_name}' raises an error on every row."),
                    resolution.to_owned(),
                )?;
            }
        }
        for policy in table.policies(database)? {
            for (clause, kind, expression) in [
                (
                    PolicyClause::Using,
                    "USING",
                    policy.using_expression(database)?,
                ),
                (
                    PolicyClause::WithCheck,
                    "WITH CHECK",
                    policy.check_expression(database)?,
                ),
            ] {
                if let Some(expression) = expression
                    && table
                        .expression_truth(database, expression, IdentifierCase::AsWritten)?
                        .raising
                        == Raising::Always
                {
                    let policy_name = policy.name();
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: expression.to_string(),
                        }],
                        format!("The {kind} expression `{expression}` on policy '{table_name}.{policy_name}' raises an error on every row."),
                        resolution.to_owned(),
                    )?;
                }
            }
        }
        Ok(())
    }
}
