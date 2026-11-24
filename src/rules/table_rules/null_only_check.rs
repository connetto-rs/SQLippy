//! Submodule providing the `NullOnlyCheck` rule.

use sql_traits::traits::{CheckConstraintLike, ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a check constraint that is never true
/// but may be `NULL`.
///
/// A `CHECK` admits a row when its expression is true or `NULL`. An
/// expression that is false on every row where it is not `NULL` admits only
/// the rows that make it `NULL`, which in practice forces the columns it reads
/// to `NULL`. A check that admits no row at all is left to
/// `unsatisfiable_check`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NullOnlyCheck::default().into();
/// let null_only = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 10 AND amount < 5));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&null_only).is_err());
/// let bounded = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 5 AND amount < 10));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&bounded).is_ok());
/// ```
pub struct NullOnlyCheck<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NullOnlyCheck<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NullOnlyCheck<DB>> for GenericConstrainer<DB> {
    fn from(rule: NullOnlyCheck<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for NullOnlyCheck<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NullOnlyCheck),
            group: LintGroup::Correctness,
            rationale: "A check that is never true admits only the rows where it is NULL, so it silently forces the columns it reads to NULL.",
            source: Some(
                "https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-CHECK-CONSTRAINTS",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 10 AND amount < 5));",
                good: "CREATE TABLE payments (id INT PRIMARY KEY, amount INT CHECK (amount > 5 AND amount < 10));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for NullOnlyCheck<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for check_constraint in table.check_constraints(database)? {
            let outcomes = check_constraint.truth_under(database, &[])?.outcomes;
            if outcomes.truth || !outcomes.null || !outcomes.falsity {
                continue;
            }
            let table_name = table.table_name();
            let expression = check_constraint.expression(database);
            let columns = check_constraint
                .columns(database)?
                .map(|column| format!("'{}'", column.column_name()))
                .collect::<Vec<_>>()
                .join(", ");
            reporter.table(
                table,
                format!(
                    "Table '{table_name}' has the check constraint CHECK ({expression}), which is never true and admits only the rows where it is NULL, so a row passes it only with a NULL in the columns it reads ({columns})."
                ),
                format!(
                    "Rewrite CHECK ({expression}) on '{table_name}' to admit the values it was meant to, or drop it."
                ),
            )?;
        }
        Ok(())
    }
}
