//! Submodule providing the `ContradictoryChecks` rule.

use sql_traits::{
    structs::{Assumption, IdentifierCase, Outcomes},
    traits::{CheckConstraintLike, ColumnLike, DatabaseLike, TableLike},
};
use sqlparser::ast::{Expr, Ident, Value};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports validated checks that each admit rows
/// on their own but together admit no row where the columns they read are all
/// non-null.
///
/// A `CHECK` admits a row when it is true or `NULL`, so such checks leave a
/// write two ways out, failing or storing `NULL` in a column they read. The
/// finding names a set of checks minimal by inclusion, found by dropping each
/// check in turn while the rest still contradict. A single check admitting no
/// such row is left to `unsatisfiable_check` and `null_only_check`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ContradictoryChecks::default().into();
/// let invalid = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE measurements (y INT CHECK (y > 0) CHECK (y < 0));",
/// ).unwrap();
/// assert!(constrainer.validate_schema(&invalid).is_err());
/// let valid = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE measurements (y INT CHECK (y > 0) CHECK (y < 10));",
/// ).unwrap();
/// assert!(constrainer.validate_schema(&valid).is_ok());
/// ```
pub struct ContradictoryChecks<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ContradictoryChecks<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ContradictoryChecks<DB>> for GenericConstrainer<DB> {
    fn from(rule: ContradictoryChecks<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ContradictoryChecks<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(ContradictoryChecks),
            group: LintGroup::Correctness,
            rationale: "Jointly contradictory checks reject every row whose referenced columns are all non-null.",
            source: Some(
                "https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-CHECK-CONSTRAINTS",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE measurements (y INT CHECK (y > 0) CHECK (y < 0));",
                good: "CREATE TABLE measurements (y INT CHECK (y > 0) CHECK (y < 10));",
            },
        };
        &METADATA
    }
}

/// Tests whether the selected checks admit a row with all their inputs non-null.
fn admits_row<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    checks: &[(&DB::CheckConstraint, Vec<Expr>)],
    omitted: Option<usize>,
) -> Result<bool, Interruption> {
    let assumptions: Vec<_> = checks
        .iter()
        .enumerate()
        .filter(|(index, _)| Some(*index) != omitted)
        .flat_map(|(_, (check, expressions))| {
            std::iter::once(Assumption::Check(*check)).chain(expressions.iter().map(|expression| {
                Assumption::Expression {
                    expression,
                    outcomes: Outcomes::TRUE,
                }
            }))
        })
        .collect();
    Ok(table
        .truth_under(
            database,
            &Expr::Value(Value::Boolean(true).into()),
            IdentifierCase::AsWritten,
            &assumptions,
        )?
        .outcomes
        != Outcomes::NONE)
}

impl<DB: DatabaseLike> TableRule for ContradictoryChecks<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &DB,
        table: &DB::Table,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        let mut eligible = Vec::new();
        for check in table.check_constraints(database)? {
            if check.is_enforced() && !check.no_inherit() && check.is_validated(database)? {
                let expressions = check
                    .columns(database)?
                    .map(|column| {
                        Expr::IsNotNull(Box::new(Expr::Identifier(Ident::with_quote(
                            '"',
                            column.stored_column_name().into_owned(),
                        ))))
                    })
                    .collect::<Vec<_>>();
                eligible.push((check, expressions));
            }
        }
        // A set admitting a row keeps admitting one as checks leave it, so the
        // whole set answers for every subset of candidates.
        if eligible.len() < 2 || admits_row(database, table, &eligible, None)? {
            return Ok(());
        }
        let mut candidates = Vec::with_capacity(eligible.len());
        for candidate in eligible {
            if admits_row(database, table, std::slice::from_ref(&candidate), None)? {
                candidates.push(candidate);
            }
        }
        if candidates.len() < 2 || admits_row(database, table, &candidates, None)? {
            return Ok(());
        }
        let mut index = 0;
        while index < candidates.len() {
            if admits_row(database, table, &candidates, Some(index))? {
                index += 1;
            } else {
                candidates.remove(index);
            }
        }
        let expressions = candidates
            .iter()
            .map(|(check, _)| format!("`CHECK ({})`", check.expression(database)))
            .collect::<Vec<_>>()
            .join(", ");
        let table_name = table.table_name();
        reporter.table(
            table,
            format!(
                "Table '{table_name}' has the checks {expressions}, which together admit no row where the columns they read are all non-null, so every write either fails or leaves one of those columns NULL."
            ),
            format!("Fix or drop one of these checks on '{table_name}'."),
        )?;
        Ok(())
    }
}
