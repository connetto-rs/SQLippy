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
/// on their own but together admit a row only through `NULL`.
///
/// A `CHECK` admits a row when it is true or `NULL`. A set is reported when
/// its checks force a column they read to be `NULL` in every row they admit,
/// as `CHECK (y > 0)` with `CHECK (y < 0)` force `y`, or when no row makes
/// all of them true, as with `CHECK (y > z)` and `CHECK (y < z)`. Checks
/// that only keep two optional columns from both being set, such as
/// `CHECK (a IS NULL OR kind = 'a')` with `CHECK (b IS NULL OR kind = 'b')`,
/// meet neither. Each finding names a set of checks minimal by inclusion,
/// found by dropping each check in turn while the rest still contradict. A
/// single check that contradicts on its own is left to `unsatisfiable_check`
/// and `null_only_check`.
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
            rationale: "Jointly contradictory checks admit rows only through NULL, either forcing a column NULL or never being all true.",
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

/// What a set of checks must admit a row for, or contradict.
#[derive(Clone, Copy)]
struct Demand<'a> {
    /// Whether the row makes every check true, rather than true or `NULL`.
    every_check_true: bool,
    /// The `IS NOT NULL` tests of the columns the row sets.
    non_null: &'a [Expr],
}

/// Tests whether the checks, but the `omitted` one, admit a row meeting
/// `demand`.
fn admits_row<'a, DB: DatabaseLike>(
    database: &'a DB,
    table: &'a DB::Table,
    checks: &[&'a DB::CheckConstraint],
    omitted: Option<usize>,
    demand: Demand<'a>,
) -> Result<bool, Interruption> {
    let assumptions: Vec<_> = checks
        .iter()
        .enumerate()
        .filter(|(index, _)| Some(*index) != omitted)
        .map(|(_, check)| {
            if demand.every_check_true {
                Assumption::Expression {
                    expression: check.expression(database),
                    outcomes: Outcomes::TRUE,
                }
            } else {
                Assumption::Check(*check)
            }
        })
        .chain(
            demand
                .non_null
                .iter()
                .map(|expression| Assumption::Expression {
                    expression,
                    outcomes: Outcomes::TRUE,
                }),
        )
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

/// Returns a set of `checks`, minimal by inclusion, that admits no row meeting
/// `demand`, or `None` when they all admit one.
fn contradicting<'a, DB: DatabaseLike>(
    database: &'a DB,
    table: &'a DB::Table,
    checks: &[&'a DB::CheckConstraint],
    demand: Demand<'a>,
) -> Result<Option<Vec<&'a DB::CheckConstraint>>, Interruption> {
    if admits_row(database, table, checks, None, demand)? {
        return Ok(None);
    }
    let mut set = checks.to_vec();
    let mut index = 0;
    while index < set.len() {
        if admits_row(database, table, &set, Some(index), demand)? {
            index += 1;
        } else {
            set.remove(index);
        }
    }
    Ok(Some(set))
}

/// Lists the `checks` as they read in a finding.
fn listed<DB: DatabaseLike>(database: &DB, checks: &[&DB::CheckConstraint]) -> String {
    checks
        .iter()
        .map(|check| format!("`CHECK ({})`", check.expression(database)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Reports each set of `checks` forcing columns `NULL`, with the columns whose
/// `IS NOT NULL` tests `non_null` holds, and returns the checks it reported.
fn report_forced_columns<'a, DB: DatabaseLike>(
    database: &'a DB,
    table: &'a DB::Table,
    checks: &[&'a DB::CheckConstraint],
    column_names: &[&str],
    non_null: &'a [Expr],
    reporter: &mut Reporter<'_, DB>,
) -> Result<Vec<&'a DB::CheckConstraint>, Interruption> {
    let table_name = table.table_name();
    let mut named = vec![false; non_null.len()];
    let mut accounted = Vec::new();
    for (index, test) in non_null.iter().enumerate() {
        if named[index] {
            continue;
        }
        let demand = Demand {
            every_check_true: false,
            non_null: std::slice::from_ref(test),
        };
        let Some(set) = contradicting(database, table, checks, demand)? else {
            continue;
        };
        let mut forced = Vec::new();
        for (other, test) in non_null.iter().enumerate().skip(index) {
            let demand = Demand {
                every_check_true: false,
                non_null: std::slice::from_ref(test),
            };
            if !named[other] && !admits_row(database, table, &set, None, demand)? {
                named[other] = true;
                forced.push(format!("'{}'", column_names[other]));
            }
        }
        reporter.table(
            table,
            format!(
                "Table '{table_name}' has the checks {}, which together admit only rows where {} {} NULL, so every write setting {} fails.",
                listed(database, &set),
                forced.join(", "),
                if forced.len() == 1 { "is" } else { "are" },
                if forced.len() == 1 { "it" } else { "one of them" },
            ),
            format!("Fix or drop one of these checks on '{table_name}'."),
        )?;
        accounted.extend(set);
    }
    Ok(accounted)
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
        let mut column_names = Vec::new();
        let mut non_null = Vec::new();
        for check in table.check_constraints(database)? {
            if !check.is_enforced() || check.no_inherit() || !check.is_validated(database)? {
                continue;
            }
            let mut read = Vec::new();
            let mut tests = Vec::new();
            for column in check.columns(database)? {
                read.push(column.column_name());
                tests.push(Expr::IsNotNull(Box::new(Expr::Identifier(
                    Ident::with_quote('"', column.stored_column_name().into_owned()),
                ))));
            }
            // `unsatisfiable_check` and `null_only_check` answer for a check contradicting alone.
            let alone = Demand {
                every_check_true: true,
                non_null: &tests,
            };
            if !admits_row(database, table, &[check], None, alone)? {
                continue;
            }
            for (name, test) in read.into_iter().zip(tests) {
                if !non_null.contains(&test) {
                    column_names.push(name);
                    non_null.push(test);
                }
            }
            eligible.push(check);
        }
        // A row making every check true with every column set meets every demand below.
        if eligible.len() < 2
            || admits_row(
                database,
                table,
                &eligible,
                None,
                Demand {
                    every_check_true: true,
                    non_null: &non_null,
                },
            )?
        {
            return Ok(());
        }
        let accounted = report_forced_columns(
            database,
            table,
            &eligible,
            &column_names,
            &non_null,
            reporter,
        )?;
        eligible.retain(|check| !accounted.iter().any(|held| std::ptr::eq(*held, *check)));
        let table_name = table.table_name();
        if let Some(set) = contradicting(
            database,
            table,
            &eligible,
            Demand {
                every_check_true: true,
                non_null: &[],
            },
        )? {
            reporter.table(
                table,
                format!(
                    "Table '{table_name}' has the checks {}, which no row makes all true, so a write passes them only where a NULL leaves one of them unknown.",
                    listed(database, &set),
                ),
                format!("Fix or drop one of these checks on '{table_name}'."),
            )?;
        }
        Ok(())
    }
}
