//! Submodule providing the `RedundantCheck` rule.

use sql_traits::{
    structs::{Assumption, Outcomes, Raising},
    traits::{CheckConstraintLike, ColumnLike, DatabaseLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a check the table's other validated
/// checks already guarantee.
///
/// The checks are walked from the last declared, and each is judged under the
/// checks still kept, so a reported check never vouches for another reported
/// one and dropping every reported check keeps the constraint. Of
/// `CHECK (a)`, `CHECK (b)` and `CHECK (a AND b)` only the third is reported.
/// Tautologies and copies of an earlier check are left to `tautological_check`
/// and `duplicate_check`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = RedundantCheck::default().into();
/// let invalid = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (amount INT, CHECK (amount > 0), CHECK (amount > -5));"
/// ).unwrap();
/// assert!(constrainer.validate_schema(&invalid).is_err());
/// let valid = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (amount INT, CHECK (amount > 0));"
/// ).unwrap();
/// assert!(constrainer.validate_schema(&valid).is_ok());
/// ```
pub struct RedundantCheck<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RedundantCheck<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RedundantCheck<DB>> for GenericConstrainer<DB> {
    fn from(rule: RedundantCheck<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for RedundantCheck<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RedundantCheck),
            group: LintGroup::Complexity,
            rationale: "A check guaranteed by the table's other checks constrains nothing and is evaluated on every write.",
            source: Some(
                "https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-CHECK-CONSTRAINTS",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE payments (amount INT, CHECK (amount > 0), CHECK (amount > -5));",
                good: "CREATE TABLE payments (amount INT, CHECK (amount > 0));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for RedundantCheck<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let checks = table.check_constraints(database)?.collect::<Vec<_>>();
        let mut kept = Vec::with_capacity(checks.len());
        for (position, check) in checks.iter().enumerate() {
            if check.is_enforced() && !check.no_inherit() && check.is_validated(database)? {
                kept.push(position);
            }
        }
        if kept.len() < 2 {
            return Ok(());
        }
        let component = components(database, table, &checks, &kept)?;
        let mut assumptions = Vec::with_capacity(kept.len());
        for position in (0..kept.len()).rev() {
            let declaration = kept[position];
            let check = checks[declaration];
            if checks[..declaration]
                .iter()
                .any(|earlier| earlier.expression(database) == check.expression(database))
            {
                kept.remove(position);
                continue;
            }
            assumptions.clear();
            assumptions.extend(
                kept.iter()
                    .filter(|&&other| {
                        other != declaration && component[other] == component[declaration]
                    })
                    .map(|&other| Assumption::Check(checks[other])),
            );
            // A check sharing no column with the others is judged on its own,
            // where only a tautology is redundant.
            if assumptions.is_empty() {
                continue;
            }
            let truth = check.truth_under(database, &assumptions)?;
            if truth.outcomes == Outcomes::NONE && truth.raising == Raising::Never {
                break;
            }
            if !truth.outcomes.falsity && truth.raising == Raising::Never {
                kept.remove(position);
                // A tautology is redundant under any checks and is
                // `tautological_check`'s finding.
                if check.is_tautology(database)? {
                    continue;
                }
                let expression = check.expression(database);
                let table_name = table.table_name();
                reporter.table(
                    table,
                    format!(
                        "Table '{table_name}' has the check constraint CHECK ({expression}), which its other checks already guarantee, so it constrains nothing and is evaluated on every write."
                    ),
                    format!("Drop CHECK ({expression}) from table '{table_name}'."),
                )?;
            }
        }
        Ok(())
    }
}

/// The component of every check of `kept`, by its position in `checks`, two
/// checks sharing a component when a chain of checks reading common columns
/// links them.
///
/// Checks of different components read disjoint columns, so one never
/// decides the other. A generated column ties the columns its expression
/// reads to its own, so a table with one puts every check in one component.
///
/// # Errors
///
/// Returns the lookup errors resolving the table's columns or a check's.
fn components<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    checks: &[&DB::CheckConstraint],
    kept: &[usize],
) -> Result<Vec<usize>, Interruption> {
    let mut component = (0..checks.len()).collect::<Vec<_>>();
    if table
        .columns(database)?
        .any(|column| column.generation_expression().is_some())
    {
        component.fill(0);
        return Ok(component);
    }
    let mut columns = Vec::with_capacity(kept.len());
    for &position in kept {
        columns.push(
            checks[position]
                .columns(database)?
                .map(|column| column.column_name().to_owned())
                .collect::<Vec<_>>(),
        );
    }
    for (first, first_columns) in columns.iter().enumerate() {
        for (second, second_columns) in columns.iter().enumerate().skip(first + 1) {
            let (merged, into) = (component[kept[second]], component[kept[first]]);
            if merged != into
                && first_columns
                    .iter()
                    .any(|name| second_columns.contains(name))
            {
                for label in &mut component {
                    if *label == merged {
                        *label = into;
                    }
                }
            }
        }
    }
    Ok(component)
}
