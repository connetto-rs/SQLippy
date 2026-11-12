//! Submodule providing the `UnsatisfiableCheck` rule, which
//! enforces that tables do not have negation (always false) check
//! constraints.

use sql_traits::traits::{CheckConstraintLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that tables do not have
/// negation check constraints.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `unsatisfiable_check` rule.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UnsatisfiableCheck::default().into();
///
/// // Invalid: has negation check constraint CHECK (false)
/// let invalid_schema = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE my_table (
///         id INT PRIMARY KEY,
///         age INT CHECK (false)
///     );",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Invalid: has negation check constraint CHECK (1 = 0)
/// let invalid_schema2 = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE my_table (
///         id INT PRIMARY KEY,
///         age INT CHECK (1 = 0)
///     );",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema2).is_err());
///
/// // Valid: has meaningful check constraint
/// let valid_schema = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE my_table (
///         id INT PRIMARY KEY,
///         age INT CHECK (age > 0)
///     );",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct UnsatisfiableCheck<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnsatisfiableCheck<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnsatisfiableCheck<DB>> for GenericConstrainer<DB> {
    fn from(constraint: UnsatisfiableCheck<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for UnsatisfiableCheck<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UnsatisfiableCheck),
            group: LintGroup::Correctness,
            rationale: "A check that no row can satisfy makes every insert and update of the table fail.",
            source: Some("https://www.postgresql.org/docs/current/sql-createtable.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE people (id INT PRIMARY KEY, age INT CHECK (false));",
                good: "CREATE TABLE people (id INT PRIMARY KEY, age INT CHECK (age > 0));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for UnsatisfiableCheck<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        // Check if any check constraint is a negation
        for check_constraint in table.check_constraints(database)? {
            if check_constraint.is_negation(database)? {
                let table_name = table.table_name();
                let expression = check_constraint.expression(database).to_string();
                reporter.table(
                    table,
                    format!(
                        "Table '{table_name}' has a negation check constraint CHECK ({expression})."
                    ),
                    format!(
                        "Remove the check constraint CHECK ({expression}) from table '{table_name}'."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
