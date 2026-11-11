//! Submodule providing the `NoTautologicalCheckRule` rule, which
//! enforces that tables do not have tautological (always true) check
//! constraints.

use sql_traits::traits::{CheckConstraintLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that tables do not have
/// tautological check constraints.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `NoTautologicalCheckRule` rule.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NoTautologicalCheckRule::default().into();
///
/// // Invalid: has tautological check constraint CHECK (true)
/// let invalid_schema = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE my_table (
///         id INT PRIMARY KEY,
///         age INT CHECK (true)
///     );",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Invalid: has tautological check constraint CHECK (1 = 1)
/// let invalid_schema2 = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE my_table (
///         id INT PRIMARY KEY,
///         age INT CHECK (1 = 1)
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
pub struct NoTautologicalCheckRule<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NoTautologicalCheckRule<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NoTautologicalCheckRule<DB>> for GenericConstrainer<DB> {
    fn from(constraint: NoTautologicalCheckRule<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for NoTautologicalCheckRule<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NoTautologicalCheckRule",
            group: LintGroup::Correctness,
            rationale: "A check that every row satisfies constrains nothing, so the condition it was meant to enforce is missing.",
            source: Some("https://www.postgresql.org/docs/current/sql-createtable.html"),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for NoTautologicalCheckRule<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        // Check if any check constraint is tautological
        for check_constraint in table.check_constraints(database)? {
            if check_constraint.is_tautology(database)? {
                let table_name = table.table_name();
                let expression = check_constraint.expression(database).to_string();
                reporter.table(
                    table,
                    format!(
                        "Table '{table_name}' has a tautological check constraint CHECK ({expression})."
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
