//! Submodule providing the `NoNegationCheckRule` rule, which
//! enforces that tables do not have negation (always false) check
//! constraints.

use sql_traits::traits::{CheckConstraintLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that tables do not have
/// negation check constraints.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `NoNegationCheckRule` rule.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NoNegationCheckRule::default().into();
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
pub struct NoNegationCheckRule<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NoNegationCheckRule<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NoNegationCheckRule<DB>> for GenericConstrainer<DB> {
    fn from(constraint: NoNegationCheckRule<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for NoNegationCheckRule<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NoNegationCheckRule",
            group: LintGroup::Correctness,
            rationale: "A check that no row can satisfy makes every insert and update of the table fail.",
            source: Some("https://www.postgresql.org/docs/current/sql-createtable.html"),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for NoNegationCheckRule<DB> {
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
