//! Submodule providing the `UniqueCheckRule` constraint, which enforces
//! that check constraints are unique per table, meaning that no two check
//! constraints have the same clause in a single table.

use sql_traits::traits::{CheckConstraintLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that check constraints are
/// unique per table.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `UniqueCheckRule` rule.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UniqueCheckRule::default().into();
///
/// let invalid_schema =
///     ParserDB::parse::<GenericDialect>("CREATE TABLE MyTable (id INT, CHECK (id > 0), CHECK (id > 0));")
///         .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema =
///     ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (id INT, CHECK (id > 0));").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct UniqueCheckRule<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UniqueCheckRule<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UniqueCheckRule<DB>> for GenericConstrainer<DB> {
    fn from(constraint: UniqueCheckRule<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for UniqueCheckRule<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "UniqueCheckRule",
            group: LintGroup::Complexity,
            rationale: "A duplicated check constraint enforces nothing more and is evaluated again on every write.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE notes (id INT PRIMARY KEY, CHECK (id > 0), CHECK (id > 0));",
                good: "CREATE TABLE notes (id INT PRIMARY KEY, CHECK (id > 0));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for UniqueCheckRule<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut constraints = table.check_constraints(database)?.collect::<Vec<_>>();
        constraints.sort_unstable_by_key(|c| c.expression(database));
        for window in constraints.windows(2) {
            if window[0].expression(database) == window[1].expression(database) {
                let table_name = table.table_name();
                let expression = window[0].expression(database).to_string();
                reporter.table(
                    table,
                    format!(
                        "Table '{table_name}' has the duplicate check constraint CHECK ({expression})."
                    ),
                    format!(
                        "Remove one of the duplicate check constraints CHECK ({expression}) from table '{table_name}'."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
