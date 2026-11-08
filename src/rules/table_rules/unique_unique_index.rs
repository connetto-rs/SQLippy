//! Submodule providing the `UniqueUniqueIndex` constraint, which enforces
//! that unique indices are unique per table, meaning that no two unique
//! indices have the same columns in a single table.

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};
use sql_traits::errors::LookupError;
use sql_traits::traits::{DatabaseLike, IndexLike, TableLike};

/// Struct defining a constraint that enforces that unique indices are unique
/// per table.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `UniqueUniqueIndex` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UniqueUniqueIndex::default().into();
///
/// let invalid_schema =
///     ParserDB::parse::<GenericDialect>("CREATE TABLE MyTable (id INT, UNIQUE (id), UNIQUE (id));").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (id INT, UNIQUE (id));").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct UniqueUniqueIndex<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UniqueUniqueIndex<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UniqueUniqueIndex<DB>> for GenericConstrainer<DB> {
    fn from(constraint: UniqueUniqueIndex<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for UniqueUniqueIndex<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "UniqueUniqueIndex",
            group: LintGroup::Complexity,
            rationale: "A duplicated unique index enforces nothing more and is maintained again on every write.",
            source: None,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for UniqueUniqueIndex<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut expressions = table
            .unique_indices(database)?
            .map(|unique_index| unique_index.expression(database))
            .collect::<Result<Vec<_>, LookupError>>()?;
        expressions.sort_unstable();
        for window in expressions.windows(2) {
            if window[0] == window[1] {
                let table_name = table.table_name();
                let duplicate_expression = window[0];
                reporter.table(
                    table,
                    format!(
                        "Table '{table_name}' has the duplicate unique index on {duplicate_expression}."
                    ),
                    format!(
                        "Remove one of the duplicate unique index definitions on {duplicate_expression} from table '{table_name}'."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
