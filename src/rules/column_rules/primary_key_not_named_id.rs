//! Submodule providing the `PrimaryKeyNotNamedId` constraint, which
//! enforces that if a column is a non-composite primary key, it must be named
//! "id".

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that if a column is a
/// non-composite primary key, it must be named "id".
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `primary_key_not_named_id` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = PrimaryKeyNotNamedId::default().into();
///
/// let invalid_schema =
///     ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (pk INT PRIMARY KEY, name TEXT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema =
///     ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (id INT PRIMARY KEY, name TEXT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// // Composite primary keys are allowed to have any name
/// let valid_composite_schema = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE mytable (pk1 INT, pk2 INT, name TEXT, PRIMARY KEY (pk1, pk2));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_composite_schema).is_ok());
/// ```
pub struct PrimaryKeyNotNamedId<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PrimaryKeyNotNamedId<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PrimaryKeyNotNamedId<DB>> for GenericConstrainer<DB> {
    fn from(constraint: PrimaryKeyNotNamedId<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for PrimaryKeyNotNamedId<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(PrimaryKeyNotNamedId),
            group: LintGroup::Style,
            rationale: "Naming every single-column primary key `id` lets references and generated code find it without a lookup.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE t (pk INT PRIMARY KEY);",
                good: "CREATE TABLE t (id INT PRIMARY KEY);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for PrimaryKeyNotNamedId<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !column.is_primary_key(database)? {
            return Ok(());
        }

        let table = column.table(database);
        let pk_columns: Vec<_> = table.primary_key_columns(database)?.collect();

        // The rule only applies to single-column primary keys.
        if pk_columns.len() > 1 || column.column_name() == "id" {
            return Ok(());
        }

        let column_name = column.column_name();
        let table_name = table.table_name();
        reporter.column(
            column,
            format!(
                "Column '{column_name}' in table '{table_name}' is a non-composite primary key but is not named 'id'."
            ),
            format!(
                "Rename the primary key column '{column_name}' to 'id' in table '{table_name}'."
            ),
        )?;
        Ok(())
    }
}
