//! Submodule providing the `MissingPrimaryKey` constraint, which enforces that
//! tables have a primary key.

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that tables have a primary key.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `missing_primary_key` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = MissingPrimaryKey::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (id INT, name TEXT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema =
///     ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (id INT PRIMARY KEY, name TEXT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct MissingPrimaryKey<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for MissingPrimaryKey<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<MissingPrimaryKey<DB>> for GenericConstrainer<DB> {
    fn from(constraint: MissingPrimaryKey<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for MissingPrimaryKey<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(MissingPrimaryKey),
            group: LintGroup::Suspicious,
            rationale: "A table without a primary key has no declared row identity, so other tables cannot reference its rows and clients cannot address one row.",
            source: Some(
                "https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-PRIMARY-KEYS",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE notes (id INT, body TEXT);",
                good: "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for MissingPrimaryKey<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !table.has_primary_key(database)? {
            let table_name = table.table_name();
            reporter.table(
                table,
                format!("Table '{table_name}' does not have a primary key."),
                format!("Add a primary key to the table '{table_name}'."),
            )?;
        }
        Ok(())
    }
}
