//! Submodule providing the `PoliciesRequireRowLevelSecurity` constraint.

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that if a table has policies, it must have RLS enabled.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `PoliciesRequireRowLevelSecurity` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = PoliciesRequireRowLevelSecurity::default().into();
///
/// // Invalid: Has policy but RLS not enabled
/// let invalid_schema = ParserDB::parse::<GenericDialect>("
///     CREATE TABLE my_table (id INT);
///     CREATE POLICY p ON my_table USING (true);
/// ").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Valid: Has policy and RLS enabled
/// let valid_schema = ParserDB::parse::<GenericDialect>("
///     CREATE TABLE my_table (id INT);
///     ALTER TABLE my_table ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY p ON my_table USING (true);
/// ").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct PoliciesRequireRowLevelSecurity<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PoliciesRequireRowLevelSecurity<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PoliciesRequireRowLevelSecurity<DB>>
    for GenericConstrainer<DB>
{
    fn from(constraint: PoliciesRequireRowLevelSecurity<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for PoliciesRequireRowLevelSecurity<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "PoliciesRequireRowLevelSecurity",
            group: LintGroup::Correctness,
            rationale: "PostgreSQL applies no policy until row-level security is enabled on the table, so the policies restrict nothing.",
            source: Some("https://www.postgresql.org/docs/current/sql-createpolicy.html"),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for PoliciesRequireRowLevelSecurity<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if table.policies(database)?.next().is_some() && !table.has_row_level_security(database)? {
            let table_name = table.table_name();
            reporter.table(
                table,
                format!("Table '{table_name}' has policies but row-level security is not enabled."),
                format!("ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;"),
            )?;
        }
        Ok(())
    }
}
