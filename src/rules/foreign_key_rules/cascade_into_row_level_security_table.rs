//! Submodule providing the `CascadeIntoRowLevelSecurityTable` rule.

use sql_traits::traits::{DatabaseLike, ForeignKeyLike, PolicyLike, TableLike};
use sqlparser::ast::CreatePolicyCommand;

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports an `ON DELETE CASCADE` foreign key
/// whose host table has row-level security and a policy governing `DELETE`.
///
/// Referential actions bypass row-level security, so deleting a parent removes
/// child rows those policies would refuse the caller.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> =
///     CascadeIntoRowLevelSecurityTable::default().into();
///
/// let cascading = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE parents (id INT PRIMARY KEY);
///      CREATE TABLE kids (parent_id INT REFERENCES parents (id) ON DELETE CASCADE);
///      ALTER TABLE kids ENABLE ROW LEVEL SECURITY;
///      CREATE POLICY kids_delete ON kids FOR DELETE USING (false);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&cascading).is_err());
/// ```
pub struct CascadeIntoRowLevelSecurityTable<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for CascadeIntoRowLevelSecurityTable<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<CascadeIntoRowLevelSecurityTable<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: CascadeIntoRowLevelSecurityTable<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for CascadeIntoRowLevelSecurityTable<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "CascadeIntoRowLevelSecurityTable",
            group: LintGroup::Pedantic,
            rationale: "Referential actions bypass row-level security, so a cascading delete removes rows of the referencing table that its DELETE policies would refuse the caller.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for CascadeIntoRowLevelSecurityTable<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !foreign_key.on_delete_cascade(database) {
            return Ok(());
        }
        let host = foreign_key.host_table(database);
        if !host.has_row_level_security(database)?
            || !host.policies(database)?.any(|policy| {
                matches!(
                    policy.command(),
                    CreatePolicyCommand::All | CreatePolicyCommand::Delete
                )
            })
        {
            return Ok(());
        }
        let name = host.table_name();
        reporter.foreign_key(
            foreign_key,
            format!("A foreign key of '{name}' deletes its rows ON DELETE CASCADE, bypassing the DELETE policies of '{name}'."),
            format!("Use ON DELETE RESTRICT or NO ACTION and delete rows of '{name}' through its policies, or allow this foreign key if the cascade is intended."),
        )?;
        Ok(())
    }
}
