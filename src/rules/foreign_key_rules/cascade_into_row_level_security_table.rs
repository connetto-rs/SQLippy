//! Submodule providing the `CascadeIntoRowLevelSecurityTable` rule.

use sql_traits::traits::{DatabaseLike, ForeignKeyLike, PolicyLike, TableLike};
use sqlparser::ast::{CreatePolicyCommand, ReferentialAction};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports a foreign key whose referential
/// action changes rows of a row-level-security table behind its policies:
/// `ON DELETE CASCADE` where a policy governs `DELETE`, and `SET NULL`,
/// `SET DEFAULT` or `ON UPDATE CASCADE` where a policy governs `UPDATE`.
///
/// Referential actions bypass row-level security, so changing a parent
/// removes or rewrites child rows those policies would refuse the caller.
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
            rationale: "Referential actions bypass row-level security, so a cascading delete removes, and a SET NULL, SET DEFAULT or ON UPDATE CASCADE rewrites, rows of the referencing table that its policies would refuse the caller.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
        };
        &METADATA
    }
}

/// The command whose policies a referential action bypasses on the
/// referencing rows, or `None` when the action rewrites no row.
fn bypassed_command(action: ReferentialAction, on_delete: bool) -> Option<CreatePolicyCommand> {
    match action {
        ReferentialAction::Cascade if on_delete => Some(CreatePolicyCommand::Delete),
        ReferentialAction::Cascade | ReferentialAction::SetNull | ReferentialAction::SetDefault => {
            Some(CreatePolicyCommand::Update)
        }
        ReferentialAction::Restrict | ReferentialAction::NoAction => None,
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
        let host = foreign_key.host_table(database);
        if !host.has_row_level_security(database)? {
            return Ok(());
        }
        let mut bypassed = Vec::new();
        for (event, action, on_delete) in [
            ("ON DELETE", foreign_key.on_delete(database), true),
            ("ON UPDATE", foreign_key.on_update(database), false),
        ] {
            let Some(command) = bypassed_command(action, on_delete) else {
                continue;
            };
            let governed = host.policies(database)?.any(|policy| {
                matches!(policy.command(), CreatePolicyCommand::All) || policy.command() == command
            });
            if governed {
                bypassed.push(format!("{event} {action} bypasses its {command} policies"));
            }
        }
        if bypassed.is_empty() {
            return Ok(());
        }
        let name = host.table_name();
        reporter.foreign_key(
            foreign_key,
            format!(
                "A foreign key of '{name}' rewrites its rows without row-level security: {}.",
                bypassed.join(", ")
            ),
            format!("Use RESTRICT or NO ACTION and change rows of '{name}' through its policies, or allow this foreign key if the action is intended."),
        )?;
        Ok(())
    }
}
