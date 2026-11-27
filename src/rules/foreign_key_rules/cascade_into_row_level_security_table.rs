//! Submodule providing the `CascadeIntoRowLevelSecurityTable` rule.

use sql_traits::traits::{DatabaseLike, ForeignKeyLike, PolicyLike, TableLike};
use sqlparser::ast::{CreatePolicyCommand, ReferentialAction};

use crate::{
    deployment::Declaration,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{acting, client_roles},
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports a foreign key whose referential
/// action lets a client role change rows of a row-level-security table
/// behind its policies. `ON DELETE CASCADE` is reported where a policy
/// governs `DELETE`, and `SET NULL`, `SET DEFAULT` or `ON UPDATE CASCADE`
/// where a policy governs `UPDATE`, each when a declared app or anonymous
/// role, or `PUBLIC`, holds the privilege that sets the action off.
///
/// Referential actions bypass row-level security, so a client deleting a
/// parent row, or updating its referenced columns, removes or rewrites child
/// rows those policies would refuse it. A parent only other roles may delete
/// or update leaves the action to them. The privilege is `DELETE` on the
/// referenced table for an `ON DELETE` action and `UPDATE` on one of its
/// referenced columns for an `ON UPDATE` action, granted to the role or to a
/// role it inherits. A `SECURITY DEFINER` function or trigger that changes
/// the referenced table on a client's behalf is not followed.
///
/// The rule does not run on SQLite, which has no row-level security
/// policies, and is inactive until the deployment declares a client role.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> =
///     CascadeIntoRowLevelSecurityTable::default().into();
/// constrainer.set_deployment(Deployment::default().with_app_role("app"));
/// let schema = |grant| {
///     ParserDB::parse::<PostgreSqlDialect>(&format!(
///         "CREATE ROLE app;
///          CREATE ROLE maintainer;
///          CREATE TABLE parents (id INT PRIMARY KEY);
///          {grant}
///          CREATE TABLE kids (parent_id INT REFERENCES parents (id) ON DELETE CASCADE);
///          ALTER TABLE kids ENABLE ROW LEVEL SECURITY;
///          CREATE POLICY kids_delete ON kids FOR DELETE USING (false);"
///     ))
///     .unwrap()
/// };
/// assert!(constrainer.validate_schema(&schema("GRANT DELETE ON parents TO app;")).is_err());
/// assert!(constrainer.validate_schema(&schema("GRANT DELETE ON parents TO maintainer;")).is_ok());
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
            name: rule_name!(CascadeIntoRowLevelSecurityTable),
            group: LintGroup::Pedantic,
            rationale: "Referential actions bypass row-level security, so a client role that may delete or update a parent row removes, through a cascading delete, or rewrites, through SET NULL, SET DEFAULT or ON UPDATE CASCADE, rows of the referencing table that its policies would refuse it.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE authenticated;\n\
CREATE TABLE parents (id INT PRIMARY KEY);\n\
GRANT DELETE ON parents TO authenticated;\n\
CREATE TABLE children (parent_id INT REFERENCES parents (id) ON DELETE CASCADE);\n\
ALTER TABLE children ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY children_delete ON children FOR DELETE USING (false);",
                good: "CREATE ROLE authenticated;\n\
CREATE TABLE parents (id INT PRIMARY KEY);\n\
GRANT DELETE ON parents TO authenticated;\n\
CREATE TABLE children (parent_id INT REFERENCES parents (id) ON DELETE RESTRICT);\n\
ALTER TABLE children ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY children_delete ON children FOR DELETE USING (false);",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::ClientRoles]
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
        if !foreign_key.is_enforced(database) || !host.has_row_level_security(database)? {
            return Ok(());
        }
        let parent = foreign_key.referenced_table(database)?;
        let parent_name = parent.table_name();
        let clients = client_roles(database, reporter.deployment());
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
            if !governed {
                continue;
            }
            let mut triggering = Vec::new();
            for (name, role) in &clients {
                let held = parent.privileges(acting(*role), database)?;
                let sets_off = if on_delete {
                    held.delete
                } else {
                    foreign_key
                        .referenced_columns(database)?
                        .any(|column| held.update.on_column(column))
                };
                if sets_off {
                    triggering.push(name.as_str());
                }
            }
            if triggering.is_empty() {
                continue;
            }
            let verb = if on_delete { "delete from" } else { "update" };
            bypassed.push(format!(
                "{event} {action} bypasses its {command} policies when {} may {verb} '{parent_name}'",
                triggering.join(" or ")
            ));
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
            format!("Use RESTRICT or NO ACTION and change rows of '{name}' through its policies, keep the privilege on '{parent_name}' from client roles, or allow it with `allow_foreign_key` if the action is intended."),
        )?;
        Ok(())
    }
}
