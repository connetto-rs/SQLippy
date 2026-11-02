//! Submodule providing the `ClientRoleBypassesRowLevelSecurity` and
//! `SettableMembershipInBypassingRole` rules.

use sql_traits::traits::{DatabaseLike, RoleLike, RoleMembershipLike};

use crate::{
    deployment::{Declaration, Deployment},
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

const SOURCE: Option<&str> = Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html");

/// Struct defining a rule that reports a declared anonymous or app role with
/// `BYPASSRLS` or `SUPERUSER`.
///
/// The rule is inactive until the deployment declares an anonymous or app
/// role.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> =
///     ClientRoleBypassesRowLevelSecurity::default().into();
/// constrainer.set_deployment(Deployment::default().with_app_role("app_user"));
///
/// let bypassing = ParserDB::parse::<PostgreSqlDialect>("CREATE ROLE app_user BYPASSRLS;").unwrap();
/// assert!(constrainer.validate_schema(&bypassing).is_err());
/// ```
pub struct ClientRoleBypassesRowLevelSecurity<DB>(std::marker::PhantomData<DB>);

/// Struct defining a rule that reports a declared anonymous or app role that
/// can `SET ROLE` to a role with `BYPASSRLS` or `SUPERUSER` through its
/// memberships.
///
/// Attributes are not inherited, but `SET ROLE` reaches every role along a
/// chain of memberships granted with the `SET` option, which PostgreSQL
/// gives a membership unless it is granted `WITH SET FALSE`. The rule is
/// inactive until the deployment declares an anonymous or app role.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> =
///     SettableMembershipInBypassingRole::default().into();
/// constrainer.set_deployment(Deployment::default().with_app_role("app_user"));
///
/// let settable = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE ROLE bypasser BYPASSRLS; CREATE ROLE app_user IN ROLE bypasser;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&settable).is_err());
/// ```
pub struct SettableMembershipInBypassingRole<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ClientRoleBypassesRowLevelSecurity<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB> Default for SettableMembershipInBypassingRole<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ClientRoleBypassesRowLevelSecurity<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: ClientRoleBypassesRowLevelSecurity<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB: DatabaseLike + 'static> From<SettableMembershipInBypassingRole<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: SettableMembershipInBypassingRole<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ClientRoleBypassesRowLevelSecurity<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "ClientRoleBypassesRowLevelSecurity",
            group: LintGroup::Correctness,
            rationale: "Superusers and roles with BYPASSRLS skip every policy, so a role clients act as sees and changes every row.",
            source: SOURCE,
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::ClientRoles]
    }
}

impl<DB> Rule for SettableMembershipInBypassingRole<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "SettableMembershipInBypassingRole",
            group: LintGroup::Suspicious,
            rationale: "A client role that can SET ROLE to a superuser or BYPASSRLS role takes on its attributes and skips every policy.",
            source: SOURCE,
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::ClientRoles]
    }
}

/// Declared client roles the schema creates.
fn client_roles<'db, DB: DatabaseLike>(
    database: &'db DB,
    deployment: &'db Deployment,
) -> impl Iterator<Item = &'db DB::Role> {
    deployment
        .anonymous_roles()
        .chain(deployment.app_roles())
        .filter_map(|name| database.role(name))
}

fn bypasses<R: RoleLike>(role: &R) -> bool {
    role.can_bypass_rls() || role.is_superuser()
}

impl<DB: DatabaseLike> SchemaRule for ClientRoleBypassesRowLevelSecurity<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for role in client_roles(database, reporter.deployment()) {
            if bypasses(role) {
                let name = role.name();
                reporter.role(
                    role,
                    format!("Client role '{name}' has BYPASSRLS or SUPERUSER, so every policy is skipped for it."),
                    format!("ALTER ROLE {name} NOSUPERUSER NOBYPASSRLS;"),
                )?;
            }
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> SchemaRule for SettableMembershipInBypassingRole<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for role in client_roles(database, reporter.deployment()) {
            let mut seen = vec![role];
            let mut frontier = vec![role];
            let mut reached = None;
            while let Some(member) = frontier.pop() {
                for parent in member
                    .memberships(database)
                    .filter(|membership| membership.set_option())
                    .filter_map(|membership| membership.role(database))
                {
                    if seen.contains(&parent) {
                        continue;
                    }
                    if bypasses(parent) {
                        reached = Some(parent);
                        frontier.clear();
                        break;
                    }
                    seen.push(parent);
                    frontier.push(parent);
                }
            }
            if let Some(bypassing) = reached {
                let (name, bypassing) = (role.name(), bypassing.name());
                reporter.role(
                    role,
                    format!("Client role '{name}' can SET ROLE to '{bypassing}', which has BYPASSRLS or SUPERUSER and skips every policy."),
                    format!("Remove the membership of '{name}' in '{bypassing}', or grant it WITH SET FALSE."),
                )?;
            }
        }
        Ok(())
    }
}
