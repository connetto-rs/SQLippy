//! Submodule providing the `RoleDefinedInSchema` rule.

use sql_traits::traits::{DatabaseLike, RoleLike, RoleMembershipLike};

use crate::{
    deployment::{ClusterBootstrap, Declaration, Membership, RoleAttributes},
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Struct defining a rule that reports every change a database-local schema
/// makes to the roles of its cluster: a role it creates, an attribute it
/// changes, a membership it grants, revokes or changes the options of, and
/// an `ALTER ROLE ... SET` it makes or resets for every database.
///
/// The roles the deployment's cluster bootstrap provisions are the
/// cluster's. The schema checked is the bootstrap followed by the
/// database-local schema, and a schema checked without the bootstrap is
/// reported only for what it creates, grants and sets. The rule is inactive
/// until the deployment declares a cluster bootstrap.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let bootstrap = "CREATE ROLE app NOLOGIN;";
/// let mut constrainer: GenericConstrainer<ParserDB> = RoleDefinedInSchema::default().into();
/// constrainer.set_rule_level("role_defined_in_schema", Level::Warn);
/// constrainer.set_deployment(Deployment::default().with_cluster_bootstrap(
///     &ParserDB::parse::<PostgreSqlDialect>(bootstrap).unwrap(),
/// ));
///
/// let local = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{bootstrap} CREATE TABLE documents (id INT); GRANT SELECT ON documents TO app;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&local).is_ok());
/// let creating = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{bootstrap} CREATE ROLE reporting NOLOGIN;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&creating).is_err());
/// ```
pub struct RoleDefinedInSchema<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RoleDefinedInSchema<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RoleDefinedInSchema<DB>> for GenericConstrainer<DB> {
    fn from(rule: RoleDefinedInSchema<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for RoleDefinedInSchema<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RoleDefinedInSchema),
            group: LintGroup::Restriction,
            rationale: "Roles, their attributes, memberships and settings belong to the cluster, so a database-local schema that changes them fails or changes every other database applying it.",
            source: Some("https://www.postgresql.org/docs/current/database-roles.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "-- cluster bootstrap\n\
CREATE ROLE authenticated NOLOGIN;\n\
-- database-local schema\n\
CREATE ROLE reporting NOLOGIN;\n\
CREATE TABLE documents (id integer PRIMARY KEY);\n\
GRANT SELECT ON documents TO reporting;",
                good: "-- cluster bootstrap\n\
CREATE ROLE authenticated NOLOGIN;\n\
-- database-local schema\n\
CREATE TABLE documents (id integer PRIMARY KEY);\n\
GRANT SELECT ON documents TO authenticated;",
            },
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::ClusterBootstrap]
    }
}

impl<DB: DatabaseLike> SchemaRule for RoleDefinedInSchema<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let Some(bootstrap) = reporter.deployment().cluster_bootstrap() else {
            return Ok(());
        };
        report_roles(database, bootstrap, reporter)?;
        report_memberships(database, bootstrap, reporter)?;
        report_settings(database, bootstrap, reporter)
    }
}

/// Reports every role `database` holds that `bootstrap` does not create,
/// and every role whose attributes differ from the ones `bootstrap` gives
/// it.
fn report_roles<DB: DatabaseLike>(
    database: &DB,
    bootstrap: &ClusterBootstrap,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    for role in database.roles() {
        let name = role.name();
        let Some(provisioned) = bootstrap.role(&role.stored_name()) else {
            reporter.role(
                role,
                format!("Role '{name}' is created by the database-local schema, but roles belong to the cluster."),
                format!("Move CREATE ROLE {name} to the cluster bootstrap."),
            )?;
            continue;
        };
        let clauses = RoleAttributes::of(role).clauses_from(provisioned).join(" ");
        if !clauses.is_empty() {
            reporter.role(
                role,
                format!("The database-local schema sets {clauses} on role '{name}', which belongs to the cluster."),
                format!("Move ALTER ROLE {name} {clauses} to the cluster bootstrap."),
            )?;
        }
    }
    Ok(())
}

/// Reports every membership `database` holds that `bootstrap` does not
/// grant with the same options, and every membership of `bootstrap` that
/// `database` revoked.
fn report_memberships<DB: DatabaseLike>(
    database: &DB,
    bootstrap: &ClusterBootstrap,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    for membership in database.role_memberships() {
        let granted = Membership::of(membership);
        if bootstrap.memberships().contains(&granted) {
            continue;
        }
        let (role, member) = (membership.role_name(), membership.member_name());
        let message = if bootstrap
            .memberships()
            .iter()
            .any(|provisioned| provisioned.joins_same_roles(&granted))
        {
            format!(
                "The database-local schema changes the options of the membership of '{member}' in '{role}', which belongs to the cluster."
            )
        } else {
            format!(
                "The database-local schema grants '{role}' to '{member}', a membership that belongs to the cluster."
            )
        };
        reporter.role_membership(
            membership,
            message,
            format!("Move GRANT {role} TO {member} to the cluster bootstrap."),
        )?;
    }
    // A membership missing from a schema holding both of its roles was
    // revoked by it, where a schema checked without the bootstrap holds
    // neither role.
    for provisioned in bootstrap.memberships() {
        let (Some(role), Some(member)) = (
            database
                .roles()
                .find(|role| role.stored_name() == provisioned.role),
            database
                .roles()
                .find(|role| role.stored_name() == provisioned.member),
        ) else {
            continue;
        };
        let revoked = !database
            .role_memberships()
            .any(|membership| Membership::of(membership).joins_same_roles(provisioned));
        if revoked {
            let (role, name) = (role.name(), member.name());
            reporter.role(
                member,
                format!("The database-local schema revokes '{role}' from '{name}', a membership that belongs to the cluster."),
                format!("Move REVOKE {role} FROM {name} to the cluster bootstrap."),
            )?;
        }
    }
    Ok(())
}

/// Reports every cluster-wide role setting `database` makes that
/// `bootstrap` does not, and every one of `bootstrap` that `database` reset
/// on a role it holds.
fn report_settings<DB: DatabaseLike>(
    database: &DB,
    bootstrap: &ClusterBootstrap,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    for setting in database.role_settings() {
        if setting.database().is_some() || bootstrap.settings().contains(setting) {
            continue;
        }
        let (role, name) = (setting.role().unwrap_or("ALL"), setting.name());
        reporter.role_setting(
            setting,
            format!("The database-local schema sets {name} for role {role} in every database of the cluster."),
            format!("Move ALTER ROLE {role} SET {name} to the cluster bootstrap."),
        )?;
    }
    for provisioned in bootstrap.settings() {
        let Some(role) = provisioned
            .role()
            .and_then(|name| database.roles().find(|role| role.stored_name() == name))
        else {
            continue;
        };
        let reset = provisioned.database().is_none()
            && !database.role_settings().any(|setting| {
                setting.database().is_none()
                    && setting.role() == provisioned.role()
                    && setting.is_named(provisioned.name())
            });
        if reset {
            let (name, setting) = (role.name(), provisioned.name());
            reporter.role(
                role,
                format!("The database-local schema resets {setting} on role '{name}' in every database of the cluster."),
                format!("Move ALTER ROLE {name} RESET {setting} to the cluster bootstrap."),
            )?;
        }
    }
    Ok(())
}
