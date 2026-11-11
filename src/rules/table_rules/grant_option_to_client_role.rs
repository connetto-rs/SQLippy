//! Submodule providing the `GrantOptionToClientRole` rule.

use std::{cell::LazyCell, collections::BTreeSet};

use sql_traits::traits::{DatabaseLike, FunctionLike, GrantLike, RoleMembershipLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    rules::{
        grant_support::{ClientRoles, column_grants_on, grantee_list},
        policy_support::held_by_name,
    },
    traits::{
        Constrainer, FunctionRule, GenericConstrainer, Reporter, SchemaRule, TableRule,
        reporter::signature,
    },
};

/// Struct defining a rule that reports a client role able to pass a privilege
/// on: a privilege on a table or its columns, or `EXECUTE` on a function,
/// granted to a client role `WITH GRANT OPTION`, and membership in a role
/// granted to one `WITH ADMIN OPTION`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = GrantOptionToClientRole::default().into();
///
/// let passable = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT); GRANT SELECT ON docs TO PUBLIC WITH GRANT OPTION;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&passable).is_err());
///
/// let kept = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT); GRANT SELECT ON docs TO PUBLIC;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&kept).is_ok());
/// ```
pub struct GrantOptionToClientRole<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for GrantOptionToClientRole<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<GrantOptionToClientRole<DB>> for GenericConstrainer<DB> {
    fn from(_rule: GrantOptionToClientRole<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(GrantOptionToClientRole::default()));
        constrainer.register_function_rule(Box::new(GrantOptionToClientRole::default()));
        constrainer.register_schema_rule(Box::new(GrantOptionToClientRole::default()));
        constrainer
    }
}

impl<DB> Rule for GrantOptionToClientRole<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "GrantOptionToClientRole",
            group: LintGroup::Suspicious,
            rationale: "A client role holding a grant option passes the privilege on to any role it reaches, outside the schema's review.",
            source: Some("https://www.postgresql.org/docs/current/sql-grant.html"),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for GrantOptionToClientRole<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let roles = LazyCell::new(|| ClientRoles::new(database, deployment));
        let mut grantees = BTreeSet::new();
        for grant in table.grants(database)? {
            if grant.with_grant_option() && roles.reach_client(database, grant) {
                grantees.insert(grantee_list(database, grant));
            }
        }
        for grant in column_grants_on(database, table) {
            if grant.with_grant_option() && roles.reach_client(database, grant) {
                grantees.insert(grantee_list(database, grant));
            }
        }
        if grantees.is_empty() {
            return Ok(());
        }
        let name = table.table_name();
        let grantees = grantees.into_iter().collect::<Vec<_>>().join(", ");
        reporter.table(
            table,
            format!("Privileges on '{name}' are granted to {grantees} WITH GRANT OPTION, so the grantee can hand them to any role."),
            format!("Grant to {grantees} without WITH GRANT OPTION, or REVOKE GRANT OPTION FOR ... ON {name} FROM {grantees};"),
        )?;
        Ok(())
    }
}

impl<DB: DatabaseLike> FunctionRule for GrantOptionToClientRole<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let owner = function.owner(database)?;
        let mut grantees = Vec::new();
        let declared = deployment
            .anonymous_roles()
            .chain(deployment.app_roles())
            .filter_map(|name| database.role(name).map(|role| (name, role)));
        for (name, role) in declared {
            // Owning the function lets a role grant it whatever its grants say.
            let owns = owner.is_some_and(|owner| held_by_name(database, name).contains(owner));
            if !owns && function.can_grant_execute(role, database)? {
                grantees.push(name);
            }
        }
        if grantees.is_empty() {
            return Ok(());
        }
        let signature = signature(function, database);
        let grantees = grantees.join(", ");
        reporter.function(
            function,
            format!("EXECUTE on '{signature}' is granted to {grantees} WITH GRANT OPTION, so the grantee can hand it to any role."),
            format!("REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION {signature} FROM {grantees};"),
        )?;
        Ok(())
    }
}

impl<DB: DatabaseLike> SchemaRule for GrantOptionToClientRole<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let clients: BTreeSet<String> = deployment
            .anonymous_roles()
            .chain(deployment.app_roles())
            .map(str::to_owned)
            .collect();
        for membership in database.role_memberships() {
            let member = membership.stored_member_name();
            let Some(role) = membership
                .role(database)
                .filter(|_| membership.admin_option() && clients.contains(member.as_ref()))
            else {
                continue;
            };
            let granted = membership.stored_role_name();
            reporter.role(
                role,
                format!("Membership in '{granted}' is granted to {member} WITH ADMIN OPTION, so the grantee can hand '{granted}' to any role."),
                format!("REVOKE ADMIN OPTION FOR {granted} FROM {member};"),
            )?;
        }
        Ok(())
    }
}
