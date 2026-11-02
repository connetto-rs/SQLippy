//! Submodule providing the `GrantOptionToClientRole` rule.

use std::{cell::LazyCell, collections::BTreeSet};

use sql_traits::traits::{DatabaseLike, GrantLike, TableLike};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::grant_support::{ClientRoles, column_grants_on, grantee_list},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a privilege on a table or its columns
/// granted to a client role `WITH GRANT OPTION`.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
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
    fn from(rule: GrantOptionToClientRole<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
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
