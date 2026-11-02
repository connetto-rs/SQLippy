//! Submodule providing the `ReferencesGrantedToClientRole` rule.

use std::{cell::LazyCell, collections::BTreeSet};

use sql_traits::traits::{DatabaseLike, TableLike};
use sqlparser::ast::Action;

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::grant_support::{ClientRoles, column_grants_on, grantee_list, grants_privilege},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports `REFERENCES` on a row-level-security
/// table granted to a client role, on the table or on its columns.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ReferencesGrantedToClientRole::default().into();
///
/// let probed = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE accounts (email TEXT PRIMARY KEY);
///      ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
///      GRANT REFERENCES ON accounts TO PUBLIC;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&probed).is_err());
/// ```
pub struct ReferencesGrantedToClientRole<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ReferencesGrantedToClientRole<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ReferencesGrantedToClientRole<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: ReferencesGrantedToClientRole<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ReferencesGrantedToClientRole<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "ReferencesGrantedToClientRole",
            group: LintGroup::Pedantic,
            rationale: "Referential integrity checks bypass row-level security, so a foreign key the grantee creates tells it which keys exist among rows it cannot read.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for ReferencesGrantedToClientRole<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !table.has_row_level_security(database)? {
            return Ok(());
        }
        let deployment = reporter.deployment();
        let roles = LazyCell::new(|| ClientRoles::new(database, deployment));
        let references = |action: &Action| matches!(action, Action::References { .. });
        let mut grantees = BTreeSet::new();
        for grant in table.grants(database)? {
            if grants_privilege(database, grant, references) && roles.reach_client(database, grant)
            {
                grantees.insert(grantee_list(database, grant));
            }
        }
        for grant in column_grants_on(database, table) {
            if grants_privilege(database, grant, references) && roles.reach_client(database, grant)
            {
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
            format!("REFERENCES on '{name}' is granted to {grantees}, whose foreign keys can probe for rows its policies hide."),
            format!("REVOKE REFERENCES ON {name} FROM {grantees};"),
        )?;
        Ok(())
    }
}
