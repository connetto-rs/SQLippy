//! Submodule providing the `PolicyToCreatingRole` and
//! `RoleKeyedPolicyWhenPooled` rules.

use std::ops::ControlFlow;

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::{Expr, FunctionArguments, Owner, Visit, Visitor};

use crate::{
    deployment::Declaration,
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a policy whose `TO` list names
/// `CURRENT_USER`, `CURRENT_ROLE` or `SESSION_USER`.
///
/// PostgreSQL resolves those names once, at `CREATE POLICY`, so the policy
/// applies to whichever role ran the migration and never follows the caller.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = PolicyToCreatingRole::default().into();
///
/// let frozen = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      CREATE POLICY mine ON docs TO CURRENT_USER USING (true);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&frozen).is_err());
/// ```
pub struct PolicyToCreatingRole<DB>(std::marker::PhantomData<DB>);

/// Struct defining a rule that reports a policy clause reading
/// `current_user`, `current_role` or `session_user` in a pooled deployment.
///
/// Every caller shares the pooled role, so such a policy admits every caller
/// or none. The rule is inactive until the deployment declares whether it is
/// pooled.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> =
///     RoleKeyedPolicyWhenPooled::default().into();
/// constrainer.set_deployment(Deployment::default().with_pooled(true));
///
/// let role_keyed = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT, owner TEXT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      CREATE POLICY mine ON docs USING (owner = current_user);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&role_keyed).is_err());
/// ```
pub struct RoleKeyedPolicyWhenPooled<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PolicyToCreatingRole<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB> Default for RoleKeyedPolicyWhenPooled<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PolicyToCreatingRole<DB>> for GenericConstrainer<DB> {
    fn from(rule: PolicyToCreatingRole<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB: DatabaseLike + 'static> From<RoleKeyedPolicyWhenPooled<DB>> for GenericConstrainer<DB> {
    fn from(rule: RoleKeyedPolicyWhenPooled<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for PolicyToCreatingRole<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "PolicyToCreatingRole",
            group: LintGroup::Suspicious,
            rationale: "PostgreSQL resolves CURRENT_USER, CURRENT_ROLE and SESSION_USER in a policy's TO list when the policy is created, so it applies to the migration's role and never to the callers it seems to name.",
            source: Some("https://www.postgresql.org/docs/current/sql-createpolicy.html"),
        };
        &METADATA
    }
}

impl<DB> Rule for RoleKeyedPolicyWhenPooled<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "RoleKeyedPolicyWhenPooled",
            group: LintGroup::Suspicious,
            rationale: "In a pooled deployment every caller shares one database role, so a policy keyed on the role admits every caller or none.",
            source: None,
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Pooled]
    }
}

impl<DB: DatabaseLike> TableRule for PolicyToCreatingRole<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            let Some(role) = policy.roles(database).find_map(|owner| match owner {
                Owner::CurrentUser => Some("CURRENT_USER"),
                Owner::CurrentRole => Some("CURRENT_ROLE"),
                Owner::SessionUser => Some("SESSION_USER"),
                Owner::Ident(_) => None,
            }) else {
                continue;
            };
            let name = policy.name();
            reporter.policies(
                vec![PolicySite {
                    table: Box::new(table.clone()),
                    policy: Box::new(policy.clone()),
                    clause: PolicyClause::To,
                    expression: role.to_owned(),
                }],
                format!("Policy '{name}' on '{}' is TO {role}, which names the role that created it, not the caller.", table.table_name()),
                format!("Name the roles the policy is for in its TO list, or drop TO {role} so it applies to PUBLIC."),
            )?;
        }
        Ok(())
    }
}

/// Finds the first read of the current or session role.
struct RoleRead;

impl Visitor for RoleRead {
    type Break = String;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(function) = expression
            && matches!(function.args, FunctionArguments::None)
            && function
                .name
                .0
                .last()
                .and_then(|part| part.as_ident())
                .is_some_and(|ident| {
                    ["current_user", "current_role", "session_user"]
                        .iter()
                        .any(|role| ident.value.eq_ignore_ascii_case(role))
                })
        {
            return ControlFlow::Break(expression.to_string());
        }
        ControlFlow::Continue(())
    }
}

impl<DB: DatabaseLike> TableRule for RoleKeyedPolicyWhenPooled<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !reporter.deployment().is_pooled() {
            return Ok(());
        }
        for policy in table.policies(database)? {
            let clauses = [
                (PolicyClause::Using, policy.using_expression(database)),
                (PolicyClause::WithCheck, policy.check_expression(database)),
            ];
            let sites: Vec<_> = clauses
                .into_iter()
                .filter_map(|(clause, expression)| {
                    let ControlFlow::Break(read) = expression?.visit(&mut RoleRead) else {
                        return None;
                    };
                    Some(PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new(policy.clone()),
                        clause,
                        expression: read,
                    })
                })
                .collect();
            if sites.is_empty() {
                continue;
            }
            let name = policy.name();
            reporter.policies(
                sites,
                format!("Policy '{name}' on '{}' reads the database role, which every caller shares in this pooled deployment.", table.table_name()),
                format!("Key '{name}' on the caller's credential, such as a session setting, rather than on the database role."),
            )?;
        }
        Ok(())
    }
}
