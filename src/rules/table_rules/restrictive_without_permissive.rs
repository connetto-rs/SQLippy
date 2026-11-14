//! Submodule providing the `RestrictiveWithoutPermissive` rule.

use std::collections::BTreeSet;

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::CreatePolicyType;

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{Command, held_roles, policy_roles},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a restrictive policy no permissive
/// policy lets take effect.
///
/// PostgreSQL grants a row only through a permissive policy and then narrows
/// it with every restrictive policy, so a restrictive policy matters only for
/// a caller and command some permissive policy also covers. A restrictive
/// policy is reported when no caller is reached both by it and by a
/// permissive policy for one of its commands. The callers considered are
/// every declared role with the roles it inherits through memberships
/// granted with `INHERIT`, as PostgreSQL follows them, every role a policy
/// names without declaring it, and a caller holding only `PUBLIC`. The
/// reported policy's roles then cannot run those commands at all, and its
/// condition never decides anything. A restrictive policy over every command
/// beside a permissive policy for one of them is the usual floor of a
/// read-only table and is not reported.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> =
///     RestrictiveWithoutPermissive::default().into();
///
/// let alone = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (is_public BOOL);
///      CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT USING (is_public);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&alone).is_err());
///
/// let narrowed = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (is_public BOOL);
///      CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT USING (is_public);
///      CREATE POLICY everyone ON docs FOR SELECT USING (true);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&narrowed).is_ok());
/// ```
pub struct RestrictiveWithoutPermissive<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RestrictiveWithoutPermissive<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RestrictiveWithoutPermissive<DB>> for GenericConstrainer<DB> {
    fn from(rule: RestrictiveWithoutPermissive<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for RestrictiveWithoutPermissive<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RestrictiveWithoutPermissive),
            group: LintGroup::Suspicious,
            rationale: "A restrictive policy only narrows what a permissive policy grants, so without a permissive policy for its commands and roles it never takes effect and those roles are denied outright.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (id INT PRIMARY KEY, is_public BOOL);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT USING (is_public);",
                good: "CREATE TABLE docs (id INT PRIMARY KEY, is_public BOOL);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY pub ON docs AS RESTRICTIVE FOR SELECT USING (is_public);\n\
CREATE POLICY everyone ON docs FOR SELECT USING (true);",
            },
        };
        &METADATA
    }
}

/// Whether a policy for `roles`, `None` standing for `PUBLIC`, applies to a
/// caller holding `held`.
fn applies(roles: Option<&[String]>, held: &BTreeSet<String>) -> bool {
    roles.is_none_or(|roles| roles.iter().any(|role| held.contains(role)))
}

impl<DB: DatabaseLike> TableRule for RestrictiveWithoutPermissive<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let policies: Vec<_> = table.policies(database)?.collect();
        let mut callers: Vec<BTreeSet<String>> = database
            .roles()
            .map(|role| held_roles(database, role))
            .collect();
        for policy in &policies {
            for role in policy_roles(database, policy).unwrap_or_default() {
                if database.role(&role).is_none() {
                    callers.push(BTreeSet::from([role]));
                }
            }
        }
        callers.push(BTreeSet::new());
        let permissive: Vec<_> = policies
            .iter()
            .filter(|policy| policy.policy_type() != CreatePolicyType::Restrictive)
            .map(|policy| (policy.command(), policy_roles(database, policy)))
            .collect();
        for policy in &policies {
            if policy.policy_type() != CreatePolicyType::Restrictive {
                continue;
            }
            let roles = policy_roles(database, policy);
            let effective = callers.iter().any(|held| {
                applies(roles.as_deref(), held)
                    && Command::ALL.iter().any(|command| {
                        command.covered_by(policy.command())
                            && permissive.iter().any(|(granted, granted_roles)| {
                                command.covered_by(*granted)
                                    && applies(granted_roles.as_deref(), held)
                            })
                    })
            });
            if effective {
                continue;
            }
            let mut sites: Vec<PolicySite<DB>> = Vec::new();
            for (clause, expression) in [
                (PolicyClause::Using, policy.using_expression(database)?),
                (PolicyClause::WithCheck, policy.check_expression(database)?),
            ] {
                if let Some(expression) = expression {
                    sites.push(PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new((*policy).clone()),
                        clause,
                        expression: expression.to_string(),
                    });
                }
            }
            let name = policy.name();
            reporter.policies(
                sites,
                format!(
                    "Restrictive policy '{name}' on '{}' narrows commands no permissive policy grants to its roles, so it never takes effect and those roles cannot run them at all.",
                    table.table_name()
                ),
                format!(
                    "Add the permissive policy that grants what '{name}' narrows, or drop '{name}' if those roles are meant to be denied."
                ),
            )?;
        }
        Ok(())
    }
}
