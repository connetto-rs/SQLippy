//! Submodule providing the `DenyListPolicy` rule.

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, PolicyLike, TableLike},
};
use sqlparser::ast::{CreatePolicyType, Expr, InTarget, UnaryOperator};

use crate::{
    error::{Interruption, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::policy_support::{Command, applied, held_by_name, is_tautology, policy_roles, unnested},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Whether the expression is a negated existence test: `NOT EXISTS` or
/// `NOT IN` over a subquery.
fn is_deny_list(expression: &Expr) -> bool {
    match unnested(expression) {
        Expr::Exists { negated, .. }
        | Expr::In {
            target: InTarget::Subquery(_),
            negated,
            ..
        } => *negated,
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => matches!(
            unnested(expr),
            Expr::Exists { negated: false, .. }
                | Expr::In {
                    target: InTarget::Subquery(_),
                    negated: false,
                    ..
                }
        ),
        _ => false,
    }
}

/// Whether a policy reaches a caller acting as `role`, or as a role no policy
/// names when `role` is `None`.
fn reaches<DB: DatabaseLike>(database: &DB, policy: &DB::Policy, role: Option<&str>) -> bool {
    match (policy_roles(database, policy), role) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(names), Some(role)) => {
            let held = held_by_name(database, role);
            names.iter().any(|name| held.contains(name))
        }
    }
}

/// Whether every permissive policy reaching `role` for `command` is always
/// true, at least one reaching it.
fn granted_to_everyone<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    permissive: &[&DB::Policy],
    command: Command,
    role: Option<&str>,
) -> Result<bool, LookupError> {
    let mut reached = false;
    for policy in permissive {
        if !command.covered_by(policy.command()) || !reaches(database, *policy, role) {
            continue;
        }
        reached = true;
        for position in applied(database, *policy, command)? {
            if !is_tautology(database, table, position.expression)? {
                return Ok(false);
            }
        }
    }
    Ok(reached)
}

/// Struct defining a rule that reports a restrictive deny list that is the
/// only narrowing of a grant to everyone.
///
/// For a command and a calling role, the rule reports a restrictive policy
/// whose clause is `NOT EXISTS` or `NOT IN` over a subquery when every
/// permissive policy reaching that role for the command is always true. A
/// caller the list does not name keeps access, so the schema fails open. A
/// deliberately public resource with a moderation block list is a legitimate
/// use.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DenyListPolicy::default().into();
/// let schema = "CREATE TABLE docs (id INT, owner TEXT); CREATE TABLE blocks (doc_id INT, member TEXT);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY not_blocked ON docs AS RESTRICTIVE FOR SELECT USING (NOT EXISTS (
///       SELECT 1 FROM blocks b WHERE b.doc_id = docs.id AND b.member = current_user));";
///
/// let open = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY everyone ON docs FOR SELECT USING (true);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&open).is_err());
///
/// let closed = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&closed).is_ok());
/// ```
pub struct DenyListPolicy<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DenyListPolicy<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DenyListPolicy<DB>> for GenericConstrainer<DB> {
    fn from(rule: DenyListPolicy<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DenyListPolicy<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "DenyListPolicy",
            group: LintGroup::Suspicious,
            rationale: "A grant to everyone narrowed only by a deny list fails open, so a caller missing from the list keeps access, while a schema that starts from no access and grants up fails closed.",
            source: Some("https://authzed.com/docs/spicedb/best-practices"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for DenyListPolicy<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let (permissive, restrictive): (Vec<&DB::Policy>, Vec<&DB::Policy>) = table
            .policies(database)?
            .partition(|policy| policy.policy_type() == CreatePolicyType::Permissive);
        let mut roles: Vec<Option<String>> = permissive
            .iter()
            .chain(&restrictive)
            .filter_map(|policy| policy_roles(database, policy))
            .flatten()
            .map(Some)
            .collect();
        roles.push(None);
        for deny in restrictive {
            let mut sites: Vec<PolicySite<DB>> = Vec::new();
            for command in Command::ALL {
                if !command.covered_by(deny.command()) {
                    continue;
                }
                let Some(position) = applied(database, deny, command)?
                    .into_iter()
                    .find(|position| is_deny_list(position.expression))
                else {
                    continue;
                };
                let mut open = false;
                for role in &roles {
                    open |= reaches(database, deny, role.as_deref())
                        && granted_to_everyone(
                            database,
                            table,
                            &permissive,
                            command,
                            role.as_deref(),
                        )?;
                }
                if open && !sites.iter().any(|site| site.clause == position.clause) {
                    sites.push(PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new(deny.clone()),
                        clause: position.clause,
                        expression: position.expression.to_string(),
                    });
                }
            }
            if sites.is_empty() {
                continue;
            }
            let (name, table_name) = (deny.name(), table.table_name());
            reporter.policies(
                sites,
                format!(
                    "Restrictive policy '{name}' on '{table_name}' is a deny list narrowing an always-true grant, so a caller the list does not name keeps access."
                ),
                format!(
                    "Replace the always-true permissive policy on '{table_name}' with one granting the callers who may access each row, and keep '{name}' on top of it."
                ),
            )?;
        }
        Ok(())
    }
}
