//! Submodule providing the `DeadPermissivePolicy` rule.

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::CreatePolicyType;

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::policy_support::{Command, applied, covers, is_tautology, policy_roles},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a permissive policy another permissive
/// policy makes dead.
///
/// PostgreSQL combines permissive policies with `OR`, so an always-true
/// permissive policy decides every command and role it covers. A narrower
/// permissive policy is dead only when such policies cover every command,
/// role and clause it applies to.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DeadPermissivePolicy::default().into();
///
/// let dead = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY everyone ON docs FOR SELECT USING (true);
///      CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&dead).is_err());
///
/// // The owner policy still decides writes, so it is alive.
/// let alive = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY everyone ON docs FOR SELECT USING (true);
///      CREATE POLICY own ON docs FOR ALL USING (owner = current_user);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&alive).is_ok());
/// ```
pub struct DeadPermissivePolicy<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DeadPermissivePolicy<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DeadPermissivePolicy<DB>> for GenericConstrainer<DB> {
    fn from(rule: DeadPermissivePolicy<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DeadPermissivePolicy<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "DeadPermissivePolicy",
            group: LintGroup::Correctness,
            rationale: "PostgreSQL combines permissive policies with OR, so an always-true permissive policy decides every command and role it covers and the narrower policy never changes the outcome.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
        };
        &METADATA
    }
}

fn site<DB: DatabaseLike>(
    table: &DB::Table,
    policy: &DB::Policy,
    clause: PolicyClause,
    expression: &sqlparser::ast::Expr,
) -> PolicySite<DB> {
    PolicySite {
        table: Box::new(table.clone()),
        policy: Box::new(policy.clone()),
        clause,
        expression: expression.to_string(),
    }
}

impl<DB: DatabaseLike> TableRule for DeadPermissivePolicy<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let permissive: Vec<&DB::Policy> = table
            .policies(database)?
            .filter(|policy| policy.policy_type() == CreatePolicyType::Permissive)
            .collect();
        let roles: Vec<Option<Vec<String>>> = permissive
            .iter()
            .map(|policy| policy_roles(database, policy))
            .collect();
        for (index, policy) in permissive.iter().enumerate() {
            let mut narrower = false;
            let mut own_sites: Vec<PolicySite<DB>> = Vec::new();
            let mut deciding_sites: Vec<PolicySite<DB>> = Vec::new();
            let mut dead = true;
            'positions: for command in Command::ALL {
                if !command.covered_by(policy.command()) {
                    continue;
                }
                for position in applied(database, *policy, command) {
                    narrower |= !is_tautology(database, table, position.expression)?;
                    let mut decided = false;
                    for (other, other_policy) in permissive.iter().enumerate() {
                        if other == index
                            || !command.covered_by(other_policy.command())
                            || !covers(database, roles[other].as_deref(), roles[index].as_deref())
                        {
                            continue;
                        }
                        for deciding in applied(database, *other_policy, command) {
                            if deciding.stage == position.stage
                                && is_tautology(database, table, deciding.expression)?
                            {
                                decided = true;
                                if !deciding_sites.iter().any(|site| {
                                    *site.policy == **other_policy && site.clause == deciding.clause
                                }) {
                                    deciding_sites.push(site(
                                        table,
                                        *other_policy,
                                        deciding.clause,
                                        deciding.expression,
                                    ));
                                }
                                break;
                            }
                        }
                        if decided {
                            break;
                        }
                    }
                    if !decided {
                        dead = false;
                        break 'positions;
                    }
                    if !own_sites.iter().any(|site| site.clause == position.clause) {
                        own_sites.push(site(table, *policy, position.clause, position.expression));
                    }
                }
            }
            if dead && narrower {
                let name = policy.name();
                let deciding_names = deciding_sites
                    .iter()
                    .map(|site| format!("'{}'", site.policy.name()))
                    .collect::<Vec<_>>()
                    .join(", ");
                own_sites.extend(deciding_sites);
                reporter.policies(
                    own_sites,
                    format!(
                        "Permissive policy '{name}' on '{}' never changes access, because the always-true {deciding_names} already allow every command and role it covers.",
                        table.table_name()
                    ),
                    format!(
                        "Drop policy '{name}', or narrow {deciding_names} with `TO` roles or a real condition."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
