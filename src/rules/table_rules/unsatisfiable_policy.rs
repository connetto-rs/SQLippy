//! Submodule providing the `UnsatisfiablePolicy` rule.

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::{CreatePolicyType, Expr};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{Command, applied, is_contradiction},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a permissive policy that grants no
/// command it covers.
///
/// PostgreSQL combines the `USING` clauses of the permissive policies of a
/// command with `OR`, and their `WITH CHECK` clauses with a separate `OR`,
/// so a permissive policy adds nothing only when every clause it applies to
/// every command it covers is false for every row, such as `USING (false)`
/// or `USING (owner = current_setting('app.user_id', true) AND false)`. Such
/// a policy grants nothing alone or beside others. A `FOR ALL USING (false)
/// WITH CHECK (owner = current_user)` still grants `INSERT`, and a `FOR
/// UPDATE USING (owner = current_user) WITH CHECK (false)` still lets the
/// rows it shows be updated into what another policy's `WITH CHECK` accepts,
/// so neither is reported. A restrictive policy false for every row denies
/// its commands outright, which is a deliberate lockout, and is not
/// reported.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UnsatisfiablePolicy::default().into();
///
/// let dead = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY own ON docs FOR SELECT USING (owner = current_user AND false);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&dead).is_err());
///
/// let own = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&own).is_ok());
/// ```
pub struct UnsatisfiablePolicy<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnsatisfiablePolicy<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnsatisfiablePolicy<DB>> for GenericConstrainer<DB> {
    fn from(rule: UnsatisfiablePolicy<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UnsatisfiablePolicy<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UnsatisfiablePolicy),
            group: LintGroup::Correctness,
            rationale: "A permissive policy clause false for every row grants nothing, so the access the policy was written for never happens.",
            source: Some("https://www.postgresql.org/docs/current/sql-createpolicy.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs FOR SELECT USING (owner = current_setting('app.user_id', true) AND false);",
                good: "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for UnsatisfiablePolicy<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            if policy.policy_type() == CreatePolicyType::Restrictive {
                continue;
            }
            let mut clauses: Vec<(PolicyClause, &Expr)> = Vec::new();
            let mut contributes = false;
            'commands: for command in Command::ALL {
                if !command.covered_by(policy.command()) {
                    continue;
                }
                for clause in applied(database, policy, command)? {
                    if !is_contradiction(database, table, clause.expression)? {
                        contributes = true;
                        break 'commands;
                    }
                    if !clauses.iter().any(|(seen, _)| *seen == clause.clause) {
                        clauses.push((clause.clause, clause.expression));
                    }
                }
            }
            if contributes || clauses.is_empty() {
                continue;
            }
            let sites: Vec<PolicySite<DB>> = clauses
                .into_iter()
                .map(|(clause, expression)| PolicySite {
                    table: Box::new(table.clone()),
                    policy: Box::new(policy.clone()),
                    clause,
                    expression: expression.to_string(),
                })
                .collect();
            let name = policy.name();
            reporter.policies(
                sites,
                format!(
                    "Policy '{name}' on '{}' grants nothing, since every clause it applies is false for every row.",
                    table.table_name()
                ),
                format!(
                    "Remove the always-false operand from '{name}', or drop the policy. A command meant to be denied takes a restrictive policy or no policy at all."
                ),
            )?;
        }
        Ok(())
    }
}
