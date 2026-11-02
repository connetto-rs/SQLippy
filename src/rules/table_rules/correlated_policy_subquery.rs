//! Submodule providing the `CorrelatedPolicySubquery` rule.

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::policy_support::correlated_subqueries,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a policy subquery joined to the row
/// being checked.
///
/// PostgreSQL evaluates a policy expression for each candidate row. A
/// subquery referencing the row runs again for each of them, while a subquery
/// that only selects the caller's keys is computed once and compared.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = CorrelatedPolicySubquery::default().into();
/// let schema = "CREATE TABLE docs (team_id INT); CREATE TABLE team_user (team_id INT, user_id TEXT);";
///
/// let joined = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY p ON docs USING (
///        current_user IN (SELECT user_id FROM team_user WHERE team_user.team_id = docs.team_id));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&joined).is_err());
///
/// let set = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY p ON docs USING (
///        team_id IN (SELECT team_id FROM team_user WHERE user_id = current_user));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&set).is_ok());
/// ```
pub struct CorrelatedPolicySubquery<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for CorrelatedPolicySubquery<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<CorrelatedPolicySubquery<DB>> for GenericConstrainer<DB> {
    fn from(rule: CorrelatedPolicySubquery<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for CorrelatedPolicySubquery<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "CorrelatedPolicySubquery",
            group: LintGroup::Perf,
            rationale: "PostgreSQL evaluates a policy against each candidate row, so a subquery joined to the row runs once per row, while a set of the caller's keys is computed once.",
            source: Some(
                "https://supabase.com/docs/guides/database/postgres/row-level-security-performance",
            ),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for CorrelatedPolicySubquery<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            let clauses = [
                (PolicyClause::Using, policy.using_expression(database)),
                (PolicyClause::WithCheck, policy.check_expression(database)),
            ];
            for (clause, expression) in clauses {
                let Some(expression) = expression else {
                    continue;
                };
                for subquery in correlated_subqueries(database, table, expression)? {
                    let (name, table_name) = (policy.name(), table.table_name());
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: subquery,
                        }],
                        format!(
                            "Policy '{name}' on '{table_name}' runs a subquery joined to the checked row in its {clause} clause."
                        ),
                        "Select the caller's keys without referencing the row and compare the row to them, for example `team_id IN (SELECT team_id FROM team_user WHERE user_id = (SELECT auth.uid()))`.".to_owned(),
                    )?;
                }
            }
        }
        Ok(())
    }
}
