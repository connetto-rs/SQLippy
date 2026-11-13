//! Submodule providing the `TautologicalPolicy` rule.

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::{CreatePolicyType, Expr, Value};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{Command, applied, is_tautology},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a policy clause true for every row
/// where the policy reads as a condition.
///
/// A restrictive policy narrows what permissive policies admit, so one whose
/// every clause PostgreSQL applies to every command it covers is true for
/// every row, such as `USING (true)` or `USING (owner IS NULL OR true)`,
/// restricts nothing. A restrictive `USING (true) WITH CHECK (owner =
/// current_user)` still checks the rows written and is not reported. A
/// permissive `USING` written as a condition that is nonetheless true for
/// every row, such as `owner = current_setting('app.user_id', true) OR
/// true`, admits every row the condition seems to filter. A permissive
/// `USING (true)` is a deliberate public read and is not reported, and an
/// always-true permissive `WITH CHECK` is judged by `tautological_with_check`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = TautologicalPolicy::default().into();
///
/// let open = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY own ON docs FOR SELECT USING (owner = current_user OR true);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&open).is_err());
///
/// let own = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&own).is_ok());
/// ```
pub struct TautologicalPolicy<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for TautologicalPolicy<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<TautologicalPolicy<DB>> for GenericConstrainer<DB> {
    fn from(rule: TautologicalPolicy<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for TautologicalPolicy<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(TautologicalPolicy),
            group: LintGroup::Suspicious,
            rationale: "A restrictive policy true for every row restricts nothing, and a permissive condition true for every row admits the rows it was written to keep out.",
            source: Some("https://www.postgresql.org/docs/current/sql-createpolicy.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs FOR SELECT USING (owner = current_setting('app.user_id', true) OR true);",
                good: "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }
}

/// Whether the expression is the literal `true`, parenthesised or not.
fn is_literal_true(expression: &Expr) -> bool {
    match expression {
        Expr::Nested(inner) => is_literal_true(inner),
        Expr::Value(literal) => matches!(literal.value, Value::Boolean(true)),
        _ => false,
    }
}

impl<DB: DatabaseLike> TableRule for TautologicalPolicy<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            let restrictive = policy.policy_type() == CreatePolicyType::Restrictive;
            let mut clauses: Vec<(PolicyClause, &Expr)> = Vec::new();
            if restrictive {
                let mut restricts_nothing = true;
                'commands: for command in Command::ALL {
                    if !command.covered_by(policy.command()) {
                        continue;
                    }
                    for clause in applied(database, policy, command)? {
                        if !is_tautology(database, table, clause.expression)? {
                            restricts_nothing = false;
                            break 'commands;
                        }
                        if !clauses.iter().any(|(seen, _)| *seen == clause.clause) {
                            clauses.push((clause.clause, clause.expression));
                        }
                    }
                }
                if !restricts_nothing {
                    clauses.clear();
                }
            } else if let Some(using) = policy.using_expression(database)?
                && !is_literal_true(using)
                && is_tautology(database, table, using)?
            {
                clauses.push((PolicyClause::Using, using));
            }
            if clauses.is_empty() {
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
            let (message, help) = if restrictive {
                (
                    format!(
                        "Restrictive policy '{name}' on '{}' is true for every row, so it restricts nothing.",
                        table.table_name()
                    ),
                    format!(
                        "Give '{name}' the condition every admitted row must also meet, or drop it."
                    ),
                )
            } else {
                (
                    format!(
                        "Policy '{name}' on '{}' admits every row, since its condition is true whatever the row holds.",
                        table.table_name()
                    ),
                    format!(
                        "Remove the always-true operand from '{name}'. A table meant to be public reads `USING (true)`."
                    ),
                )
            };
            reporter.policies(sites, message, help)?;
        }
        Ok(())
    }
}
