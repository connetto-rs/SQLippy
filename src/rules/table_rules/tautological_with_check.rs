//! Submodule providing the `TautologicalWithCheck` rule.

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::CreatePolicyCommand;

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{is_tautology, reads_row},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports an explicit always-true `WITH CHECK`
/// beside a `USING` that depends on the row.
///
/// Without `WITH CHECK`, PostgreSQL checks new rows against `USING`. An
/// explicit `WITH CHECK (true)` replaces that check, so a caller can write
/// rows `USING` would never show them.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = TautologicalWithCheck::default().into();
///
/// let open = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY own ON docs FOR UPDATE USING (owner = current_user) WITH CHECK (true);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&open).is_err());
///
/// let checked = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY own ON docs FOR UPDATE USING (owner = current_user);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&checked).is_ok());
/// ```
pub struct TautologicalWithCheck<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for TautologicalWithCheck<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<TautologicalWithCheck<DB>> for GenericConstrainer<DB> {
    fn from(rule: TautologicalWithCheck<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for TautologicalWithCheck<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(TautologicalWithCheck),
            group: LintGroup::Suspicious,
            rationale: "An explicit always-true WITH CHECK replaces the default check against USING, so a caller can write rows the policy would never let them read.",
            source: Some("https://www.postgresql.org/docs/current/sql-createpolicy.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON notes FOR UPDATE USING (owner = current_setting('app.user_id', true)) WITH CHECK (true);",
                good: "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON notes FOR UPDATE USING (owner = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for TautologicalWithCheck<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            if !matches!(
                policy.command(),
                CreatePolicyCommand::All | CreatePolicyCommand::Update
            ) {
                continue;
            }
            let (Some(using), Some(check)) = (
                policy.using_expression(database)?,
                policy.check_expression(database)?,
            ) else {
                continue;
            };
            if is_tautology(database, table, check)?
                && !is_tautology(database, table, using)?
                && reads_row(database, table, None, using)?
            {
                let name = policy.name();
                reporter.policies(
                    vec![PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new(policy.clone()),
                        clause: PolicyClause::WithCheck,
                        expression: check.to_string(),
                    }],
                    format!(
                        "Policy '{name}' on '{}' checks new rows with an always-true WITH CHECK while USING ({using}) depends on the row.",
                        table.table_name()
                    ),
                    format!(
                        "Drop the WITH CHECK clause of '{name}' so new rows must pass USING, or repeat the USING condition in WITH CHECK."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
