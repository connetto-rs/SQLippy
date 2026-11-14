//! Submodule providing the `PolicyWithoutRowReference` rule.

use sql_traits::{
    structs::IdentifierCase,
    traits::{DatabaseLike, PolicyLike, TableLike},
};
use sqlparser::ast::CreatePolicyType;

use crate::{
    error::{Interruption, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        policy_read_support::reads_relation,
        policy_support::{Command, applied, reads_row},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a permissive write policy whose clause
/// for some write command depends on the session alone.
///
/// A clause that is not constant and reads no column of its table and no
/// table or view, directly or through the functions it calls, such as
/// `USING (auth.uid() IS NOT NULL)`, admits or refuses a caller as a whole.
/// Every caller it admits may then update or delete every row, or insert any
/// row. Each write command is judged through the clauses PostgreSQL applies
/// to it. Read commands are not judged, since a read open to every admitted
/// caller is a deliberate public read, and restrictive policies are not
/// judged, since a session gate there only narrows what permissive policies
/// grant. Constant clauses are left to `tautological_policy` and
/// `unsatisfiable_policy`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
/// let constrainer: GenericConstrainer<ParserDB> = PolicyWithoutRowReference::default().into();
/// let database = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY own ON docs FOR UPDATE USING (current_user = 'app');"
/// ).unwrap();
/// assert!(constrainer.validate_schema(&database).is_err());
/// let database = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner TEXT);
///      CREATE POLICY own ON docs FOR UPDATE USING (owner = current_user);"
/// ).unwrap();
/// assert!(constrainer.validate_schema(&database).is_ok());
/// ```
pub struct PolicyWithoutRowReference<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PolicyWithoutRowReference<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PolicyWithoutRowReference<DB>> for GenericConstrainer<DB> {
    fn from(rule: PolicyWithoutRowReference<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for PolicyWithoutRowReference<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(PolicyWithoutRowReference),
            group: LintGroup::Suspicious,
            rationale: "A permissive write policy decided by the session alone lets every caller it admits update or delete every row, or insert any row.",
            source: Some("https://www.postgresql.org/docs/current/sql-createpolicy.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (owner TEXT); CREATE POLICY own ON docs FOR UPDATE USING (current_user = 'app');",
                good: "CREATE TABLE docs (owner TEXT); CREATE POLICY own ON docs FOR UPDATE USING (owner = current_user);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for PolicyWithoutRowReference<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &DB,
        table: &DB::Table,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            if policy.policy_type() == CreatePolicyType::Restrictive {
                continue;
            }
            let mut sites: Vec<PolicySite<DB>> = Vec::new();
            let mut commands = Vec::new();
            for (command, name) in [
                (Command::Insert, "INSERT"),
                (Command::Update, "UPDATE"),
                (Command::Delete, "DELETE"),
            ] {
                if !command.covered_by(policy.command()) {
                    continue;
                }
                let mut session_only = false;
                for clause in applied(database, policy, command)? {
                    if sites.iter().any(|site| site.clause == clause.clause) {
                        session_only = true;
                        continue;
                    }
                    if table
                        .expression_truth(database, clause.expression, IdentifierCase::AsWritten)?
                        .is_some()
                        || reads_row(database, table, None, clause.expression)?
                        || reads_relation(database, policy, clause.expression)?
                    {
                        continue;
                    }
                    session_only = true;
                    sites.push(PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new(policy.clone()),
                        clause: clause.clause,
                        expression: clause.expression.to_string(),
                    });
                }
                if session_only {
                    commands.push(name);
                }
            }
            if !commands.is_empty() {
                reporter.policies(
                    sites,
                    format!(
                        "Policy '{}' on '{}' decides {} by the session alone, reading no column of '{}' and no table, so every caller it admits may write any row.",
                        policy.name(),
                        table.table_name(),
                        commands.join(", "),
                        table.table_name(),
                    ),
                    "Compare the written row's columns with the caller, or read a table that relates the caller to the row."
                        .to_owned(),
                )?;
            }
        }
        Ok(())
    }
}
