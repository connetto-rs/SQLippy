//! Submodule providing the `SelfGrantingWrite` rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, PolicyLike, TableLike},
};
use sqlparser::ast::{BinaryOperator, CreatePolicyType, Expr};

use crate::{
    deployment::Declaration,
    error::{Interruption, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::{
        authority_support::authority_columns,
        credential_support::CredentialJudge,
        policy_support::{
            Command, Stage, applied, covers, holds_sublink_or_call, policy_roles, reads_row,
        },
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Whether every way `expression` can be true constrains `column` of the
/// row with a sublink or call that requires a credential.
fn constrains<DB: DatabaseLike>(
    judge: &CredentialJudge<'_, DB>,
    database: &DB,
    table: &DB::Table,
    column: &DB::Column,
    expression: &Expr,
) -> Result<bool, LookupError> {
    Ok(match expression {
        Expr::Nested(inner) => constrains(judge, database, table, column, inner)?,
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            constrains(judge, database, table, column, left)?
                || constrains(judge, database, table, column, right)?
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => {
            constrains(judge, database, table, column, left)?
                && constrains(judge, database, table, column, right)?
        }
        _ => {
            holds_sublink_or_call(expression)
                && reads_row(database, table, Some(column), expression)?
                && judge.requires(expression)?
        }
    })
}

/// Whether `column` sits in a foreign key to another table and is not the
/// table's whole primary key.
fn scopes_another_table<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    column: &DB::Column,
) -> Result<bool, LookupError> {
    let key: Vec<&DB::Column> = table.primary_key_columns(database)?.collect();
    if key == [column] {
        return Ok(false);
    }
    for foreign_key in table.foreign_keys(database)? {
        if !foreign_key.is_self_referential(database)?
            && foreign_key
                .host_columns(database)?
                .any(|host| host == column)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Struct defining a rule that reports a write policy on an authority table
/// letting the writer choose a scope column without a credential-backed
/// check.
///
/// An authority table is one a policy reads, in a sublink or in a
/// set-returning `LANGUAGE sql` helper it calls, by comparing a column with a
/// declared credential. Its scope columns are the ones compared with the
/// outer row there or returned as the set the outer row is compared with. A
/// permissive `INSERT` or `UPDATE` policy whose new-row clause leaves such a
/// column, held in a foreign key to another table, free of a sublink or call
/// requiring a credential lets any caller write a row granting themselves
/// that scope. A restrictive policy for the same command covering the
/// policy's roles closes the gap when it constrains the column.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = SelfGrantingWrite::default().into();
/// constrainer.set_deployment(
///     Deployment::default().with_credential("current_setting('app.user_id', true)").unwrap(),
/// );
/// let schema = "CREATE TABLE teams (id INT PRIMARY KEY);
///     CREATE TABLE members (team_id INT REFERENCES teams (id), member TEXT);
///     CREATE TABLE invitations (team_id INT, invitee TEXT);
///     CREATE TABLE docs (team_id INT);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///     ALTER TABLE members ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY docs_read ON docs FOR SELECT USING (team_id IN (
///       SELECT team_id FROM members WHERE member = current_setting('app.user_id', true)));";
///
/// let open = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY join_team ON members FOR INSERT WITH CHECK (
///        member = current_setting('app.user_id', true));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&open).is_err());
///
/// let invited = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY join_team ON members FOR INSERT WITH CHECK (
///        member = current_setting('app.user_id', true) AND team_id IN (
///          SELECT team_id FROM invitations WHERE invitee = current_setting('app.user_id', true)));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&invited).is_ok());
/// ```
pub struct SelfGrantingWrite<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for SelfGrantingWrite<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<SelfGrantingWrite<DB>> for GenericConstrainer<DB> {
    fn from(rule: SelfGrantingWrite<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for SelfGrantingWrite<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "SelfGrantingWrite",
            group: LintGroup::Suspicious,
            rationale: "Policies read an authority table to decide what the caller may reach, so a write that lets the caller choose a row's scope freely lets them grant themselves that scope.",
            source: None,
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Credentials]
    }
}

impl<DB: DatabaseLike> SchemaRule for SelfGrantingWrite<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let scopes = authority_columns(database, deployment)?.scopes;
        let tables = database
            .tables()
            .filter_map(|table| database.table_id(table).map(|id| (table, id)));
        for (table, id) in tables {
            let mut columns = Vec::new();
            for column in table.columns(database)? {
                let scope = (id, column.stored_column_name().into_owned());
                if scopes.contains(&scope) && scopes_another_table(database, table, column)? {
                    columns.push(column);
                }
            }
            if columns.is_empty() {
                continue;
            }
            let (restrictive, permissive): (Vec<&DB::Policy>, Vec<&DB::Policy>) = table
                .policies(database)?
                .partition(|policy| policy.policy_type() == CreatePolicyType::Restrictive);
            for policy in permissive {
                let judge = CredentialJudge::new(database, policy, deployment);
                let roles = policy_roles(database, policy);
                let mut sites: Vec<PolicySite<DB>> = Vec::new();
                let mut free: Vec<&str> = Vec::new();
                for command in [Command::Insert, Command::Update] {
                    if !command.covered_by(policy.command()) {
                        continue;
                    }
                    for position in applied(database, policy, command)? {
                        if position.stage != Stage::Check {
                            continue;
                        }
                        for &column in &columns {
                            if constrains(&judge, database, table, column, position.expression)? {
                                continue;
                            }
                            let mut guarded = false;
                            for guard in &restrictive {
                                if !command.covered_by(guard.command())
                                    || !covers(
                                        database,
                                        policy_roles(database, guard).as_deref(),
                                        roles.as_deref(),
                                    )
                                {
                                    continue;
                                }
                                let guard_judge = CredentialJudge::new(database, guard, deployment);
                                for check in applied(database, guard, command)? {
                                    guarded |= check.stage == Stage::Check
                                        && constrains(
                                            &guard_judge,
                                            database,
                                            table,
                                            column,
                                            check.expression,
                                        )?;
                                }
                            }
                            if guarded {
                                continue;
                            }
                            if !free.contains(&column.column_name()) {
                                free.push(column.column_name());
                            }
                            if !sites.iter().any(|site| site.clause == position.clause) {
                                sites.push(PolicySite {
                                    table: Box::new(table.clone()),
                                    policy: Box::new(policy.clone()),
                                    clause: position.clause,
                                    expression: position.expression.to_string(),
                                });
                            }
                        }
                    }
                }
                if sites.is_empty() {
                    continue;
                }
                let (name, table_name) = (policy.name(), table.table_name());
                let free = free
                    .iter()
                    .map(|column| format!("'{column}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                reporter.policies(
                    sites,
                    format!(
                        "Policy '{name}' on '{table_name}' lets a writer choose {free}, which policies read to grant access, without a check requiring a credential, so a caller can grant themselves that access."
                    ),
                    format!(
                        "Constrain {free} in the new-row clause of '{name}' with a sublink or helper that requires the caller's credential, such as an invitation or an admin membership for that value."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
