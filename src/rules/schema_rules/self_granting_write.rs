//! Submodule providing the `SelfGrantingWrite` rule.

use sql_traits::{
    errors::LookupError,
    structs::{ExpressionContext, ExpressionScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, PolicyLike, TableLike},
};
use sqlparser::ast::{BinaryOperator, CreatePolicyType, Expr, InTarget};

use crate::{
    deployment::{Declaration, Deployment},
    engine::Engine,
    error::{Interruption, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        authority_support::authority_columns,
        credential_support::CredentialJudge,
        grant_support::withheld,
        null_support::{null_when, rejects_null},
        policy_support::{
            Command, Stage, applied, covers, holds_sublink_or_call, is_column_reference,
            policy_roles, reads_row, unnested,
        },
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// The columns a new-row clause binds to a credential and the columns it
/// keeps non-null, by position in the table, over every way it can be true.
///
/// A bound column holds, whenever it is non-null, a value a sublink or call
/// requiring a credential admits, directly or through a composite foreign
/// key tying it to such a column.
struct Bound {
    constrained: Vec<bool>,
    non_null: Vec<bool>,
}

/// A table whose new rows are checked, with its columns, those declared
/// `NOT NULL`, those its scope or composite foreign keys hold, and those keys
/// as the positions of their host columns with whether they match `FULL`.
struct CheckedRow<'db, DB: DatabaseLike> {
    database: &'db DB,
    table: &'db DB::Table,
    columns: Vec<&'db DB::Column>,
    declared_non_null: Vec<bool>,
    relevant: Vec<bool>,
    keys: Vec<(Vec<usize>, bool)>,
}

impl<'db, DB: DatabaseLike> CheckedRow<'db, DB> {
    /// The checked row of `table`, whose scope columns sit at
    /// `scope_positions`.
    fn new(
        database: &'db DB,
        table: &'db DB::Table,
        scope_positions: &[usize],
    ) -> Result<Self, LookupError> {
        let columns: Vec<&DB::Column> = table.columns(database)?.collect();
        let mut declared_non_null = Vec::with_capacity(columns.len());
        for column in &columns {
            declared_non_null.push(!column.is_nullable(database)?);
        }
        let mut relevant = vec![false; columns.len()];
        for &position in scope_positions {
            relevant[position] = true;
        }
        let mut keys = Vec::new();
        for foreign_key in table
            .foreign_keys(database)?
            .filter(|foreign_key| foreign_key.is_enforced(database))
        {
            let hosts: Vec<usize> = foreign_key
                .host_columns(database)?
                .filter_map(|host| columns.iter().position(|column| *column == host))
                .collect();
            if hosts.len() > 1 {
                for &host in &hosts {
                    relevant[host] = true;
                }
                keys.push((hosts, foreign_key.match_full(database)));
            }
        }
        Ok(Self {
            database,
            table,
            columns,
            declared_non_null,
            relevant,
            keys,
        })
    }

    /// What the new-row clause `clause` binds, judging credentials with
    /// `judge`.
    fn bound(&self, judge: &CredentialJudge<'_, DB>, clause: &Expr) -> Result<Bound, LookupError> {
        let table = ExpressionScope::Table(self.table);
        let types = ExpressionContext::for_expression(
            clause,
            &table,
            self.database,
            IdentifierCase::Folded,
        )?;
        self.binds(judge, &types, clause)
    }

    /// What `expression` binds, judging credentials with `judge` and reading
    /// operators as `types` types them.
    fn binds(
        &self,
        judge: &CredentialJudge<'_, DB>,
        types: &ExpressionContext<'_, '_, DB>,
        expression: &Expr,
    ) -> Result<Bound, LookupError> {
        Ok(match expression {
            Expr::Nested(inner) => self.binds(judge, types, inner)?,
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => self.conjoin(
                self.binds(judge, types, left)?,
                &self.binds(judge, types, right)?,
            ),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
            } => {
                let mut left = self.binds(judge, types, left)?;
                let right = self.binds(judge, types, right)?;
                for (mine, theirs) in left.constrained.iter_mut().zip(right.constrained) {
                    *mine &= theirs;
                }
                for (mine, theirs) in left.non_null.iter_mut().zip(right.non_null) {
                    *mine &= theirs;
                }
                left
            }
            _ => self.leaf(judge, types, expression)?,
        })
    }

    /// What a predicate outside `AND` and `OR` binds, which is the columns
    /// its credential-backed sublink or call reads and those it cannot be true
    /// without.
    fn leaf(
        &self,
        judge: &CredentialJudge<'_, DB>,
        types: &ExpressionContext<'_, '_, DB>,
        expression: &Expr,
    ) -> Result<Bound, LookupError> {
        let mut bound = Bound {
            constrained: vec![false; self.columns.len()],
            non_null: self.declared_non_null.clone(),
        };
        let holds = holds_sublink_or_call(expression);
        let mut credential = None;
        for (position, &column) in self.columns.iter().enumerate() {
            if !self.relevant[position] {
                continue;
            }
            if holds && reads_row(self.database, self.table, Some(column), expression)? {
                if credential.is_none() {
                    credential = Some(judge.requires(expression)?);
                }
                bound.constrained[position] = credential == Some(true);
            }
            if !bound.non_null[position] {
                bound.non_null[position] = self.rejects_null(types, expression, column)?;
            }
        }
        self.close(&mut bound);
        Ok(bound)
    }

    /// Whether `predicate` cannot be true while `column` of the row is null.
    fn rejects_null(
        &self,
        types: &ExpressionContext<'_, '_, DB>,
        predicate: &Expr,
        column: &DB::Column,
    ) -> Result<bool, LookupError> {
        let is_column = |expression: &Expr| {
            Ok(is_column_reference(expression)
                && reads_row(self.database, self.table, Some(column), expression)?)
        };
        match unnested(predicate) {
            Expr::In {
                expr,
                target: InTarget::Subquery(_),
                negated: false,
                ..
            } => null_when(expr, &is_column, self.database, types),
            _ => rejects_null(predicate, &is_column, self.database, types),
        }
    }

    /// What both `left` and `right` bind together.
    fn conjoin(&self, mut left: Bound, right: &Bound) -> Bound {
        for (mine, theirs) in left.constrained.iter_mut().zip(&right.constrained) {
            *mine |= theirs;
        }
        for (mine, theirs) in left.non_null.iter_mut().zip(&right.non_null) {
            *mine |= theirs;
        }
        self.close(&mut left);
        left
    }

    /// Extends `bound` through the composite foreign keys until none binds
    /// another column. A key binds a column to a bound one beside it when
    /// PostgreSQL checks the key whenever that column is non-null, which
    /// `MATCH FULL` does always and `MATCH SIMPLE` does when every other key
    /// column is non-null. A null column grants no scope, so it needs no proof.
    fn close(&self, bound: &mut Bound) {
        let mut changed = true;
        while changed {
            changed = false;
            for (hosts, full) in &self.keys {
                for &target in hosts {
                    if bound.constrained[target] {
                        continue;
                    }
                    let mut others = hosts.iter().filter(|&&host| host != target);
                    if others.clone().any(|&host| bound.constrained[host])
                        && (*full || others.all(|&host| bound.non_null[host]))
                    {
                        bound.constrained[target] = true;
                        changed = true;
                    }
                }
            }
        }
    }

    /// The positions in `scope_positions` of the columns the roles of
    /// `policy` may write with `command`.
    fn writable(
        &self,
        deployment: &Deployment,
        policy: &DB::Policy,
        command: Command,
        scope_positions: &[usize],
    ) -> Result<Vec<usize>, LookupError> {
        let mut writable = Vec::with_capacity(scope_positions.len());
        for &position in scope_positions {
            let column = self.columns[position];
            if !withheld(
                self.database,
                deployment,
                self.table,
                policy,
                command,
                column,
            )? {
                writable.push(position);
            }
        }
        Ok(writable)
    }
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
/// policy's roles closes the gap when it constrains the column. A composite
/// foreign key holding the column beside one the clause constrains also
/// closes it when PostgreSQL checks the key whenever the column is non-null,
/// which `MATCH FULL` does always and `MATCH SIMPLE` does once the clause
/// keeps every other key column non-null. So does the source proving that the
/// policy's roles, or the declared client roles for a policy applying to
/// `PUBLIC`, lack the command's privilege on the column, as
/// [`SubjectSettableAttribute`](crate::rules::SubjectSettableAttribute) reads it.
///
/// The rule does not run on SQLite, which has no row-level security policies.
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
            name: rule_name!(SelfGrantingWrite),
            group: LintGroup::Suspicious,
            rationale: "Policies read an authority table to decide what the caller may reach, so a write that lets the caller choose a row's scope freely lets them grant themselves that scope.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE teams (id INT PRIMARY KEY);\n\
CREATE TABLE members (team_id INT REFERENCES teams (id), member TEXT);\n\
CREATE TABLE invitations (team_id INT, invitee TEXT);\n\
CREATE TABLE docs (team_id INT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
ALTER TABLE members ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY docs_read ON docs FOR SELECT USING (team_id IN (SELECT team_id FROM members WHERE member = current_setting('app.user_id', true)));\n\
CREATE POLICY join_team ON members FOR INSERT WITH CHECK (member = current_setting('app.user_id', true));",
                good: "CREATE TABLE teams (id INT PRIMARY KEY);\n\
CREATE TABLE members (team_id INT REFERENCES teams (id), member TEXT);\n\
CREATE TABLE invitations (team_id INT, invitee TEXT);\n\
CREATE TABLE docs (team_id INT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
ALTER TABLE members ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY docs_read ON docs FOR SELECT USING (team_id IN (SELECT team_id FROM members WHERE member = current_setting('app.user_id', true)));\n\
CREATE POLICY join_team ON members FOR INSERT WITH CHECK (member = current_setting('app.user_id', true) AND team_id IN (SELECT team_id FROM invitations WHERE invitee = current_setting('app.user_id', true)));",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
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
            let mut scope_positions = Vec::new();
            for (position, column) in table.columns(database)?.enumerate() {
                let scope = (id, column.stored_column_name().into_owned());
                if scopes.contains(&scope) && scopes_another_table(database, table, column)? {
                    scope_positions.push(position);
                }
            }
            if scope_positions.is_empty() {
                continue;
            }
            let row = CheckedRow::new(database, table, &scope_positions)?;
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
                    let writable = row.writable(deployment, policy, command, &scope_positions)?;
                    for position in applied(database, policy, command)? {
                        if position.stage != Stage::Check {
                            continue;
                        }
                        let mut bound = row.bound(&judge, position.expression)?;
                        if writable.iter().all(|&column| bound.constrained[column]) {
                            continue;
                        }
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
                                if check.stage == Stage::Check {
                                    bound = row.conjoin(
                                        bound,
                                        &row.bound(&guard_judge, check.expression)?,
                                    );
                                }
                            }
                        }
                        for &column in &writable {
                            if bound.constrained[column] {
                                continue;
                            }
                            let name = row.columns[column].column_name();
                            if !free.contains(&name) {
                                free.push(name);
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
