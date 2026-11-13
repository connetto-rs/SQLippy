//! Submodule providing the `NullCredentialRead` rule.

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::CreatePolicyType;

use crate::{
    deployment::Declaration,
    error::{Interruption, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        credential_support::CredentialJudge,
        policy_support::{Command, Stage, anonymous_callers, applied, applies_to},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a read policy admitting a caller
/// because its credential is `NULL`.
///
/// The rule judges the `USING` clause PostgreSQL applies to `SELECT` for
/// each permissive policy reaching `PUBLIC` or a declared anonymous role. A
/// clause that reads a declared credential and can still be true with every
/// credential `NULL`, through an operand such as `auth.uid() IS NULL`,
/// `COALESCE(auth.uid(), owner) = owner` or `auth.uid() IS DISTINCT FROM
/// owner`, is reported when some anonymous caller it applies to, each
/// declared anonymous role or a caller holding only `PUBLIC`, has no
/// restrictive policy requiring a credential for `SELECT`. A clause passing
/// without a credential only through operands that read none, such as
/// `is_public` or `true`, is a deliberate public read and is not reported.
/// Writes are judged by `credential_free_write`. The rule is inactive until
/// the deployment declares a credential.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = NullCredentialRead::default().into();
/// constrainer.set_deployment(
///     Deployment::default().with_credential("current_setting('app.user_id', true)").unwrap(),
/// );
/// let schema = "CREATE TABLE posts (id INT, owner TEXT);
///               ALTER TABLE posts ENABLE ROW LEVEL SECURITY;";
///
/// let inverted = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY r ON posts FOR SELECT USING (
///        current_setting('app.user_id', true) IS NULL
///        OR owner = current_setting('app.user_id', true));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&inverted).is_err());
///
/// let owned = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY r ON posts FOR SELECT USING (
///        owner = current_setting('app.user_id', true));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&owned).is_ok());
/// ```
pub struct NullCredentialRead<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NullCredentialRead<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NullCredentialRead<DB>> for GenericConstrainer<DB> {
    fn from(rule: NullCredentialRead<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for NullCredentialRead<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NullCredentialRead),
            group: LintGroup::Suspicious,
            rationale: "A read policy that tests the credential and still passes when it is NULL shows every row it covers to a caller who never signed in, which is the opposite of what the credential test is there for.",
            source: Some("https://supabase.com/docs/guides/database/postgres/row-level-security"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE posts (id INT, owner TEXT);\n\
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY r ON posts FOR SELECT USING (current_setting('app.user_id', true) IS NULL OR owner = current_setting('app.user_id', true));",
                good: "CREATE TABLE posts (id INT, owner TEXT);\n\
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY r ON posts FOR SELECT USING (owner = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Credentials]
    }
}

impl<DB: DatabaseLike> TableRule for NullCredentialRead<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !table.has_row_level_security(database)? {
            return Ok(());
        }
        let deployment = reporter.deployment();
        let policies: Vec<_> = table
            .policies(database)?
            .filter(|policy| Command::Select.covered_by(policy.command()))
            .collect();
        let mut unguarded = Vec::new();
        for held in anonymous_callers(database, deployment) {
            let mut guarded = false;
            for policy in &policies {
                if policy.policy_type() != CreatePolicyType::Restrictive
                    || !applies_to(database, policy, &held)
                {
                    continue;
                }
                let judge = CredentialJudge::new(database, policy, deployment);
                for clause in applied(database, policy, Command::Select)? {
                    if clause.stage == Stage::Filter && judge.requires(clause.expression)? {
                        guarded = true;
                    }
                }
            }
            if !guarded {
                unguarded.push(held);
            }
        }
        for policy in &policies {
            if policy.policy_type() == CreatePolicyType::Restrictive
                || !unguarded
                    .iter()
                    .any(|held| applies_to(database, policy, held))
            {
                continue;
            }
            let judge = CredentialJudge::new(database, policy, deployment);
            let mut sites: Vec<PolicySite<DB>> = Vec::new();
            for clause in applied(database, policy, Command::Select)? {
                if clause.stage != Stage::Filter {
                    continue;
                }
                if let Some(operand) = judge.absence_admitter(clause.expression)? {
                    sites.push(PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new((*policy).clone()),
                        clause: clause.clause,
                        expression: operand.to_string(),
                    });
                }
            }
            if sites.is_empty() {
                continue;
            }
            let name = policy.name();
            reporter.policies(
                sites,
                format!(
                    "Policy '{name}' on '{}' lets a caller with no credential read its rows, since it tests the credential and still passes when it is NULL.",
                    table.table_name()
                ),
                format!(
                    "Drop the operand of '{name}' that passes on a NULL credential, so every read compares a column to the credential. Rows meant to be public take a separate condition that reads no credential, such as a flag column."
                ),
            )?;
        }
        Ok(())
    }
}
