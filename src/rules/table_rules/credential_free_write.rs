//! Submodule providing the `CredentialFreeWrite` rule.

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

/// Struct defining a rule that reports a write policy a caller holding no
/// credential can pass.
///
/// For `INSERT`, `UPDATE` and `DELETE`, the rule judges each permissive
/// policy reaching `PUBLIC` or a declared anonymous role, on the clause
/// PostgreSQL applies (`WITH CHECK` or its `USING` fallback for `INSERT`,
/// `USING` for `UPDATE` and `DELETE`). A clause that can be true with every
/// declared credential `NULL` is reported when some anonymous caller it
/// applies to, each declared anonymous role or a caller holding only
/// `PUBLIC`, has no restrictive policy requiring a credential for the same
/// command. A column compared to the set a set-returning `LANGUAGE sql`
/// helper returns, written `= ANY (ARRAY(SELECT f()))` or `IN (SELECT f())`,
/// requires a credential when every `UNION` arm of the helper's body does,
/// reading nested helpers the same way. The rule is inactive until the
/// deployment declares a credential.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = CredentialFreeWrite::default().into();
/// constrainer.set_deployment(
///     Deployment::default().with_credential("current_setting('app.user_id', true)").unwrap(),
/// );
/// let schema = "CREATE TABLE posts (id INT, owner TEXT, is_public BOOL);
///               ALTER TABLE posts ENABLE ROW LEVEL SECURITY;";
///
/// let open = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY d ON posts FOR DELETE USING (
///        owner = current_setting('app.user_id', true) OR is_public);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&open).is_err());
///
/// let owned = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY d ON posts FOR DELETE USING (
///        owner = current_setting('app.user_id', true));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&owned).is_ok());
/// ```
pub struct CredentialFreeWrite<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for CredentialFreeWrite<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<CredentialFreeWrite<DB>> for GenericConstrainer<DB> {
    fn from(rule: CredentialFreeWrite<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for CredentialFreeWrite<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(CredentialFreeWrite),
            group: LintGroup::Suspicious,
            rationale: "A write policy that can pass with every credential NULL lets a caller who never signed in insert, change or delete the rows it covers.",
            source: Some(
                "https://github.com/supabase/splinter/blob/main/lints/0024_rls_policy_always_true.sql",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE posts (id INT, owner TEXT, is_public BOOL);\n\
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY d ON posts FOR DELETE USING (owner = current_setting('app.user_id', true) OR is_public);",
                good: "CREATE TABLE posts (id INT, owner TEXT, is_public BOOL);\n\
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY d ON posts FOR DELETE USING (owner = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Credentials]
    }
}

/// The writes judged, with their keyword and the stage PostgreSQL judges them
/// by: new rows for `INSERT`, existing rows for `UPDATE` and `DELETE`.
const WRITES: [(Command, &str, Stage); 3] = [
    (Command::Insert, "INSERT", Stage::Check),
    (Command::Update, "UPDATE", Stage::Filter),
    (Command::Delete, "DELETE", Stage::Filter),
];

impl<DB: DatabaseLike> TableRule for CredentialFreeWrite<DB> {
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
        let callers = anonymous_callers(database, deployment);
        let policies: Vec<_> = table
            .policies(database)?
            .filter(|policy| {
                callers
                    .iter()
                    .any(|held| applies_to(database, policy, held))
            })
            .collect();
        let mut unguarded = Vec::new();
        for (command, _, stage) in WRITES {
            for held in &callers {
                let mut requires = false;
                for policy in &policies {
                    if policy.policy_type() != CreatePolicyType::Restrictive
                        || !command.covered_by(policy.command())
                        || !applies_to(database, policy, held)
                    {
                        continue;
                    }
                    let judge = CredentialJudge::new(database, policy, deployment);
                    for clause in applied(database, policy, command)? {
                        if clause.stage == stage && judge.requires(clause.expression)? {
                            requires = true;
                        }
                    }
                }
                if !requires {
                    unguarded.push((command, held));
                }
            }
        }
        for policy in &policies {
            if policy.policy_type() == CreatePolicyType::Restrictive {
                continue;
            }
            let judge = CredentialJudge::new(database, policy, deployment);
            let mut commands = Vec::new();
            let mut sites: Vec<PolicySite<DB>> = Vec::new();
            for (command, keyword, stage) in WRITES {
                if !command.covered_by(policy.command())
                    || !unguarded
                        .iter()
                        .any(|(open, held)| *open == command && applies_to(database, policy, held))
                {
                    continue;
                }
                for clause in applied(database, policy, command)? {
                    if clause.stage != stage || judge.requires(clause.expression)? {
                        continue;
                    }
                    commands.push(keyword);
                    let expression = judge.witness(clause.expression)?.to_string();
                    if !sites
                        .iter()
                        .any(|site| site.clause == clause.clause && site.expression == expression)
                    {
                        sites.push(PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new((*policy).clone()),
                            clause: clause.clause,
                            expression,
                        });
                    }
                }
            }
            if sites.is_empty() {
                continue;
            }
            let (name, commands) = (policy.name(), commands.join(", "));
            reporter.policies(
                sites,
                format!(
                    "Policy '{name}' on '{}' lets a caller with no credential {commands}, since its clause can be true with every credential NULL.",
                    table.table_name()
                ),
                format!(
                    "Make every arm of '{name}' compare a column to a credential, or add a restrictive policy requiring one. A deliberate anonymous write takes an allowance."
                ),
            )?;
        }
        Ok(())
    }
}
