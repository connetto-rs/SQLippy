//! Submodule providing the `UnconditionalClientWritePolicy` rule.

use std::collections::BTreeSet;

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::{CreatePolicyType, Expr, Value};

use crate::{
    deployment::{Declaration, Deployment},
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{Command, Stage, applied, applies_to, held_by_name, is_tautology},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

rule_definition!(
    /// Struct defining a rule that reports a permissive `INSERT`, `UPDATE`,
    /// `DELETE` or `ALL` policy through which a client role writes every row.
    ///
    /// For each write the rule reads the clause PostgreSQL applies: `WITH
    /// CHECK`, or `USING` in its place, for the rows `INSERT` adds, and `USING`
    /// for the rows `UPDATE` and `DELETE` reach. The policy is reported when
    /// that clause is true for every row and it applies to a declared app
    /// role or, while the deployment declares no credential, to `PUBLIC` or a
    /// declared anonymous role, unless a restrictive policy on that role and
    /// command limits the rows. `credential_free_write` judges anonymous
    /// callers once a credential is declared, `tautological_policy` judges a
    /// `USING` true through an always-true operand, and
    /// `tautological_with_check` judges an always-true `WITH CHECK` beside a
    /// row-dependent `USING`, so this rule reads only a literal-true `USING`.
    /// A `SELECT` policy reading `USING (true)` is a deliberate public read
    /// and is not judged.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> =
    ///     UnconditionalClientWritePolicy::default().into();
    /// constrainer.set_deployment(Deployment::default().with_app_role("member"));
    /// let schema = "CREATE ROLE member; CREATE TABLE docs (id INT, owner TEXT);
    ///               ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";
    ///
    /// let open = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE POLICY d ON docs FOR DELETE TO member USING (true);"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&open).is_err());
    ///
    /// let owned = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE POLICY d ON docs FOR DELETE TO member USING (owner = current_user);"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&owned).is_ok());
    /// ```
    UnconditionalClientWritePolicy,
    register_table_rule,
    LintGroup::Suspicious,
    "Signing in does not entitle a client to every tenant's rows, so a write policy true for every row lets any client role insert, change or delete rows that belong to others.",
    Some("https://github.com/supabase/splinter/blob/main/lints/0024_rls_policy_always_true.sql"),
    RuleExample {
        bad: "CREATE ROLE authenticated NOLOGIN;\n\
CREATE TABLE public.documents (identifier INT PRIMARY KEY, owner_name TEXT);\n\
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;\n\
GRANT DELETE ON public.documents TO authenticated;\n\
CREATE POLICY delete_documents ON public.documents FOR DELETE TO authenticated USING (true);",
        good: "CREATE ROLE authenticated NOLOGIN;\n\
CREATE TABLE public.documents (identifier INT PRIMARY KEY, owner_name TEXT);\n\
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;\n\
GRANT DELETE ON public.documents TO authenticated;\n\
CREATE POLICY delete_documents ON public.documents FOR DELETE TO authenticated\n\
USING (owner_name = current_user);",
    },
    Basis::Declared
);

/// The writes judged, with their keyword and the stage whose rows a client
/// chooses: new rows for `INSERT`, existing rows for `UPDATE` and `DELETE`.
const WRITES: [(Command, &str, Stage); 3] = [
    (Command::Insert, "INSERT", Stage::Check),
    (Command::Update, "UPDATE", Stage::Filter),
    (Command::Delete, "DELETE", Stage::Filter),
];

/// Whether the expression is the literal `true`, parentheses aside.
fn is_literal_true(expression: &Expr) -> bool {
    match expression {
        Expr::Nested(inner) => is_literal_true(inner),
        Expr::Value(literal) => matches!(literal.value, Value::Boolean(true)),
        _ => false,
    }
}

/// The client callers judged, each named for messages with the roles it
/// holds: every declared app role, and while no credential is declared, each
/// declared anonymous role and a caller holding only `PUBLIC`.
fn client_callers<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
) -> Vec<(String, BTreeSet<String>)> {
    let mut callers: Vec<_> = deployment
        .app_roles()
        .map(|role| (format!("role '{role}'"), held_by_name(database, role)))
        .collect();
    if !deployment.declares(Declaration::Credentials) {
        callers.extend(
            deployment
                .anonymous_roles()
                .map(|role| (format!("role '{role}'"), held_by_name(database, role))),
        );
        callers.push(("PUBLIC".to_owned(), BTreeSet::new()));
    }
    callers
}

impl<DB: DatabaseLike> TableRule for UnconditionalClientWritePolicy<DB> {
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
        let callers = client_callers(database, reporter.deployment());
        let policies: Vec<_> = table.policies(database)?.collect();
        let mut unguarded: Vec<(Command, &str)> = Vec::new();
        for (command, _, stage) in WRITES {
            'callers: for (label, held) in &callers {
                for policy in &policies {
                    if policy.policy_type() != CreatePolicyType::Restrictive
                        || !command.covered_by(policy.command())
                        || !applies_to(database, *policy, held)
                    {
                        continue;
                    }
                    for clause in applied(database, *policy, command)? {
                        if clause.stage == stage
                            && !is_tautology(database, table, clause.expression)?
                        {
                            continue 'callers;
                        }
                    }
                }
                unguarded.push((command, label));
            }
        }
        for policy in &policies {
            if policy.policy_type() == CreatePolicyType::Restrictive {
                continue;
            }
            let mut commands = Vec::new();
            let mut writers = BTreeSet::new();
            let mut sites: Vec<PolicySite<DB>> = Vec::new();
            for (command, keyword, stage) in WRITES {
                if !command.covered_by(policy.command()) {
                    continue;
                }
                let reached: Vec<&str> = callers
                    .iter()
                    .filter(|(label, held)| {
                        applies_to(database, *policy, held)
                            && unguarded.contains(&(command, label.as_str()))
                    })
                    .map(|(label, _)| label.as_str())
                    .collect();
                if reached.is_empty() {
                    continue;
                }
                for clause in applied(database, *policy, command)? {
                    if clause.stage != stage
                        || (clause.clause == PolicyClause::Using
                            && !is_literal_true(clause.expression))
                        || !is_tautology(database, table, clause.expression)?
                    {
                        continue;
                    }
                    commands.push(keyword);
                    writers.extend(reached.iter().copied());
                    let expression = clause.expression.to_string();
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
            let name = policy.name();
            let commands = commands.join(", ");
            let writers = writers.into_iter().collect::<Vec<_>>().join(", ");
            reporter.policies(
                sites,
                format!(
                    "Policy '{name}' on '{}' lets {writers} {commands} every row, since its clause is true whatever the row holds.",
                    table.table_name()
                ),
                format!(
                    "Make '{name}' compare the row to the caller, such as its owner or tenant column, or keep the write to a role no client holds. Allow a deliberate unconditional write with `allow_policy`."
                ),
            )?;
        }
        Ok(())
    }
}
