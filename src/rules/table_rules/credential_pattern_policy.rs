//! Submodule providing the `CredentialPatternPolicy` rule.

use std::ops::ControlFlow;

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::{BinaryOperator, Expr, Visitor};

use crate::{
    deployment::{Declaration, Deployment},
    engine::Engine,
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::walk_support::walk,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a policy clause using a declared
/// credential as the pattern of a match.
///
/// `LIKE`, `ILIKE` and `SIMILAR TO` read `%` and `_` in their pattern as
/// wildcards, and `~` and `~*` read a regular expression, so a caller whose
/// credential holds `%` or `.*` matches the rows of every other caller. The
/// clause is judged with its subqueries, and the credential may stand under
/// casts or parentheses. The negated forms are not reported, since a wildcard
/// there hides rows, nor a credential on the matched side or passed through a
/// function first, such as one escaping its wildcards. The rule is inactive
/// until the deployment declares a credential.
///
/// The rule does not run on SQLite, which has no row-level security policies.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = CredentialPatternPolicy::default().into();
/// constrainer.set_deployment(
///     Deployment::default().with_credential("current_setting('app.email', true)").unwrap(),
/// );
/// let pattern = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner_email TEXT);
///      CREATE POLICY own ON docs USING (owner_email LIKE current_setting('app.email', true));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&pattern).is_err());
/// let equality = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (owner_email TEXT);
///      CREATE POLICY own ON docs USING (owner_email = current_setting('app.email', true));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&equality).is_ok());
/// ```
pub struct CredentialPatternPolicy<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for CredentialPatternPolicy<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<CredentialPatternPolicy<DB>> for GenericConstrainer<DB> {
    fn from(rule: CredentialPatternPolicy<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for CredentialPatternPolicy<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(CredentialPatternPolicy),
            group: LintGroup::Suspicious,
            rationale: "A policy matching rows against the credential as a pattern lets a caller whose credential holds a wildcard such as `%` read or write the rows of every other caller.",
            source: Some("https://www.postgresql.org/docs/current/functions-matching.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (owner TEXT);\n\
CREATE POLICY own ON docs USING (owner LIKE current_setting('app.user_id', true));",
                good: "CREATE TABLE docs (owner TEXT);\n\
CREATE POLICY own ON docs USING (owner = current_setting('app.user_id', true));",
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

/// Collects the matches whose pattern is a declared credential.
struct CredentialPatterns<'a> {
    deployment: &'a Deployment,
    found: Vec<String>,
}

impl CredentialPatterns<'_> {
    /// Whether `pattern`, under casts and parentheses, is a declared
    /// credential.
    fn is_credential(&self, mut pattern: &Expr) -> bool {
        loop {
            if self.deployment.is_credential(pattern) {
                return true;
            }
            match pattern {
                Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => pattern = inner,
                _ => return false,
            }
        }
    }
}

impl Visitor for CredentialPatterns<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        let (Expr::Like {
            negated: false,
            pattern,
            ..
        }
        | Expr::ILike {
            negated: false,
            pattern,
            ..
        }
        | Expr::SimilarTo {
            negated: false,
            pattern,
            ..
        }
        | Expr::BinaryOp {
            op: BinaryOperator::PGRegexMatch | BinaryOperator::PGRegexIMatch,
            right: pattern,
            ..
        }) = expr
        else {
            return ControlFlow::Continue(());
        };
        if self.is_credential(pattern) {
            self.found.push(expr.to_string());
        }
        ControlFlow::Continue(())
    }
}

impl<DB: DatabaseLike> TableRule for CredentialPatternPolicy<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &DB,
        table: &DB::Table,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            let mut sites: Vec<PolicySite<DB>> = Vec::new();
            let mut matches = Vec::new();
            for (clause, expression) in [
                (PolicyClause::Using, policy.written_using(database)?),
                (PolicyClause::WithCheck, policy.written_check(database)?),
            ] {
                let Some(expression) = expression else {
                    continue;
                };
                let mut patterns = CredentialPatterns {
                    deployment: reporter.deployment(),
                    found: Vec::new(),
                };
                let _ = walk(expression, &mut patterns);
                if patterns.found.is_empty() {
                    continue;
                }
                sites.push(PolicySite {
                    table: Box::new(table.clone()),
                    policy: Box::new(policy.clone()),
                    clause,
                    expression: patterns.found.join(", "),
                });
                matches.extend(patterns.found.into_iter().map(|found| format!("`{found}`")));
            }
            if !sites.is_empty() {
                reporter.policies(
                    sites,
                    format!(
                        "Policy '{}' on '{}' matches against the credential as a pattern in {}, so wildcards in the credential match rows meant for other callers.",
                        policy.name(),
                        table.table_name(),
                        matches.join(", "),
                    ),
                    "Compare with `=`, or escape the credential's wildcards before matching against it."
                        .to_owned(),
                )?;
            }
        }
        Ok(())
    }
}
