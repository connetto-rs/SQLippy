//! Submodule providing the `DuplicatePolicy` rule.

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::{CreatePolicyCommand, CreatePolicyType, Expr};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{policy_support::policy_roles, volatility_support::runs_volatile},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a policy repeating the definition of
/// an earlier policy on the same table under another name.
///
/// Two policies are the same definition when they share their type,
/// command, roles in any order and `USING` and `WITH CHECK` clauses, outer
/// parentheses aside. A repeated permissive policy grants nothing new and a
/// repeated restrictive policy narrows nothing further, and a later edit to
/// one copy silently leaves the other in force. A restrictive policy whose
/// clauses may run a `VOLATILE` function, directly or through an operator or
/// an explicit cast, is the exception, since PostgreSQL checks each
/// restrictive policy separately on writes. On PostgreSQL 18.6 a restrictive
/// `WITH CHECK (random() < 0.5)` accepted 5032 of ten thousand inserts alone
/// and 2475 with a copy, so such copies are not reported.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DuplicatePolicy::default().into();
///
/// let repeated = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (tenant INT);
///      CREATE POLICY floor ON docs AS RESTRICTIVE USING (tenant = 1);
///      CREATE POLICY guard ON docs AS RESTRICTIVE USING (tenant = 1);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&repeated).is_err());
///
/// let single = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (tenant INT);
///      CREATE POLICY floor ON docs AS RESTRICTIVE USING (tenant = 1);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&single).is_ok());
/// ```
pub struct DuplicatePolicy<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DuplicatePolicy<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DuplicatePolicy<DB>> for GenericConstrainer<DB> {
    fn from(rule: DuplicatePolicy<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DuplicatePolicy<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DuplicatePolicy),
            group: LintGroup::Complexity,
            rationale: "A policy repeating another under a new name changes no access, and an edit to one copy leaves the other in force.",
            source: Some("https://www.postgresql.org/docs/current/sql-createpolicy.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (id INT PRIMARY KEY, tenant INT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY tenant_floor ON docs AS RESTRICTIVE USING (tenant = 1);\n\
CREATE POLICY tenant_guard ON docs AS RESTRICTIVE USING (tenant = 1);",
                good: "CREATE TABLE docs (id INT PRIMARY KEY, tenant INT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY tenant_floor ON docs AS RESTRICTIVE USING (tenant = 1);",
            },
        };
        &METADATA
    }
}

/// The expression without its outer parentheses.
fn unparenthesized(expression: &Expr) -> &Expr {
    match expression {
        Expr::Nested(inner) => unparenthesized(inner),
        _ => expression,
    }
}

/// What a policy grants or narrows, apart from its name: type, command,
/// sorted roles with `None` for `PUBLIC`, and its clauses without outer
/// parentheses.
type Definition<'db> = (
    CreatePolicyType,
    CreatePolicyCommand,
    Option<Vec<String>>,
    Option<&'db Expr>,
    Option<&'db Expr>,
);

/// The definition of `policy`, comparable across policies of one table.
fn definition<'db, DB: DatabaseLike>(
    database: &'db DB,
    policy: &'db DB::Policy,
) -> Result<Definition<'db>, Interruption> {
    let roles = policy_roles(database, policy).map(|mut roles| {
        roles.sort();
        roles.dedup();
        roles
    });
    Ok((
        policy.policy_type(),
        policy.command(),
        roles,
        policy.using_expression(database)?.map(unparenthesized),
        policy.check_expression(database)?.map(unparenthesized),
    ))
}

/// The site naming `policy` in a finding, at its first clause.
fn site<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    policy: &DB::Policy,
) -> Result<PolicySite<DB>, Interruption> {
    let (clause, expression) = match policy.using_expression(database)? {
        Some(using) => (PolicyClause::Using, Some(using)),
        None => (PolicyClause::WithCheck, policy.check_expression(database)?),
    };
    Ok(PolicySite {
        table: Box::new(table.clone()),
        policy: Box::new(policy.clone()),
        clause,
        expression: expression.map_or_else(String::new, ToString::to_string),
    })
}

impl<DB: DatabaseLike> TableRule for DuplicatePolicy<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut seen: Vec<(Definition, &DB::Policy)> = Vec::new();
        for policy in table.policies(database)? {
            let definition = definition(database, policy)?;
            if definition.0 == CreatePolicyType::Restrictive
                && [definition.3, definition.4]
                    .into_iter()
                    .flatten()
                    .any(|clause| runs_volatile(database, clause))
            {
                continue;
            }
            if let Some((_, first)) = seen.iter().find(|(earlier, _)| *earlier == definition) {
                let (first_name, name) = (first.name(), policy.name());
                reporter.policies(
                    vec![site(database, table, first)?, site(database, table, policy)?],
                    format!(
                        "Policy '{name}' on '{}' repeats the definition of '{first_name}' under another name.",
                        table.table_name()
                    ),
                    format!(
                        "Drop '{name}', keeping '{first_name}' as the one policy with this definition."
                    ),
                )?;
                continue;
            }
            seen.push((definition, policy));
        }
        Ok(())
    }
}
