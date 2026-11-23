//! Submodule providing the `PolicyTargetsBypassRole` rule.

use sql_traits::{
    traits::{DatabaseLike, PolicyLike, RoleLike, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::Owner;

use crate::{
    engine::Engine,
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a policy whose `TO` list names a role
/// with `BYPASSRLS` or `SUPERUSER`.
///
/// Such a role skips every row security policy, so the policy never applies
/// to it and whatever restriction it was meant to put on that role is
/// missing. Role attributes are not inherited, so a member of such a role is
/// subject to the policy and is not reported. A policy that also names
/// `PUBLIC` applies to every role and is not reported either.
///
/// The rule does not run on SQLite, which has no row-level security policies.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = PolicyTargetsBypassRole::default().into();
///
/// let bypassing = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE ROLE byp BYPASSRLS;
///      CREATE TABLE docs (id INT);
///      CREATE POLICY visible ON docs TO byp USING (true);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&bypassing).is_err());
///
/// let subject = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE ROLE app;
///      CREATE TABLE docs (id INT);
///      CREATE POLICY visible ON docs TO app USING (true);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&subject).is_ok());
/// ```
pub struct PolicyTargetsBypassRole<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PolicyTargetsBypassRole<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PolicyTargetsBypassRole<DB>> for GenericConstrainer<DB> {
    fn from(rule: PolicyTargetsBypassRole<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for PolicyTargetsBypassRole<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(PolicyTargetsBypassRole),
            group: LintGroup::Suspicious,
            rationale: "A role with `BYPASSRLS` or `SUPERUSER` skips every row security policy, so policies targeting it never apply to it.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE app BYPASSRLS;\n\
CREATE TABLE docs (id INT PRIMARY KEY);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY visible ON docs TO app USING (true);",
                good: "CREATE ROLE app;\n\
CREATE TABLE docs (id INT PRIMARY KEY);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY visible ON docs TO app USING (true);",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

impl<DB: DatabaseLike> TableRule for PolicyTargetsBypassRole<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            for owner in policy.roles(database) {
                let Owner::Ident(ident) = owner else {
                    continue;
                };
                let name = normalize_identifier(&ident.value, ident.quote_style.is_some());
                let Some(role) = database.role(&name) else {
                    continue;
                };
                if !role.can_bypass_rls() && !role.is_superuser() {
                    continue;
                }
                reporter.policies(
                    vec![PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new(policy.clone()),
                        clause: PolicyClause::To,
                        expression: owner.to_string(),
                    }],
                    format!(
                        "Policy '{}' on '{}' targets role '{name}', which skips every policy so this one never applies to it.",
                        policy.name(),
                        table.table_name(),
                    ),
                    format!(
                        "Target a role without `BYPASSRLS` or `SUPERUSER`, or remove those attributes from '{name}'."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
