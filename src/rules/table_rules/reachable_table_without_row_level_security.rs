//! Submodule providing the `ReachableTableWithoutRowLevelSecurity` rule.

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::grant_support::client_reach,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a table without row-level security a
/// client role reaches, through a grant or an exposed schema.
///
/// Client roles are `PUBLIC` and the anonymous and app roles of the
/// [`Deployment`](crate::deployment::Deployment), together with the roles they
/// inherit. A missing grant never excuses a table, since default privileges
/// live outside the schema.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> =
///     ReachableTableWithoutRowLevelSecurity::default().into();
/// constrainer.set_deployment(Deployment::default().with_anonymous_role("anon"));
///
/// let open = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE ROLE anon; CREATE TABLE secrets (id INT); GRANT SELECT ON secrets TO anon;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&open).is_err());
///
/// let protected = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE ROLE anon; CREATE TABLE secrets (id INT);
///      ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
///      GRANT SELECT ON secrets TO anon;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&protected).is_ok());
/// ```
pub struct ReachableTableWithoutRowLevelSecurity<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ReachableTableWithoutRowLevelSecurity<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ReachableTableWithoutRowLevelSecurity<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: ReachableTableWithoutRowLevelSecurity<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ReachableTableWithoutRowLevelSecurity<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(ReachableTableWithoutRowLevelSecurity),
            group: LintGroup::Suspicious,
            rationale: "A table without row-level security shows every row to each role that reaches it, so a client role reads or changes all of them.",
            source: Some(
                "https://github.com/supabase/splinter/blob/main/lints/0013_rls_disabled_in_public.sql",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE public.notes (id INT PRIMARY KEY);",
                good: "CREATE TABLE public.notes (id INT PRIMARY KEY);\n\
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for ReachableTableWithoutRowLevelSecurity<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if table.has_row_level_security(database)? {
            return Ok(());
        }
        let reasons = client_reach(database, reporter.deployment(), table)?;
        if reasons.is_empty() {
            return Ok(());
        }
        let name = table.table_name();
        let reasons = reasons.into_iter().collect::<Vec<_>>().join(" and ");
        reporter.table(
            table,
            format!("Table '{name}' has no row-level security and {reasons}, so a client role reaches every row."),
            format!("ALTER TABLE {name} ENABLE ROW LEVEL SECURITY; with policies for what clients may do, or a SELECT USING (true) policy and no write policy for a reference table."),
        )?;
        Ok(())
    }
}
