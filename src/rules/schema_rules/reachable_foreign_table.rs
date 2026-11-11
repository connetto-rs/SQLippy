//! Submodule providing the `ReachableForeignTable` rule.

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    rules::grant_support::client_reach,
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Struct defining a rule that reports a foreign table a client role reaches,
/// through a grant or an exposed schema.
///
/// PostgreSQL refuses row-level security and policies on a foreign table, so
/// a client role reaching one reads or changes every remote row. Client roles
/// are `PUBLIC` and the anonymous and app roles of the
/// [`Deployment`](crate::deployment::Deployment), together with the roles they
/// inherit.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = ReachableForeignTable::default().into();
/// constrainer.set_deployment(Deployment::default().with_app_role("app"));
/// let schema = "CREATE ROLE app; CREATE FOREIGN TABLE sales (id INT) SERVER warehouse;";
///
/// let granted =
///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} GRANT SELECT ON sales TO app;"))
///         .unwrap();
/// assert!(constrainer.validate_schema(&granted).is_err());
///
/// let kept = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&kept).is_ok());
/// ```
pub struct ReachableForeignTable<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ReachableForeignTable<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ReachableForeignTable<DB>> for GenericConstrainer<DB> {
    fn from(rule: ReachableForeignTable<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ReachableForeignTable<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "ReachableForeignTable",
            group: LintGroup::Suspicious,
            rationale: "PostgreSQL applies no row-level security to a foreign table, so a client role reaching one reads or changes every remote row.",
            source: Some(
                "https://github.com/supabase/splinter/blob/main/lints/0017_foreign_table_in_api.sql",
            ),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for ReachableForeignTable<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for table in database.foreign_tables() {
            let reasons = client_reach(database, reporter.deployment(), table)?;
            if reasons.is_empty() {
                continue;
            }
            let name = table.table_name();
            let reasons = reasons.into_iter().collect::<Vec<_>>().join(" and ");
            reporter.table(
                table,
                format!("Foreign table '{name}' {reasons}, and PostgreSQL applies no row-level security to a foreign table, so a client role reaches every remote row."),
                format!("Revoke the client roles' privileges on '{name}' and keep it out of exposed schemas, serving clients the remote rows they may see through a function that filters them."),
            )?;
        }
        Ok(())
    }
}
