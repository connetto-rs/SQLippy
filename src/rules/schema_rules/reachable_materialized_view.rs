//! Submodule providing the `ReachableMaterializedView` rule.

use std::{cell::LazyCell, collections::BTreeSet};

use sql_traits::traits::{
    ColumnGrantLike, DataStatementLike, DatabaseLike, Relation, TableGrantLike, TableLike, ViewLike,
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::grant_support::{ClientRoles, grantee_list, schema_of},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Struct defining a rule that reports a materialized view over a
/// row-level-security table that a client role reaches, through a grant or an
/// exposed schema.
///
/// PostgreSQL refuses row-level security on a materialized view, so its rows
/// are whatever the role refreshing it could see.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ReachableMaterializedView::default().into();
///
/// let published = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT, owner TEXT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      CREATE MATERIALIZED VIEW doc_owners AS SELECT owner FROM docs;
///      GRANT SELECT ON doc_owners TO PUBLIC;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&published).is_err());
/// ```
pub struct ReachableMaterializedView<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ReachableMaterializedView<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ReachableMaterializedView<DB>> for GenericConstrainer<DB> {
    fn from(rule: ReachableMaterializedView<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ReachableMaterializedView<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "ReachableMaterializedView",
            group: LintGroup::Suspicious,
            rationale: "A materialized view cannot have row-level security, so it shows a client every row its refreshing role could read from the protected tables.",
            source: Some(
                "https://github.com/supabase/splinter/blob/main/lints/0016_materialized_view_in_api.sql",
            ),
        };
        &METADATA
    }
}

/// Whether the grant relation is the given materialized view.
fn is_view<DB: DatabaseLike>(
    relation: Option<Relation<'_, DB>>,
    view: &DB::MaterializedView,
) -> bool {
    matches!(relation, Some(Relation::MaterializedView(granted)) if granted == view)
}

impl<DB: DatabaseLike> SchemaRule for ReachableMaterializedView<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let roles = LazyCell::new(|| ClientRoles::new(database, deployment));
        for view in database.materialized_views() {
            let mut protected = BTreeSet::new();
            for table in view.definition().referenced_tables(database)? {
                if table.has_row_level_security(database)? {
                    protected.insert(table.table_name());
                }
            }
            if protected.is_empty() {
                continue;
            }
            let mut reasons = BTreeSet::new();
            let schema = schema_of(database, view.stored_view_schema());
            if deployment.exposes_schema(&schema) {
                reasons.insert(format!("sits in the exposed schema '{schema}'"));
            }
            for grant in database.table_grants() {
                if grant
                    .relations(database)
                    .any(|relation| is_view(Some(relation), view))
                    && roles.reach_client(database, grant)
                {
                    reasons.insert(format!("is granted to {}", grantee_list(database, grant)));
                }
            }
            for grant in database.column_grants() {
                if is_view(grant.relation(database), view) && roles.reach_client(database, grant) {
                    reasons.insert(format!("is granted to {}", grantee_list(database, grant)));
                }
            }
            if reasons.is_empty() {
                continue;
            }
            let name = view.view_name();
            let protected = protected.into_iter().collect::<Vec<_>>().join(", ");
            let reasons = reasons.into_iter().collect::<Vec<_>>().join(" and ");
            reporter.materialized_view(
                view,
                format!("Materialized view '{name}' reads the row-level-security table(s) {protected} and {reasons}, so no policy filters what a client reads from it."),
                format!("Revoke client access to {name} and move it out of exposed schemas, or replace it with a view WITH (security_invoker = true)."),
            )?;
        }
        Ok(())
    }
}
