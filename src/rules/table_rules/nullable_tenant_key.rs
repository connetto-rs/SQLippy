//! Submodule providing the `NullableTenantKey` rule.

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    deployment::Declaration,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::grant_support::tenant_column,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a table whose declared tenant key
/// allows `NULL`.
///
/// A row whose tenant key is `NULL` belongs to no tenant, so a policy
/// comparing the key with `=` hides it from every tenant, and an arm such as
/// `organization_id IS NULL OR ...` shows it to all of them. The rule is
/// inactive until the deployment declares a tenant key, and does not run on
/// SQLite, which has no row-level security.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = NullableTenantKey::default().into();
/// constrainer.set_deployment(Deployment::default().with_tenant_key(
///     "public",
///     "documents",
///     "organization_id",
/// ));
/// let nullable = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&nullable).is_err());
/// let required = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&required).is_ok());
/// ```
pub struct NullableTenantKey<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NullableTenantKey<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NullableTenantKey<DB>> for GenericConstrainer<DB> {
    fn from(rule: NullableTenantKey<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for NullableTenantKey<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NullableTenantKey),
            group: LintGroup::Suspicious,
            rationale: "A row whose tenant key is NULL belongs to no tenant, so a policy comparing the key with = hides it from every tenant, and one that admits a NULL key shows it to all of them.",
            source: Some("https://www.postgresql.org/docs/current/functions-comparison.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT);",
                good: "CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL);",
            },
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::TenantKeys]
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

impl<DB: DatabaseLike> TableRule for NullableTenantKey<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let Some(column) = tenant_column(database, reporter.deployment(), table)? else {
            return Ok(());
        };
        if !column.is_nullable(database)? {
            return Ok(());
        }
        let name = table.table_name();
        let column = column.column_name();
        reporter.table(
            table,
            format!("Column '{column}', the declared tenant key of '{name}', allows NULL, so a row without a tenant is hidden from every tenant or shown to all of them, depending on how each policy treats NULL."),
            format!("ALTER TABLE {name} ALTER COLUMN {column} SET NOT NULL; once every row carries its tenant."),
        )?;
        Ok(())
    }
}
