//! Submodule providing the `TenantLocalReference` rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};

use crate::{
    deployment::Declaration,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        grant_support::tenant_column,
        key_support::{KeyPairs, checks_every_row_of, equality_keys, key_pairs},
    },
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

rule_definition!(
    /// Struct defining a rule that reports a foreign key between two tables
    /// with declared tenant keys whose column pairs do not match the tenant
    /// key of the referencing table with the tenant key of the referenced one.
    ///
    /// A key on a globally unique identifier proves only that the referenced
    /// row exists and says nothing of its tenant, so a row of one tenant can
    /// point at a row of another. Pairing the tenant keys, in any position of
    /// the key, makes PostgreSQL reject that row.
    /// A key is also accepted when a wider key of the same table into the same
    /// table pairs the tenant keys and checks every row it checks. A table
    /// without a declared tenant key, such as a global `users` table, is
    /// never an endpoint of a finding. A key that crosses tenants on purpose
    /// is excused with [`Constrainer::allow_foreign_key`].
    ///
    /// [`Deployment::with_tenant_key`](crate::deployment::Deployment::with_tenant_key)
    /// declares the tenant keys, and the rule is inactive until one is
    /// declared or [`Deployment::without_tenant_keys`](crate::deployment::Deployment::without_tenant_keys)
    /// declares that there is none.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> = TenantLocalReference::default().into();
    /// constrainer.set_deployment(
    ///     Deployment::default()
    ///         .with_tenant_key("public", "projects", "organization_id")
    ///         .with_tenant_key("public", "documents", "organization_id"),
    /// );
    /// let projects = "CREATE TABLE projects (id INT PRIMARY KEY, organization_id INT NOT NULL,
    ///     UNIQUE (organization_id, id));";
    /// let any_tenant = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{projects} CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
    ///        project_id INT NOT NULL REFERENCES projects (id));"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&any_tenant).is_err());
    /// let same_tenant = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{projects} CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
    ///        project_id INT NOT NULL,
    ///        FOREIGN KEY (organization_id, project_id) REFERENCES projects (organization_id, id));"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&same_tenant).is_ok());
    /// ```
    TenantLocalReference,
    register_foreign_key_rule,
    LintGroup::Suspicious,
    "A foreign key on an identifier alone proves only that the referenced row exists, so a row of one tenant can point at a row of another.",
    Some("https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-FK"),
    RuleExample {
        bad: "CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL, UNIQUE (organization_id, id));\n\
CREATE TABLE caps (id INT PRIMARY KEY, organization_id INT NOT NULL, resource_id INT NOT NULL REFERENCES resources (id));",
        good: "CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL, UNIQUE (organization_id, id));\n\
CREATE TABLE caps (id INT PRIMARY KEY, organization_id INT NOT NULL, resource_id INT NOT NULL, FOREIGN KEY (organization_id, resource_id) REFERENCES resources (organization_id, id));",
    },
    Basis::Declared,
    &Engine::ALL,
    &[Declaration::TenantKeys]
);

/// Whether `foreign_key` pairs `host_tenant` with `parent_tenant`.
fn pairs_tenants<DB: DatabaseLike>(
    database: &DB,
    foreign_key: &DB::ForeignKey,
    host_tenant: &DB::Column,
    parent_tenant: &DB::Column,
) -> Result<bool, LookupError> {
    Ok(key_pairs(database, foreign_key)?
        .into_iter()
        .any(|(host, referenced)| host == host_tenant && referenced == parent_tenant))
}

/// Whether `table` has a primary or unique key over exactly `columns`, in
/// any order, which a foreign key to them requires.
fn has_key_over<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    columns: &[&DB::Column],
) -> Result<bool, LookupError> {
    let same_set = |key: &[&DB::Column]| {
        key.len() == columns.len() && columns.iter().all(|column| key.contains(column))
    };
    let primary_key: Vec<&DB::Column> = table.primary_key_columns(database)?.collect();
    Ok(same_set(&primary_key)
        || equality_keys(database, table)?
            .iter()
            .any(|key| same_set(key)))
}

/// The names of `columns`, separated by commas.
fn listed<DB: DatabaseLike>(columns: &[&DB::Column]) -> String {
    columns
        .iter()
        .map(ColumnLike::column_name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The column pairs of `foreign_key` with its tenant keys paired first. The
/// columns other than the tenant keys keep their order on each side and are
/// paired by position, which undoes a key that swaps a tenant key with
/// another column. When the two sides hold different numbers of them, only
/// the pairs without a tenant key on either side are kept.
fn tenant_paired<'db, DB: DatabaseLike>(
    database: &'db DB,
    foreign_key: &'db DB::ForeignKey,
    host_tenant: &'db DB::Column,
    parent_tenant: &'db DB::Column,
) -> Result<KeyPairs<'db, DB>, LookupError> {
    let pairs = key_pairs(database, foreign_key)?;
    let host_columns: Vec<&DB::Column> = pairs
        .iter()
        .map(|&(host, _)| host)
        .filter(|&host| host != host_tenant)
        .collect();
    let parent_columns: Vec<&DB::Column> = pairs
        .iter()
        .map(|&(_, parent)| parent)
        .filter(|&parent| parent != parent_tenant)
        .collect();
    let mut paired = vec![(host_tenant, parent_tenant)];
    if host_columns.len() == parent_columns.len() {
        paired.extend(host_columns.into_iter().zip(parent_columns));
    } else {
        paired.extend(
            pairs
                .into_iter()
                .filter(|&(host, parent)| host != host_tenant && parent != parent_tenant),
        );
    }
    Ok(paired)
}

impl<DB: DatabaseLike> ForeignKeyRule for TenantLocalReference<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let host = foreign_key.host_table(database);
        let parent = foreign_key.referenced_table(database)?;
        let Some(host_tenant) = tenant_column(database, reporter.deployment(), host)? else {
            return Ok(());
        };
        let Some(parent_tenant) = tenant_column(database, reporter.deployment(), parent)? else {
            return Ok(());
        };
        if pairs_tenants(database, foreign_key, host_tenant, parent_tenant)? {
            return Ok(());
        }
        for wider in host.foreign_keys(database)? {
            if wider.referenced_table(database)? == parent
                && pairs_tenants(database, wider, host_tenant, parent_tenant)?
                && checks_every_row_of(database, wider, foreign_key)?
            {
                return Ok(());
            }
        }
        let (host_columns, parent_columns): (Vec<_>, Vec<_>) =
            tenant_paired(database, foreign_key, host_tenant, parent_tenant)?
                .into_iter()
                .unzip();
        let (host_name, parent_name) = (host.table_name(), parent.table_name());
        let (host_list, parent_list) = (listed::<DB>(&host_columns), listed::<DB>(&parent_columns));
        let reference =
            format!("reference {parent_name} ({parent_list}) from ({host_list}) of '{host_name}'");
        let fix = if has_key_over(database, parent, &parent_columns)? {
            format!("Make the key {reference}")
        } else {
            format!(
                "Add UNIQUE ({parent_list}) to '{parent_name}', which a composite reference requires, and make the key {reference}"
            )
        };
        reporter.foreign_key(
            foreign_key,
            format!(
                "A foreign key of '{host_name}' into '{parent_name}' does not pair tenant key '{}' of '{host_name}' with tenant key '{}' of '{parent_name}', so a row of '{host_name}' can reference a row of '{parent_name}' that belongs to another tenant.",
                host_tenant.column_name(),
                parent_tenant.column_name(),
            ),
            format!(
                "{fix}, or allow it with `allow_foreign_key` if the reference crosses tenants on purpose."
            ),
        )?;
        Ok(())
    }
}
