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
        grant_support::tenant_columns,
        key_support::{
            KeyPairs, checked_whenever_set, checks_every_row_of, equality_keys, key_pairs,
        },
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
    /// the key, makes PostgreSQL reject that row. A tenant key of several
    /// columns, such as `(organization_namespace_id, organization_id)`, is
    /// paired column by column in its declared order, so a key pairing only
    /// some of them is reported, and tenant keys of different lengths are
    /// never paired.
    /// A key is also accepted when a wider key of the same table into the same
    /// table pairs the tenant keys and checks every row it checks, or when
    /// both columns of one of its pairs are bound, each with the tenant key of
    /// its table, to the same column of a root table that alone tells its rows
    /// apart, such as `(organization_id, id)` of both tables referencing
    /// `resources (organization_id, id)`. Equal values then name one row of
    /// the root, and both rows carry its tenant. A table without a declared
    /// tenant key, such as a global `users` table, is never an endpoint of a
    /// finding. A key that crosses tenants on purpose is excused with
    /// [`Constrainer::allow_foreign_key`].
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
    ///         .with_tenant_key("public", "projects", ["organization_id"])
    ///         .with_tenant_key("public", "documents", ["organization_id"]),
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

/// Whether `foreign_key` pairs every column of `host_tenant` with the column
/// in the same position of `parent_tenant`.
fn pairs_tenants<DB: DatabaseLike>(
    database: &DB,
    foreign_key: &DB::ForeignKey,
    host_tenant: &[&DB::Column],
    parent_tenant: &[&DB::Column],
) -> Result<bool, LookupError> {
    let pairs = key_pairs(database, foreign_key)?;
    Ok(host_tenant.len() == parent_tenant.len()
        && host_tenant
            .iter()
            .zip(parent_tenant)
            .all(|(&host, &parent)| pairs.contains(&(host, parent))))
}

/// Whether `table` has a primary or unique key over exactly `columns`, in
/// any order, that is not deferrable, which a foreign key to them requires.
fn has_key_over<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    columns: &[&DB::Column],
) -> Result<bool, LookupError> {
    Ok(equality_keys(database, table)?
        .iter()
        .any(|key| key.len() == columns.len() && columns.iter().all(|column| key.contains(column))))
}

/// The names of `columns`, separated by commas.
fn listed<DB: DatabaseLike>(columns: &[&DB::Column]) -> String {
    columns
        .iter()
        .map(ColumnLike::column_name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The root columns of one foreign key that each column of a tenant key is
/// bound to, in the order of the tenant key, and the root columns another
/// column is bound to.
type RootBinding<'db, DB> = (
    Vec<Vec<&'db <DB as DatabaseLike>::Column>>,
    Vec<&'db <DB as DatabaseLike>::Column>,
);

/// The bindings of `tenant` and `column` by each foreign key of the table of
/// `column` that checks every row in which `column` is set and binds every
/// column of `tenant` and `column`.
fn root_bindings<'db, DB: DatabaseLike>(
    database: &'db DB,
    tenant: &[&'db DB::Column],
    column: &'db DB::Column,
) -> Result<Vec<RootBinding<'db, DB>>, LookupError> {
    let mut bindings = Vec::new();
    for foreign_key in column.foreign_keys(database)? {
        if !checked_whenever_set(database, foreign_key, column)? {
            continue;
        }
        let pairs = key_pairs(database, foreign_key)?;
        let roots_of = |bound: &DB::Column| -> Vec<&'db DB::Column> {
            pairs
                .iter()
                .filter(|&&(host, _)| host == bound)
                .map(|&(_, root)| root)
                .collect()
        };
        let tenant_roots: Vec<Vec<&DB::Column>> =
            tenant.iter().map(|&bound| roots_of(bound)).collect();
        let column_roots = roots_of(column);
        if tenant_roots.iter().all(|roots| !roots.is_empty()) {
            bindings.push((tenant_roots, column_roots));
        }
    }
    Ok(bindings)
}

/// Whether `host_column` and `parent_column` are each bound, with the tenant
/// key of their table, to the same columns of one root table, the one bound
/// to `host_column` and `parent_column` alone being a key of the root. A row
/// whose `host_column` equals `parent_column` of the row it references then
/// shares that row's root row and so its tenant.
fn share_root_row<'db, DB: DatabaseLike>(
    database: &'db DB,
    (host_tenant, host_column): (&[&'db DB::Column], &'db DB::Column),
    (parent_tenant, parent_column): (&[&'db DB::Column], &'db DB::Column),
) -> Result<bool, LookupError> {
    if host_tenant.len() != parent_tenant.len() {
        return Ok(false);
    }
    let parent_bindings = root_bindings(database, parent_tenant, parent_column)?;
    for (host_tenant_roots, host_roots) in root_bindings(database, host_tenant, host_column)? {
        for (parent_tenant_roots, parent_roots) in &parent_bindings {
            if !host_tenant_roots
                .iter()
                .zip(parent_tenant_roots)
                .all(|(host, parent)| host.iter().any(|root| parent.contains(root)))
            {
                continue;
            }
            for &root_column in &host_roots {
                if parent_roots.contains(&root_column)
                    && has_key_over(database, root_column.table(database), &[root_column])?
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// The column pairs of `foreign_key` with the columns of its tenant keys
/// paired first, by position. The columns other than the tenant keys keep
/// their order on each side and are paired by position, which undoes a key
/// that swaps a tenant key with another column. When the two sides hold
/// different numbers of them, only the pairs without a tenant key column on
/// either side are kept.
fn tenant_paired<'db, DB: DatabaseLike>(
    database: &'db DB,
    foreign_key: &'db DB::ForeignKey,
    host_tenant: &[&'db DB::Column],
    parent_tenant: &[&'db DB::Column],
) -> Result<KeyPairs<'db, DB>, LookupError> {
    let pairs = key_pairs(database, foreign_key)?;
    let host_columns: Vec<&DB::Column> = pairs
        .iter()
        .map(|&(host, _)| host)
        .filter(|host| !host_tenant.contains(host))
        .collect();
    let parent_columns: Vec<&DB::Column> = pairs
        .iter()
        .map(|&(_, parent)| parent)
        .filter(|parent| !parent_tenant.contains(parent))
        .collect();
    let mut paired: KeyPairs<'db, DB> = host_tenant
        .iter()
        .copied()
        .zip(parent_tenant.iter().copied())
        .collect();
    if host_columns.len() == parent_columns.len() {
        paired.extend(host_columns.into_iter().zip(parent_columns));
    } else {
        paired.extend(pairs.into_iter().filter(|(host, parent)| {
            !host_tenant.contains(host) && !parent_tenant.contains(parent)
        }));
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
        let Some(host_tenant) = tenant_columns(database, reporter.deployment(), host)? else {
            return Ok(());
        };
        let Some(parent_tenant) = tenant_columns(database, reporter.deployment(), parent)? else {
            return Ok(());
        };
        if pairs_tenants(database, foreign_key, &host_tenant, &parent_tenant)? {
            return Ok(());
        }
        for wider in host.foreign_keys(database)? {
            if wider.referenced_table(database)? == parent
                && pairs_tenants(database, wider, &host_tenant, &parent_tenant)?
                && checks_every_row_of(database, wider, foreign_key)?
            {
                return Ok(());
            }
        }
        for (host_column, parent_column) in key_pairs(database, foreign_key)? {
            if share_root_row(
                database,
                (&host_tenant, host_column),
                (&parent_tenant, parent_column),
            )? {
                return Ok(());
            }
        }
        let (host_name, parent_name) = (host.table_name(), parent.table_name());
        let (host_key, parent_key) = (listed::<DB>(&host_tenant), listed::<DB>(&parent_tenant));
        let fix = if host_tenant.len() == parent_tenant.len() {
            let (host_columns, parent_columns): (Vec<_>, Vec<_>) =
                tenant_paired(database, foreign_key, &host_tenant, &parent_tenant)?
                    .into_iter()
                    .unzip();
            let (host_list, parent_list) =
                (listed::<DB>(&host_columns), listed::<DB>(&parent_columns));
            let reference = format!(
                "reference {parent_name} ({parent_list}) from ({host_list}) of '{host_name}'"
            );
            if has_key_over(database, parent, &parent_columns)? {
                format!("Make the key {reference}")
            } else {
                format!(
                    "Add UNIQUE ({parent_list}) to '{parent_name}', which a composite reference requires, and make the key {reference}"
                )
            }
        } else {
            format!(
                "Declare the tenant keys of '{host_name}' and '{parent_name}' with corresponding columns, since no key pairs ({host_key}) with ({parent_key})"
            )
        };
        reporter.foreign_key(
            foreign_key,
            format!(
                "A foreign key of '{host_name}' into '{parent_name}' does not pair tenant key ({host_key}) of '{host_name}' with tenant key ({parent_key}) of '{parent_name}', so a row of '{host_name}' can reference a row of '{parent_name}' that belongs to another tenant."
            ),
            format!(
                "{fix}, or allow it with `allow_foreign_key` if the reference crosses tenants on purpose."
            ),
        )?;
        Ok(())
    }
}
