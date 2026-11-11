//! Submodule providing the `UnscopedUniqueConstraintOnRowLevelSecurityTable`
//! rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, IndexLike, TableLike, UniqueIndexLike},
};

use crate::{
    deployment::Declaration,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    rules::authority_support::{TableColumn, authority_columns},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Whether an index's columns include one of `subjects`, the subject columns
/// of its table.
fn scoped<DB: DatabaseLike, I: IndexLike<DB = DB>>(
    database: &DB,
    index: &I,
    subjects: &[&str],
) -> Result<bool, LookupError> {
    Ok(index
        .columns(database)?
        .any(|column| subjects.contains(&column.stored_column_name().as_ref())))
}

/// Struct defining a rule that reports a unique constraint or unique index on
/// a table with row-level security whose columns omit the table's subject
/// column, the column its policies compare with a credential.
///
/// A duplicate-key error then tells a caller that the value exists in rows
/// its policies hide, such as another tenant's. The primary key is not
/// reported. The rule needs declared credentials.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> =
///     UnscopedUniqueConstraintOnRowLevelSecurityTable::default().into();
/// constrainer.set_deployment(
///     Deployment::default().with_credential("current_setting('app.tenant', true)").unwrap(),
/// );
/// let schema = "CREATE TABLE users (id INT PRIMARY KEY, email TEXT, tenant_id INT);
///     ALTER TABLE users ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY users_rls ON users USING (tenant_id = current_setting('app.tenant', true)::int);";
/// let global = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE UNIQUE INDEX users_email ON users (email);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&global).is_err());
/// let scoped = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE UNIQUE INDEX users_email ON users (tenant_id, lower(email));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&scoped).is_ok());
/// ```
pub struct UnscopedUniqueConstraintOnRowLevelSecurityTable<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnscopedUniqueConstraintOnRowLevelSecurityTable<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnscopedUniqueConstraintOnRowLevelSecurityTable<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: UnscopedUniqueConstraintOnRowLevelSecurityTable<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UnscopedUniqueConstraintOnRowLevelSecurityTable<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "UnscopedUniqueConstraintOnRowLevelSecurityTable",
            group: LintGroup::Suspicious,
            rationale: "A unique constraint spans the whole table whatever its policies hide, so a duplicate-key error tells a caller that a value exists in rows it cannot see, such as another tenant's.",
            source: Some("https://www.bytebase.com/blog/postgres-row-level-security-footguns"),
            basis: Basis::Declared,
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Credentials]
    }
}

impl<DB: DatabaseLike> SchemaRule for UnscopedUniqueConstraintOnRowLevelSecurityTable<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let subjects: Vec<TableColumn> =
            authority_columns(database, reporter.deployment())?.subjects;
        for table in database.tables() {
            let own: Vec<&str> = subjects
                .iter()
                .filter(|(id, _)| database.table_id(table) == Some(*id))
                .map(|(_, column)| column.as_str())
                .collect();
            if own.is_empty() || !table.has_row_level_security(database)? {
                continue;
            }
            let mut unscoped = Vec::new();
            for index in table.unique_indices(database)? {
                if !index.is_primary_key(database)? && !scoped(database, index, &own)? {
                    let columns: Vec<&str> = index
                        .columns(database)?
                        .map(ColumnLike::column_name)
                        .collect();
                    unscoped.push(
                        index
                            .name()
                            .map_or_else(|| columns.join(", "), str::to_owned),
                    );
                }
            }
            for index in table.indices(database)? {
                if index.is_unique() && !scoped(database, index, &own)? {
                    unscoped.extend(index.name().map(str::to_owned));
                }
            }
            let (name, subject) = (table.table_name(), own.join("', '"));
            for index in unscoped {
                reporter.table(
                    table,
                    format!("Unique constraint '{index}' on '{name}' leaves out '{subject}', so a duplicate-key error reveals values in rows the caller's policies hide."),
                    format!("Include '{subject}' in '{index}' so uniqueness holds per subject, or allow it if the value is meant to be unique across all of them."),
                )?;
            }
        }
        Ok(())
    }
}
