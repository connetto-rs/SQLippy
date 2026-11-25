//! Submodule providing the `UnscopedUniqueConstraintOnRowLevelSecurityTable`
//! rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, IndexLike, TableIndexLike, TableLike, UniqueIndexLike},
};

use crate::{
    deployment::{Declaration, Deployment},
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{authority_support::read_authority_columns, index_support::read_columns},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::index_name},
};

/// Whether an index's columns include one of `subjects`, the subject columns
/// of its table.
fn scoped<DB: DatabaseLike, I: TableIndexLike<DB = DB>>(
    database: &DB,
    index: &I,
    subjects: &[&str],
) -> Result<bool, LookupError> {
    Ok(index
        .columns(database)?
        .any(|column| subjects.contains(&column.stored_column_name().as_ref())))
}

/// Whether a declared client role may put a row under `index` of `table`, by
/// inserting into `table` or updating a column the index reads.
///
/// A role the schema never creates may hold the privileges from outside it,
/// and a deployment declaring no client role proves nothing.
fn client_writable<DB: DatabaseLike, I: TableIndexLike<DB = DB>>(
    database: &DB,
    deployment: &Deployment,
    table: &DB::Table,
    index: &I,
) -> Result<bool, LookupError> {
    let mut roles = deployment
        .app_roles()
        .chain(deployment.anonymous_roles())
        .peekable();
    if roles.peek().is_none() {
        return Ok(true);
    }
    let Some(read) = read_columns(database, index)? else {
        return Ok(true);
    };
    for name in roles {
        let Some(role) = database.role(name) else {
            return Ok(true);
        };
        let possible = table.possible_privileges(role, database)?;
        if possible.insert.on_any_column()
            || read.iter().any(|column| possible.update.on_column(column))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The name an index goes by in a finding: the one an allowance takes, else
/// its columns.
fn label<DB: DatabaseLike, I: TableIndexLike<DB = DB>>(
    database: &DB,
    index: &I,
) -> Result<String, LookupError> {
    Ok(match index_name(index, database)? {
        Some(name) => name.into_owned(),
        None => index
            .columns(database)?
            .map(ColumnLike::column_name)
            .collect::<Vec<_>>()
            .join(", "),
    })
}

/// Struct defining a rule that reports a unique constraint or unique index on
/// a table with row-level security whose columns omit the table's subject
/// column, the column the `USING` clause of a policy applying to `SELECT`
/// compares with a credential.
///
/// A duplicate-key error then tells a caller that the value exists in rows
/// its policies hide, such as another tenant's. A comparison only a
/// `WITH CHECK` clause or an `UPDATE` or `DELETE` policy makes hides no row
/// from reads and makes no subject. The primary key is not reported, and
/// neither is an index no declared client role can write under, by an
/// `INSERT` into the table or an `UPDATE` of a column the index reads, since
/// a duplicate-key error needs one of them. Writes a `SECURITY DEFINER`
/// function makes for a caller are not considered. The rule needs declared
/// credentials.
///
/// The rule does not run on SQLite, which has no row-level security.
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
            name: rule_name!(UnscopedUniqueConstraintOnRowLevelSecurityTable),
            group: LintGroup::Suspicious,
            rationale: "A unique constraint spans the whole table whatever its policies hide, so a duplicate-key error tells a caller that a value exists in rows it cannot see, such as another tenant's.",
            source: Some("https://www.bytebase.com/blog/postgres-row-level-security-footguns"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE users (id INT PRIMARY KEY, email TEXT, owner TEXT);\n\
ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON users USING (owner = current_setting('app.user_id', true));\n\
CREATE UNIQUE INDEX users_email ON users (email);",
                good: "CREATE TABLE users (id INT PRIMARY KEY, email TEXT, owner TEXT);\n\
ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON users USING (owner = current_setting('app.user_id', true));\n\
CREATE UNIQUE INDEX users_email ON users (owner, email);",
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

impl<DB: DatabaseLike> SchemaRule for UnscopedUniqueConstraintOnRowLevelSecurityTable<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let subjects = read_authority_columns(database, deployment)?.subjects;
        for table in database.tables() {
            let own: Vec<&str> = subjects
                .iter()
                .filter(|(id, _)| database.table_id(table) == Some(*id))
                .map(|(_, column)| column.as_str())
                .collect();
            if own.is_empty() || !table.has_row_level_security(database)? {
                continue;
            }
            let (name, subject) = (table.table_name(), own.join("', '"));
            let message = |index: &str| {
                format!(
                    "Unique constraint '{index}' on '{name}' leaves out '{subject}', so a duplicate-key error reveals values in rows the caller's policies hide."
                )
            };
            let resolution = |index: &str| {
                format!(
                    "Include '{subject}' in '{index}' so uniqueness holds per subject, or allow it with `allow_index` if the value is meant to be unique across all of them."
                )
            };
            for index in table.unique_indices(database)? {
                if !index.is_primary_key(database)?
                    && !scoped(database, index, &own)?
                    && client_writable(database, deployment, table, index)?
                {
                    let label = label(database, index)?;
                    reporter.unique_index(index, message(&label), resolution(&label))?;
                }
            }
            for index in table.indices(database)? {
                if index.is_unique()
                    && index.name().is_some()
                    && !scoped(database, index, &own)?
                    && client_writable(database, deployment, table, index)?
                {
                    let label = label(database, index)?;
                    reporter.index(index, message(&label), resolution(&label))?;
                }
            }
        }
        Ok(())
    }
}
