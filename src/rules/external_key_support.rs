//! Declared external foreign keys resolved against the schema the rules read.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, TableLike},
};

use crate::{
    deployment::{Deployment, ExternalForeignKey},
    error::UnresolvedForeignKey,
    rules::grant_support::schema_of,
};

/// The table with these stored schema and table names.
fn declared_table<'db, DB: DatabaseLike>(
    database: &'db DB,
    (schema, table): (&str, &str),
) -> Option<&'db DB::Table> {
    database.tables().find(|candidate| {
        candidate.stored_table_name() == table
            && schema_of(database, candidate.stored_table_schema()) == schema
    })
}

/// The columns of `table` with the stored `names`, in order, or the first
/// name it lacks.
fn declared_columns<'db, 'names, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
    names: &'names [String],
) -> Result<Result<Vec<&'db DB::Column>, &'names str>, LookupError> {
    let mut columns = Vec::with_capacity(names.len());
    for name in names {
        let Some(column) = table
            .columns(database)?
            .find(|column| column.stored_column_name() == name.as_str())
        else {
            return Ok(Err(name));
        };
        columns.push(column);
    }
    Ok(Ok(columns))
}

/// Why `key` does not resolve in `database`, or `None` when it does.
fn problem<DB: DatabaseLike>(
    database: &DB,
    key: &ExternalForeignKey,
) -> Result<Option<String>, LookupError> {
    let (columns, referenced_columns) = (key.columns(), key.referenced_columns());
    if columns.is_empty() || columns.len() != referenced_columns.len() {
        return Ok(Some(format!(
            "has {} columns referencing {}",
            columns.len(),
            referenced_columns.len()
        )));
    }
    for (table, names) in [
        (key.host(), columns),
        (key.referenced(), referenced_columns),
    ] {
        let (schema, name) = table;
        let Some(found) = declared_table(database, table) else {
            return Ok(Some(format!(
                "names table '{schema}.{name}', which the schema lacks"
            )));
        };
        if let Err(column) = declared_columns(database, found, names)? {
            return Ok(Some(format!(
                "names column '{column}', which '{schema}.{name}' lacks"
            )));
        }
    }
    Ok(None)
}

/// The declared external foreign keys naming a table or column `database`
/// lacks, in declaration order.
pub(crate) fn unresolved_external_foreign_keys<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
) -> Result<Vec<UnresolvedForeignKey>, LookupError> {
    let mut unresolved = Vec::new();
    for key in deployment.external_foreign_keys() {
        if let Some(problem) = problem(database, key)? {
            unresolved.push(UnresolvedForeignKey {
                key: key.clone(),
                problem,
            });
        }
    }
    Ok(unresolved)
}

/// The host columns of every declared external foreign key of `table` that
/// resolves.
pub(crate) fn external_host_columns<'db, DB: DatabaseLike>(
    database: &'db DB,
    deployment: &'db Deployment,
    table: &'db DB::Table,
) -> Result<Vec<Vec<&'db DB::Column>>, LookupError> {
    let schema = schema_of(database, table.stored_table_schema());
    let name = table.stored_table_name();
    let mut keys = Vec::new();
    for key in deployment.external_foreign_keys() {
        if key.host() == (schema.as_ref(), name.as_ref())
            && let Ok(columns) = declared_columns(database, table, key.columns())?
        {
            keys.push(columns);
        }
    }
    Ok(keys)
}
