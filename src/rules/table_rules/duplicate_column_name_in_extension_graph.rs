//! Submodule providing the `DuplicateColumnNameInExtensionGraph` constraint,
//! which enforces that column names are unique within an extension graph.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        key_support::{KeyPairs, key_pairs},
        null_support::may_hold_null,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces that column names are unique
/// within an extension graph (i.e., a table which extends other tables cannot
/// have a column whose name also appears in other tables it extends).
///
/// A column that foreign keys keep equal to every same-named column of the
/// hierarchy is not reported, as a tenant column is when the subtype keys
/// `(organization_id, id)` to the same columns of its parent. Each such key
/// pairs the primary keys of the two tables, so both rows describe one
/// entity, and checks every row, through `MATCH FULL` or `NOT NULL` columns.
/// The equality may pass through a column of another name, as when two
/// subtypes each key their `project_id` to the `parent_id` of their root.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `duplicate_column_name_in_extension_graph` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> =
///     DuplicateColumnNameInExtensionGraph::default().into();
///
/// // Invalid: child_table has 'name' column, which also exists in parent_table
/// let invalid_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     name TEXT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// // Valid: child_table has unique column names
/// let valid_schema = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     description TEXT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// // Valid: non-extension tables can have any column names
/// let valid_non_extension = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE table1 (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE table2 (id INT PRIMARY KEY, name TEXT);
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_non_extension).is_ok());
///
/// // Valid: primary key column (id) can be shared in extension
/// let valid_shared_pk = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     value INT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_shared_pk).is_ok());
///
/// // Invalid: transitive extension - grandchild cannot have column from grandparent
/// let invalid_transitive = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE grandparent_table (id INT PRIMARY KEY, name TEXT);
/// CREATE TABLE parent_table (
///     id INT PRIMARY KEY,
///     age INT,
///     FOREIGN KEY (id) REFERENCES grandparent_table(id)
/// );
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     name TEXT,
///     FOREIGN KEY (id) REFERENCES parent_table(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_transitive).is_err());
///
/// // Valid: a foreign key keeps the tenant column equal to the parent's
/// let valid_tenant = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE parent_table (id INT PRIMARY KEY, tenant_id INT NOT NULL, UNIQUE (tenant_id, id));
/// CREATE TABLE child_table (
///     id INT PRIMARY KEY,
///     tenant_id INT NOT NULL,
///     FOREIGN KEY (id) REFERENCES parent_table(id),
///     FOREIGN KEY (tenant_id, id) REFERENCES parent_table(tenant_id, id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_tenant).is_ok());
/// ```
pub struct DuplicateColumnNameInExtensionGraph<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DuplicateColumnNameInExtensionGraph<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DuplicateColumnNameInExtensionGraph<DB>>
    for GenericConstrainer<DB>
{
    fn from(constraint: DuplicateColumnNameInExtensionGraph<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for DuplicateColumnNameInExtensionGraph<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DuplicateColumnNameInExtensionGraph),
            group: LintGroup::Suspicious,
            rationale: "A column name repeated across an extension hierarchy makes the merged row ambiguous.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE records (id INT PRIMARY KEY, name TEXT);\n\
CREATE TABLE notes (id INT PRIMARY KEY REFERENCES records (id), name TEXT);",
                good: "CREATE TABLE records (id INT PRIMARY KEY, name TEXT);\n\
CREATE TABLE notes (id INT PRIMARY KEY REFERENCES records (id), description TEXT);",
            },
        };
        &METADATA
    }
}

/// The column pairs of the enforced `foreign_key` that hold one value on
/// every row, when the key pairs its host's primary key with the primary key
/// of the referenced table, so the host row and the row it references
/// describe one entity. `None` when the key may join rows of two entities or
/// skip a row.
fn entity_equalities<'db, DB: DatabaseLike>(
    database: &'db DB,
    foreign_key: &'db DB::ForeignKey,
) -> Result<Option<KeyPairs<'db, DB>>, LookupError> {
    if !foreign_key.is_enforced(database) {
        return Ok(None);
    }
    let pairs = key_pairs(database, foreign_key)?;
    let referenced_primary_key: Vec<&DB::Column> = foreign_key
        .referenced_table(database)?
        .primary_key_columns(database)?
        .collect();
    let mut paired = Vec::new();
    for host_column in foreign_key
        .host_table(database)
        .primary_key_columns(database)?
    {
        let Some((_, referenced)) = pairs.iter().find(|(host, _)| *host == host_column) else {
            return Ok(None);
        };
        paired.push(*referenced);
    }
    if paired.is_empty()
        || paired.len() != referenced_primary_key.len()
        || !referenced_primary_key
            .iter()
            .all(|column| paired.contains(column))
    {
        return Ok(None);
    }
    if !foreign_key.match_full(database) {
        for (host, _) in &pairs {
            if may_hold_null(database, *host)? {
                return Ok(None);
            }
        }
    }
    Ok(Some(pairs))
}

impl<DB: DatabaseLike> DuplicateColumnNameInExtensionGraph<DB> {
    /// The columns of `table` outside its primary key that share their name
    /// with a column of a table it extends, directly or transitively, and
    /// that some such column may differ from.
    ///
    /// The pairs of [`entity_equalities`] of the tables of the hierarchy, and
    /// of the tables they reach that way, hold the row of the same entity and
    /// tie their columns into groups that hold one value. A column is
    /// reported unless every same-named column of the hierarchy is in its
    /// group.
    fn find_duplicate_columns<'db>(
        database: &'db DB,
        table: &'db DB::Table,
    ) -> Result<Vec<&'db DB::Column>, LookupError> {
        let mut tables: Vec<&DB::Table> = vec![table];
        let mut tables_to_check: Vec<&DB::Table> = table.extended_tables(database)?.collect();
        while let Some(extended_table) = tables_to_check.pop() {
            if tables.contains(&extended_table) {
                continue;
            }
            tables.push(extended_table);
            tables_to_check.extend(extended_table.extended_tables(database)?);
        }
        let hierarchy = tables.len();
        if hierarchy == 1 {
            return Ok(Vec::new());
        }

        let mut equalities: KeyPairs<'db, DB> = Vec::new();
        let mut next = 0;
        while let Some(&host) = tables.get(next) {
            next += 1;
            for foreign_key in host.foreign_keys(database)? {
                let referenced = foreign_key.referenced_table(database)?;
                if referenced == host {
                    continue;
                }
                if let Some(pairs) = entity_equalities(database, foreign_key)? {
                    equalities.extend(pairs);
                    if !tables.contains(&referenced) {
                        tables.push(referenced);
                    }
                }
            }
        }

        let primary_key: Vec<&DB::Column> = table.primary_key_columns(database)?.collect();
        let mut carriers: Vec<&DB::Column> = Vec::new();
        let mut tied: Vec<&DB::Column> = Vec::new();
        let mut duplicates = Vec::new();
        for column in table.columns(database)? {
            if primary_key.contains(&column) {
                continue;
            }
            let column_name = column.column_name();
            carriers.clear();
            for &ancestor in &tables[1..hierarchy] {
                carriers.extend(
                    ancestor
                        .columns(database)?
                        .filter(|other| other.column_name() == column_name),
                );
            }
            if carriers.is_empty() {
                continue;
            }

            tied.clear();
            tied.push(column);
            let mut grown = true;
            while grown {
                grown = false;
                for &(host, referenced) in &equalities {
                    if tied.contains(&host) != tied.contains(&referenced) {
                        tied.push(if tied.contains(&host) {
                            referenced
                        } else {
                            host
                        });
                        grown = true;
                    }
                }
            }
            if !carriers.iter().all(|carrier| tied.contains(carrier)) {
                duplicates.push(column);
            }
        }
        Ok(duplicates)
    }
}

impl<DB: DatabaseLike> TableRule for DuplicateColumnNameInExtensionGraph<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table_name = table.table_name();
        for column in Self::find_duplicate_columns(database, table)? {
            let column_name = column.column_name();
            reporter.column(
                column,
                format!(
                    "Column '{column_name}' of table '{table_name}' conflicts with a column of the same name in the tables it extends."
                ),
                format!(
                    "Rename the column '{column_name}' in table '{table_name}' so its name is unique across the extension hierarchy."
                ),
            )?;
        }
        Ok(())
    }
}
