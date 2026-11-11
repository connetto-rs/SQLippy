//! Submodule providing the `NullableCompositeForeignKey` and
//! `UnindexedForeignKey` rules.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, IndexLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports a composite foreign key with a
/// nullable column under `MATCH SIMPLE`.
///
/// Under `MATCH SIMPLE`, a row with any foreign key column `NULL` needs no
/// match, so a half-filled key points nowhere.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NullableCompositeForeignKey::default().into();
/// let schema = "CREATE TABLE p (a INT, b INT, PRIMARY KEY (a, b));";
/// let simple = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE TABLE c (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&simple).is_err());
/// let full = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE TABLE c (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b) MATCH FULL);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&full).is_ok());
/// ```
pub struct NullableCompositeForeignKey<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NullableCompositeForeignKey<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NullableCompositeForeignKey<DB>> for GenericConstrainer<DB> {
    fn from(rule: NullableCompositeForeignKey<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for NullableCompositeForeignKey<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NullableCompositeForeignKey",
            group: LintGroup::Suspicious,
            rationale: "Under MATCH SIMPLE a composite foreign key with any column NULL needs no matching row, so a partly filled key references nothing.",
            source: Some("https://www.postgresql.org/docs/current/sql-createtable.html"),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for NullableCompositeForeignKey<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if foreign_key.match_full(database)
            || !foreign_key.is_composite(database)?
            || !foreign_key.has_nullable_host_columns(database)?
        {
            return Ok(());
        }
        let host = foreign_key.host_table(database).table_name();
        reporter.foreign_key(
            foreign_key,
            format!("A composite foreign key of '{host}' has a nullable column under MATCH SIMPLE, so a row with one key column NULL references nothing."),
            "Declare every key column NOT NULL, or add MATCH FULL so a key is either complete or entirely NULL.".to_owned(),
        )?;
        Ok(())
    }
}

/// Whether an index without a predicate leads with exactly `columns`, in
/// any order.
fn leads<DB: DatabaseLike, I: IndexLike<DB = DB>>(
    database: &DB,
    index: &I,
    columns: &[&DB::Column],
) -> Result<bool, LookupError> {
    if index.predicate().is_some() {
        return Ok(false);
    }
    let indexed: Vec<&DB::Column> = index.columns(database)?.collect();
    Ok(indexed.len() >= columns.len()
        && indexed[..columns.len()]
            .iter()
            .all(|column| columns.contains(column)))
}

/// Struct defining a rule that reports a foreign key whose columns lead no
/// index of their table.
///
/// Deleting a referenced row or updating its key then scans the
/// referencing table for the rows to check or change.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UnindexedForeignKey::default().into();
/// let schema = "CREATE TABLE p (id INT PRIMARY KEY); CREATE TABLE c (p_id INT REFERENCES p (id));";
/// let bare = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&bare).is_err());
/// let indexed =
///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} CREATE INDEX ON c (p_id);")).unwrap();
/// assert!(constrainer.validate_schema(&indexed).is_ok());
/// ```
pub struct UnindexedForeignKey<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnindexedForeignKey<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnindexedForeignKey<DB>> for GenericConstrainer<DB> {
    fn from(rule: UnindexedForeignKey<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UnindexedForeignKey<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "UnindexedForeignKey",
            group: LintGroup::Perf,
            rationale: "A delete of a referenced row or an update of its key checks the referencing table, which scans it when no index leads with the foreign key columns.",
            source: Some("https://www.postgresql.org/docs/current/ddl-constraints.html"),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for UnindexedForeignKey<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let host = foreign_key.host_table(database);
        let columns: Vec<&DB::Column> = foreign_key.host_columns(database)?.collect();
        for index in host.indices(database)? {
            if leads(database, index, &columns)? {
                return Ok(());
            }
        }
        for index in host.unique_indices(database)? {
            if leads(database, index, &columns)? {
                return Ok(());
            }
        }
        let (table, names) = (
            host.table_name(),
            columns
                .iter()
                .map(ColumnLike::column_name)
                .collect::<Vec<_>>()
                .join(", "),
        );
        reporter.foreign_key(
            foreign_key,
            format!("No index of '{table}' leads with its foreign key columns ({names}), so deleting or rekeying a referenced row scans '{table}'."),
            format!("CREATE INDEX ON {table} ({names});"),
        )?;
        Ok(())
    }
}
