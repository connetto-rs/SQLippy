//! Submodule providing the `NullableCompositeForeignKey` and
//! `UnindexedForeignKey` rules.

use sql_traits::{
    errors::LookupError,
    structs::{Assumption, IdentifierCase, Outcomes},
    traits::{
        CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, TableIndexLike, TableLike,
    },
};
use sqlparser::ast::{Expr, Ident};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        index_support::entry_columns,
        key_support::{indexed_keys, nullable_host_columns},
    },
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// `column IS NULL`, or `column IS NOT NULL` when `null` is unset.
fn null_test<C: ColumnLike>(column: &C, null: bool) -> Expr {
    let column = Box::new(Expr::Identifier(Ident::with_quote(
        '"',
        column.stored_column_name().into_owned(),
    )));
    if null {
        Expr::IsNull(column)
    } else {
        Expr::IsNotNull(column)
    }
}

/// Whether the enforced and validated checks of `table` keep each of the
/// nullable key columns `rest` `NULL` exactly when `first` is, so that no
/// row they admit holds `first` `NULL` and one of `rest` set, or the
/// reverse.
fn null_together<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    first: &DB::Column,
    rest: &[&DB::Column],
) -> Result<bool, LookupError> {
    let assumed = [null_test(first, true), null_test(first, false)];
    let targets: Vec<Expr> = rest.iter().map(|column| null_test(*column, true)).collect();
    let mut assumptions = Vec::new();
    for check in table.check_constraints(database)? {
        if check.is_enforced() && check.is_validated(database)? {
            assumptions.push(Assumption::Check(check));
        }
    }
    for (null, assumed) in [true, false].into_iter().zip(&assumed) {
        assumptions.push(Assumption::Expression {
            expression: assumed,
            outcomes: Outcomes::TRUE,
        });
        for target in &targets {
            let outcomes = table
                .truth_under(database, target, IdentifierCase::AsWritten, &assumptions)?
                .outcomes;
            let apart = if null {
                outcomes.falsity
            } else {
                outcomes.truth
            };
            if apart {
                return Ok(false);
            }
        }
        assumptions.pop();
    }
    Ok(true)
}

/// Struct defining a rule that reports a composite foreign key with two or
/// more nullable columns under `MATCH SIMPLE`.
///
/// Under `MATCH SIMPLE`, a row with any foreign key column `NULL` needs no
/// match, so a key with one nullable column set and another `NULL` points
/// nowhere. A key with one nullable column is an optional reference, such as
/// `invitation_id` under `FOREIGN KEY (tenant_id, invitation_id)` with
/// `tenant_id` `NOT NULL`, and is checked whole whenever that column is set.
/// So is a key whose nullable columns the table's enforced and validated
/// checks keep `NULL` together, such as `previous_id` and `previous_version`
/// under `FOREIGN KEY (previous_id, name, previous_version)` with `name`
/// `NOT NULL` and `CHECK ((previous_id IS NULL) = (previous_version IS
/// NULL))`, or `parent_id` and `parent_kind` under
/// `CHECK ((kind = 'root') = (parent_id IS NULL))` and
/// `CHECK ((kind = 'root') = (parent_kind IS NULL))` with `kind` `NOT NULL`.
///
/// SQLite applies `MATCH SIMPLE` semantics even to a declared `MATCH FULL`.
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
            name: rule_name!(NullableCompositeForeignKey),
            group: LintGroup::Suspicious,
            rationale: "Under MATCH SIMPLE a composite foreign key with any column NULL needs no matching row, so a key with two nullable columns that no check keeps NULL together can be partly filled and reference nothing.",
            source: Some("https://www.postgresql.org/docs/current/sql-createtable.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE parents (a INT, b INT, PRIMARY KEY (a, b));\n\
CREATE TABLE children (a INT, b INT, FOREIGN KEY (a, b) REFERENCES parents (a, b));",
                good: "CREATE TABLE parents (a INT, b INT, PRIMARY KEY (a, b));\n\
CREATE TABLE children (a INT, b INT, FOREIGN KEY (a, b) REFERENCES parents (a, b) MATCH FULL);",
            },
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
        if !foreign_key.is_enforced(database)
            || Engine::of(database) == Engine::PostgreSql && foreign_key.match_full(database)
        {
            return Ok(());
        }
        let nullable = nullable_host_columns(database, foreign_key)?;
        let [first, rest @ ..] = nullable.as_slice() else {
            return Ok(());
        };
        if rest.is_empty()
            || null_together(database, foreign_key.host_table(database), first, rest)?
        {
            return Ok(());
        }
        let host = foreign_key.host_table(database).table_name();
        let resolution = match Engine::of(database) {
            Engine::PostgreSql => {
                "Declare all but one key column NOT NULL, add MATCH FULL so a key is either complete or entirely NULL, or add checks such as (a IS NULL) = (b IS NULL) that keep the nullable key columns NULL together."
            }
            Engine::Sqlite => {
                "Declare all but one key column NOT NULL, or add checks such as (a IS NULL) = (b IS NULL) that keep the nullable key columns NULL together."
            }
        };
        reporter.foreign_key(
            foreign_key,
            format!("A composite foreign key of '{host}' has more than one nullable column under MATCH SIMPLE, so a row with one key column NULL and another set references nothing."),
            resolution.to_owned(),
        )?;
        Ok(())
    }
}

/// The distinct `columns` an index leads with, in any order, each a bare
/// column rather than an expression over it, up to its first entry that is
/// none of them. An index with a predicate leads with none.
fn leading<'db, DB: DatabaseLike, I: TableIndexLike<DB = DB>>(
    database: &'db DB,
    index: &'db I,
    columns: &[&DB::Column],
) -> Result<Vec<&'db DB::Column>, LookupError> {
    let mut run = Vec::new();
    if index.predicate().is_some() {
        return Ok(run);
    }
    for entry in entry_columns(database, index)? {
        match entry {
            Some(column) if columns.contains(&column) => {
                if !run.contains(&column) {
                    run.push(column);
                }
            }
            _ => break,
        }
    }
    Ok(run)
}

/// Struct defining a rule that reports a foreign key whose referencing rows
/// no index of its table finds.
///
/// Deleting a referenced row or updating its key then scans the
/// referencing table for the rows to check or change. An index leading
/// with the columns that reference a unique key, such as `parent_id` under
/// `FOREIGN KEY (parent_id, parent_kind) REFERENCES parents (id, kind)` with
/// `parents.id` unique, already finds the rows of one referenced row. So
/// does a unique key over some of the foreign key columns, such as a
/// primary key on `id` under `FOREIGN KEY (id, kind)`.
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
            name: rule_name!(UnindexedForeignKey),
            group: LintGroup::Perf,
            rationale: "A delete of a referenced row or an update of its key checks the referencing table, which scans it when no index leads with the foreign key columns or with those referencing a unique key, and no unique key over some of them finds the row.",
            source: Some("https://www.postgresql.org/docs/current/ddl-constraints.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (parent_id INT REFERENCES parents (id));",
                good: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (parent_id INT REFERENCES parents (id));\n\
CREATE INDEX ON children (parent_id);",
            },
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
        if !foreign_key.is_enforced(database) {
            return Ok(());
        }
        let host = foreign_key.host_table(database);
        let pairs: Vec<(&DB::Column, &DB::Column)> = foreign_key
            .host_columns(database)?
            .zip(foreign_key.referenced_columns(database)?)
            .collect();
        let columns: Vec<&DB::Column> = pairs.iter().map(|(column, _)| *column).collect();
        let referenced_keys = indexed_keys(database, foreign_key.referenced_table(database)?)?;
        let serves = |run: &[&DB::Column]| {
            columns.iter().all(|column| run.contains(column))
                || referenced_keys.iter().any(|key| {
                    key.iter().all(|key_column| {
                        pairs.iter().any(|(column, referenced)| {
                            referenced == key_column && run.contains(column)
                        })
                    })
                })
        };
        for index in host.indices(database)? {
            if serves(&leading(database, index, &columns)?) {
                return Ok(());
            }
        }
        for index in host.unique_indices(database)? {
            if serves(&leading(database, index, &columns)?) {
                return Ok(());
            }
        }
        for key in indexed_keys(database, host)? {
            if key.iter().all(|column| columns.contains(column)) {
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
