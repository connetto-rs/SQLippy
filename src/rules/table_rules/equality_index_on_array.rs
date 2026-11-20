//! Submodule providing the `EqualityIndexOnArray` rule.

use sql_traits::traits::{ColumnLike, DataTypeLike, DatabaseLike, IndexLike, TableLike};
use sqlparser::ast::IndexType;

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::index_support::entry_columns,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

rule_definition!(
    /// Struct defining a rule that reports a btree or hash index keyed on an
    /// array column.
    ///
    /// A btree or hash index compares an array as one value, so it serves
    /// whole-array `=`, and a btree also `<`, `>` and `ORDER BY`. The lookups
    /// an array column is queried with test its elements: `@>`, `<@`, `&&`
    /// and `= ANY`, and no btree or hash index serves them, so every such
    /// query reads the whole table while each write still maintains the
    /// index. A `GIN` index serves `@>`, `<@` and `&&`.
    ///
    /// Unique indexes, unique constraints and primary keys are not judged,
    /// since enforcing that no two rows hold the same array is the
    /// whole-array equality such an index exists for. A key over an
    /// expression is not judged either, and the column's type is read
    /// through domains.
    ///
    /// The rule does not run on SQLite, which has no array type.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = EqualityIndexOnArray::default().into();
    ///
    /// let btree = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE posts (id BIGINT PRIMARY KEY, tags TEXT[] NOT NULL);
    ///      CREATE INDEX posts_tags ON posts (tags);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&btree).is_err());
    ///
    /// let gin = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE posts (id BIGINT PRIMARY KEY, tags TEXT[] NOT NULL);
    ///      CREATE INDEX posts_tags ON posts USING gin (tags);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&gin).is_ok());
    /// ```
    EqualityIndexOnArray,
    register_table_rule,
    LintGroup::Perf,
    "A btree or hash index compares an array only as a whole, so it serves none of the `@>`, `<@`, `&&` and `= ANY` lookups an array column is queried with, while every write still maintains it.",
    Some("https://www.postgresql.org/docs/current/indexes-types.html"),
    RuleExample {
        bad: "CREATE TABLE posts (id BIGINT PRIMARY KEY, tags TEXT[] NOT NULL);\n\
CREATE INDEX posts_tags ON posts (tags);",
        good: "CREATE TABLE posts (id BIGINT PRIMARY KEY, tags TEXT[] NOT NULL);\n\
CREATE INDEX posts_tags ON posts USING gin (tags);",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

/// Whether `column` holds an array, directly or through a domain.
fn holds_array<DB: DatabaseLike>(database: &DB, column: &DB::Column) -> bool {
    let data_type = column.data_type(database);
    data_type
        .base_type(database)
        .unwrap_or(data_type)
        .array_element(database)
        .is_some()
}

impl<DB: DatabaseLike> TableRule for EqualityIndexOnArray<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for index in table.indices(database)? {
            let method = match index.access_method() {
                None | Some(IndexType::BTree) => "btree",
                Some(IndexType::Hash) => "hash",
                Some(_) => continue,
            };
            if index.is_unique() {
                continue;
            }
            let arrays: Vec<&str> = entry_columns(database, index)?
                .into_iter()
                .flatten()
                .filter(|column| holds_array(database, column))
                .map(ColumnLike::column_name)
                .collect();
            let keys = match arrays.as_slice() {
                [] => continue,
                [column] => format!("array column '{column}'"),
                _ => format!("array columns '{}'", arrays.join("', '")),
            };
            reporter.index(
                index,
                format!(
                    "A {method} index on '{}' is keyed on {keys}, so it compares an array only as a whole and serves none of `@>`, `<@`, `&&` and `= ANY`.",
                    table.table_name()
                ),
                format!(
                    "Replace it with a `USING gin` index on {keys}, which serves `@>`, `<@` and `&&`, and write `value = ANY (column)` as `column @> ARRAY[value]`. When the elements reference rows of another table, move them to a child table with a row per element and a foreign key."
                ),
            )?;
        }
        Ok(())
    }
}
