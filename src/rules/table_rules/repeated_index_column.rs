//! Submodule providing the `RepeatedIndexColumn` rule.

use sql_traits::{
    errors::LookupError,
    structs::TargetName,
    traits::{ColumnLike, DatabaseLike, IndexLike, TableLike},
    utils::columns_in_expression,
};
use sqlparser::ast::Expr;

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{is_column_reference, unnested},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports an index naming one column more than
/// once among its keys.
///
/// PostgreSQL accepts `CREATE INDEX ON t (a, a)` and `CREATE UNIQUE INDEX ON
/// t (b, c, b)`, storing the column twice. Once the first copy has ordered
/// and constrained the entries, the repeated one adds nothing: rows equal on
/// the first copy are equal on the second, so the index sorts and enforces
/// uniqueness exactly as it would without it, while storing every value
/// again. Indexes over expressions are not judged, and neither are `UNIQUE`
/// and `PRIMARY KEY` constraints, which PostgreSQL refuses to create with a
/// repeated column.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = RepeatedIndexColumn::default().into();
///
/// let repeated = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (a INT, b INT);
///      CREATE INDEX t_a_a ON t (a, a);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&repeated).is_err());
///
/// let distinct = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (a INT, b INT);
///      CREATE INDEX t_a_b ON t (a, b);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&distinct).is_ok());
/// ```
pub struct RepeatedIndexColumn<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RepeatedIndexColumn<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RepeatedIndexColumn<DB>> for GenericConstrainer<DB> {
    fn from(rule: RepeatedIndexColumn<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for RepeatedIndexColumn<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RepeatedIndexColumn),
            group: LintGroup::Complexity,
            rationale: "A column repeated among an index's keys orders and constrains nothing its first copy did not, while every value is stored twice.",
            source: Some("https://www.postgresql.org/docs/current/indexes-multicolumn.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE t (id INT PRIMARY KEY, a INT);\n\
CREATE INDEX t_a_a ON t (a, a);",
                good: "CREATE TABLE t (id INT PRIMARY KEY, a INT);\n\
CREATE INDEX t_a ON t (a);",
            },
        };
        &METADATA
    }
}

/// The name of an index, or its columns when it has none, and the first key
/// column it names more than once, for an index over plain columns.
///
/// Each key is resolved on its own because [`IndexLike::columns`] lists every
/// column once, however many keys name it.
fn repeated<'db, DB: DatabaseLike, I: IndexLike<DB = DB>>(
    database: &'db DB,
    index: &'db I,
) -> Result<Option<(String, &'db DB::Column)>, LookupError> {
    let elements: Vec<&Expr> = match unnested(index.expression(database)?) {
        Expr::Tuple(elements) => elements.iter().collect(),
        single => vec![single],
    };
    if !elements.iter().all(|element| is_column_reference(element)) {
        return Ok(None);
    }
    let table = IndexLike::table(index, database);
    let declared: Vec<&DB::Column> = table.columns(database)?.collect();
    let mut target = TargetName::new(table.table_name(), table.table_name_is_quoted());
    if let Some(schema) = table.table_schema() {
        target = target.with_schema(schema, table.table_schema_is_quoted());
    }
    let keys: Vec<&DB::Column> = elements
        .into_iter()
        .flat_map(|element| {
            columns_in_expression(element, database.catalog_name(), &target, &declared)
                .unwrap_or_default()
        })
        .collect();
    let Some(column) = keys.iter().enumerate().find_map(|(position, column)| {
        keys[..position]
            .iter()
            .any(|earlier| std::ptr::eq(*earlier, *column))
            .then_some(*column)
    }) else {
        return Ok(None);
    };
    let name = index.name().map_or_else(
        || {
            keys.iter()
                .map(ColumnLike::column_name)
                .collect::<Vec<_>>()
                .join(", ")
        },
        str::to_owned,
    );
    Ok(Some((name, column)))
}

impl<DB: DatabaseLike> TableRule for RepeatedIndexColumn<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for index in table.indices(database)? {
            let Some((name, column)) = repeated(database, index)? else {
                continue;
            };
            reporter.table(
                table,
                format!(
                    "Index '{name}' on '{}' names column '{}' more than once, and the repeated key orders and constrains nothing the first did not.",
                    table.table_name(),
                    column.column_name()
                ),
                format!("Recreate '{name}' naming '{}' once.", column.column_name()),
            )?;
        }
        Ok(())
    }
}
