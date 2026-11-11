//! Submodule providing the `PrefixRedundantIndex` rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, IndexLike, TableLike},
};
use sqlparser::ast::{Expr, IndexType};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    rules::policy_support::{is_column_reference, unnested},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// What decides whether one index can serve another's lookups.
struct Shape<'db, DB: DatabaseLike> {
    name: String,
    columns: Vec<&'db DB::Column>,
    method: IndexType,
    partial: bool,
    unique: bool,
    includes: bool,
}

impl<'db, DB: DatabaseLike> Shape<'db, DB> {
    /// The shape of an index over plain columns, or `None` for an index over
    /// expressions.
    fn of<I: IndexLike<DB = DB>>(
        database: &'db DB,
        index: &'db I,
        unique: bool,
    ) -> Result<Option<Self>, LookupError> {
        let elements: Vec<&Expr> = match unnested(index.expression(database)?) {
            Expr::Tuple(elements) => elements.iter().collect(),
            single => vec![single],
        };
        if !elements.iter().all(|element| is_column_reference(element)) {
            return Ok(None);
        }
        let columns: Vec<&DB::Column> = index.columns(database)?.collect();
        Ok(Some(Self {
            name: index.name().map_or_else(
                || {
                    columns
                        .iter()
                        .map(ColumnLike::column_name)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                str::to_owned,
            ),
            columns,
            method: index.access_method().cloned().unwrap_or(IndexType::BTree),
            partial: index.predicate().is_some(),
            unique,
            includes: index.include_columns(database)?.next().is_some(),
        }))
    }

    /// Whether `other` serves every lookup this index serves, `earlier`
    /// telling which of two equal indexes stays.
    fn served_by(&self, other: &Self, earlier: bool) -> bool {
        !self.unique
            && !self.partial
            && !self.includes
            && !other.partial
            && self.method == other.method
            && other.columns.starts_with(&self.columns)
            && (other.columns.len() > self.columns.len() || other.unique || earlier)
    }
}

/// Struct defining a rule that reports an index whose columns are a leading
/// prefix of another index's.
///
/// The longer index serves every lookup the shorter one does when both use
/// the same method and have no predicate, and the shorter one enforces no
/// uniqueness and includes no columns. Of two equal indexes, the later one is
/// reported. Indexes over expressions are not compared.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = PrefixRedundantIndex::default().into();
/// let schema = "CREATE TABLE t (a INT, b INT); CREATE INDEX t_a_b ON t (a, b);";
/// let prefix =
///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} CREATE INDEX t_a ON t (a);")).unwrap();
/// assert!(constrainer.validate_schema(&prefix).is_err());
/// let other =
///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} CREATE INDEX t_b ON t (b);")).unwrap();
/// assert!(constrainer.validate_schema(&other).is_ok());
/// ```
pub struct PrefixRedundantIndex<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PrefixRedundantIndex<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PrefixRedundantIndex<DB>> for GenericConstrainer<DB> {
    fn from(rule: PrefixRedundantIndex<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for PrefixRedundantIndex<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "PrefixRedundantIndex",
            group: LintGroup::Perf,
            rationale: "An index whose columns lead another index of the same method serves no lookup the longer one cannot, and still costs space and every write.",
            source: Some("https://github.com/pmpetit/pglinter/blob/main/docs/rules/README.md"),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for PrefixRedundantIndex<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut shapes: Vec<Shape<'_, DB>> = Vec::new();
        for index in table.unique_indices(database)? {
            shapes.extend(Shape::of(database, index, true)?);
        }
        for index in table.indices(database)? {
            shapes.extend(Shape::of(database, index, index.is_unique())?);
        }
        for (position, shape) in shapes.iter().enumerate() {
            let Some(longer) = shapes.iter().enumerate().find_map(|(other, longer)| {
                (other != position && shape.served_by(longer, other < position)).then_some(longer)
            }) else {
                continue;
            };
            reporter.table(
                table,
                format!(
                    "Index '{}' on '{}' leads index '{}' with the same columns, so '{}' serves every lookup it does.",
                    shape.name,
                    table.table_name(),
                    longer.name,
                    longer.name
                ),
                format!("DROP INDEX {};", shape.name),
            )?;
        }
        Ok(())
    }
}
