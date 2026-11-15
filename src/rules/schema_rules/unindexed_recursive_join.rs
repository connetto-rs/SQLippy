//! Submodule providing the `UnindexedRecursiveJoin` rule.

use std::borrow::Cow;

use sql_traits::{
    errors::LookupError,
    structs::IdentifierCase,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, TableLike},
};
use sqlparser::ast::{Statement, Visit};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::{stored_table, walks},
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        index_support::indexed,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Finds the recursive walks that join the walked table on no index.
struct UnindexedJoins;

/// The unindexed recursive joins of `node`, resolving walked relations on
/// `path`, or on the database's search path when `None`.
fn unindexed<DB: DatabaseLike, V: Visit + ?Sized>(
    database: &DB,
    node: &V,
    path: Option<&[(Cow<'_, str>, bool)]>,
) -> Result<Vec<(String, String)>, LookupError> {
    let mut found = Vec::new();
    walks(node, |item, recursive, name, exposed| {
        let Some(table) = stored_table(database, name, path)? else {
            return Ok(());
        };
        let mut unindexed = None;
        for column in recursive.joined_columns(exposed) {
            let Some(column) =
                table.column(&column.to_string(), database, IdentifierCase::AsWritten)?
            else {
                continue;
            };
            if indexed(database, table, column)? {
                return Ok(());
            }
            unindexed.get_or_insert(column);
        }
        let Some(column) = unindexed else {
            return Ok(());
        };
        // `unindexed_foreign_key` already reports a single-column foreign key.
        for foreign_key in table.foreign_keys(database)? {
            if foreign_key.host_column(database)? == Some(column) {
                return Ok(());
            }
        }
        found.push((
            format!(
                "the recursive `WITH` item '{}' joining its working table to '{}' on '{}', which no index of '{}' leads with",
                item.alias.name,
                table.table_name(),
                column.column_name(),
                table.table_name()
            ),
            item.to_string(),
        ));
        Ok(())
    })?;
    Ok(found)
}

impl ExpressionFinder for UnindexedJoins {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        unindexed(database, node, None)
    }

    fn find_in_body<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        function: &DB::Function,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        unindexed(database, node, function.search_path(database)?.as_deref())
    }

    fn problem(&self) -> &'static str {
        "so every step of the walk scans the whole table"
    }

    fn resolution(&self) -> &'static str {
        "Create an index on the walked table leading with the column the recursive term joins on."
    }
}

/// Struct defining a rule that reports a `WITH RECURSIVE` item whose
/// recursive term joins the walked table on a column no index leads with.
///
/// Each step of a recursive walk joins the rows the last step produced to
/// the walked table, so without an index leading with the join column every
/// step scans the table. Walking a 111-row subtree of 200,000 groups took
/// 26.8 ms with a hash join scanning the table on each of three steps, and
/// 0.120 ms with an index on the parent column. A join column that is a
/// single-column foreign key is left to `unindexed_foreign_key`, so it is
/// reported once. The rule reads views, materialized views, policies, SQL
/// and PL/pgSQL function bodies, judging a body under the function's own
/// `search_path`, and, as a query rule, statements.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UnindexedRecursiveJoin::default().into();
/// let walk = "CREATE VIEW below AS WITH RECURSIVE r(id) AS (SELECT 1
///     UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r;";
/// let scanned = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT); {walk}"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&scanned).is_err());
/// let indexed = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT);
///      CREATE INDEX groups_parent ON groups (parent_id); {walk}"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&indexed).is_ok());
/// ```
pub struct UnindexedRecursiveJoin<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnindexedRecursiveJoin<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnindexedRecursiveJoin<DB>> for GenericConstrainer<DB> {
    fn from(rule: UnindexedRecursiveJoin<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(UnindexedRecursiveJoin::default()));
        constrainer
    }
}

impl<DB> Rule for UnindexedRecursiveJoin<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UnindexedRecursiveJoin),
            group: LintGroup::Perf,
            rationale: "Each step of a recursive walk joins the rows found so far to the walked table, so without an index leading with the join column every step scans the table, and a 111-row subtree of 200,000 groups took 26.8 ms instead of 0.120 ms.",
            source: Some(
                "https://www.postgresql.org/docs/18/queries-with.html#QUERIES-WITH-RECURSIVE",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT);\n\
CREATE VIEW below_one AS WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r;",
                good: "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT);\n\
CREATE INDEX groups_parent ON groups (parent_id);\n\
CREATE VIEW below_one AS WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for UnindexedRecursiveJoin<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&UnindexedJoins, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for UnindexedRecursiveJoin<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&UnindexedJoins, database, statement, reporter)
    }
}
