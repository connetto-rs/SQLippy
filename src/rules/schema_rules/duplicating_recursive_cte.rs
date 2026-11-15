//! Submodule providing the `DuplicatingRecursiveCte` rule.

use std::borrow::Cow;

use sql_traits::{
    errors::LookupError,
    structs::TargetName,
    traits::{ColumnLike, DatabaseLike, FunctionLike, TableLike},
};
use sqlparser::ast::{
    Ident, ObjectNamePart, SelectItem, SelectItemQualifiedWildcardKind, Statement, Visit,
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::{same_name, stored_column, stored_table, walks},
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        key_support::equality_keys,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Finds the `UNION ALL` walks that yield a row once per path reaching it.
struct DuplicatingItems;

/// The duplicating walks of `node`, resolving walked relations on `path`, or
/// on the database's search path when `None`.
fn duplicating<DB: DatabaseLike, V: Visit + ?Sized>(
    database: &DB,
    node: &V,
    path: Option<&[(Cow<'_, str>, bool)]>,
) -> Result<Vec<(String, String)>, LookupError> {
    let mut found = Vec::new();
    walks(node, |item, recursive, name, exposed, alias| {
        if !recursive.keeps_duplicates {
            return Ok(());
        }
        let Some(table) = stored_table(database, name, path)? else {
            return Ok(());
        };
        let aliases = alias.map_or(&[][..], |alias| alias.columns.as_slice());
        let keys = equality_keys(database, table)?;
        let keyed = |column: &Ident| -> Result<Option<bool>, LookupError> {
            Ok(stored_column(database, table, alias, column)?
                .map(|column| keys.iter().any(|key| key.as_slice() == [column])))
        };
        for column in recursive.joined_columns(exposed) {
            if keyed(column)? == Some(true) {
                return Ok(());
            }
        }
        let mut projected = Vec::new();
        for output in &recursive.term.projection {
            let expression = match output {
                SelectItem::UnnamedExpr(expression)
                | SelectItem::ExprWithAlias {
                    expr: expression, ..
                } => Some(expression),
                SelectItem::QualifiedWildcard(
                    SelectItemQualifiedWildcardKind::ObjectName(name),
                    _,
                ) if matches!(name.0.as_slice(), [ObjectNamePart::Identifier(written)] if same_name(written, exposed)) => {
                    None
                }
                _ => continue,
            };
            if let Some(expression) = expression {
                let Some(column) = recursive.walked_column(exposed, expression) else {
                    continue;
                };
                match keyed(column)? {
                    Some(true) => return Ok(()),
                    Some(false) => projected.push(format!("`{expression}`")),
                    None => {}
                }
            } else {
                for (position, column) in table.columns(database)?.enumerate() {
                    if keys.iter().any(|key| key.as_slice() == [column]) {
                        return Ok(());
                    }
                    let name = aliases.get(position).map_or_else(
                        || TargetName::new(column.column_name(), column.column_name_is_quoted()),
                        |alias| {
                            TargetName::new(&alias.name.value, alias.name.quote_style.is_some())
                        },
                    );
                    projected.push(format!("`{exposed}.{name}`"));
                }
            }
        }
        if !projected.is_empty() {
            found.push((
                format!(
                    "the recursive `WITH` item '{}' combined with `UNION ALL` and projecting {} of '{}', which no single-column key of it makes unique",
                    item.alias.name,
                    projected.join(", "),
                    table.table_name()
                ),
                item.to_string(),
            ));
        }
        Ok(())
    })?;
    Ok(found)
}

impl ExpressionFinder for DuplicatingItems {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        duplicating(database, node, None)
    }

    fn find_in_body<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        function: &DB::Function,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        duplicating(database, node, function.search_path(database)?.as_deref())
    }

    fn problem(&self) -> &'static str {
        "so a row reachable by several paths is produced once per path, and the walk grows with the number of paths instead of the number of rows"
    }

    fn resolution(&self) -> &'static str {
        "Combine the terms with `UNION` and project only the walked key columns, so each reached row is produced once."
    }
}

/// Struct defining a rule that reports a `WITH RECURSIVE` item whose
/// `UNION ALL` walk produces a row once for every path reaching it.
///
/// Under `UNION ALL` each step joins every row the last step produced, so a
/// row of the walked relation reachable along two paths comes out twice, and
/// its descendants twice each. A walk projecting a column some single-column
/// key of the walked relation makes unique, such as a child's primary key in
/// a tree where every row has one parent, reaches each row once, and so does
/// a walk that equates such a key with the working table, which matches at
/// most one row of the walked relation per working row. A walk over an edge
/// table where a child has several parents does not, and a layered graph of
/// 20 levels with two parents per node yields 2,097,151 rows for 41 nodes.
/// The rule reads views, materialized views, policies, SQL and PL/pgSQL
/// function bodies, judging a body under the function's own `search_path`,
/// and, as a query rule, statements.
/// Findings require a projected column of a stored table, including columns
/// expanded from its qualified wildcard. Constant-only projections and
/// columns reached through derived tables or views are outside this scope.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DuplicatingRecursiveCte::default().into();
/// let edges = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE edges (child INT, parent INT, PRIMARY KEY (child, parent));
///      CREATE VIEW below AS WITH RECURSIVE r(id) AS (SELECT 0
///        UNION ALL SELECT e.child FROM edges AS e JOIN r ON e.parent = r.id) SELECT id FROM r;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&edges).is_err());
/// let tree = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT);
///      CREATE VIEW below AS WITH RECURSIVE r(id) AS (SELECT 1
///        UNION ALL SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&tree).is_ok());
/// ```
pub struct DuplicatingRecursiveCte<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DuplicatingRecursiveCte<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DuplicatingRecursiveCte<DB>> for GenericConstrainer<DB> {
    fn from(rule: DuplicatingRecursiveCte<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(DuplicatingRecursiveCte::default()));
        constrainer
    }
}

impl<DB> Rule for DuplicatingRecursiveCte<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DuplicatingRecursiveCte),
            group: LintGroup::Perf,
            rationale: "A UNION ALL walk keeps every row each step produces, so a row reachable along several paths, and every row below it, comes out once per path, and over a graph where children have several parents the rows grow with the number of paths rather than the number of rows.",
            source: Some(
                "https://www.postgresql.org/docs/18/queries-with.html#QUERIES-WITH-RECURSIVE",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE dag_edges (child INT, parent INT, PRIMARY KEY (child, parent));\n\
CREATE INDEX dag_edges_parent ON dag_edges (parent);\n\
CREATE VIEW below_root AS WITH RECURSIVE r(id) AS (SELECT 0 UNION ALL SELECT e.child FROM dag_edges AS e JOIN r ON e.parent = r.id) SELECT id FROM r;",
                good: "CREATE TABLE dag_edges (child INT, parent INT, PRIMARY KEY (child, parent));\n\
CREATE INDEX dag_edges_parent ON dag_edges (parent);\n\
CREATE VIEW below_root AS WITH RECURSIVE r(id) AS (SELECT 0 UNION SELECT e.child FROM dag_edges AS e JOIN r ON e.parent = r.id) SELECT id FROM r;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for DuplicatingRecursiveCte<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&DuplicatingItems, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for DuplicatingRecursiveCte<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&DuplicatingItems, database, statement, reporter)
    }
}
