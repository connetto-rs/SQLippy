//! Submodule providing the `CteShadowsRelation` rule.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{IdentifierCase, TargetName},
    traits::{DatabaseLike, FunctionLike, Relation, TableLike, ViewLike},
};
use sqlparser::ast::{Ident, Query, Statement, Visit, Visitor};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Finds the `WITH` items named like a relation the search path reaches.
struct ShadowingItems;

/// The name and rendering of every `WITH` item a node holds.
#[derive(Default)]
struct Items(Vec<(Ident, String)>);

impl Visitor for Items {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        if let Some(with) = &query.with {
            self.0.extend(
                with.cte_tables
                    .iter()
                    .map(|item| (item.alias.name.clone(), item.to_string())),
            );
        }
        ControlFlow::Continue(())
    }
}

/// The items of `node` whose name `path`, or the database's search path when
/// `None`, resolves to a stored relation.
fn shadowing<DB: DatabaseLike, V: Visit + ?Sized>(
    database: &DB,
    node: &V,
    path: Option<&[(Cow<'_, str>, bool)]>,
) -> Result<Vec<(String, String)>, LookupError> {
    let mut items = Items::default();
    let _ = walk(node, &mut items);
    let mut found = Vec::new();
    for (name, item) in items.0 {
        let target = TargetName::new(&name.value, name.quote_style.is_some());
        let relation = match path {
            Some(path) => {
                database.resolve_target_relation_on_path(target, path, IdentifierCase::AsWritten)?
            }
            None => database.resolve_target_relation(target, IdentifierCase::AsWritten)?,
        };
        let (kind, relation) = match relation {
            Some(Relation::Table(table)) => ("table", table.table_name()),
            Some(Relation::ForeignTable(table)) => ("foreign table", table.table_name()),
            Some(Relation::View(view)) => ("view", view.view_name()),
            Some(Relation::MaterializedView(view)) => ("materialized view", view.view_name()),
            Some(Relation::Sequence(_)) | None => continue,
        };
        found.push((
            format!("the `WITH` item '{name}', named like the {kind} '{relation}'"),
            item,
        ));
    }
    Ok(found)
}

impl ExpressionFinder for ShadowingItems {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        shadowing(database, node, None)
    }

    fn find_in_body<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        function: &DB::Function,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        shadowing(database, node, function.search_path(database)?.as_deref())
    }

    fn problem(&self) -> &'static str {
        "so every unqualified read of that name where the item is visible reads the item instead"
    }

    fn resolution(&self) -> &'static str {
        "Rename the item, or read the relation where the statement means to read it."
    }
}

/// Struct defining a rule that reports a `WITH` item named like a table or
/// view the search path reaches.
///
/// PostgreSQL resolves an unqualified name to a visible `WITH` item before
/// any stored relation, so text that reads like a read of the table reads the
/// item. In a policy that turns a membership check into a grant to every
/// caller. A function body is judged under the function's own
/// `search_path`, and a schema-qualified read never binds an item. The rule
/// reads views, materialized views, policies, SQL and PL/pgSQL function
/// bodies and, as a query rule, statements.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = CteShadowsRelation::default().into();
/// let schema = "CREATE TABLE grants (group_id INT, principal TEXT);";
/// let shadowing = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS WITH grants AS (SELECT 1 AS group_id) SELECT group_id FROM grants;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&shadowing).is_err());
/// let renamed = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS WITH granted AS (SELECT 1 AS group_id) SELECT group_id FROM granted;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&renamed).is_ok());
/// ```
pub struct CteShadowsRelation<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for CteShadowsRelation<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<CteShadowsRelation<DB>> for GenericConstrainer<DB> {
    fn from(rule: CteShadowsRelation<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(CteShadowsRelation::default()));
        constrainer
    }
}

impl<DB> Rule for CteShadowsRelation<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(CteShadowsRelation),
            group: LintGroup::Suspicious,
            rationale: "An unqualified name resolves to a visible WITH item before any stored relation, so a WITH item named like a table makes every unqualified read of that name where the item is visible read the item.",
            source: Some("https://www.postgresql.org/docs/18/queries-with.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE grants (group_id INT, principal TEXT);\n\
WITH grants AS (SELECT 1 AS group_id, 'x' AS principal)\n\
SELECT group_id FROM grants WHERE principal = 'x';",
                good: "CREATE TABLE grants (group_id INT, principal TEXT);\n\
WITH granted AS (SELECT 1 AS group_id, 'x' AS principal)\n\
SELECT group_id FROM granted WHERE principal = 'x';",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for CteShadowsRelation<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&ShadowingItems, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for CteShadowsRelation<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&ShadowingItems, database, statement, reporter)
    }
}
