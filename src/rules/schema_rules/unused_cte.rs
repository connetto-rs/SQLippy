//! Submodule providing the `UnusedCte` rule.

use std::ops::ControlFlow;

use sql_traits::{errors::LookupError, traits::DatabaseLike};
use sqlparser::ast::{ObjectName, Query, Statement, Visit, Visitor};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::{ItemBinding, WithScopes, modifies_data, table_commands},
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Finds the `WITH` items nothing outside their own body reads.
struct UnusedItems;

/// Collects the unread items of every `WITH` clause a node holds, reported
/// once the walk leaves the query carrying the clause.
#[derive(Default)]
struct Unread {
    scopes: WithScopes,
    read: Vec<ItemBinding>,
    found: Vec<(String, String)>,
}

impl Visitor for Unread {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        self.scopes.enter(query);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        let (scopes, read) = (&self.scopes, &mut self.read);
        table_commands(&query.body, &mut |name| {
            read.extend(scopes.unqualified_binding(name));
        });
        if let Some(with) = &query.with {
            for (position, item) in with.cte_tables.iter().enumerate() {
                if self.read.iter().any(|read| {
                    std::ptr::eq(read.owner, query) && read.item == position && !read.in_own_body
                }) {
                    continue;
                }
                let described = if modifies_data(item) {
                    format!(
                        "the data-modifying `WITH` item '{}' that nothing reads, which PostgreSQL still runs",
                        item.alias.name
                    )
                } else {
                    format!(
                        "the `WITH` item '{}' that nothing reads, which PostgreSQL never evaluates",
                        item.alias.name
                    )
                };
                self.found.push((described, item.to_string()));
            }
        }
        self.scopes.leave(query);
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<()> {
        self.read.extend(self.scopes.binding(relation));
        ControlFlow::Continue(())
    }
}

impl ExpressionFinder for UnusedItems {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        _database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let mut unread = Unread::default();
        let _ = walk(node, &mut unread);
        Ok(unread.found)
    }

    fn problem(&self) -> &'static str {
        "so the statement does not do what its text suggests"
    }

    fn resolution(&self) -> &'static str {
        "Remove the item, or read it where the statement is meant to use it."
    }
}

/// Struct defining a rule that reports a `WITH` item no part of its
/// statement reads.
///
/// PostgreSQL never evaluates an unread `SELECT` item, so its text runs
/// nothing, and always runs an unread `INSERT`, `UPDATE`, `DELETE` or `MERGE`
/// item to completion, so its write happens although nothing uses it. A
/// recursive item's reference to itself does not count. The rule reads
/// views, materialized views, policies, SQL and PL/pgSQL function bodies
/// and, as a query rule, statements.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UnusedCte::default().into();
/// let unread = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE VIEW v AS WITH u AS (SELECT 1 AS x) SELECT 2 AS x;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&unread).is_err());
/// let read = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE VIEW v AS WITH u AS (SELECT 1 AS x) SELECT x FROM u;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&read).is_ok());
/// ```
pub struct UnusedCte<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnusedCte<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnusedCte<DB>> for GenericConstrainer<DB> {
    fn from(rule: UnusedCte<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(UnusedCte::default()));
        constrainer
    }
}

impl<DB> Rule for UnusedCte<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UnusedCte),
            group: LintGroup::Suspicious,
            rationale: "PostgreSQL never evaluates a WITH item nothing reads unless it modifies data, and then always runs it, so the item either does nothing or writes where the text reads as dead code.",
            source: Some("https://www.postgresql.org/docs/18/queries-with.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE audit (n INT);\n\
WITH logged AS (INSERT INTO audit VALUES (4) RETURNING n) SELECT 1;",
                good: "CREATE TABLE audit (n INT);\n\
WITH logged AS (INSERT INTO audit VALUES (4) RETURNING n) SELECT count(*) FROM logged;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for UnusedCte<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&UnusedItems, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for UnusedCte<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&UnusedItems, database, statement, reporter)
    }
}
