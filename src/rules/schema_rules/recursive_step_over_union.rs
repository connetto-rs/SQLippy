//! Submodule providing the `RecursiveStepOverUnion` rule.

use sql_traits::{errors::LookupError, traits::DatabaseLike};
use sqlparser::ast::{
    SetExpr, SetOperator, SetQuantifier, Statement, TableFactor, TableWithJoins, Visit,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::recursive_items,
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Whether a set expression contains duplicate-eliminating unions in its derived relations or arms.
fn union_body(body: &SetExpr) -> bool {
    match body {
        SetExpr::SetOperation {
            op,
            set_quantifier,
            left,
            right,
        } => {
            (*op == SetOperator::Union
                && matches!(
                    set_quantifier,
                    SetQuantifier::None | SetQuantifier::Distinct
                ))
                || union_body(left)
                || union_body(right)
        }
        SetExpr::Query(query) => union_body(&query.body),
        SetExpr::Select(select) => select.from.iter().any(union_from),
        _ => false,
    }
}

/// Whether a joined relation contains a derived duplicate-eliminating union.
fn union_from(from: &TableWithJoins) -> bool {
    union_factor(&from.relation) || from.joins.iter().any(|join| union_factor(&join.relation))
}

/// Whether a relation is or contains a derived duplicate-eliminating union.
fn union_factor(factor: &TableFactor) -> bool {
    match factor {
        TableFactor::Derived { subquery, .. } => union_body(&subquery.body),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => union_from(table_with_joins),
        _ => false,
    }
}

/// Finds recursive items joining duplicate-eliminating derived relations.
struct UnionSteps(Engine);

impl ExpressionFinder for UnionSteps {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        _database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let mut found = Vec::new();
        recursive_items(node, |item, recursive| {
            if recursive.term.from.iter().any(union_from) {
                found.push((format!("the recursive `WITH` item '{}' joining a duplicate-eliminating derived `UNION`", item.alias.name), item.to_string()));
            }
            Ok(())
        })?;
        Ok(found)
    }

    fn problem(&self) -> &'static str {
        match self.0 {
            Engine::PostgreSql => {
                "which can repeat duplicate elimination over the edge inputs at each step"
            }
            Engine::Sqlite => "which requires duplicate elimination over the edge inputs",
        }
    }

    fn resolution(&self) -> &'static str {
        match self.0 {
            Engine::PostgreSql => {
                "Use `UNION ALL` when duplicate edges do not change the result, allowing a flattenable union to use parameterized index scans on each arm."
            }
            Engine::Sqlite => {
                "Use `UNION ALL` when duplicate edges do not change the result to avoid duplicate elimination in the edge inputs."
            }
        }
    }
}

/// Reports recursive steps joining a derived `UNION` that eliminates duplicates.
///
/// Views and non-recursive common table expressions are not followed.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
/// let constrainer: GenericConstrainer<ParserDB> = RecursiveStepOverUnion::default().into();
/// let schema = "CREATE TABLE first_edges (parent_id INT, child_id INT);
/// CREATE TABLE second_edges (parent_id INT, child_id INT);
/// CREATE VIEW reachable_view AS WITH RECURSIVE reachable(id) AS (SELECT 1 UNION
/// SELECT edge.child_id FROM reachable JOIN (SELECT * FROM first_edges UNION SELECT * FROM second_edges) edge
/// ON edge.parent_id = reachable.id) SELECT id FROM reachable;";
/// let bad = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&bad).is_err());
/// let good = ParserDB::parse::<PostgreSqlDialect>(&schema.replace("first_edges UNION", "first_edges UNION ALL")).unwrap();
/// assert!(constrainer.validate_schema(&good).is_ok());
/// ```
pub struct RecursiveStepOverUnion<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RecursiveStepOverUnion<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RecursiveStepOverUnion<DB>> for GenericConstrainer<DB> {
    fn from(rule: RecursiveStepOverUnion<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(RecursiveStepOverUnion::default()));
        constrainer
    }
}

impl<DB> Rule for RecursiveStepOverUnion<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RecursiveStepOverUnion),
            group: LintGroup::Perf,
            rationale: "Duplicate elimination in a derived edge union adds work that UNION ALL avoids when duplicate edges do not change the result.",
            source: Some("https://www.postgresql.org/docs/17/queries-union.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE first_edges (parent_id INT, child_id INT); CREATE TABLE second_edges (parent_id INT, child_id INT); CREATE VIEW reachable_view AS WITH RECURSIVE reachable(id) AS (SELECT 1 UNION SELECT edge.child_id FROM reachable JOIN (SELECT * FROM first_edges UNION SELECT * FROM second_edges) edge ON edge.parent_id = reachable.id) SELECT id FROM reachable;",
                good: "CREATE TABLE first_edges (parent_id INT, child_id INT); CREATE TABLE second_edges (parent_id INT, child_id INT); CREATE VIEW reachable_view AS WITH RECURSIVE reachable(id) AS (SELECT 1 UNION SELECT edge.child_id FROM reachable JOIN (SELECT * FROM first_edges UNION ALL SELECT * FROM second_edges) edge ON edge.parent_id = reachable.id) SELECT id FROM reachable;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for RecursiveStepOverUnion<DB> {
    type Database = DB;
    fn check_schema(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        check_schema(&UnionSteps(Engine::of(database)), database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for RecursiveStepOverUnion<DB> {
    type Database = DB;
    fn check_statement(
        &self,
        database: &DB,
        statement: &Statement,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        check_statement(
            &UnionSteps(Engine::of(database)),
            database,
            statement,
            reporter,
        )
    }
}
