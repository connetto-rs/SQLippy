//! `NOT IN` over a subquery, shared by the rules reporting it.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, TableLike},
};
use sqlparser::ast::{Expr, InTarget, Query, SelectItem, SetExpr, Visit, Visitor};

use crate::rules::{
    expression_site_support::ExpressionFinder, policy_support::conjuncts, walk_support::walk,
};

/// One `NOT IN` over a subquery.
pub(crate) struct NotIn {
    /// The `NOT IN` expression rendered as SQL.
    pub(crate) expression: String,
    /// The nullable column the subquery returns, as `table.column`.
    pub(crate) nullable: Option<String>,
}

/// The nullable column a `NOT IN` subquery returns, unless its `WHERE`
/// excludes `NULL`.
fn nullable_output<DB: DatabaseLike>(
    database: &DB,
    query: &Query,
) -> Result<Option<String>, LookupError> {
    // Expression evaluator: the output counts as possibly `NULL` only when it
    // is a nullable column that no `WHERE` conjunct tests with `IS NOT NULL`.
    // The evaluator decides whether any output expression can be `NULL`, so
    // computed outputs such as `a_id + 1` and filters such as `a_id > 0` are
    // judged too.
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Ok(None);
    };
    let [SelectItem::UnnamedExpr(output) | SelectItem::ExprWithAlias { expr: output, .. }] =
        select.projection.as_slice()
    else {
        return Ok(None);
    };
    let scope = ColumnScope::from_query(query, database, IdentifierCase::Folded)?;
    let Some(ColumnDefinition::Base { table, column, .. }) =
        scope.resolve_column_definition(output)?
    else {
        return Ok(None);
    };
    let excluded = select.selection.iter().flat_map(conjuncts).any(|filter| {
        matches!(filter, Expr::IsNotNull(tested) if tested.to_string() == output.to_string())
    });
    Ok((!excluded && column.is_nullable(database)?)
        .then(|| format!("{}.{}", table.table_name(), column.column_name())))
}

/// Collects the `NOT IN` subqueries of a node.
struct NotIns<'db, DB: DatabaseLike> {
    database: &'db DB,
    found: Vec<NotIn>,
}

impl<DB: DatabaseLike> Visitor for NotIns<'_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        let Expr::In {
            target: InTarget::Subquery(query),
            negated: true,
            ..
        } = expression
        else {
            return ControlFlow::Continue(());
        };
        nullable_output(self.database, query).map_or_else(ControlFlow::Break, |nullable| {
            self.found.push(NotIn {
                expression: expression.to_string(),
                nullable,
            });
            ControlFlow::Continue(())
        })
    }
}

/// The `NOT IN` subqueries a node holds.
fn not_ins<DB: DatabaseLike, V: Visit + ?Sized>(
    database: &DB,
    node: &V,
) -> Result<Vec<NotIn>, LookupError> {
    let mut found = NotIns {
        database,
        found: Vec::new(),
    };
    walk(node, &mut found).break_value().map_or(Ok(()), Err)?;
    Ok(found.found)
}

/// How one rule describes the `NOT IN` subqueries it reports.
pub(crate) struct NotInCheck {
    /// Describes a `NOT IN` the rule reports, or skips it.
    pub(crate) describe: fn(&NotIn) -> Option<String>,
    /// Why the described `NOT IN` is a problem, continuing its sentence.
    pub(crate) problem: &'static str,
    /// The corrected shape.
    pub(crate) resolution: &'static str,
}

impl ExpressionFinder for NotInCheck {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        Ok(not_ins(database, node)?
            .into_iter()
            .filter_map(|not_in| {
                (self.describe)(&not_in).map(|described| (described, not_in.expression))
            })
            .collect())
    }

    fn problem(&self) -> &'static str {
        self.problem
    }

    fn resolution(&self) -> &'static str {
        self.resolution
    }
}
