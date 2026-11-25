//! The `WHERE`, `ON` and select-list expressions of the queries and
//! statements within a node.

use std::ops::ControlFlow;

use sql_traits::errors::LookupError;
use sqlparser::ast::{
    Expr, FromTable, JoinConstraint, Select, SelectItem, Statement, TableFactor, TableWithJoins,
    UpdateTableFromKind, Visit, Visitor,
};

use crate::rules::{cte_support::join_constraint, walk_support::walk};

/// Where a query or statement reads an expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Clause {
    /// The `WHERE` of a `SELECT`, an `UPDATE` or a `DELETE`.
    Where,
    /// The `ON` of a join.
    On,
    /// An expression of a select list.
    Selected,
}

/// Calls `visit` with every `WHERE`, `ON` and select-list expression of the
/// queries and statements within `node`, subqueries included, each `SELECT`
/// in the order `WHERE`, `ON`, select list.
///
/// # Errors
///
/// Returns the first error `visit` returns.
pub(crate) fn visit_clauses<N: Visit + ?Sized>(
    node: &N,
    visit: impl FnMut(Clause, &Expr) -> Result<(), LookupError>,
) -> Result<(), LookupError> {
    match walk(node, &mut Clauses { visit }) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(error) => Err(error),
    }
}

/// Calls `visit` with the clauses it walks.
struct Clauses<F> {
    visit: F,
}

impl<F: FnMut(Clause, &Expr) -> Result<(), LookupError>> Clauses<F> {
    /// Visits `selection` as a `WHERE` and the `ON` clauses of `from`.
    fn filtered<'f>(
        &mut self,
        selection: Option<&Expr>,
        from: impl IntoIterator<Item = &'f TableWithJoins>,
    ) -> Result<(), LookupError> {
        if let Some(selection) = selection {
            (self.visit)(Clause::Where, selection)?;
        }
        for join in from.into_iter().flat_map(|item| &item.joins) {
            if let Some(JoinConstraint::On(condition)) = join_constraint(&join.join_operator) {
                (self.visit)(Clause::On, condition)?;
            }
        }
        Ok(())
    }
}

/// Continues a walk on `Ok`, and breaks it with the error otherwise.
fn flow(result: Result<(), LookupError>) -> ControlFlow<LookupError> {
    match result {
        Ok(()) => ControlFlow::Continue(()),
        Err(error) => ControlFlow::Break(error),
    }
}

impl<F: FnMut(Clause, &Expr) -> Result<(), LookupError>> Visitor for Clauses<F> {
    type Break = LookupError;

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        flow(
            self.filtered(select.selection.as_ref(), &select.from)
                .and_then(|()| {
                    select.projection.iter().try_for_each(|item| match item {
                        SelectItem::UnnamedExpr(expression)
                        | SelectItem::ExprWithAlias {
                            expr: expression, ..
                        } => (self.visit)(Clause::Selected, expression),
                        _ => Ok(()),
                    })
                }),
        )
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        match factor {
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => flow(self.filtered(None, [table_with_joins.as_ref()])),
            _ => ControlFlow::Continue(()),
        }
    }

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        match statement {
            Statement::Update(update) => {
                let from = match &update.from {
                    Some(
                        UpdateTableFromKind::BeforeSet(from) | UpdateTableFromKind::AfterSet(from),
                    ) => from.as_slice(),
                    None => &[],
                };
                flow(self.filtered(
                    update.selection.as_ref(),
                    std::iter::once(&update.table).chain(from),
                ))
            }
            Statement::Delete(delete) => {
                let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) =
                    &delete.from;
                flow(self.filtered(
                    delete.selection.as_ref(),
                    from.iter().chain(delete.using.iter().flatten()),
                ))
            }
            _ => ControlFlow::Continue(()),
        }
    }
}
