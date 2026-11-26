//! Walks the syntax tree through one trait object, so the traversal compiles
//! once per break type instead of once per visitor.

use std::{convert::Infallible, ops::ControlFlow};

use sql_traits::errors::LookupError;

use sqlparser::ast::{
    Expr, GroupByExpr, Ident, ObjectName, OrderBy, OrderByExpr, Query, Select, Statement,
    TableFactor, ValueWithSpan, Visit, Visitor, visit_expressions_mut,
};

use crate::rules::{policy_support::unnested, trigger_support::stored};

/// Walks `node` with `visitor`.
#[expect(
    clippy::disallowed_methods,
    reason = "the one place the traversal is instantiated, for the trait object"
)]
pub(crate) fn walk<N, B>(node: &N, visitor: &mut dyn Visitor<Break = B>) -> ControlFlow<B>
where
    N: Visit + ?Sized,
{
    node.visit(&mut Dynamic(visitor))
}

/// Whether an expression holds a sublink.
pub(crate) fn holds_subquery(expression: &Expr) -> bool {
    struct Sublink;
    impl Visitor for Sublink {
        type Break = ();
        fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
            ControlFlow::Break(())
        }
    }
    walk(expression, &mut Sublink).is_break()
}

/// `expression` with every identifier spelled as the quoted name it stores
/// and without enclosing parentheses, so two spellings of one value compare
/// equal.
pub(crate) fn canonical(expression: &Expr) -> String {
    let mut expression = unnested(expression).clone();
    let ControlFlow::Continue(()) = visit_expressions_mut(&mut expression, |node| {
        let idents = match node {
            Expr::Identifier(ident) => std::slice::from_mut(ident),
            Expr::CompoundIdentifier(parts) => parts.as_mut_slice(),
            _ => return ControlFlow::<Infallible>::Continue(()),
        };
        for ident in idents {
            ident.value = stored(ident).into_owned();
            ident.quote_style = Some('"');
        }
        ControlFlow::Continue(())
    });
    expression.to_string()
}

/// Forwards every hook to a borrowed visitor, so each `Visitor` method needs
/// an override here or the inner visitor never sees that hook.
struct Dynamic<'v, B>(&'v mut dyn Visitor<Break = B>);

impl<B> Visitor for Dynamic<'_, B> {
    type Break = B;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<B> {
        self.0.pre_visit_query(query)
    }

    fn post_visit_query(&mut self, query: &Query) -> ControlFlow<B> {
        self.0.post_visit_query(query)
    }

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<B> {
        self.0.pre_visit_select(select)
    }

    fn post_visit_select(&mut self, select: &Select) -> ControlFlow<B> {
        self.0.post_visit_select(select)
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<B> {
        self.0.pre_visit_relation(relation)
    }

    fn post_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<B> {
        self.0.post_visit_relation(relation)
    }

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<B> {
        self.0.pre_visit_table_factor(table_factor)
    }

    fn post_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<B> {
        self.0.post_visit_table_factor(table_factor)
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<B> {
        self.0.pre_visit_expr(expr)
    }

    fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<B> {
        self.0.post_visit_expr(expr)
    }

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<B> {
        self.0.pre_visit_statement(statement)
    }

    fn post_visit_statement(&mut self, statement: &Statement) -> ControlFlow<B> {
        self.0.post_visit_statement(statement)
    }

    fn pre_visit_value(&mut self, value: &ValueWithSpan) -> ControlFlow<B> {
        self.0.pre_visit_value(value)
    }

    fn post_visit_value(&mut self, value: &ValueWithSpan) -> ControlFlow<B> {
        self.0.post_visit_value(value)
    }

    fn pre_visit_ident(&mut self, ident: &Ident) -> ControlFlow<B> {
        self.0.pre_visit_ident(ident)
    }

    fn post_visit_ident(&mut self, ident: &Ident) -> ControlFlow<B> {
        self.0.post_visit_ident(ident)
    }

    fn pre_visit_order_by(&mut self, order_by: &OrderBy) -> ControlFlow<B> {
        self.0.pre_visit_order_by(order_by)
    }

    fn post_visit_order_by(&mut self, order_by: &OrderBy) -> ControlFlow<B> {
        self.0.post_visit_order_by(order_by)
    }

    fn pre_visit_order_by_expr(&mut self, order_by_expr: &OrderByExpr) -> ControlFlow<B> {
        self.0.pre_visit_order_by_expr(order_by_expr)
    }

    fn post_visit_order_by_expr(&mut self, order_by_expr: &OrderByExpr) -> ControlFlow<B> {
        self.0.post_visit_order_by_expr(order_by_expr)
    }

    fn pre_visit_group_by(&mut self, group_by: &GroupByExpr) -> ControlFlow<B> {
        self.0.pre_visit_group_by(group_by)
    }

    fn post_visit_group_by(&mut self, group_by: &GroupByExpr) -> ControlFlow<B> {
        self.0.post_visit_group_by(group_by)
    }
}

/// Continues on `Ok(false)` and stops on `Ok(true)` or on an error, which it
/// carries.
pub(crate) fn stop_on(result: Result<bool, LookupError>) -> ControlFlow<Option<LookupError>> {
    result.map_or_else(
        |error| ControlFlow::Break(Some(error)),
        |stop| {
            if stop {
                ControlFlow::Break(None)
            } else {
                ControlFlow::Continue(())
            }
        },
    )
}

/// Whether a walk `stop_on` drove stopped on `Ok(true)`.
pub(crate) fn stopped(flow: ControlFlow<Option<LookupError>>) -> Result<bool, LookupError> {
    flow.break_value()
        .map_or(Ok(false), |error| error.map_or(Ok(true), Err))
}
