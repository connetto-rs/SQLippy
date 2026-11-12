//! Walks the syntax tree through one trait object, so the traversal compiles
//! once per break type instead of once per visitor.

use std::ops::ControlFlow;

use sqlparser::ast::{
    Expr, GroupByExpr, Ident, ObjectName, OrderBy, OrderByExpr, Query, Select, Statement,
    TableFactor, ValueWithSpan, Visit, Visitor,
};

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
