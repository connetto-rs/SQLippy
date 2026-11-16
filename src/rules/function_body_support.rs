//! Traversal and parameter references in function bodies.

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, FunctionLike},
};
use sqlparser::ast::{Expr, Statement};

use super::expression_site_support::body_statements;

/// A parsed function body node.
pub(crate) enum BodyNode<'body> {
    /// A SQL or embedded procedural statement.
    Statement(&'body Statement),
    /// A SQL return expression.
    Expression(&'body Expr),
}

/// Visits each parsed statement or expression of a function body.
pub(crate) fn function_body<DB: DatabaseLike, Error: From<LookupError>>(
    database: &DB,
    function: &DB::Function,
    mut visit: impl FnMut(BodyNode<'_>) -> Result<(), Error>,
) -> Result<(), Error> {
    for statement in &body_statements(function) {
        visit(BodyNode::Statement(statement))?;
    }
    if let Some(statements) = function.atomic_statements(database)? {
        for statement in statements.iter() {
            visit(BodyNode::Statement(statement))?;
        }
    }
    if let Some(expression) = function.body_expression(database)? {
        visit(BodyNode::Expression(expression.as_ref()))?;
    }
    Ok(())
}
