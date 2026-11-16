//! Traversal and parameter references in function bodies.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, FunctionLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{Expr, Statement, Value, Visitor};

use super::{expression_site_support::body_statements, walk_support::walk};

/// A parsed function body node.
pub(crate) enum BodyNode<'body> {
    /// A SQL or embedded procedural statement.
    Statement(&'body Statement),
    /// A SQL return expression.
    Expression(&'body Expr),
}

impl BodyNode<'_> {
    /// Walks the node with the rule's visitor.
    pub(crate) fn walk<V: Visitor>(&self, visitor: &mut V) -> ControlFlow<V::Break> {
        match self {
            Self::Statement(statement) => walk(*statement, visitor),
            Self::Expression(expression) => walk(*expression, visitor),
        }
    }
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

/// Resolves a named, qualified or positional function parameter.
pub(crate) fn parameter<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
    expression: &Expr,
) -> Option<usize> {
    let name = match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => {
            return parameter(database, function, inner);
        }
        Expr::Value(value) => {
            let Value::Placeholder(position) = &value.value else {
                return None;
            };
            let position = position
                .strip_prefix('$')?
                .parse::<usize>()
                .ok()?
                .checked_sub(1)?;
            return function
                .argument_names(database)
                .nth(position)
                .map(|_| position);
        }
        Expr::Identifier(name) => name,
        Expr::CompoundIdentifier(names) if names.len() == 2 => {
            let target = function.target_name();
            if normalize_identifier(&names[0].value, names[0].quote_style.is_some())
                != normalize_identifier(target.name(), target.name_is_quoted())
            {
                return None;
            }
            &names[1]
        }
        _ => return None,
    };
    let stored = normalize_identifier(&name.value, name.quote_style.is_some());
    function
        .stored_argument_names(database)
        .position(|argument| argument.is_some_and(|argument| argument == stored))
}
