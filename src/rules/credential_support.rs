//! Whether a policy expression can be true for a caller holding no
//! credential, judged conservatively with every declared credential `NULL`.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::FunctionKind,
    traits::{DatabaseLike, FunctionLike, PolicyLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr,
    InTarget, JoinConstraint, JoinOperator, Query, Select, SelectItem, SetExpr, UnaryOperator,
    Visit, Visitor,
};

use crate::deployment::Deployment;

/// Judges the expressions of one policy against the declared credentials.
pub(crate) struct CredentialJudge<'a, DB: DatabaseLike> {
    pub(crate) database: &'a DB,
    pub(crate) policy: &'a DB::Policy,
    pub(crate) deployment: &'a Deployment,
}

impl<DB: DatabaseLike> CredentialJudge<'_, DB> {
    /// Whether the expression is `NULL` when every credential is `NULL`.
    pub(crate) fn is_null(&self, expression: &Expr) -> Result<bool, LookupError> {
        if self.deployment.is_credential(expression) {
            return Ok(true);
        }
        Ok(match expression {
            Expr::Nested(inner)
            | Expr::Cast { expr: inner, .. }
            | Expr::UnaryOp {
                op: UnaryOperator::Minus | UnaryOperator::Plus | UnaryOperator::Not,
                expr: inner,
            } => self.is_null(inner)?,
            Expr::BinaryOp { left, op, right } => {
                is_strict_operator(op) && (self.is_null(left)? || self.is_null(right)?)
            }
            Expr::Like { expr, pattern, .. }
            | Expr::ILike { expr, pattern, .. }
            | Expr::SimilarTo { expr, pattern, .. } => {
                self.is_null(expr)? || self.is_null(pattern)?
            }
            Expr::AnyOp { right, .. } => self.is_null(right)?,
            Expr::In {
                expr,
                target: InTarget::List(_),
                ..
            } => self.is_null(expr)?,
            Expr::Function(call) => self.call_is_null(call)?,
            Expr::Subquery(query) => match single_select(query) {
                Some(select) if !self.may_yield_row_from_no_input(select)? => {
                    self.filter_requires(select)?
                        || match select.projection.as_slice() {
                            [
                                SelectItem::UnnamedExpr(item)
                                | SelectItem::ExprWithAlias { expr: item, .. },
                            ] => self.is_null(item)?,
                            _ => false,
                        }
                }
                _ => false,
            },
            _ => false,
        })
    }

    /// Whether the expression cannot be true when every credential is
    /// `NULL`.
    pub(crate) fn requires(&self, expression: &Expr) -> Result<bool, LookupError> {
        if self.is_null(expression)? {
            return Ok(true);
        }
        Ok(match expression {
            Expr::Nested(inner) => self.requires(inner)?,
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => self.requires(left)? || self.requires(right)?,
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
            } => self.requires(left)? && self.requires(right)?,
            Expr::IsNotNull(inner) => self.is_null(inner)?,
            Expr::AnyOp { left, .. } => self.is_null(left)?,
            Expr::In {
                target: InTarget::List(list),
                ..
            } => self.all_null(list)?,
            Expr::Exists {
                subquery,
                negated: false,
            } => self.subquery_requires(subquery)?,
            Expr::In {
                expr,
                target: InTarget::Subquery(subquery),
                negated: false,
                ..
            } => self.is_null(expr)? || self.subquery_requires(subquery)?,
            _ => false,
        })
    }

    /// The sub-expression that lets a caller without a credential through:
    /// the first `OR` operand that does not require one, followed down.
    pub(crate) fn witness<'e>(&self, expression: &'e Expr) -> Result<&'e Expr, LookupError> {
        match expression {
            Expr::Nested(inner) => self.witness(inner),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
            } => {
                if self.requires(left)? {
                    self.witness(right)
                } else {
                    self.witness(left)
                }
            }
            _ => Ok(expression),
        }
    }

    fn all_null(&self, expressions: &[Expr]) -> Result<bool, LookupError> {
        for expression in expressions {
            if !self.is_null(expression)? {
                return Ok(false);
            }
        }
        Ok(!expressions.is_empty())
    }

    /// Whether every function the call may reach returns `NULL` for a
    /// positional argument that is `NULL`.
    fn call_is_null(&self, call: &Function) -> Result<bool, LookupError> {
        let FunctionArguments::List(list) = &call.args else {
            return Ok(false);
        };
        let mut null_positions = Vec::new();
        for (index, argument) in list.args.iter().enumerate() {
            if let FunctionArg::Unnamed(FunctionArgExpr::Expr(argument)) = argument
                && self.is_null(argument)?
            {
                null_positions.push(index);
            }
        }
        if null_positions.is_empty() {
            return Ok(false);
        }
        let mut reached_any = false;
        for function in self.policy.functions_reached_by(call, self.database)? {
            reached_any = true;
            if !null_positions
                .iter()
                .any(|&index| function.returns_null_on_null_argument(self.database, index))
            {
                return Ok(false);
            }
        }
        Ok(reached_any)
    }

    /// Whether a subquery returns no row when every credential is `NULL`.
    fn subquery_requires(&self, query: &Query) -> Result<bool, LookupError> {
        match single_select(query) {
            Some(select) => {
                Ok(!self.may_yield_row_from_no_input(select)? && self.filter_requires(select)?)
            }
            None => Ok(false),
        }
    }

    /// Whether the `WHERE` or the `ON` of an inner join requires a
    /// credential, so no row survives.
    fn filter_requires(&self, select: &Select) -> Result<bool, LookupError> {
        if let Some(selection) = &select.selection
            && self.requires(selection)?
        {
            return Ok(true);
        }
        for table in &select.from {
            for join in &table.joins {
                if let JoinOperator::Join(JoinConstraint::On(condition))
                | JoinOperator::Inner(JoinConstraint::On(condition)) = &join.join_operator
                    && self.requires(condition)?
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether the query can return a row though its filter removes every
    /// input row, which an aggregate without `GROUP BY` does.
    ///
    /// A projection call without `OVER` counts as an aggregate when a
    /// function it may reach is one, or when it reaches no known function,
    /// unless the call is a declared credential.
    fn may_yield_row_from_no_input(&self, select: &Select) -> Result<bool, LookupError> {
        let grouped = !matches!(
            &select.group_by,
            GroupByExpr::Expressions(expressions, _) if expressions.is_empty()
        );
        if grouped {
            return Ok(false);
        }
        let mut finder = AggregateCall {
            judge: self,
            depth: 0,
        };
        for item in &select.projection {
            let (SelectItem::UnnamedExpr(expression)
            | SelectItem::ExprWithAlias {
                expr: expression, ..
            }) = item
            else {
                continue;
            };
            if let ControlFlow::Break(outcome) = expression.visit(&mut finder) {
                return outcome.map(|()| true);
            }
        }
        Ok(false)
    }
}

/// Finds an aggregate call in a projection, outside nested subqueries.
struct AggregateCall<'j, 'a, DB: DatabaseLike> {
    judge: &'j CredentialJudge<'a, DB>,
    depth: usize,
}

impl<DB: DatabaseLike> Visitor for AggregateCall<'_, '_, DB> {
    type Break = Result<(), LookupError>;

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        let Expr::Function(call) = expression else {
            return ControlFlow::Continue(());
        };
        if self.depth != 0 || call.over.is_some() || self.judge.deployment.is_credential(expression)
        {
            return ControlFlow::Continue(());
        }
        match self.judge.may_aggregate(call) {
            Ok(false) => ControlFlow::Continue(()),
            outcome => ControlFlow::Break(outcome.map(drop)),
        }
    }
}

impl<DB: DatabaseLike> CredentialJudge<'_, DB> {
    /// Whether a call may run an aggregate: a function it reaches is one, or
    /// it reaches no known function.
    fn may_aggregate(&self, call: &Function) -> Result<bool, LookupError> {
        let mut known = false;
        for function in self.policy.functions_reached_by(call, self.database)? {
            known = true;
            if function.kind(self.database)? == FunctionKind::Aggregate {
                return Ok(true);
            }
        }
        Ok(!known)
    }
}

/// The query's single `SELECT`, when it has no set operation.
fn single_select(query: &Query) -> Option<&Select> {
    match query.body.as_ref() {
        SetExpr::Select(select) => Some(select),
        _ => None,
    }
}

/// Operators that yield `NULL` when an operand is `NULL`.
fn is_strict_operator(operator: &BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Lt
            | BinaryOperator::LtEq
            | BinaryOperator::Gt
            | BinaryOperator::GtEq
            | BinaryOperator::Plus
            | BinaryOperator::Minus
            | BinaryOperator::Multiply
            | BinaryOperator::Divide
            | BinaryOperator::Modulo
            | BinaryOperator::StringConcat
            | BinaryOperator::PGRegexMatch
            | BinaryOperator::PGRegexIMatch
            | BinaryOperator::PGRegexNotMatch
            | BinaryOperator::PGRegexNotIMatch
            | BinaryOperator::Arrow
            | BinaryOperator::LongArrow
    )
}
