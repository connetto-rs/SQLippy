//! Whether a policy expression can be true for a caller holding no
//! credential, judged conservatively with every declared credential `NULL`.

use std::{cell::RefCell, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::IdentifierCase,
    traits::{DatabaseLike, FunctionLike, PolicyLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr,
    InTarget, JoinConstraint, JoinOperator, Query, Select, SelectItem, SetExpr, SetOperator,
    UnaryOperator, Value, Visitor,
};

use crate::rules::walk_support::walk;
use crate::{
    deployment::Deployment,
    rules::policy_support::{may_aggregate, sql_set_body},
};

/// Finds a declared credential.
struct CredentialTerm<'a>(&'a Deployment);

impl Visitor for CredentialTerm<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if self.0.is_credential(expression) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Judges the expressions of one policy against the declared credentials.
pub(crate) struct CredentialJudge<'a, DB: DatabaseLike> {
    database: &'a DB,
    policy: &'a DB::Policy,
    deployment: &'a Deployment,
    /// Functions whose bodies are being read, so a recursive one is not
    /// read again.
    reading: RefCell<Vec<&'a DB::Function>>,
}

impl<'a, DB: DatabaseLike> CredentialJudge<'a, DB> {
    pub(crate) fn new(
        database: &'a DB,
        policy: &'a DB::Policy,
        deployment: &'a Deployment,
    ) -> Self {
        Self {
            database,
            policy,
            deployment,
            reading: RefCell::default(),
        }
    }

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
            Expr::Value(literal) => matches!(literal.value, Value::Null),
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
            Expr::Value(literal) => matches!(literal.value, Value::Boolean(false)),
            Expr::IsDistinctFrom(left, right) => self.is_null(left)? && self.is_null(right)?,
            Expr::AnyOp { left, right, .. } => {
                self.is_null(left)?
                    || match right.as_ref() {
                        Expr::Function(Function {
                            name,
                            args: FunctionArguments::Subquery(subquery),
                            ..
                        }) if name
                            .0
                            .last()
                            .and_then(|part| part.as_ident())
                            .is_some_and(|ident| ident.value.eq_ignore_ascii_case("array")) =>
                        {
                            self.subquery_requires(subquery)?
                        }
                        _ => false,
                    }
            }
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

    /// The operand through which a caller without a credential passes
    /// `expression` while it reads a declared credential, such as
    /// `auth.uid() IS NULL` in `auth.uid() IS NULL OR owner = auth.uid()`.
    /// `None` when the expression requires a credential or only passes
    /// without one through operands that read none, such as `is_public`.
    pub(crate) fn absence_admitter<'e>(
        &self,
        expression: &'e Expr,
    ) -> Result<Option<&'e Expr>, LookupError> {
        if self.requires(expression)?
            || walk(expression, &mut CredentialTerm(self.deployment)).is_continue()
        {
            return Ok(None);
        }
        match expression {
            Expr::Nested(inner) => self.absence_admitter(inner),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or | BinaryOperator::And,
                right,
            } => match self.absence_admitter(left)? {
                Some(operand) => Ok(Some(operand)),
                None => self.absence_admitter(right),
            },
            _ => Ok(Some(expression)),
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
        for function in self.reached(call)? {
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
        self.set_requires(&query.body)
    }

    /// Whether a query body returns no row when every credential is `NULL`,
    /// which a `UNION` does when every arm does.
    fn set_requires(&self, body: &SetExpr) -> Result<bool, LookupError> {
        Ok(match body {
            SetExpr::Select(select) => {
                !self.may_yield_row_from_no_input(select)?
                    && (self.filter_requires(select)? || self.projects_no_row(select)?)
            }
            SetExpr::Query(query) => self.subquery_requires(query)?,
            SetExpr::SetOperation {
                op: SetOperator::Union,
                left,
                right,
                ..
            } => self.set_requires(left)? && self.set_requires(right)?,
            _ => false,
        })
    }

    /// Whether a `SELECT` projects one set-returning call that returns no row
    /// when every credential is `NULL`, so no row survives.
    fn projects_no_row(&self, select: &Select) -> Result<bool, LookupError> {
        let [
            SelectItem::UnnamedExpr(Expr::Function(call))
            | SelectItem::ExprWithAlias {
                expr: Expr::Function(call),
                ..
            },
        ] = select.projection.as_slice()
        else {
            return Ok(false);
        };
        let mut reached = false;
        for function in self.reached(call)? {
            reached = true;
            if !self.body_returns_no_row(function)? {
                return Ok(false);
            }
        }
        Ok(reached)
    }

    /// Functions a call may reach, resolved by the policy, or by the database
    /// for a call in a function body being read.
    fn reached(
        &self,
        call: &Function,
    ) -> Result<impl Iterator<Item = &'a DB::Function>, LookupError> {
        let in_body = !self.reading.borrow().is_empty();
        let from_policy = if in_body {
            None
        } else {
            Some(self.policy.functions_reached_by(call, self.database)?)
        };
        let from_body = if in_body {
            Some(
                self.database
                    .functions_reached_by(call, IdentifierCase::Folded)?,
            )
        } else {
            None
        };
        Ok(from_policy
            .into_iter()
            .flatten()
            .chain(from_body.into_iter().flatten()))
    }

    /// Whether a set-returning `LANGUAGE sql` function's body, one query,
    /// returns no row when every credential is `NULL`.
    fn body_returns_no_row(&self, function: &'a DB::Function) -> Result<bool, LookupError> {
        let reading = self
            .reading
            .borrow()
            .iter()
            .any(|reading| std::ptr::eq(*reading, function));
        let Some(query) = sql_set_body(function).filter(|_| !reading) else {
            return Ok(false);
        };
        self.reading.borrow_mut().push(function);
        let requires = self.subquery_requires(&query);
        self.reading.borrow_mut().pop();
        requires
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
            if let ControlFlow::Break(outcome) = walk(expression, &mut finder) {
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
        may_aggregate(self.database, self.reached(call)?)
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
