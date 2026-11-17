//! Whether a policy expression can be true for a caller holding no
//! credential, judged conservatively with every declared credential `NULL`.

use std::{cell::RefCell, ops::ControlFlow, ptr};

use sql_traits::{
    errors::LookupError,
    structs::IdentifierCase,
    traits::{DatabaseLike, FunctionLike, PolicyLike},
};
use sqlparser::ast::{
    BinaryOperator, Cte, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments,
    GroupByExpr, InTarget, JoinConstraint, JoinOperator, ObjectNamePart, Query, Select, SelectItem,
    SetExpr, SetOperator, TableFactor, UnaryOperator, Value, Visitor, With,
};

use crate::rules::walk_support::walk;
use crate::{
    deployment::Deployment,
    rules::{
        cte_support::same_name,
        policy_support::{may_aggregate, sql_set_body},
    },
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

/// The `WITH` items a judged query can read, innermost clause first.
struct Items<'s> {
    clause: &'s With,
    /// How many items, from the first, the query sees.
    visible: usize,
    outer: Scope<'s>,
}

/// The `WITH` items in reach, `None` outside every `WITH`.
type Scope<'s> = Option<&'s Items<'s>>;

impl<'s> Items<'s> {
    /// Calls `judge` with the scope of `query`, which sees its own `WITH`
    /// items before those of `outer`.
    fn within<R>(query: &'s Query, outer: Scope<'s>, judge: impl FnOnce(Scope<'_>) -> R) -> R {
        match &query.with {
            Some(clause) => judge(Some(&Items {
                clause,
                visible: clause.cte_tables.len(),
                outer,
            })),
            None => judge(outer),
        }
    }

    /// The item `factor` reads and the scope of its body, which sees the
    /// items before it, or every item under `WITH RECURSIVE`, as PostgreSQL
    /// scopes them.
    fn read_by(&'s self, factor: &TableFactor) -> Option<(&'s Cte, Self)> {
        let TableFactor::Table {
            name, args: None, ..
        } = factor
        else {
            return None;
        };
        let [ObjectNamePart::Identifier(written)] = name.0.as_slice() else {
            return None;
        };
        let mut frame = Some(self);
        while let Some(items) = frame {
            if let Some(position) = items.clause.cte_tables[..items.visible]
                .iter()
                .position(|item| same_name(&item.alias.name, written))
            {
                let body = Items {
                    clause: items.clause,
                    visible: if items.clause.recursive {
                        items.clause.cte_tables.len()
                    } else {
                        position
                    },
                    outer: items.outer,
                };
                return Some((&items.clause.cte_tables[position], body));
            }
            frame = items.outer;
        }
        None
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
    /// `WITH` items whose bodies are being judged, by address, each taken
    /// to return no row where it reads itself.
    judging: RefCell<Vec<*const Cte>>,
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
            judging: RefCell::default(),
        }
    }

    /// Whether the expression cannot be true when every credential is
    /// `NULL`.
    pub(crate) fn requires(&self, expression: &Expr) -> Result<bool, LookupError> {
        self.requires_within(expression, None)
    }

    /// Whether the expression is `NULL` when every credential is `NULL`.
    fn is_null(&self, expression: &Expr, scope: Scope<'_>) -> Result<bool, LookupError> {
        if self.deployment.is_credential(expression) {
            return Ok(true);
        }
        Ok(match expression {
            Expr::Nested(inner)
            | Expr::Cast { expr: inner, .. }
            | Expr::UnaryOp {
                op: UnaryOperator::Minus | UnaryOperator::Plus | UnaryOperator::Not,
                expr: inner,
            } => self.is_null(inner, scope)?,
            Expr::Value(literal) => matches!(literal.value, Value::Null),
            Expr::BinaryOp { left, op, right } => {
                is_strict_operator(op)
                    && (self.is_null(left, scope)? || self.is_null(right, scope)?)
            }
            Expr::Like { expr, pattern, .. }
            | Expr::ILike { expr, pattern, .. }
            | Expr::SimilarTo { expr, pattern, .. } => {
                self.is_null(expr, scope)? || self.is_null(pattern, scope)?
            }
            Expr::AnyOp { right, .. } => self.is_null(right, scope)?,
            Expr::In {
                expr,
                target: InTarget::List(_),
                ..
            } => self.is_null(expr, scope)?,
            Expr::Function(call) => self.call_is_null(call, scope)?,
            Expr::Subquery(query) => {
                Items::within(query, scope, |scope| match single_select(query) {
                    Some(select) if !self.may_yield_row_from_no_input(select)? => Ok(self
                        .select_returns_no_row(select, scope)?
                        || match select.projection.as_slice() {
                            [
                                SelectItem::UnnamedExpr(item)
                                | SelectItem::ExprWithAlias { expr: item, .. },
                            ] => self.is_null(item, scope)?,
                            _ => false,
                        }),
                    _ => Ok(false),
                })?
            }
            _ => false,
        })
    }

    /// Whether the expression cannot be true when every credential is
    /// `NULL`, read where `scope` is in reach.
    fn requires_within(&self, expression: &Expr, scope: Scope<'_>) -> Result<bool, LookupError> {
        if self.is_null(expression, scope)? {
            return Ok(true);
        }
        Ok(match expression {
            Expr::Nested(inner) => self.requires_within(inner, scope)?,
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => self.requires_within(left, scope)? || self.requires_within(right, scope)?,
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
            } => self.requires_within(left, scope)? && self.requires_within(right, scope)?,
            Expr::IsNotNull(inner) => self.is_null(inner, scope)?,
            Expr::Value(literal) => matches!(literal.value, Value::Boolean(false)),
            Expr::IsDistinctFrom(left, right) => {
                self.is_null(left, scope)? && self.is_null(right, scope)?
            }
            Expr::AnyOp { left, right, .. } => {
                self.is_null(left, scope)?
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
                            self.subquery_requires(subquery, scope)?
                        }
                        _ => false,
                    }
            }
            Expr::In {
                target: InTarget::List(list),
                ..
            } => self.all_null(list, scope)?,
            Expr::Exists {
                subquery,
                negated: false,
            } => self.subquery_requires(subquery, scope)?,
            Expr::In {
                expr,
                target: InTarget::Subquery(subquery),
                negated: false,
                ..
            } => self.is_null(expr, scope)? || self.subquery_requires(subquery, scope)?,
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

    fn all_null(&self, expressions: &[Expr], scope: Scope<'_>) -> Result<bool, LookupError> {
        for expression in expressions {
            if !self.is_null(expression, scope)? {
                return Ok(false);
            }
        }
        Ok(!expressions.is_empty())
    }

    /// Whether every function the call may reach returns `NULL` for a
    /// positional argument that is `NULL`.
    fn call_is_null(&self, call: &Function, scope: Scope<'_>) -> Result<bool, LookupError> {
        let FunctionArguments::List(list) = &call.args else {
            return Ok(false);
        };
        let mut null_positions = Vec::new();
        for (index, argument) in list.args.iter().enumerate() {
            if let FunctionArg::Unnamed(FunctionArgExpr::Expr(argument)) = argument
                && self.is_null(argument, scope)?
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
    fn subquery_requires(&self, query: &Query, scope: Scope<'_>) -> Result<bool, LookupError> {
        Items::within(query, scope, |scope| self.set_requires(&query.body, scope))
    }

    /// Whether a query body returns no row when every credential is `NULL`,
    /// which a `UNION` does when every arm does.
    fn set_requires(&self, body: &SetExpr, scope: Scope<'_>) -> Result<bool, LookupError> {
        Ok(match body {
            SetExpr::Select(select) => {
                !self.may_yield_row_from_no_input(select)?
                    && (self.select_returns_no_row(select, scope)?
                        || self.projects_no_row(select)?)
            }
            SetExpr::Query(query) => self.subquery_requires(query, scope)?,
            SetExpr::SetOperation {
                op: SetOperator::Union,
                left,
                right,
                ..
            } => self.set_requires(left, scope)? && self.set_requires(right, scope)?,
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
        if reading {
            return Ok(false);
        }
        let Some(query) = sql_set_body(self.database, function)? else {
            return Ok(false);
        };
        self.reading.borrow_mut().push(function);
        let requires = self.subquery_requires(&query, None);
        self.reading.borrow_mut().pop();
        requires
    }

    /// Whether a `SELECT`'s filter or one of the relations every output row
    /// needs removes every row when every credential is `NULL`.
    fn select_returns_no_row(
        &self,
        select: &Select,
        scope: Scope<'_>,
    ) -> Result<bool, LookupError> {
        Ok(self.filter_requires(select, scope)? || self.reads_no_row(select, scope)?)
    }

    /// Whether the `WHERE` or the `ON` of an inner join requires a
    /// credential, so no row survives.
    fn filter_requires(&self, select: &Select, scope: Scope<'_>) -> Result<bool, LookupError> {
        if let Some(selection) = &select.selection
            && self.requires_within(selection, scope)?
        {
            return Ok(true);
        }
        for table in &select.from {
            for join in &table.joins {
                if let JoinOperator::Join(JoinConstraint::On(condition))
                | JoinOperator::Inner(JoinConstraint::On(condition)) = &join.join_operator
                    && self.requires_within(condition, scope)?
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether one of a `SELECT`'s `FROM` items is empty when every
    /// credential is `NULL`, because it joins a `WITH` item that returns no
    /// row through joins that keep no row of an empty side.
    fn reads_no_row(&self, select: &Select, scope: Scope<'_>) -> Result<bool, LookupError> {
        let Some(items) = scope else {
            return Ok(false);
        };
        for table in &select.from {
            let mut empty = self.item_returns_no_row(items, &table.relation)?;
            for join in &table.joins {
                empty = match join.join_operator {
                    JoinOperator::Join(_) | JoinOperator::Inner(_) | JoinOperator::CrossJoin(_) => {
                        empty || self.item_returns_no_row(items, &join.relation)?
                    }
                    JoinOperator::Left(_) | JoinOperator::LeftOuter(_) => empty,
                    JoinOperator::Right(_) | JoinOperator::RightOuter(_) => {
                        self.item_returns_no_row(items, &join.relation)?
                    }
                    _ => false,
                };
            }
            if empty {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether `factor` reads a `WITH` item of `items` that returns no row
    /// when every credential is `NULL`.
    ///
    /// An item read inside its own body counts as returning none, which
    /// judges a recursive item by its non-recursive term, since PostgreSQL
    /// feeds the recursive term only the rows the non-recursive term
    /// returns.
    fn item_returns_no_row(
        &self,
        items: &Items<'_>,
        factor: &TableFactor,
    ) -> Result<bool, LookupError> {
        let Some((item, body)) = items.read_by(factor) else {
            return Ok(false);
        };
        if self
            .judging
            .borrow()
            .iter()
            .any(|judged| ptr::eq(*judged, item))
        {
            return Ok(true);
        }
        self.judging.borrow_mut().push(item);
        let requires = self.subquery_requires(&item.query, Some(&body));
        self.judging.borrow_mut().pop();
        requires
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
pub(crate) fn is_strict_operator(operator: &BinaryOperator) -> bool {
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
