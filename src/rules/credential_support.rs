//! Whether a policy expression can be true for a caller holding no
//! credential, judged conservatively with every declared credential `NULL`.

use std::{borrow::Cow, cell::RefCell, ops::ControlFlow, ptr};

use sql_traits::{
    errors::LookupError,
    structs::{ExpressionContext, ExpressionScope, IdentifierCase, WrittenCall},
    traits::{DatabaseLike, FunctionLike, PolicyLike, Relation, ViewLike},
    utils::identifier_resolution::SearchPath,
};
use sqlparser::ast::{
    ArgMode, BinaryOperator, Cte, Distinct, Expr, Function, FunctionArg, FunctionArgExpr,
    FunctionArguments, GroupByExpr, Ident, InTarget, JoinConstraint, JoinOperator, ObjectName,
    ObjectNamePart, OrderBy, Query, Select, SelectItem, SetExpr, SetOperator, TableFactor,
    TableFunctionArgs, TableWithJoins, UnaryOperator, Value, Visitor, With,
};

use crate::rules::{null_support::strictness, walk_support::walk};
use crate::{
    deployment::Deployment,
    rules::{
        cte_support::{same_name, stored_relation},
        policy_support::{may_aggregate, sql_set_body},
    },
};

/// Finds a declared credential.
pub(crate) struct CredentialTerm<'a>(pub(crate) &'a Deployment);

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
    outer: Option<&'s Items<'s>>,
}

/// Where a judged node is read: the `WITH` items in reach, `None` outside
/// every `WITH`, and the context typing the nodes of the policy expression,
/// function body or view definition holding it.
struct Scope<'s, 'q, 'a, DB: DatabaseLike> {
    items: Option<&'s Items<'s>>,
    types: &'s ExpressionContext<'q, 'a, DB>,
}

impl<'s, 'q, 'a, DB: DatabaseLike> Scope<'s, 'q, 'a, DB> {
    /// Calls `judge` with the scope of `query`, which sees its own `WITH`
    /// items before those in reach here.
    fn within<R>(&self, query: &'s Query, judge: impl FnOnce(&Scope<'_, 'q, 'a, DB>) -> R) -> R {
        match &query.with {
            Some(clause) => judge(&Scope {
                items: Some(&Items {
                    clause,
                    visible: clause.cte_tables.len(),
                    outer: self.items,
                }),
                types: self.types,
            }),
            None => judge(self),
        }
    }
}

impl<'s> Items<'s> {
    /// The item `name` reads and the scope of its body, which sees the items
    /// before it, or every item under `WITH RECURSIVE`, as PostgreSQL scopes
    /// them. A schema-qualified name never reads an item.
    fn read_by(&'s self, name: &ObjectName) -> Option<(&'s Cte, Self)> {
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

/// A function body or view definition being read, whose calls and names
/// resolve against the database.
struct Reading<'a, F> {
    /// The function whose body is read, or [`None`] for a view.
    function: Option<&'a F>,
    /// The search path the function sets.
    path: Option<SearchPath<'a>>,
    /// The positions of the input parameters the call passes a `NULL`
    /// credential to.
    null_arguments: Vec<usize>,
}

/// Judges the expressions of one policy against the declared credentials.
pub(crate) struct CredentialJudge<'a, DB: DatabaseLike> {
    database: &'a DB,
    policy: &'a DB::Policy,
    deployment: &'a Deployment,
    /// Function bodies and view definitions being read, so a recursive
    /// function is not read again.
    reading: RefCell<Vec<Reading<'a, DB::Function>>>,
    /// Queries of `WITH` items and views being judged, by address, each
    /// taken to return no row where it reads itself.
    judging: RefCell<Vec<*const Query>>,
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
        let table = ExpressionScope::Table(self.policy.table(self.database)?);
        let types = ExpressionContext::for_expression(
            expression,
            &table,
            self.database,
            IdentifierCase::Folded,
        )?;
        self.requires_within(
            expression,
            &Scope {
                items: None,
                types: &types,
            },
        )
    }

    /// Whether the expression is `NULL` when every credential is `NULL`.
    fn is_null(
        &self,
        expression: &Expr,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        if self.deployment.is_credential(expression)
            || self.reads_null_argument(expression, scope)?
        {
            return Ok(true);
        }
        Ok(match expression {
            Expr::Nested(inner)
            | Expr::Cast { expr: inner, .. }
            | Expr::Collate { expr: inner, .. }
            | Expr::UnaryOp {
                op: UnaryOperator::Minus | UnaryOperator::Plus | UnaryOperator::Not,
                expr: inner,
            } => self.is_null(inner, scope)?,
            Expr::Value(literal) => matches!(literal.value, Value::Null),
            Expr::BinaryOp { left, op, right } => {
                let (left_strict, right_strict) =
                    strictness(self.database, scope.types, expression, op)?;
                (left_strict && self.is_null(left, scope)?)
                    || (right_strict && self.is_null(right, scope)?)
            }
            Expr::Like { expr, pattern, .. }
            | Expr::ILike { expr, pattern, .. }
            | Expr::SimilarTo { expr, pattern, .. } => {
                self.is_null(expr, scope)? || self.is_null(pattern, scope)?
            }
            Expr::Trim {
                expr, trim_what, ..
            } => {
                self.is_null(expr, scope)?
                    || match trim_what {
                        Some(characters) => self.is_null(characters, scope)?,
                        None => false,
                    }
            }
            Expr::AnyOp {
                right, compare_op, ..
            } => match right.as_ref() {
                Expr::Subquery(_) => false,
                Expr::Array(array) => {
                    strictness(self.database, scope.types, expression, compare_op)?.1
                        && self.all_null(&array.elem, scope)?
                }
                _ => self.is_null(right, scope)?,
            },
            Expr::In {
                expr,
                target: InTarget::List(_),
                ..
            } => self.is_null(expr, scope)?,
            Expr::Case {
                conditions,
                else_result,
                ..
            } => {
                self.all_null(conditions.iter().map(|arm| &arm.result), scope)?
                    && match else_result {
                        Some(otherwise) => self.is_null(otherwise, scope)?,
                        None => true,
                    }
            }
            Expr::Function(call) => {
                if let Some(arguments) = keyword_arguments(call, "nullif") {
                    self.all_null(arguments.take(1), scope)?
                } else if let Some(arguments) = keyword_arguments(call, "coalesce") {
                    self.all_null(arguments, scope)?
                } else {
                    self.call_is_null(call, scope)?
                }
            }
            Expr::Subquery(query) => {
                self.projects_null(query, scope)?
                    || scope.within(query, |scope| match single_select(query) {
                        Some(select)
                            if !self.may_yield_row_from_no_input(
                                select,
                                query.order_by.as_ref(),
                                scope,
                            )? =>
                        {
                            self.select_returns_no_row(select, scope)
                        }
                        _ => Ok(false),
                    })?
            }
            _ => false,
        })
    }

    /// Whether the expression cannot be true when every credential is
    /// `NULL`, read where `scope` is in reach.
    fn requires_within(
        &self,
        expression: &Expr,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        if self.is_null(expression, scope)? {
            return Ok(true);
        }
        Ok(match expression {
            Expr::Nested(inner) | Expr::IsTrue(inner) => self.requires_within(inner, scope)?,
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
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => match (left.as_ref(), right.as_ref()) {
                (Expr::Tuple(left), Expr::Tuple(right)) if left.len() == right.len() => {
                    let mut paired_with_null = false;
                    for (left, right) in left.iter().zip(right) {
                        if self.is_null(left, scope)? || self.is_null(right, scope)? {
                            paired_with_null = true;
                            break;
                        }
                    }
                    paired_with_null
                }
                _ => false,
            },
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
                                || self.projects_null(subquery, scope)?
                        }
                        Expr::Subquery(subquery) => {
                            self.subquery_requires(subquery, scope)?
                                || self.projects_null(subquery, scope)?
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
            } => {
                self.is_null(expr, scope)?
                    || self.subquery_requires(subquery, scope)?
                    || self.projects_null(subquery, scope)?
            }
            Expr::Case {
                conditions,
                else_result,
                ..
            } => {
                self.all_require(conditions.iter().map(|arm| &arm.result), scope)?
                    && match else_result {
                        Some(otherwise) => self.requires_within(otherwise, scope)?,
                        None => true,
                    }
            }
            Expr::Function(call) => match keyword_arguments(call, "coalesce") {
                Some(arguments) => self.all_require(arguments, scope)?,
                None => false,
            },
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

    /// Whether there is at least one of `expressions` and each is `NULL`
    /// when every credential is `NULL`.
    fn all_null<'e>(
        &self,
        expressions: impl IntoIterator<Item = &'e Expr>,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        let mut any = false;
        for expression in expressions {
            if !self.is_null(expression, scope)? {
                return Ok(false);
            }
            any = true;
        }
        Ok(any)
    }

    /// Whether there is at least one of `expressions` and none can be true
    /// when every credential is `NULL`.
    fn all_require<'e>(
        &self,
        expressions: impl IntoIterator<Item = &'e Expr>,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        let mut any = false;
        for expression in expressions {
            if !self.requires_within(expression, scope)? {
                return Ok(false);
            }
            any = true;
        }
        Ok(any)
    }

    /// The positions of the positional `arguments` that are `NULL` when
    /// every credential is `NULL`.
    fn null_arguments(
        &self,
        arguments: &[FunctionArg],
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<Vec<usize>, LookupError> {
        let mut positions = Vec::new();
        for (index, argument) in arguments.iter().enumerate() {
            if let FunctionArg::Unnamed(FunctionArgExpr::Expr(argument)) = argument
                && self.is_null(argument, scope)?
            {
                positions.push(index);
            }
        }
        Ok(positions)
    }

    /// Whether `expression` reads an input parameter of the function whose
    /// body is read that the call passes a `NULL` credential to, by its
    /// position, its name or its name qualified by the function's, where no
    /// column of the body's relations takes the name first.
    fn reads_null_argument(
        &self,
        expression: &Expr,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        let reading = self.reading.borrow();
        let Some(Reading {
            function: Some(function),
            null_arguments,
            ..
        }) = reading.last()
        else {
            return Ok(false);
        };
        if null_arguments.is_empty() {
            return Ok(false);
        }
        let position = match expression {
            Expr::Value(literal) => match &literal.value {
                Value::Placeholder(placeholder) => placeholder
                    .strip_prefix('$')
                    .and_then(|number| number.parse::<usize>().ok())
                    .and_then(|number| number.checked_sub(1)),
                _ => None,
            },
            Expr::Identifier(name) if scope.types.reference(expression)?.is_none() => {
                self.input_position(function, name)
            }
            Expr::CompoundIdentifier(parts)
                if let [qualifier, name] = parts.as_slice()
                    && folded(qualifier) == function.stored_name()
                    && scope.types.reference(expression)?.is_none() =>
            {
                self.input_position(function, name)
            }
            _ => None,
        };
        Ok(position.is_some_and(|position| null_arguments.contains(&position)))
    }

    /// The position among the input parameters of `function` of the one
    /// named `name`.
    fn input_position(&self, function: &'a DB::Function, name: &Ident) -> Option<usize> {
        let name = folded(name);
        function
            .argument_modes()
            .zip(function.stored_argument_names(self.database))
            .filter(|(mode, _)| !matches!(mode, ArgMode::Out))
            .position(|(_, stored)| stored.as_deref() == Some(name.as_ref()))
    }

    /// Whether every function the call may reach returns `NULL` for a
    /// positional argument that is `NULL`.
    fn call_is_null(
        &self,
        call: &Function,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        let FunctionArguments::List(list) = &call.args else {
            return Ok(false);
        };
        let null_arguments = self.null_arguments(&list.args, scope)?;
        if null_arguments.is_empty() {
            return Ok(false);
        }
        let mut reached_any = false;
        for function in self.reached(call)? {
            reached_any = true;
            if !null_arguments
                .iter()
                .any(|&index| function.returns_null_on_null_argument(self.database, index))
            {
                return Ok(false);
            }
        }
        Ok(reached_any)
    }

    /// Whether every row the query returns holds `NULL` in its one column
    /// when every credential is `NULL`.
    fn projects_null(
        &self,
        query: &Query,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        scope.within(query, |scope| {
            match single_select(query).map(|select| select.projection.as_slice()) {
                Some(
                    [
                        SelectItem::UnnamedExpr(item)
                        | SelectItem::ExprWithAlias { expr: item, .. },
                    ],
                ) => self.is_null(item, scope),
                _ => Ok(false),
            }
        })
    }

    /// Whether a subquery returns no row when every credential is `NULL`.
    fn subquery_requires(
        &self,
        query: &Query,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        scope.within(query, |scope| {
            self.set_requires(&query.body, query.order_by.as_ref(), scope)
        })
    }

    /// Whether a query body, ordered by `order_by`, returns no row when
    /// every credential is `NULL`, which a `UNION` does when every arm does,
    /// an `INTERSECT` when one arm does and an `EXCEPT` when its left arm
    /// does.
    fn set_requires(
        &self,
        body: &SetExpr,
        order_by: Option<&OrderBy>,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        Ok(match body {
            SetExpr::Select(select) => {
                !self.may_yield_row_from_no_input(select, order_by, scope)?
                    && (self.select_returns_no_row(select, scope)?
                        || self.projects_no_row(select, scope)?)
            }
            SetExpr::Query(query) => self.subquery_requires(query, scope)?,
            SetExpr::SetOperation {
                op: SetOperator::Union,
                left,
                right,
                ..
            } => self.set_requires(left, None, scope)? && self.set_requires(right, None, scope)?,
            SetExpr::SetOperation {
                op: SetOperator::Intersect,
                left,
                right,
                ..
            } => self.set_requires(left, None, scope)? || self.set_requires(right, None, scope)?,
            SetExpr::SetOperation {
                op: SetOperator::Except,
                left,
                ..
            } => self.set_requires(left, None, scope)?,
            _ => false,
        })
    }

    /// Whether a `SELECT` projects one set-returning call that returns no row
    /// when every credential is `NULL`, so no row survives.
    fn projects_no_row(
        &self,
        select: &Select,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        let [
            SelectItem::UnnamedExpr(Expr::Function(
                call @ Function {
                    args: FunctionArguments::List(list),
                    ..
                },
            ))
            | SelectItem::ExprWithAlias {
                expr:
                    Expr::Function(
                        call @ Function {
                            args: FunctionArguments::List(list),
                            ..
                        },
                    ),
                ..
            },
        ] = select.projection.as_slice()
        else {
            return Ok(false);
        };
        let null_arguments = self.null_arguments(&list.args, scope)?;
        self.call_returns_no_row(call, &null_arguments)
    }

    /// Whether a call reaches a function and every function it may reach
    /// returns no row when every credential is `NULL`, given the positions
    /// of the arguments that are `NULL` then. A strict set-returning
    /// function returns none for a `NULL` argument, and a set-returning
    /// `LANGUAGE sql` one none when its body returns none with those
    /// parameters `NULL`.
    fn call_returns_no_row<'c>(
        &self,
        call: impl Into<WrittenCall<'c>>,
        null_arguments: &[usize],
    ) -> Result<bool, LookupError> {
        let mut reached = false;
        for function in self.reached(call)? {
            reached = true;
            let strict_on_null = function.returns_set()
                && null_arguments
                    .iter()
                    .any(|&index| function.returns_null_on_null_argument(self.database, index));
            if !strict_on_null && !self.body_returns_no_row(function, null_arguments)? {
                return Ok(false);
            }
        }
        Ok(reached)
    }

    /// Functions a call may reach, resolved by the policy, or by the database
    /// for a call in a function body or view definition being read.
    fn reached<'c>(
        &self,
        call: impl Into<WrittenCall<'c>>,
    ) -> Result<impl Iterator<Item = &'a DB::Function>, LookupError> {
        let call = call.into();
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
    /// returns no row when every credential is `NULL`, as are the input
    /// parameters at `null_arguments`.
    fn body_returns_no_row(
        &self,
        function: &'a DB::Function,
        null_arguments: &[usize],
    ) -> Result<bool, LookupError> {
        let reading = self
            .reading
            .borrow()
            .iter()
            .any(|reading| reading.function.is_some_and(|read| ptr::eq(read, function)));
        if reading {
            return Ok(false);
        }
        let Some(query) = sql_set_body(self.database, function)? else {
            return Ok(false);
        };
        let types = ExpressionContext::new(&query, self.database, IdentifierCase::Folded)?;
        let path = function.search_path(self.database)?;
        self.reading.borrow_mut().push(Reading {
            function: Some(function),
            path,
            null_arguments: null_arguments.to_vec(),
        });
        let requires = self.subquery_requires(
            &query,
            &Scope {
                items: None,
                types: &types,
            },
        );
        self.reading.borrow_mut().pop();
        requires
    }

    /// Whether a `SELECT`'s filter or one of the relations every output row
    /// needs removes every row when every credential is `NULL`.
    fn select_returns_no_row(
        &self,
        select: &Select,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        Ok(self.filter_requires(select, scope)? || self.reads_no_row(select, scope)?)
    }

    /// Whether the `WHERE` or the `ON` of an inner join requires a
    /// credential, so no row survives.
    fn filter_requires(
        &self,
        select: &Select,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
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

    /// Whether one of a `SELECT`'s `FROM` items returns no row when every
    /// credential is `NULL`.
    fn reads_no_row(
        &self,
        select: &Select,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        for table in &select.from {
            if self.joined_returns_no_row(table, scope)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether a `FROM` item returns no row when every credential is `NULL`,
    /// because it joins a relation returning none through joins that keep no
    /// row of an empty side.
    fn joined_returns_no_row(
        &self,
        table: &TableWithJoins,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        let mut empty = self.relation_returns_no_row(&table.relation, scope)?;
        for join in &table.joins {
            empty = match join.join_operator {
                JoinOperator::Join(_) | JoinOperator::Inner(_) | JoinOperator::CrossJoin(_) => {
                    empty || self.relation_returns_no_row(&join.relation, scope)?
                }
                JoinOperator::Left(_) | JoinOperator::LeftOuter(_) => empty,
                JoinOperator::Right(_) | JoinOperator::RightOuter(_) => {
                    self.relation_returns_no_row(&join.relation, scope)?
                }
                _ => false,
            };
        }
        Ok(empty)
    }

    /// Whether `factor` returns no row when every credential is `NULL`, as a
    /// derived table, a parenthesized join, a `WITH` item or a view whose
    /// query returns none does, or a call to helpers whose bodies return none.
    fn relation_returns_no_row(
        &self,
        factor: &TableFactor,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        match factor {
            TableFactor::Derived { subquery, .. } => self.subquery_requires(subquery, scope),
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => self.joined_returns_no_row(table_with_joins, scope),
            TableFactor::Table {
                name, args: None, ..
            } => {
                if let Some((item, body)) = scope.items.and_then(|items| items.read_by(name)) {
                    return self.defined_returns_no_row(
                        &item.query,
                        &Scope {
                            items: Some(&body),
                            types: scope.types,
                        },
                    );
                }
                let relation = {
                    let reading = self.reading.borrow();
                    let path = reading.last().and_then(|reading| reading.path.as_deref());
                    stored_relation(self.database, name, path)?
                };
                match relation {
                    Some(Relation::View(view)) => {
                        let definition = view.definition();
                        let types = ExpressionContext::new(
                            definition,
                            self.database,
                            IdentifierCase::Folded,
                        )?;
                        self.reading.borrow_mut().push(Reading {
                            function: None,
                            path: None,
                            null_arguments: Vec::new(),
                        });
                        let requires = self.defined_returns_no_row(
                            definition,
                            &Scope {
                                items: None,
                                types: &types,
                            },
                        );
                        self.reading.borrow_mut().pop();
                        requires
                    }
                    _ => Ok(false),
                }
            }
            TableFactor::Table {
                args:
                    Some(TableFunctionArgs {
                        args: arguments, ..
                    }),
                ..
            }
            | TableFactor::Function {
                args: arguments, ..
            } => {
                let null_arguments = self.null_arguments(arguments, scope)?;
                WrittenCall::relation(factor).map_or(Ok(false), |call| {
                    self.call_returns_no_row(call, &null_arguments)
                })
            }
            _ => Ok(false),
        }
    }

    /// Whether the query defining a `WITH` item or a view returns no row
    /// when every credential is `NULL`.
    ///
    /// A query read inside itself counts as returning none, which judges a
    /// recursive item by its non-recursive term, since PostgreSQL feeds the
    /// recursive term only the rows the non-recursive term returns.
    fn defined_returns_no_row(
        &self,
        query: &Query,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        if self
            .judging
            .borrow()
            .iter()
            .any(|judged| ptr::eq(*judged, query))
        {
            return Ok(true);
        }
        self.judging.borrow_mut().push(query);
        let requires = self.subquery_requires(query, scope);
        self.judging.borrow_mut().pop();
        requires
    }

    /// Whether the query can return a row though its filter removes every
    /// input row, which an aggregating query does when its grouping sets
    /// include the empty one and its `HAVING` can pass. A query without
    /// `GROUP BY` groups by the empty set alone, and aggregates when it has a
    /// `HAVING` or calls an aggregate in its projection, its `DISTINCT ON`,
    /// its named windows or its `ORDER BY`, here `order_by`.
    ///
    /// A call without `OVER` counts as an aggregate when a function it may
    /// reach is one, or when it reaches no known function, unless the call
    /// is a declared credential.
    fn may_yield_row_from_no_input(
        &self,
        select: &Select,
        order_by: Option<&OrderBy>,
        scope: &Scope<'_, '_, 'a, DB>,
    ) -> Result<bool, LookupError> {
        let grouping = match &select.group_by {
            GroupByExpr::Expressions(grouping, _) if grouping.iter().all(may_group_by_nothing) => {
                grouping
            }
            _ => return Ok(false),
        };
        if let Some(having) = &select.having {
            return Ok(!self.requires_within(having, scope)?);
        }
        if !grouping.is_empty() {
            return Ok(true);
        }
        let mut finder = AggregateCall {
            judge: self,
            depth: 0,
        };
        let projected = select.projection.iter().filter_map(|item| match item {
            SelectItem::UnnamedExpr(expression)
            | SelectItem::ExprWithAlias {
                expr: expression, ..
            } => Some(expression),
            _ => None,
        });
        let distinct_on = match &select.distinct {
            Some(Distinct::On(expressions)) => expressions.as_slice(),
            _ => &[],
        };
        let mut found = projected
            .chain(distinct_on)
            .try_for_each(|expression| walk(expression, &mut finder));
        if found.is_continue() {
            found = walk(&select.named_window, &mut finder);
        }
        if found.is_continue()
            && let Some(order_by) = order_by
        {
            found = walk(order_by, &mut finder);
        }
        match found {
            ControlFlow::Break(outcome) => outcome.map(|()| true),
            ControlFlow::Continue(()) => Ok(false),
        }
    }
}

/// Whether a `GROUP BY` item can add no column to a grouping set, as `()`,
/// `ROLLUP`, `CUBE` and a `GROUPING SETS` listing such a set can.
fn may_group_by_nothing(item: &Expr) -> bool {
    match item {
        Expr::Tuple(columns) => columns.is_empty(),
        Expr::Rollup(_) | Expr::Cube(_) => true,
        Expr::GroupingSets(sets) => sets.iter().any(|set| set.iter().all(may_group_by_nothing)),
        _ => false,
    }
}

/// Finds an aggregate call in the clauses of one query level, outside
/// nested subqueries.
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

/// The arguments of `call` when PostgreSQL's grammar reads it as the
/// expression `keyword`, which it does for a bare unquoted name such as
/// `coalesce` or `nullif`, rather than as a call to a function. `None` when
/// an argument is no plain expression, as a whole row `t.*` is.
fn keyword_arguments<'c>(
    call: &'c Function,
    keyword: &str,
) -> Option<impl Iterator<Item = &'c Expr>> {
    let [
        ObjectNamePart::Identifier(Ident {
            value,
            quote_style: None,
            ..
        }),
    ] = call.name.0.as_slice()
    else {
        return None;
    };
    let FunctionArguments::List(list) = &call.args else {
        return None;
    };
    let readable = |argument: &'c FunctionArg| match argument {
        FunctionArg::Unnamed(FunctionArgExpr::Expr(argument)) => Some(argument),
        _ => None,
    };
    (value.eq_ignore_ascii_case(keyword)
        && list
            .args
            .iter()
            .all(|argument| readable(argument).is_some()))
    .then(|| list.args.iter().filter_map(readable))
}

/// The name PostgreSQL stores for `name`, folded to lowercase unless
/// quoted.
fn folded(name: &Ident) -> Cow<'_, str> {
    match name.quote_style {
        Some(_) => Cow::Borrowed(&name.value),
        None => Cow::Owned(name.value.to_lowercase()),
    }
}
