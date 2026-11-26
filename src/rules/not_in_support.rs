//! `NOT IN` over a subquery or a list holding a `NULL`, shared by the rules
//! reporting it.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ExpressionContext, IdentifierCase, RangeTableEntry, TargetName},
    traits::{ColumnLike, DatabaseLike, TableLike},
    utils::identifier_resolution::identifiers_match,
};
use sqlparser::ast::{
    BinaryOperator, CastKind, Cte, Expr, FunctionArg, FunctionArgExpr, FunctionArguments,
    GroupByExpr, Ident, InTarget, JoinConstraint, JoinOperator, ObjectNamePart, Query, Select,
    SelectItem, SetExpr, SetOperator, SetQuantifier, TableFactor, TableWithJoins, UnaryOperator,
    Value, Visit, Visitor, With,
};

use crate::rules::{
    expression_site_support::{ExpressionFinder, is_null_literal},
    null_support::{
        extracts_part, find_null_passing_argument, rejects_null, strictness,
        yields_value_for_values,
    },
    policy_support::conjuncts,
    walk_support::walk,
};

/// One `NOT IN`, or `<> ALL` over an array.
pub(crate) struct NotIn {
    /// The expression rendered as SQL.
    pub(crate) expression: String,
    /// What the values are compared against.
    pub(crate) operand: NotInOperand,
}

/// What a `NOT IN` compares against.
pub(crate) enum NotInOperand {
    /// A subquery, with its nullable base column or output expression.
    Subquery(Option<String>),
    /// A list or array literal holding a `NULL`.
    NullList,
}

/// Whether `expression`, under casts and parentheses, is an array literal
/// holding a `NULL`.
fn is_null_array(mut expression: &Expr) -> bool {
    loop {
        match expression {
            Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => expression = inner,
            Expr::Array(array) => return array.elem.iter().any(is_null_literal),
            _ => return false,
        }
    }
}

/// A declared output judgment, retaining a borrowed witness until reporting.
enum Nullability<'query> {
    Nullable(Culprit<'query>),
    NotNull,
    Unknown,
}

/// The borrowed column or expression witnessing a nullable output.
enum Culprit<'query> {
    Column(&'query str, &'query str),
    Expression(&'query Expr),
}

impl Nullability<'_> {
    /// Combines outputs when either operand can introduce a null.
    fn union(self, other: Self) -> Self {
        match (self, other) {
            (nullable @ Self::Nullable(_), _) | (_, nullable @ Self::Nullable(_)) => nullable,
            (Self::NotNull, Self::NotNull) => Self::NotNull,
            _ => Self::Unknown,
        }
    }

    /// Combines outputs when both operands must admit a null.
    fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (Self::NotNull, _) | (_, Self::NotNull) => Self::NotNull,
            (nullable @ Self::Nullable(_), Self::Nullable(_)) => nullable,
            _ => Self::Unknown,
        }
    }
}

/// The declared nullable output, with unknown outputs left unjudged.
fn nullable_output<DB: DatabaseLike>(
    database: &DB,
    query: &Query,
) -> Result<Option<String>, LookupError> {
    let types = ExpressionContext::new(query, database, IdentifierCase::Folded)?;
    let mut judge = OutputJudge {
        database,
        types: &types,
        visible: Vec::new(),
        visible_head: None,
        visited: Vec::new(),
    };
    Ok(match judge.query(query)? {
        Nullability::Nullable(Culprit::Column(table, column)) => Some(format!("{table}.{column}")),
        Nullability::Nullable(Culprit::Expression(expression)) => Some(expression.to_string()),
        Nullability::NotNull | Nullability::Unknown => None,
    })
}

/// Judges outputs in their declared scopes without rendering intermediate results.
struct OutputJudge<'scope, 'query, 'database, DB: DatabaseLike> {
    database: &'database DB,
    types: &'scope ExpressionContext<'query, 'database, DB>,
    visible: Vec<WithScope<'scope>>,
    visible_head: Option<usize>,
    visited: Vec<&'scope Expr>,
}

/// A visible `WITH` prefix and its enclosing visibility boundary.
struct WithScope<'query> {
    clause: &'query With,
    length: usize,
    parent: Option<usize>,
}

impl<'scope, 'query: 'scope, 'database: 'scope, DB: DatabaseLike>
    OutputJudge<'scope, 'query, 'database, DB>
{
    /// Judges a single-output query within its `WITH` visibility boundary.
    fn query(&mut self, query: &'scope Query) -> Result<Nullability<'scope>, LookupError> {
        let length = self.visible.len();
        let parent = self.visible_head;
        if let Some(with) = &query.with {
            self.visible.push(WithScope {
                clause: with,
                length: with.cte_tables.len(),
                parent,
            });
            self.visible_head = Some(length);
        }
        let result = self.body(&query.body);
        self.visible.truncate(length);
        self.visible_head = parent;
        result
    }

    /// Judges the declared column of a single-column `TABLE` query.
    fn table(&self, table: &sqlparser::ast::Table) -> Result<Nullability<'scope>, LookupError> {
        let Some(name) = &table.table_name else {
            return Ok(Nullability::Unknown);
        };
        let mut target = TargetName::new(&name.value, name.quote_style.is_some());
        if let Some(schema) = &table.schema_name {
            target = target.with_schema(&schema.value, schema.quote_style.is_some());
        }
        let Some(table) = self
            .database
            .resolve_target_table(target, IdentifierCase::Folded)?
        else {
            return Ok(Nullability::Unknown);
        };
        let mut columns = table.columns(self.database)?;
        match (columns.next(), columns.next()) {
            (Some(column), None) if column.is_nullable(self.database)? => Ok(
                Nullability::Nullable(Culprit::Column(table.table_name(), column.column_name())),
            ),
            _ => Ok(Nullability::Unknown),
        }
    }

    /// Judges the sole output of a query body.
    fn body(&mut self, body: &'scope SetExpr) -> Result<Nullability<'scope>, LookupError> {
        Ok(match body {
            SetExpr::Select(select) => match select.projection.as_slice() {
                [
                    SelectItem::UnnamedExpr(output)
                    | SelectItem::ExprWithAlias { expr: output, .. },
                ] => self.expression(Some(select), output)?,
                _ => Nullability::Unknown,
            },
            SetExpr::Query(query) => self.query(query)?,
            SetExpr::Table(table) => self.table(table)?,
            SetExpr::SetOperation {
                op,
                left,
                right,
                set_quantifier,
            } => {
                let left = self.body(left)?;
                match op {
                    SetOperator::Union => left.union(self.body(right)?),
                    SetOperator::Intersect => left.intersect(self.body(right)?),
                    SetOperator::Except | SetOperator::Minus
                        if matches!(
                            set_quantifier,
                            SetQuantifier::None | SetQuantifier::Distinct
                        ) && guaranteed_null(right) =>
                    {
                        Nullability::NotNull
                    }
                    SetOperator::Except | SetOperator::Minus => left,
                }
            }
            SetExpr::Values(values) => {
                let mut result = Nullability::NotNull;
                for row in &values.rows {
                    let [expression] = row.as_slice() else {
                        return Ok(Nullability::Unknown);
                    };
                    result = result.union(self.expression(None, expression)?);
                }
                result
            }
            _ => Nullability::Unknown,
        })
    }

    /// Judges a stored column or a set definition reached through a wildcard.
    fn definition(
        definition: &ColumnDefinition<'scope, 'query, 'database, DB>,
    ) -> Result<Nullability<'scope>, LookupError> {
        Ok(match definition {
            ColumnDefinition::Base {
                table,
                column,
                database,
            } => {
                if column.is_nullable(database)? {
                    Nullability::Nullable(Culprit::Column(
                        (*table).table_name(),
                        (*column).column_name(),
                    ))
                } else {
                    Nullability::NotNull
                }
            }
            ColumnDefinition::SetOperation {
                operator,
                left,
                right,
            } => {
                let left = Self::definition(&left.definition())?;
                match operator {
                    SetOperator::Union => left.union(Self::definition(&right.definition())?),
                    SetOperator::Intersect => {
                        left.intersect(Self::definition(&right.definition())?)
                    }
                    SetOperator::Except | SetOperator::Minus => left,
                }
            }
            _ => Nullability::Unknown,
        })
    }

    /// Judges an expression using the select scope that defines its columns.
    fn expression(
        &mut self,
        select: Option<&'scope Select>,
        expression: &'scope Expr,
    ) -> Result<Nullability<'scope>, LookupError> {
        Ok(match expression {
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => match select {
                Some(select) => self.column(select, expression)?,
                None => Nullability::Unknown,
            },
            Expr::Value(value) => {
                if matches!(value.value, Value::Null) {
                    Nullability::Nullable(Culprit::Expression(expression))
                } else {
                    Nullability::NotNull
                }
            }
            Expr::Nested(inner)
            | Expr::Cast {
                kind: CastKind::Cast | CastKind::DoubleColon,
                expr: inner,
                ..
            }
            | Expr::UnaryOp {
                op: UnaryOperator::Plus | UnaryOperator::Minus | UnaryOperator::Not,
                expr: inner,
            } => self.expression(select, inner)?,
            Expr::BinaryOp { left, op, right } => {
                let (left_strict, right_strict) =
                    strictness(self.database, self.types, expression, op)?;
                match (
                    self.expression(select, left)?,
                    self.expression(select, right)?,
                ) {
                    (nullable @ Nullability::Nullable(_), _) if left_strict => nullable,
                    (_, nullable @ Nullability::Nullable(_)) if right_strict => nullable,
                    _ if extracts_part(op) => {
                        Nullability::Nullable(Culprit::Expression(expression))
                    }
                    (Nullability::NotNull, Nullability::NotNull) if yields_value_for_values(op) => {
                        Nullability::NotNull
                    }
                    _ => Nullability::Unknown,
                }
            }
            Expr::IsNull(_)
            | Expr::IsNotNull(_)
            | Expr::IsTrue(_)
            | Expr::IsNotTrue(_)
            | Expr::IsFalse(_)
            | Expr::IsNotFalse(_)
            | Expr::IsUnknown(_)
            | Expr::IsNotUnknown(_)
            | Expr::IsDistinctFrom(_, _)
            | Expr::IsNotDistinctFrom(_, _)
            | Expr::Exists { .. } => Nullability::NotNull,
            Expr::Case {
                conditions,
                else_result,
                ..
            } => {
                let Some(otherwise) = else_result else {
                    return Ok(Nullability::Nullable(Culprit::Expression(expression)));
                };
                let mut result = self.expression(select, otherwise)?;
                for condition in conditions {
                    result = result.union(self.expression(select, &condition.result)?);
                }
                result
            }
            Expr::Function(call) => self.call(select, expression, call)?,
            Expr::Subquery(query) => match query.body.as_ref() {
                SetExpr::Select(inner) if scalar_output_is_single(query, inner) => {
                    self.query(query)?
                }
                _ => Nullability::Nullable(Culprit::Expression(expression)),
            },
            _ => Nullability::Unknown,
        })
    }

    /// Judges recognized null-handling functions and aggregates.
    fn call(
        &mut self,
        select: Option<&'scope Select>,
        expression: &'scope Expr,
        call: &'scope sqlparser::ast::Function,
    ) -> Result<Nullability<'scope>, LookupError> {
        let [ObjectNamePart::Identifier(name)] = call.name.0.as_slice() else {
            return Ok(Nullability::Unknown);
        };
        let named = |expected: &str| same_name(name, expected, false);
        Ok(if named("nullif") {
            Nullability::Nullable(Culprit::Expression(expression))
        } else if named("count") {
            Nullability::NotNull
        } else if named("coalesce") {
            let FunctionArguments::List(arguments) = &call.args else {
                return Ok(Nullability::Unknown);
            };
            let mut result = Nullability::Nullable(Culprit::Expression(expression));
            for argument in &arguments.args {
                let FunctionArg::Unnamed(FunctionArgExpr::Expr(argument)) = argument else {
                    return Ok(Nullability::Unknown);
                };
                result = result.intersect(self.expression(select, argument)?);
            }
            result
        } else if is_aggregate(call) {
            let ungrouped = select.is_none_or(|select| {
                matches!(&select.group_by, GroupByExpr::Expressions(expressions, _) if expressions.is_empty())
            });
            if call.filter.is_some() || call.over.is_some() || ungrouped {
                Nullability::Nullable(Culprit::Expression(expression))
            } else if named("array_agg") || named("json_agg") || named("jsonb_agg") {
                Nullability::NotNull
            } else if let FunctionArguments::List(arguments) = &call.args
                && let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(argument))) =
                    arguments.args.first()
            {
                self.expression(select, argument)?
            } else {
                Nullability::Unknown
            }
        } else {
            let (database, types) = (self.database, self.types);
            find_null_passing_argument(database, types, expression, |argument| {
                Ok(match self.expression(select, argument)? {
                    nullable @ Nullability::Nullable(_) => Some(nullable),
                    Nullability::NotNull | Nullability::Unknown => None,
                })
            })?
            .unwrap_or(Nullability::Unknown)
        })
    }

    /// Follows a bound column through filters, joins and derived projections.
    fn column(
        &mut self,
        select: &'scope Select,
        output: &'scope Expr,
    ) -> Result<Nullability<'scope>, LookupError> {
        let Some((definition, binding)) = self.types.reference(output)? else {
            return Ok(Nullability::Unknown);
        };
        if let Some(entry) = binding.entry() {
            if excludes_null(self.database, self.types, select, entry)? {
                return Ok(Nullability::NotNull);
            }
            if select
                .from
                .iter()
                .any(|joined| null_extended(joined, entry.factor(), false))
            {
                return Ok(match definition {
                    ColumnDefinition::Base { table, column, .. } => Nullability::Nullable(
                        Culprit::Column(table.table_name(), column.column_name()),
                    ),
                    _ => Nullability::Nullable(Culprit::Expression(output)),
                });
            }
            if self
                .visited
                .iter()
                .any(|previous| std::ptr::eq(*previous, output))
            {
                return Ok(Nullability::Unknown);
            }
            self.visited.push(output);
            let result = match entry.factor() {
                TableFactor::Derived { subquery, .. } => self.projected(subquery, entry.ordinal()),
                factor => match read_item(&self.visible, self.visible_head, factor) {
                    Some((item, clause_position, item_position)) => {
                        let parent = self.visible_head;
                        let length = self.visible[clause_position].length;
                        self.visible_head = Some(clause_position);
                        if !self.visible[clause_position].clause.recursive {
                            self.visible[clause_position].length = item_position;
                        }
                        let result = self.projected(&item.query, entry.ordinal());
                        self.visible[clause_position].length = length;
                        self.visible_head = parent;
                        match result? {
                            Nullability::Unknown => Self::definition(&definition),
                            result => Ok(result),
                        }
                    }
                    None => Self::definition(&definition),
                },
            };
            self.visited.pop();
            return result;
        }
        Self::definition(&definition)
    }

    /// Judges a selected output position within a query's visibility boundary.
    fn projected(
        &mut self,
        query: &'scope Query,
        ordinal: usize,
    ) -> Result<Nullability<'scope>, LookupError> {
        let length = self.visible.len();
        let parent = self.visible_head;
        if let Some(with) = &query.with {
            self.visible.push(WithScope {
                clause: with,
                length: with.cte_tables.len(),
                parent,
            });
            self.visible_head = Some(length);
        }
        let result = self.projected_body(&query.body, ordinal);
        self.visible.truncate(length);
        self.visible_head = parent;
        result
    }

    /// Follows one output position through parenthesized and set-operation bodies.
    fn projected_body(
        &mut self,
        body: &'scope SetExpr,
        ordinal: usize,
    ) -> Result<Nullability<'scope>, LookupError> {
        match body {
            SetExpr::Select(select) => match select.projection.get(ordinal) {
                Some(
                    SelectItem::UnnamedExpr(expression)
                    | SelectItem::ExprWithAlias {
                        expr: expression, ..
                    },
                ) => self.expression(Some(select), expression),
                _ => Ok(Nullability::Unknown),
            },
            SetExpr::Query(query) => self.projected(query, ordinal),
            SetExpr::SetOperation {
                op,
                left,
                right,
                set_quantifier,
            } => {
                let left = self.projected_body(left, ordinal)?;
                Ok(match op {
                    SetOperator::Union => left.union(self.projected_body(right, ordinal)?),
                    SetOperator::Intersect => left.intersect(self.projected_body(right, ordinal)?),
                    SetOperator::Except | SetOperator::Minus
                        if ordinal == 0
                            && matches!(
                                set_quantifier,
                                SetQuantifier::None | SetQuantifier::Distinct
                            )
                            && guaranteed_null(right) =>
                    {
                        Nullability::NotNull
                    }
                    SetOperator::Except | SetOperator::Minus => left,
                })
            }
            _ => Ok(Nullability::Unknown),
        }
    }
}

/// Whether a call names one of the recognized aggregate functions.
fn is_aggregate(call: &sqlparser::ast::Function) -> bool {
    let [ObjectNamePart::Identifier(name)] = call.name.0.as_slice() else {
        return false;
    };
    [
        "count",
        "min",
        "max",
        "sum",
        "avg",
        "array_agg",
        "string_agg",
        "bool_and",
        "bool_or",
        "every",
        "json_agg",
        "jsonb_agg",
    ]
    .iter()
    .any(|expected| same_name(name, expected, false))
}

/// Finds an aggregate in an output without counting nested subqueries.
struct AggregateOutput {
    depth: usize,
    aggregate: fn(&sqlparser::ast::Function) -> bool,
}

impl Visitor for AggregateOutput {
    type Break = ();

    /// Excludes aggregates belonging to nested queries.
    fn pre_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    /// Restores the enclosing expression's query depth.
    fn post_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    /// Stops at an aggregate evaluated by the enclosing select.
    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if self.depth == 0
            && matches!(expression, Expr::Function(call) if call.over.is_none() && (self.aggregate)(call))
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Whether `projection` calls an aggregate `aggregate` recognizes outside
/// its nested queries.
pub(crate) fn projects_aggregate(
    projection: &[SelectItem],
    aggregate: fn(&sqlparser::ast::Function) -> bool,
) -> bool {
    projection.iter().any(|item| {
        walk(
            item,
            &mut AggregateOutput {
                depth: 0,
                aggregate,
            },
        )
        .is_break()
    })
}

/// Whether a scalar select returns one row even when its input is empty.
fn scalar_output_is_single(query: &Query, select: &Select) -> bool {
    query.limit_clause.is_none()
        && query.fetch.is_none()
        && select.having.is_none()
        && matches!(&select.group_by, GroupByExpr::Expressions(expressions, _) if expressions.is_empty())
        && ((select.from.is_empty() && select.selection.is_none())
            || projects_aggregate(&select.projection, is_aggregate))
}

/// Whether the body necessarily emits a null row that `EXCEPT` removes.
fn guaranteed_null(body: &SetExpr) -> bool {
    match body {
        SetExpr::Query(query) if query.limit_clause.is_none() && query.fetch.is_none() => {
            guaranteed_null(&query.body)
        }
        SetExpr::Select(select)
            if select.from.is_empty() && select.selection.is_none() && select.having.is_none() =>
        {
            matches!(select.projection.as_slice(),
                [SelectItem::UnnamedExpr(expression) | SelectItem::ExprWithAlias { expr: expression, .. }]
                    if is_null_literal(expression))
        }
        SetExpr::Values(values) => values
            .rows
            .iter()
            .any(|row| matches!(row.as_slice(), [expression] if is_null_literal(expression))),
        _ => false,
    }
}

/// Whether a column's range-table entry is null-extended by a join.
pub(crate) fn null_extended(
    joined: &TableWithJoins,
    target: &TableFactor,
    inherited: bool,
) -> bool {
    let extends_left = |operator: &JoinOperator| {
        matches!(
            operator,
            JoinOperator::Right(_) | JoinOperator::RightOuter(_) | JoinOperator::FullOuter(_)
        )
    };
    let relation_extended = inherited
        || joined
            .joins
            .iter()
            .any(|join| extends_left(&join.join_operator));
    if factor_extended(&joined.relation, target, relation_extended) {
        return true;
    }
    joined.joins.iter().enumerate().any(|(position, join)| {
        let extended = inherited
            || matches!(
                join.join_operator,
                JoinOperator::Left(_) | JoinOperator::LeftOuter(_) | JoinOperator::FullOuter(_)
            )
            || joined.joins[position + 1..]
                .iter()
                .any(|later| extends_left(&later.join_operator));
        factor_extended(&join.relation, target, extended)
    })
}

/// Applies inherited null extension to a factor and its nested joins.
fn factor_extended(factor: &TableFactor, target: &TableFactor, extended: bool) -> bool {
    (extended && std::ptr::eq(factor, target))
        || match factor {
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => null_extended(table_with_joins, target, extended),
            _ => false,
        }
}

/// Whether an expression is a column reference to the bound column of
/// `entry`.
fn bound_to<DB: DatabaseLike>(
    types: &ExpressionContext<'_, '_, DB>,
    entry: RangeTableEntry<'_>,
) -> impl Fn(&Expr) -> Result<bool, LookupError> {
    move |expression| {
        Ok(types
            .reference(expression)?
            .is_some_and(|(_, binding)| binding.entry() == Some(entry)))
    }
}

/// Whether a filter rejects a null value of this exact bound column.
fn excludes_null<DB: DatabaseLike>(
    database: &DB,
    types: &ExpressionContext<'_, '_, DB>,
    select: &Select,
    entry: RangeTableEntry<'_>,
) -> Result<bool, LookupError> {
    let bound = bound_to(types, entry);
    for filter in select.selection.iter().flat_map(conjuncts) {
        if rejects_null(filter, &bound, database, types)? {
            return Ok(true);
        }
    }
    for joined in &select.from {
        if join_rejects_null(database, types, joined, entry)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Finds inner-join predicates whose effect survives subsequent outer joins.
fn join_rejects_null<DB: DatabaseLike>(
    database: &DB,
    types: &ExpressionContext<'_, '_, DB>,
    joined: &TableWithJoins,
    entry: RangeTableEntry<'_>,
) -> Result<bool, LookupError> {
    let bound = bound_to(types, entry);
    if let TableFactor::NestedJoin {
        table_with_joins, ..
    } = &joined.relation
        && !null_extended(joined, entry.factor(), false)
        && join_rejects_null(database, types, table_with_joins, entry)?
    {
        return Ok(true);
    }
    for (position, join) in joined.joins.iter().enumerate() {
        if joined.joins[position + 1..].iter().any(|later| {
            matches!(
                later.join_operator,
                JoinOperator::Right(_) | JoinOperator::RightOuter(_) | JoinOperator::FullOuter(_)
            )
        }) {
            continue;
        }
        if let JoinOperator::Join(JoinConstraint::On(filter))
        | JoinOperator::Inner(JoinConstraint::On(filter)) = &join.join_operator
        {
            for filter in conjuncts(filter) {
                if rejects_null(filter, &bound, database, types)? {
                    return Ok(true);
                }
            }
        }
        if let TableFactor::NestedJoin {
            table_with_joins, ..
        } = &join.relation
            && !null_extended(joined, entry.factor(), false)
            && join_rejects_null(database, types, table_with_joins, entry)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Resolves a `WITH` item and the visibility boundary inside its definition.
fn read_item<'query>(
    visible: &[WithScope<'query>],
    mut current: Option<usize>,
    factor: &TableFactor,
) -> Option<(&'query Cte, usize, usize)> {
    let TableFactor::Table { name, .. } = factor else {
        return None;
    };
    let [ObjectNamePart::Identifier(written)] = name.0.as_slice() else {
        return None;
    };
    while let Some(position) = current {
        let frame = &visible[position];
        if let Some(item_position) =
            frame.clause.cte_tables[..frame.length]
                .iter()
                .position(|item| {
                    same_name(
                        &item.alias.name,
                        &written.value,
                        written.quote_style.is_some(),
                    )
                })
        {
            return Some((
                &frame.clause.cte_tables[item_position],
                position,
                item_position,
            ));
        }
        current = frame.parent;
    }
    None
}

/// Whether `ident` and the name `value` denote the same identifier.
fn same_name(ident: &Ident, value: &str, quoted: bool) -> bool {
    identifiers_match(&ident.value, ident.quote_style.is_some(), value, quoted)
}

/// Collects the `NOT IN` subqueries and `NULL` lists of a node.
struct NotIns<'db, DB: DatabaseLike> {
    database: &'db DB,
    found: Vec<NotIn>,
}

impl<DB: DatabaseLike> Visitor for NotIns<'_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        let operand = match expression {
            Expr::In {
                target: InTarget::Subquery(query),
                negated: true,
                ..
            } => match nullable_output(self.database, query) {
                Ok(nullable) => NotInOperand::Subquery(nullable),
                Err(error) => return ControlFlow::Break(error),
            },
            Expr::In {
                target: InTarget::List(list),
                negated: true,
                ..
            } if list.iter().any(is_null_literal) => NotInOperand::NullList,
            Expr::AllOp {
                compare_op: BinaryOperator::NotEq,
                right,
                ..
            } if is_null_array(right) => NotInOperand::NullList,
            _ => return ControlFlow::Continue(()),
        };
        self.found.push(NotIn {
            expression: expression.to_string(),
            operand,
        });
        ControlFlow::Continue(())
    }
}

/// The `NOT IN` subqueries and `NULL` lists a node holds.
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
