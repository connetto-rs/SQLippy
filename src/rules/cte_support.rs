//! The `WITH` items a walk over a query can see, the item a relation name
//! reads, and the terms of a recursive item, shared by the rules on common
//! table expressions.

use std::{iter, ops::ControlFlow, ptr};

use sql_traits::utils::identifier_resolution::identifiers_match;
use sqlparser::ast::{
    Cte, Expr, Ident, JoinConstraint, JoinOperator, ObjectName, ObjectNamePart, Query, Select,
    SelectItem, SetExpr, SetOperator, SetQuantifier, TableFactor, Visitor,
};

use crate::rules::{
    policy_support::{conjuncts, unnested},
    walk_support::walk,
};

/// The `WITH` items visible where a walk over a query stands, scoped as
/// PostgreSQL scopes them.
///
/// An item's body sees the items before it, or every item under `WITH
/// RECURSIVE`, and the rest of the query sees them all, so a body naming its
/// own item reads the stored relation unless the `WITH` is recursive. The
/// walk calls [`enter`](Self::enter) before visiting each query and
/// [`leave`](Self::leave) after it.
#[derive(Default)]
pub(crate) struct WithScopes {
    frames: Vec<WithFrame>,
}

/// The items one `WITH` clause binds, identified by address since the walk
/// borrows each query only for the length of one visit.
struct WithFrame {
    owner: *const Query,
    bodies: Vec<*const Query>,
    names: Vec<Ident>,
    recursive: bool,
    /// How many items, from the first, the walk currently sees.
    visible: usize,
    /// The item whose body the walk stands in.
    current: Option<usize>,
}

/// The `WITH` item a relation name reads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ItemBinding {
    /// The address of the query whose `WITH` clause holds the item.
    pub(crate) owner: *const Query,
    /// The item's position in that clause.
    pub(crate) item: usize,
    /// Whether the name stands inside the item's own body.
    pub(crate) in_own_body: bool,
}

impl WithScopes {
    pub(crate) fn enter(&mut self, query: &Query) {
        if let Some(frame) = self.frames.last_mut()
            && let Some(position) = frame.bodies.iter().position(|body| ptr::eq(*body, query))
        {
            frame.visible = if frame.recursive {
                frame.names.len()
            } else {
                position
            };
            frame.current = Some(position);
        }
        if let Some(with) = &query.with {
            self.frames.push(WithFrame {
                owner: query,
                bodies: with
                    .cte_tables
                    .iter()
                    .map(|item| &raw const *item.query)
                    .collect(),
                names: with
                    .cte_tables
                    .iter()
                    .map(|item| item.alias.name.clone())
                    .collect(),
                recursive: with.recursive,
                visible: 0,
                current: None,
            });
        }
    }

    pub(crate) fn leave(&mut self, query: &Query) {
        if self
            .frames
            .last()
            .is_some_and(|frame| ptr::eq(frame.owner, query))
        {
            self.frames.pop();
        }
        if let Some(frame) = self.frames.last_mut()
            && let Some(position) = frame.bodies.iter().position(|body| ptr::eq(*body, query))
        {
            frame.current = None;
            if !frame.recursive {
                frame.visible = position + 1;
            }
        }
    }

    /// The visible `WITH` item `name` reads, or `None` for a stored relation.
    /// A schema-qualified name never reads an item.
    pub(crate) fn binding(&self, name: &ObjectName) -> Option<ItemBinding> {
        let [ObjectNamePart::Identifier(written)] = name.0.as_slice() else {
            return None;
        };
        self.unqualified_binding(written)
    }

    /// The visible `WITH` item the unqualified name `written` reads, or
    /// `None` for a stored relation.
    pub(crate) fn unqualified_binding(&self, written: &Ident) -> Option<ItemBinding> {
        self.frames.iter().rev().find_map(|frame| {
            frame.names[..frame.visible]
                .iter()
                .position(|item| same_name(item, written))
                .map(|item| ItemBinding {
                    owner: frame.owner,
                    item,
                    in_own_body: frame.current == Some(item),
                })
        })
    }
}

/// Whether two written identifiers name the same object.
pub(crate) fn same_name(left: &Ident, right: &Ident) -> bool {
    identifiers_match(
        &left.value,
        left.quote_style.is_some(),
        &right.value,
        right.quote_style.is_some(),
    )
}

/// Whether a `WITH` item's body is an `INSERT`, `UPDATE`, `DELETE` or
/// `MERGE`, which PostgreSQL runs whether or not anything reads the item.
pub(crate) fn modifies_data(item: &Cte) -> bool {
    matches!(
        item.query.body.as_ref(),
        SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_) | SetExpr::Merge(_)
    )
}

/// Calls `read` with each unqualified name the `TABLE` commands of a set
/// expression read, leaving nested queries to their own visit.
pub(crate) fn table_commands(body: &SetExpr, read: &mut dyn FnMut(&Ident)) {
    match body {
        SetExpr::Table(table) if table.schema_name.is_none() => {
            if let Some(name) = &table.table_name {
                read(name);
            }
        }
        SetExpr::SetOperation { left, right, .. } => {
            table_commands(left, read);
            table_commands(right, read);
        }
        _ => {}
    }
}

/// A `WITH RECURSIVE` item split into the terms PostgreSQL iterates.
pub(crate) struct RecursiveItem<'q> {
    /// Whether `UNION ALL` combines the terms, so no repeated row is dropped.
    pub(crate) keeps_duplicates: bool,
    /// The recursive term.
    pub(crate) term: &'q Select,
    /// The name the recursive term reads the working table by.
    pub(crate) working: &'q Ident,
    /// The item's output column names by position, `None` where the
    /// non-recursive term leaves one unnamed.
    pub(crate) columns: Vec<Option<&'q Ident>>,
}

impl<'q> RecursiveItem<'q> {
    /// The terms of `item` from a `WITH RECURSIVE` clause, or `None` when its
    /// body is not a `UNION` whose right term reads the item.
    pub(crate) fn split(item: &'q Cte) -> Option<Self> {
        let SetExpr::SetOperation {
            op: SetOperator::Union,
            set_quantifier,
            left,
            right,
        } = item.query.body.as_ref()
        else {
            return None;
        };
        let keeps_duplicates = match set_quantifier {
            SetQuantifier::All => true,
            SetQuantifier::None | SetQuantifier::Distinct => false,
            _ => return None,
        };
        let term = single_select(right)?;
        let working = term
            .from
            .iter()
            .flat_map(|from| {
                iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
            })
            .find_map(|factor| match factor {
                TableFactor::Table { name, alias, .. } => match name.0.as_slice() {
                    [ObjectNamePart::Identifier(written)]
                        if same_name(written, &item.alias.name) =>
                    {
                        Some(alias.as_ref().map_or(written, |alias| &alias.name))
                    }
                    _ => None,
                },
                _ => None,
            })?;
        let columns = if item.alias.columns.is_empty() {
            leftmost_select(left)
                .and_then(|anchor| {
                    anchor
                        .projection
                        .iter()
                        .map(|output| output_expression(output).map(|_| output_name(output)))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            item.alias
                .columns
                .iter()
                .map(|column| Some(&column.name))
                .collect()
        };
        Some(Self {
            keeps_duplicates,
            term,
            working,
            columns,
        })
    }

    /// The working table column `expression` reads as it stands.
    pub(crate) fn working_column<'e>(&self, expression: &'e Expr) -> Option<&'e Ident> {
        match unnested(expression) {
            Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                [table, column] if same_name(table, self.working) => Some(column),
                _ => None,
            },
            Expr::Identifier(column) if self.position(column).is_some() => Some(column),
            _ => None,
        }
    }

    /// Whether `expression` reads a column of the working table outside any
    /// subquery, whose own names may hide the working table's.
    pub(crate) fn reads_working(&self, expression: &Expr) -> bool {
        self.reads_working_where(expression, |_| true)
    }

    /// Whether `expression` reads, outside any subquery, a working table
    /// column that `accept` holds for.
    pub(crate) fn reads_working_where(
        &self,
        expression: &Expr,
        accept: impl Fn(&Ident) -> bool,
    ) -> bool {
        walk(
            expression,
            &mut WorkingReads {
                item: self,
                accept: &accept,
                depth: 0,
            },
        )
        .is_break()
    }

    /// The conjuncts every row the recursive term yields satisfies, from its
    /// `WHERE` and from the `ON` of its inner joins.
    pub(crate) fn conditions(&self) -> Vec<&'q Expr> {
        let joined = self
            .term
            .from
            .iter()
            .flat_map(|from| &from.joins)
            .filter_map(|join| match &join.join_operator {
                JoinOperator::Join(JoinConstraint::On(condition))
                | JoinOperator::Inner(JoinConstraint::On(condition)) => Some(condition),
                _ => None,
            });
        self.term
            .selection
            .iter()
            .chain(joined)
            .flat_map(conjuncts)
            .collect()
    }

    /// The output position of the item column `column` names.
    pub(crate) fn position(&self, column: &Ident) -> Option<usize> {
        self.columns
            .iter()
            .position(|name| name.is_some_and(|name| same_name(name, column)))
    }

    /// The recursive term's output expressions by position, or `None` when a
    /// wildcard or a multi-name alias hides how they line up with the item's
    /// columns.
    pub(crate) fn outputs(&self) -> Option<Vec<&'q Expr>> {
        self.term.projection.iter().map(output_expression).collect()
    }
}

/// Stops at the first working table column read outside a subquery that
/// `accept` holds for.
struct WorkingReads<'r, 'q> {
    item: &'r RecursiveItem<'q>,
    accept: &'r dyn Fn(&Ident) -> bool,
    depth: usize,
}

impl Visitor for WorkingReads<'_, '_> {
    type Break = ();

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if self.depth == 0
            && self
                .item
                .working_column(expression)
                .is_some_and(self.accept)
        {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// The `SELECT` a set expression is, through parentheses.
fn single_select(body: &SetExpr) -> Option<&Select> {
    match body {
        SetExpr::Select(select) => Some(select),
        SetExpr::Query(query) => single_select(&query.body),
        _ => None,
    }
}

/// The `SELECT` that names the columns of a set expression.
fn leftmost_select(body: &SetExpr) -> Option<&Select> {
    match body {
        SetExpr::Select(select) => Some(select),
        SetExpr::Query(query) => leftmost_select(&query.body),
        SetExpr::SetOperation { left, .. } => leftmost_select(left),
        _ => None,
    }
}

/// The expression a `SELECT` output computes, or `None` for a wildcard or a
/// multi-name alias, whose width the query alone does not tell.
fn output_expression(output: &SelectItem) -> Option<&Expr> {
    match output {
        SelectItem::UnnamedExpr(expression)
        | SelectItem::ExprWithAlias {
            expr: expression, ..
        } => Some(expression),
        SelectItem::ExprWithAliases { .. }
        | SelectItem::QualifiedWildcard(..)
        | SelectItem::Wildcard(_) => None,
    }
}

/// The name PostgreSQL gives a `SELECT` output, or `None` for one it leaves
/// unnamed.
fn output_name(output: &SelectItem) -> Option<&Ident> {
    match output {
        SelectItem::ExprWithAlias { alias, .. } => Some(alias),
        SelectItem::UnnamedExpr(Expr::Identifier(name)) => Some(name),
        SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => parts.last(),
        _ => None,
    }
}
