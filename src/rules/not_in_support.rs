//! `NOT IN` over a subquery or a list holding a `NULL`, shared by the rules
//! reporting it.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, TableLike},
    utils::identifier_resolution::identifiers_match,
};
use sqlparser::ast::{
    BinaryOperator, Cte, Expr, Ident, InTarget, ObjectNamePart, Query, Select, SelectItem, SetExpr,
    TableFactor, Visit, Visitor, With,
};

use crate::rules::{
    expression_site_support::{ExpressionFinder, is_null_literal},
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
    /// A subquery, with the nullable column it returns as `table.column`.
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

/// The nullable column a `NOT IN` subquery returns, unless a `WHERE` of the
/// subquery or of a `WITH` item the output passes through excludes `NULL`.
fn nullable_output<DB: DatabaseLike>(
    database: &DB,
    query: &Query,
) -> Result<Option<String>, LookupError> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Ok(None);
    };
    let [SelectItem::UnnamedExpr(output) | SelectItem::ExprWithAlias { expr: output, .. }] =
        select.projection.as_slice()
    else {
        return Ok(None);
    };
    let scope = ColumnScope::from_query(query, database, IdentifierCase::Folded)?;
    let Some(ColumnDefinition::Base { table, column, .. }) =
        scope.resolve_column_definition(output)?
    else {
        return Ok(None);
    };
    Ok(
        (!excludes_null(&scope, query, select, output)? && column.is_nullable(database)?)
            .then(|| format!("{}.{}", table.table_name(), column.column_name())),
    )
}

/// Whether a `WHERE` conjunct tests `output` of `query` with `IS NOT NULL`,
/// following the output into the `WITH` items it is read from.
fn excludes_null<DB: DatabaseLike>(
    scope: &ColumnScope<'_, '_, DB>,
    query: &Query,
    select: &Select,
    output: &Expr,
) -> Result<bool, LookupError> {
    let mut visible = Vec::new();
    let mut visited: Vec<(&Query, &Expr)> = Vec::new();
    let (mut query, mut select, mut output) = (query, select, output);
    loop {
        if visited.iter().any(|(previous_query, previous_output)| {
            std::ptr::eq(*previous_query, query) && std::ptr::eq(*previous_output, output)
        }) {
            return Ok(false);
        }
        visited.push((query, output));
        let rendered = output.to_string();
        if select.selection.iter().flat_map(conjuncts).any(
            |filter| matches!(filter, Expr::IsNotNull(tested) if tested.to_string() == rendered),
        ) {
            return Ok(true);
        }
        visible.extend(query.with.iter().map(|with| (with, with.cte_tables.len())));
        let Some(select_scope) = scope.scope_for_select(select) else {
            return Ok(false);
        };
        let Some((_, binding)) = select_scope.resolve_column_binding(output)? else {
            return Ok(false);
        };
        let Some(item) = binding
            .entry()
            .and_then(|entry| read_item(&mut visible, entry.factor()))
        else {
            return Ok(false);
        };
        let Some((next_select, next)) = binding
            .exposed()
            .and_then(|(name, quoted)| item_output(item, name, quoted))
        else {
            return Ok(false);
        };
        (query, select, output) = (&item.query, next_select, next);
    }
}

/// Resolves a `FROM` item and retains the clauses visible inside its body.
fn read_item<'query>(
    visible: &mut Vec<(&'query With, usize)>,
    factor: &TableFactor,
) -> Option<&'query Cte> {
    let TableFactor::Table { name, .. } = factor else {
        return None;
    };
    let [ObjectNamePart::Identifier(written)] = name.0.as_slice() else {
        return None;
    };
    let (clause_position, item_position) =
        visible
            .iter()
            .enumerate()
            .rev()
            .find_map(|(clause_position, (with, length))| {
                with.cte_tables[..*length]
                    .iter()
                    .position(|item| {
                        same_name(
                            &item.alias.name,
                            &written.value,
                            written.quote_style.is_some(),
                        )
                    })
                    .map(|item_position| (clause_position, item_position))
            })?;
    let with = visible[clause_position].0;
    visible.truncate(clause_position + 1);
    if !with.recursive {
        visible[clause_position].1 = item_position;
    }
    Some(&with.cte_tables[item_position])
}

/// A `WITH` item's `SELECT` and the expression it projects as its column
/// `name`.
fn item_output<'query>(
    item: &'query Cte,
    name: &str,
    quoted: bool,
) -> Option<(&'query Select, &'query Expr)> {
    let SetExpr::Select(select) = item.query.body.as_ref() else {
        return None;
    };
    let expression = |projected: &'query SelectItem| match projected {
        SelectItem::UnnamedExpr(expression)
        | SelectItem::ExprWithAlias {
            expr: expression, ..
        } => Some((select.as_ref(), expression)),
        _ => None,
    };
    if !item.alias.columns.is_empty() {
        let position = item
            .alias
            .columns
            .iter()
            .position(|column| same_name(&column.name, name, quoted))?;
        return select.projection.get(position).and_then(expression);
    }
    select.projection.iter().find_map(|projected| {
        let output_name = match projected {
            SelectItem::ExprWithAlias { alias, .. } => alias,
            SelectItem::UnnamedExpr(Expr::Identifier(column)) => column,
            SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => parts.last()?,
            _ => return None,
        };
        same_name(output_name, name, quoted)
            .then(|| expression(projected))
            .flatten()
    })
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
