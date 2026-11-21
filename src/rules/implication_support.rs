//! Whether a filter implies the conditions of row-level-security policies,
//! compared as written once the columns each tests go by one name.

use std::{borrow::Cow, mem, ops::ControlFlow};

use sql_traits::{errors::LookupError, structs::RowGate, traits::DatabaseLike};
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArguments, Ident, InTarget, Query, SelectItem, SetExpr, Value,
    Visit, VisitMut, VisitorMut, visit_expressions,
};

use crate::{
    deployment::Deployment,
    rules::{
        closed_set_support::stored_name,
        policy_support::{
            conjuncts, disjuncts, is_column_reference, is_tautology, unnested, unwrapped,
        },
    },
};

/// How the columns a policy condition tests map onto those a filter tests.
pub(crate) trait Columns {
    /// The condition columns a set membership tests.
    type Tested;

    /// The deployment declaring which sets lie within which.
    fn deployment(&self) -> &Deployment;

    /// The name the filter gives the condition column stored as `column`.
    fn rename(&self, column: Cow<'_, str>) -> Option<String>;

    /// The condition columns `column` names, when it names one the filter can
    /// test.
    fn tested(&self, column: &Expr) -> Option<Self::Tested>;

    /// Whether the filter column `column` is one of `tested`.
    fn tests(&self, column: &Expr, tested: &Self::Tested) -> bool;

    /// Whether `clause` alone meets every condition.
    fn settles(&self, _clause: &Expr) -> bool {
        false
    }
}

/// A policy condition as a filter would state it.
pub(crate) struct Condition<'e, T> {
    /// The condition with each column it tests named as the filter names it,
    /// when the filter names every one.
    renamed: Option<Expr>,
    /// The columns the condition tests against a set, and the expression
    /// yielding the members of the set.
    membership: Option<(T, &'e Expr)>,
    /// The conjuncts of an `AND`, each implied for the whole.
    pub(crate) parts: Vec<Self>,
    /// The arms of an `OR`, one implied for the whole.
    arms: Vec<Self>,
}

impl<'e, T> Condition<'e, T> {
    /// `condition` as a filter naming columns as `columns` does would state
    /// it, split into its conjuncts and arms.
    pub(crate) fn new<C: Columns<Tested = T>>(columns: &C, condition: &'e Expr) -> Self {
        let condition = unnested(condition);
        let split = |operands: Vec<&'e Expr>| {
            if operands.len() > 1 {
                operands
                    .into_iter()
                    .map(|operand| Self::new(columns, operand))
                    .collect()
            } else {
                Vec::new()
            }
        };
        Self {
            renamed: renamed(condition, |column| {
                stored_name(column).and_then(|name| columns.rename(name))
            }),
            membership: membership(condition)
                .and_then(|(column, members)| Some((columns.tested(column)?, members))),
            parts: split(conjuncts(condition)),
            arms: split(disjuncts(condition)),
        }
    }
}

/// Whether every row `clause` admits meets `condition`, as when the clause
/// settles it, states it, tests the same column against a set within the
/// condition's, implies it in every arm or in one of its conjuncts, or
/// implies each conjunct or one arm of `condition`.
pub(crate) fn clause_implies<C: Columns>(
    columns: &C,
    clause: &Expr,
    condition: &Condition<'_, C::Tested>,
) -> bool {
    let clause = unnested(clause);
    if columns.settles(clause) {
        return true;
    }
    if let Some(stated) = &condition.renamed
        && renamed(clause, |column| stored_name(column).map(Cow::into_owned)).as_ref()
            == Some(stated)
    {
        return true;
    }
    if let Some((tested, wider)) = &condition.membership
        && let Some((column, members)) = membership(clause)
        && columns.tests(column, tested)
        && columns.deployment().is_set_within(members, wider)
    {
        return true;
    }
    let arms = disjuncts(clause);
    if arms.len() > 1
        && arms
            .iter()
            .all(|arm| clause_implies(columns, arm, condition))
    {
        return true;
    }
    if !condition.parts.is_empty()
        && condition
            .parts
            .iter()
            .all(|part| clause_implies(columns, clause, part))
    {
        return true;
    }
    let parts = conjuncts(clause);
    (parts.len() > 1
        && parts
            .iter()
            .any(|part| clause_implies(columns, part, condition)))
        || condition
            .arms
            .iter()
            .any(|arm| clause_implies(columns, clause, arm))
}

/// Whether `gates` admit every row of `table` that meets each condition
/// `implied` accepts, which holds when every restrictive term and one
/// permissive term of each gate is a tautology or accepted.
pub(crate) fn admits<DB: DatabaseLike, C: Columns>(
    database: &DB,
    table: &DB::Table,
    gates: &[RowGate<'_, DB::Policy>],
    columns: &C,
    implied: impl Fn(&Condition<'_, C::Tested>) -> bool,
) -> Result<bool, LookupError> {
    let holds = |condition: &Expr| -> Result<bool, LookupError> {
        Ok(is_tautology(database, table, condition)?
            || implied(&Condition::new(columns, condition)))
    };
    for gate in gates {
        for term in gate.restrictive() {
            if !holds(term.expression().expression())? {
                return Ok(false);
            }
        }
        let mut admitted = false;
        for term in gate.permissive() {
            if holds(term.expression().expression())? {
                admitted = true;
                break;
            }
        }
        if !admitted {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `expression` is a column reference, bare or qualified.
pub(crate) fn is_column(expression: &Expr) -> bool {
    is_column_reference(unwrapped(expression))
}

/// Whether `node` mentions a column, which in a policy can be one of the
/// row's.
fn references_column<V: Visit>(node: &V) -> bool {
    visit_expressions(node, |expression| {
        if is_column(expression) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .is_break()
}

/// `expression` with every column reference named, quoted, by `rename`, and
/// every scalar subquery that reads no relation, such as
/// `(SELECT auth.uid())`, replaced by the value it projects. `None` when
/// `rename` names none for a column or a subquery reads a column, which may
/// resolve to another table's.
pub(crate) fn renamed(expression: &Expr, rename: impl Fn(&Expr) -> Option<String>) -> Option<Expr> {
    struct Renamer<F> {
        rename: F,
        depth: usize,
    }

    impl<F: Fn(&Expr) -> Option<String>> VisitorMut for Renamer<F> {
        type Break = ();

        fn pre_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            self.depth += 1;
            ControlFlow::Continue(())
        }

        fn post_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            self.depth -= 1;
            ControlFlow::Continue(())
        }

        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            if let Expr::Subquery(query) = expression
                && sole_item(query).is_some()
                && let SetExpr::Select(select) = query.body.as_mut()
                && let [
                    SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. },
                ] = select.projection.as_mut_slice()
            {
                *expression = mem::replace(value, Expr::Value(Value::Null.into()));
                return ControlFlow::Continue(());
            }
            if !is_column_reference(expression) {
                return ControlFlow::Continue(());
            }
            if self.depth > 0 {
                return ControlFlow::Break(());
            }
            match (self.rename)(expression) {
                Some(name) => {
                    *expression = Expr::Identifier(Ident::with_quote('"', name));
                    ControlFlow::Continue(())
                }
                None => ControlFlow::Break(()),
            }
        }
    }

    let mut renamed = expression.clone();
    VisitMut::visit(&mut renamed, &mut Renamer { rename, depth: 0 })
        .is_continue()
        .then_some(renamed)
}

/// The expression yielding the values `value` holds as the operand of `=`,
/// when it reads no column.
fn value_members(value: &Expr) -> Option<&Expr> {
    match unwrapped(value) {
        Expr::Subquery(query) => query_members(query),
        value => (!references_column(value)).then_some(value),
    }
}

/// The expression yielding the rows of `query`, when the query projects it
/// alone and reads, filters and limits nothing.
fn query_members(query: &Query) -> Option<&Expr> {
    sole_item(query).and_then(value_members)
}

/// The one expression `query` projects, when it reads, filters and limits
/// nothing, so it yields that value in one row.
fn sole_item(query: &Query) -> Option<&Expr> {
    if let SetExpr::Select(select) = query.body.as_ref()
        && let [SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. }] =
            select.projection.as_slice()
        && query.with.is_none()
        && query.limit_clause.is_none()
        && query.fetch.is_none()
        && query.pipe_operators.is_empty()
        && select.from.is_empty()
        && select.selection.is_none()
        && select.having.is_none()
    {
        Some(value)
    } else {
        None
    }
}

/// The expression yielding the elements of `array` as the operand of
/// `= ANY`, when it reads no column.
fn array_members(array: &Expr) -> Option<&Expr> {
    let array = unwrapped(array);
    if let Expr::Function(function) = array
        && function.name.to_string().eq_ignore_ascii_case("array")
        && let FunctionArguments::Subquery(query) = &function.args
    {
        return query_members(query);
    }
    (!references_column(array)).then_some(array)
}

/// The column `condition` tests against a set with `=`, `= ANY` or `IN`,
/// and the expression yielding the members of the set. Column types keep
/// one expression from yielding a value in one spelling and an array in
/// another.
fn membership(condition: &Expr) -> Option<(&Expr, &Expr)> {
    match unwrapped(condition) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => [(left, right), (right, left)]
            .into_iter()
            .find_map(|(column, value)| {
                if is_column(column) {
                    Some((column.as_ref(), value_members(value)?))
                } else {
                    None
                }
            }),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } if is_column(left) => Some((left, array_members(right)?)),
        Expr::In {
            expr,
            target: InTarget::Subquery(query),
            negated: false,
            ..
        } if is_column(expr) => Some((expr, query_members(query)?)),
        _ => None,
    }
}
