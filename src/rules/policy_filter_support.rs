//! The comparisons a policy's `USING` clause filters rows by the caller
//! with, shared by the rules that ask whether PostgreSQL can find those rows
//! through an index.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnScope, IdentifierCase},
    traits::DatabaseLike,
};
use sqlparser::ast::{Expr, Query, Visit, Visitor};

use crate::{
    deployment::Deployment,
    rules::{
        index_support::{Side, comparison_sides},
        policy_support::{derives_from_caller, holds_caller, is_column_reference},
        walk_support::walk,
    },
};

/// Inspects the column side of a comparison, resolved through the scope it
/// stands in, and answers what a rule records for it.
type Probe<'p, DB, T> =
    dyn FnMut(&ColumnScope<'_, '_, DB>, &Expr) -> Result<Option<T>, LookupError> + 'p;

/// Finds a column reference.
struct ColumnReference;

impl Visitor for ColumnReference {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if is_column_reference(expression) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// The policy table and deployment a comparison's other side is judged
/// against.
struct Caller<'a, 'db, DB: DatabaseLike> {
    database: &'db DB,
    table: &'db DB::Table,
    deployment: &'a Deployment,
}

impl<DB: DatabaseLike> Caller<'_, '_, DB> {
    /// Whether a side derives from the caller, judged against the policy's
    /// row outside sublinks and with no column reference inside them.
    fn derives<V: Visit>(&self, node: &V, in_sublink: bool) -> Result<bool, LookupError> {
        if in_sublink {
            return Ok(holds_caller(self.deployment, node)
                && walk(node, &mut ColumnReference).is_continue());
        }
        derives_from_caller(self.database, self.table, self.deployment, node)
    }

    fn side(&self, side: Side<'_>, in_sublink: bool) -> Result<bool, LookupError> {
        match side {
            Side::Expr(expression) => self.derives(expression, in_sublink),
            Side::List(list) => self.derives(list, in_sublink),
            Side::Query(query) => self.derives(query, in_sublink),
        }
    }
}

/// The caller a comparison is judged against, with what the rule records
/// for each comparison by the caller.
struct Judge<'a, 'db, 'p, DB: DatabaseLike, T> {
    caller: Caller<'a, 'db, DB>,
    probe: &'a mut Probe<'p, DB, T>,
    found: Vec<(T, String)>,
}

impl<DB: DatabaseLike, T> Judge<'_, '_, '_, DB, T> {
    /// Records what the probe answers for each column side, resolved through
    /// `scope`, that `expression` compares with the caller.
    fn consider(
        &mut self,
        scope: &ColumnScope<'_, '_, DB>,
        expression: &Expr,
        in_sublink: bool,
    ) -> Result<(), LookupError> {
        let Self {
            caller,
            probe,
            found,
        } = self;
        comparison_sides(expression, |column, side| {
            if let Some(answer) = probe(scope, column)?
                && caller.side(side, in_sublink)?
            {
                found.push((answer, expression.to_string()));
            }
            Ok(())
        })
    }
}

/// Comparisons a policy expression filters by, outside sublinks.
struct Filters<'j, 'a, 'db, 'p, DB: DatabaseLike, T> {
    judge: &'j mut Judge<'a, 'db, 'p, DB, T>,
    scope: ColumnScope<'db, 'db, DB>,
    depth: usize,
}

/// Comparisons in the top-level query of one sublink.
struct SublinkFilters<'f, 'a, 'db, 'p, 'q, DB: DatabaseLike, T> {
    judge: &'f mut Judge<'a, 'db, 'p, DB, T>,
    local: ColumnScope<'q, 'db, DB>,
    depth: usize,
}

impl<DB: DatabaseLike, T> Visitor for SublinkFilters<'_, '_, '_, '_, '_, DB, T> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if self.depth != 1 {
            return ControlFlow::Continue(());
        }
        self.judge
            .consider(&self.local, expression, true)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

impl<DB: DatabaseLike, T> Visitor for Filters<'_, '_, '_, '_, DB, T> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        ColumnScope::from_query(query, self.judge.caller.database, IdentifierCase::Folded)
            .map_or_else(ControlFlow::Break, |local| {
                walk(
                    query,
                    &mut SublinkFilters {
                        judge: self.judge,
                        local,
                        depth: 0,
                    },
                )
            })
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if self.depth != 0 {
            return ControlFlow::Continue(());
        }
        self.judge
            .consider(&self.scope, expression, false)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// What `probe` answers for each column side the `USING` expression `using`
/// of a policy on `table` compares with the caller, with the comparison
/// rendered, in traversal order.
///
/// A side counts as the caller's when it derives from the caller alone: a
/// declared credential, a `current_setting` call, a read of the current role,
/// or a set computed from them. Comparisons of the policy's own level are
/// resolved against `table`, and those of each sublink's top-level query
/// against that query's scope, where a side reading any column does not count
/// as the caller's. The probe runs before the caller is judged.
pub(crate) fn caller_filters<DB: DatabaseLike, T>(
    database: &DB,
    table: &DB::Table,
    deployment: &Deployment,
    using: &Expr,
    probe: &mut Probe<'_, DB, T>,
) -> Result<Vec<(T, String)>, LookupError> {
    let mut judge = Judge {
        caller: Caller {
            database,
            table,
            deployment,
        },
        probe,
        found: Vec::new(),
    };
    let mut filters = Filters {
        judge: &mut judge,
        scope: ColumnScope::for_table(table, database, IdentifierCase::Folded),
        depth: 0,
    };
    walk(using, &mut filters)
        .break_value()
        .map_or(Ok(()), Err)?;
    Ok(judge.found)
}
