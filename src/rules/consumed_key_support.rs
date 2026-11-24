//! Keys an `AFTER` row trigger takes out of the set a check admits them from.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike, TriggerLike},
};
use sqlparser::ast::{
    AssignmentTarget, BinaryOperator, Expr, Ident, Query, ReferentialAction, Statement,
    TableFactor, TriggerEvent, TriggerPeriod, Update, VisitMut, VisitorMut,
};
use sqlparser_plpgsql::embedded::{Node, NodeKind};

use crate::{
    deployment::Deployment,
    rules::{
        closed_set_support::stored_name,
        cte_support::stored_table,
        function_reach_support::Reach,
        guarded_parent_support::always_runs,
        key_support::{checked_whenever_set, equality_keys, key_pairs},
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        policy_read_support::reads_every_row,
        policy_support::{acting, client_roles, is_column_reference, is_contradiction, unwrapped},
        trigger_support::{
            WritesTable, fires_for_clients, fires_on_insert, names_new_field, new_field, row,
            row_trigger, stored, stored_parts,
        },
    },
};

/// A row trigger of the written table that sets columns of the row of
/// another table each stored key names, for every row a client stores.
pub(crate) struct Consumption<'db, DB: DatabaseLike> {
    database: &'db DB,
    /// The written table.
    written: &'db DB::Table,
    /// The stored name of the written table's column holding the key.
    column: String,
    /// The table whose row the key names.
    table: &'db DB::Table,
    /// The stored name of the column of `table` that names the row.
    referenced: String,
    /// Each column of the named row the trigger sets, with the value it
    /// sets, `NEW`'s fields written as columns of the written table.
    assignments: Vec<(String, Expr)>,
}

impl<DB: DatabaseLike> Consumption<'_, DB> {
    /// The stored name of the written table's column holding the key.
    pub(crate) fn column(&self) -> &str {
        &self.column
    }

    /// Whether the row of `table` named by `column` is the row the trigger
    /// writes.
    pub(crate) fn names(&self, table: &DB::Table, column: &str) -> bool {
        self.table == table && self.referenced == column
    }

    /// Whether no row the trigger has written meets `fact`, a condition on
    /// the columns of the named row.
    pub(crate) fn rejects(&self, fact: &Expr) -> Result<bool, LookupError> {
        let Some(substituted) = substituted(fact, &self.assignments) else {
            return Ok(false);
        };
        is_contradiction(self.database, self.written, &substituted)
    }
}

/// The consumptions of `table`'s triggers whose written rows no client role
/// can bring back.
pub(crate) fn consumptions<'db, DB: DatabaseLike>(
    database: &'db DB,
    deployment: &Deployment,
    table: &'db DB::Table,
) -> Result<Vec<Consumption<'db, DB>>, LookupError> {
    let mut found = Vec::new();
    for trigger in table.triggers(database)? {
        if !row_trigger(trigger, TriggerPeriod::After)
            || !fires_on_insert(trigger)
            || !fires_for_clients(database, trigger)?
        {
            continue;
        }
        let Some(function) = trigger.function(database) else {
            continue;
        };
        let Some(block) = plpgsql_block(function) else {
            continue;
        };
        let mut body = Body::default();
        walk_block(&mut body, &block, Untracked);
        if body.dynamic {
            continue;
        }
        let mut candidates = body.statements.iter().filter_map(|statement| {
            consuming_update(database, table, statement).map(|found| (statement, found))
        });
        let (Some((statement, consumption)), None) = (candidates.next(), candidates.next()) else {
            continue;
        };
        let mut reach = Reach::new(database, WritesTable::new(database, consumption.table));
        let writes_elsewhere = body
            .statements
            .iter()
            .filter(|other| *other != statement)
            .any(|other| !reach.occurrences(other).is_empty())
            || body
                .queries
                .iter()
                .any(|query| !reach.occurrences(query).is_empty());
        if writes_elsewhere
            || !trigger
                .condition()
                .is_none_or(|condition| tests_key_set(condition, &consumption.column))
            || !always_runs(&block, "new", |run| run == statement)
            || !reads_every_row(database, function, consumption.table)?
            || !stays_written(database, deployment, trigger, &consumption)?
        {
            continue;
        }
        found.push(consumption);
    }
    Ok(found)
}

/// Whether `condition`, under parentheses, is `NEW.column IS NOT NULL`, which
/// skips only rows whose key no check compares.
fn tests_key_set(condition: &Expr, column: &str) -> bool {
    matches!(unwrapped(condition), Expr::IsNotNull(field) if names_new_field(field, column))
}

/// The consumption `statement` is, as `UPDATE other SET ... WHERE column =
/// NEW.key` over one table other than `table`, setting each column to a
/// value built from literals and `NEW`'s fields.
fn consuming_update<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
    statement: &Statement,
) -> Option<Consumption<'db, DB>> {
    let Statement::Update(Update {
        table: target,
        assignments,
        from: None,
        selection: Some(selection),
        returning: None,
        ..
    }) = statement
    else {
        return None;
    };
    let TableFactor::Table {
        name, args: None, ..
    } = &target.relation
    else {
        return None;
    };
    if !target.joins.is_empty() {
        return None;
    }
    let named = stored_table(database, name, None).ok()??;
    if named == table {
        return None;
    }
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = unwrapped(selection)
    else {
        return None;
    };
    let (referenced, column) = [(left, right), (right, left)]
        .into_iter()
        .find_map(|(referenced, key)| Some((updated_column(referenced)?, new_field(key)?)))?;
    let mut set = Vec::new();
    for assignment in assignments {
        let AssignmentTarget::ColumnName(target) = &assignment.target else {
            return None;
        };
        let assigned = stored_parts(target).pop()?.into_owned();
        if let Some(value) = written_value(&assignment.value) {
            set.push((assigned, value));
        }
    }
    Some(Consumption {
        database,
        written: table,
        column: column.into_owned(),
        table: named,
        referenced,
        assignments: set,
    })
}

/// The stored name of the column of the updated table `expression`, under
/// parentheses and casts, names bare or qualified by anything but a trigger
/// row.
fn updated_column(expression: &Expr) -> Option<String> {
    let name = match unwrapped(expression) {
        Expr::Identifier(name) => name,
        Expr::CompoundIdentifier(parts) => match parts.as_slice() {
            [qualifier, name] if row(qualifier).is_none() => name,
            _ => return None,
        },
        _ => return None,
    };
    Some(stored(name).into_owned())
}

/// `value` with each `NEW.field` written as the column `field`, or `None`
/// when it reads another column or a query.
fn written_value(value: &Expr) -> Option<Expr> {
    /// Rewrites `NEW`'s fields, breaking on any other column or a query.
    struct Fields;

    impl VisitorMut for Fields {
        type Break = ();

        fn pre_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            ControlFlow::Break(())
        }

        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            if !is_column_reference(expression) {
                return ControlFlow::Continue(());
            }
            let Some(field) = new_field(expression) else {
                return ControlFlow::Break(());
            };
            *expression = Expr::Identifier(Ident::new(field));
            ControlFlow::Continue(())
        }
    }

    let mut rewritten = value.clone();
    VisitMut::visit(&mut rewritten, &mut Fields)
        .is_continue()
        .then_some(rewritten)
}

/// `fact` with each column in `assignments` replaced by its value, or `None`
/// when it reads another column or a query.
fn substituted(fact: &Expr, assignments: &[(String, Expr)]) -> Option<Expr> {
    /// Replaces assigned columns, breaking on any other column or a query.
    struct Substitution<'a> {
        assignments: &'a [(String, Expr)],
    }

    impl VisitorMut for Substitution<'_> {
        type Break = ();

        fn pre_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            ControlFlow::Break(())
        }

        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            if !is_column_reference(expression) {
                return ControlFlow::Continue(());
            }
            let column = stored_name(expression);
            let Some((_, value)) = self
                .assignments
                .iter()
                .find(|(assigned, _)| column.as_deref() == Some(assigned.as_str()))
            else {
                return ControlFlow::Break(());
            };
            *expression = Expr::Nested(Box::new(value.clone()));
            ControlFlow::Continue(())
        }
    }

    let mut replaced = fact.clone();
    VisitMut::visit(&mut replaced, &mut Substitution { assignments })
        .is_continue()
        .then_some(replaced)
}

/// Whether no client role can bring a row `consumption` writes back or store
/// a key that bypasses `trigger`. A function a client calls that writes the
/// named table is not followed.
fn stays_written<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    trigger: &DB::Trigger,
    consumption: &Consumption<'_, DB>,
) -> Result<bool, LookupError> {
    let named = consumption.table;
    for other in named.triggers(database)? {
        if row_trigger(other, TriggerPeriod::Before)
            && other
                .events()
                .iter()
                .any(|event| matches!(event, TriggerEvent::Update(_)))
            && fires_for_clients(database, other)?
        {
            return Ok(false);
        }
    }
    let (Some(key), Some(referenced)) = (
        column_named(database, consumption.written, &consumption.column)?,
        column_named(database, named, &consumption.referenced)?,
    ) else {
        return Ok(false);
    };
    let mut assigned = Vec::new();
    for (name, _) in &consumption.assignments {
        let Some(column) = column_named(database, named, name)? else {
            return Ok(false);
        };
        assigned.push(column);
    }
    let follows_updates = trigger.events().iter().any(|event| {
        matches!(event, TriggerEvent::Update(columns)
            if columns.is_empty() || columns.iter().any(|column| stored(column) == consumption.column))
    });
    let (mut inserts, mut removes) = (false, false);
    for (_, role) in client_roles(database, deployment) {
        let on_named = named.privileges(acting(role), database)?;
        if on_named.update.on_column(referenced)
            || assigned
                .iter()
                .any(|column| on_named.update.on_column(column))
        {
            return Ok(false);
        }
        if !follows_updates
            && consumption
                .written
                .privileges(acting(role), database)?
                .update
                .on_column(key)
        {
            return Ok(false);
        }
        inserts |= on_named.insert.on_any_column();
        removes |= on_named.delete || on_named.truncate;
    }
    if !(inserts && removes) {
        return Ok(true);
    }
    // A removed row then comes back only once its referencing rows are gone.
    let unique = equality_keys(database, named)?
        .iter()
        .any(|columns| columns.as_slice() == [referenced]);
    if !unique {
        return Ok(false);
    }
    for foreign_key in consumption.written.foreign_keys(database)? {
        if foreign_key.referenced_table(database)? == named
            && key_pairs(database, foreign_key)?.contains(&(key, referenced))
            && checked_whenever_set(database, foreign_key, key)?
            && matches!(
                foreign_key.on_delete(database),
                ReferentialAction::Restrict
                    | ReferentialAction::Cascade
                    | ReferentialAction::SetNull
            )
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The column of `table` whose stored name is `name`.
fn column_named<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
    name: &str,
) -> Result<Option<&'db DB::Column>, LookupError> {
    Ok(table
        .columns(database)?
        .find(|column| column.stored_column_name() == Cow::Borrowed(name)))
}

/// A path state carrying nothing.
#[derive(Clone)]
struct Untracked;

impl FlowState for Untracked {
    fn join(&mut self, _other: Self) {}
}

/// The statements and queries a trigger function's body runs.
#[derive(Default)]
struct Body {
    statements: Vec<Statement>,
    queries: Vec<Query>,
    /// Whether the body runs dynamic SQL, which may write any table.
    dynamic: bool,
}

impl FlowVisitor for Body {
    type State = Untracked;

    fn query(&mut self, query: &Query, _state: &mut Untracked) {
        if !self.queries.contains(query) {
            self.queries.push(query.clone());
        }
    }

    fn statement(&mut self, statement: &Statement, _state: &mut Untracked) {
        if !self.statements.contains(statement) {
            self.statements.push(statement.clone());
        }
    }

    fn step(&mut self, node: &Node, _state: &mut Untracked) {
        self.dynamic |= matches!(node.kind, NodeKind::Dynamic { .. });
    }
}
