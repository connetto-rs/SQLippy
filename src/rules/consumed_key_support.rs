//! Keys an `AFTER` row trigger takes out of the set a check admits them from.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{IdentifierCase, TriggerRow},
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, TableLike, TriggerLike},
};
use sqlparser::ast::{
    Assignment, AssignmentTarget, BinaryOperator, Delete, Expr, FromTable, FunctionArg,
    FunctionArgExpr, FunctionArguments, FunctionCalledOnNull, FunctionSecurity, Ident, InTarget,
    ObjectName, Query, ReferentialAction, SelectItem, SetExpr, Statement, TableAlias, TableFactor,
    TableWithJoins, TriggerEvent, TriggerPeriod, Update, VisitMut, VisitorMut,
};
use sqlparser_plpgsql::embedded::{Node, NodeKind};

use crate::{
    deployment::Deployment,
    rules::{
        closed_set_support::stored_name,
        cte_support::stored_table,
        expression_site_support::parsed_body_statements,
        function_body_support::parameter,
        function_reach_support::Reach,
        guarded_parent_support::always_runs_unless,
        key_support::{checked_whenever_set, equality_keys, key_pairs},
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        policy_read_support::reads_every_row,
        policy_support::{
            acting, client_roles, conjuncts, is_column_reference, is_contradiction,
            sets_only_search_path, unwrapped,
        },
        trigger_support::{
            WritesTable, fires_for_clients, fires_on_insert, names_new_field, new_field, row,
            row_trigger, stored, stored_parts,
        },
    },
};

/// A row trigger of the written table that writes the row of another table
/// each stored key names, for every row a client stores.
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
    effect: Effect,
}

/// What a trigger does to the row each stored key names.
enum Effect {
    /// Sets each column to its value, `NEW`'s fields written as columns of
    /// the written table, when the row meets each guard, a further
    /// condition of the trigger's `WHERE` on columns it sets.
    Update {
        assignments: Vec<(String, Expr)>,
        guards: Vec<Expr>,
    },
    /// Deletes the row.
    Delete,
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
    /// the columns of the named row, and every row meeting it is one the
    /// trigger writes.
    pub(crate) fn rejects(&self, fact: &Expr) -> Result<bool, LookupError> {
        let Effect::Update {
            assignments,
            guards,
        } = &self.effect
        else {
            return Ok(true);
        };
        let Some(substituted) = substituted(fact, assignments) else {
            return Ok(false);
        };
        if !is_contradiction(self.database, self.written, &substituted)? {
            return Ok(false);
        }
        for guard in guards {
            let skipped = Expr::BinaryOp {
                left: Box::new(Expr::Nested(Box::new(fact.clone()))),
                op: BinaryOperator::And,
                right: Box::new(Expr::IsNotTrue(Box::new(Expr::Nested(Box::new(
                    guard.clone(),
                ))))),
            };
            if !is_contradiction(self.database, self.table, &skipped)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The stored names of the named row's columns the trigger sets.
    fn assigned(&self) -> impl Iterator<Item = &str> {
        let assignments = match &self.effect {
            Effect::Update { assignments, .. } => assignments.as_slice(),
            Effect::Delete => &[],
        };
        assignments.iter().map(|(name, _)| name.as_str())
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
        if trigger.timing() != Some(TriggerPeriod::After)
            || !fires_on_insert(trigger)
            || !fires_for_clients(database, trigger)?
        {
            continue;
        }
        // A statement trigger reads the stored rows from its new transition
        // table, by its stored name.
        let new_rows = if row_trigger(trigger, TriggerPeriod::After) {
            None
        } else {
            let Some(new_rows) = trigger
                .transition_tables()
                .find(|transition| transition.rows() == TriggerRow::New)
            else {
                continue;
            };
            Some(new_rows.stored_name())
        };
        let Some((function, block)) = trigger
            .function(database)
            .and_then(|function| Some((function, plpgsql_block(function)?)))
        else {
            continue;
        };
        let mut body = Body::default();
        walk_block(&mut body, &block, Untracked);
        if body.dynamic {
            continue;
        }
        let mut candidates = body.statements.iter().filter_map(|statement| {
            consumption_of(database, table, function, statement, new_rows.as_deref())
                .map(|(found, runner)| (statement, found, runner))
        });
        let (Some((statement, consumption, runner)), None) = (candidates.next(), candidates.next())
        else {
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
        // `NEW` is `NULL` in a statement trigger, so only a row trigger may
        // skip the consumption over a `NULL` key.
        let skips_null_key = |condition: &Expr, holds: bool| {
            new_rows.is_none() && leaves_key_null(condition, holds, &consumption.column)
        };
        if writes_elsewhere
            || !trigger
                .condition()
                .is_none_or(|condition| skips_null_key(condition, false))
            || !always_runs_unless(&block, "new", |run| run == statement, skips_null_key)
            || !reads_every_row(database, runner, consumption.table)?
            || !stays_written(database, deployment, trigger, &consumption)?
        {
            continue;
        }
        found.push(consumption);
    }
    Ok(found)
}

/// Whether a path on which `condition` evaluated to `holds` carries a `NULL`
/// key in `column`, which no unique key compares.
fn leaves_key_null(condition: &Expr, holds: bool, column: &str) -> bool {
    match unwrapped(condition) {
        Expr::IsNotNull(field) => !holds && names_new_field(field, column),
        Expr::IsNull(field) => holds && names_new_field(field, column),
        _ => false,
    }
}

/// The consumption `statement` of the trigger function `function` runs,
/// with the function whose rights it runs under. A row trigger may run it
/// through a `PERFORM` of a `LANGUAGE sql` function whose body is one
/// consuming statement, and a statement trigger names the rows by the
/// stored keys its new transition table `new_rows` holds.
fn consumption_of<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
    function: &'db DB::Function,
    statement: &Statement,
    new_rows: Option<&str>,
) -> Option<(Consumption<'db, DB>, &'db DB::Function)> {
    if let Some(found) = consuming_statement(database, table, statement, None, new_rows) {
        return Some((found, function));
    }
    if new_rows.is_some() {
        return None;
    }
    let (called, arguments) = performed_call(database, statement)?;
    let [body]: [Statement; 1] = parsed_body_statements(called)?.try_into().ok()?;
    let path = called.search_path(database).ok()?;
    let rewritten = with_arguments(database, called, body, &arguments, path.as_deref())?;
    let found = consuming_statement(database, table, &rewritten, path.as_deref(), None)?;
    // A strict function skips its body when an argument is `NULL`, which
    // only a `NULL` key may do.
    if called.null_input_behavior() != FunctionCalledOnNull::CalledOnNullInput
        && !arguments
            .iter()
            .all(|argument| new_field(argument).is_some_and(|field| field == found.column))
    {
        return None;
    }
    let runner = if called.security_mode() == FunctionSecurity::Definer {
        called
    } else {
        function
    };
    Some((found, runner))
}

/// The `LANGUAGE sql` function `statement`, as `PERFORM function(arguments)`,
/// calls with a positional argument for each of its parameters, when it sets
/// no parameter but the search path, with those arguments.
fn performed_call<'db, 's, DB: DatabaseLike>(
    database: &'db DB,
    statement: &'s Statement,
) -> Option<(&'db DB::Function, Vec<&'s Expr>)> {
    let Statement::Query(query) = statement else {
        return None;
    };
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let ([SelectItem::UnnamedExpr(Expr::Function(call))], [], None, None, None, None) = (
        select.projection.as_slice(),
        select.from.as_slice(),
        &select.selection,
        &query.with,
        &query.limit_clause,
        &query.order_by,
    ) else {
        return None;
    };
    let FunctionArguments::List(list) = &call.args else {
        return None;
    };
    let arguments = list
        .args
        .iter()
        .map(|argument| match argument {
            FunctionArg::Unnamed(FunctionArgExpr::Expr(value)) => Some(value),
            _ => None,
        })
        .collect::<Option<Vec<&Expr>>>()?;
    let mut reached = database
        .functions_reached_by(call, IdentifierCase::Folded)
        .ok()?;
    let (Some(called), None) = (reached.next(), reached.next()) else {
        return None;
    };
    (called.stored_language().as_deref() == Some("sql")
        && sets_only_search_path(called)
        && called.argument_names(database).count() == arguments.len())
    .then_some((called, arguments))
}

/// `statement`, the body of `called`, with each parameter it reads replaced
/// by its argument among `arguments`. A name of a column of the table it
/// writes is that column, as PostgreSQL resolves it, and the table is
/// resolved on `path`.
fn with_arguments<DB: DatabaseLike>(
    database: &DB,
    called: &DB::Function,
    mut statement: Statement,
    arguments: &[&Expr],
    path: Option<&[(Cow<'_, str>, bool)]>,
) -> Option<Statement> {
    /// Replaces parameters, breaking on a query, whose own columns may
    /// shadow them where the statement's shape does not show.
    struct Parameters<'a, DB: DatabaseLike> {
        database: &'a DB,
        called: &'a DB::Function,
        arguments: &'a [&'a Expr],
        /// The name the statement reads the written table under.
        exposed: String,
        columns: Vec<String>,
    }

    impl<DB: DatabaseLike> VisitorMut for Parameters<'_, DB> {
        type Break = ();

        fn pre_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            ControlFlow::Break(())
        }

        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            let column = match &*expression {
                Expr::Identifier(name) => Some(name),
                Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                    [qualifier, name] if stored(qualifier) == self.exposed.as_str() => Some(name),
                    _ => None,
                },
                Expr::Value(_) => None,
                _ => return ControlFlow::Continue(()),
            };
            if column.is_some_and(|name| self.columns.contains(&stored(name).into_owned())) {
                return ControlFlow::Continue(());
            }
            if let Some(position) = parameter(self.database, self.called, expression) {
                *expression = Expr::Nested(Box::new(self.arguments[position].clone()));
            }
            ControlFlow::Continue(())
        }
    }

    let (name, alias) = match &statement {
        Statement::Update(update) => match &update.table.relation {
            TableFactor::Table { name, alias, .. } => (name, alias),
            _ => return None,
        },
        Statement::Delete(delete) => deleted_table(delete)?.0,
        _ => return None,
    };
    let exposed = match alias {
        Some(alias) => stored(&alias.name).into_owned(),
        None => stored(name.0.last()?.as_ident()?).into_owned(),
    };
    let columns = stored_table(database, name, path)
        .ok()??
        .columns(database)
        .ok()?
        .map(|column| column.stored_column_name().into_owned())
        .collect();
    let mut visitor = Parameters {
        database,
        called,
        arguments,
        exposed,
        columns,
    };
    VisitMut::visit(&mut statement, &mut visitor)
        .is_continue()
        .then_some(statement)
}

/// The consumption `statement` is, over one table other than `table`
/// resolved on `path`. It is `UPDATE other SET ... WHERE column = NEW.key`,
/// setting each column to a value built from literals and `NEW`'s fields,
/// whose further `AND` conjuncts may read only the columns it sets, or
/// `DELETE FROM other WHERE column = NEW.key`. In a statement trigger whose
/// new transition table is `new_rows`, the key condition is `column IN
/// (SELECT key FROM new_rows)` and the values are built from literals.
fn consuming_statement<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
    statement: &Statement,
    path: Option<&[(Cow<'_, str>, bool)]>,
    new_rows: Option<&str>,
) -> Option<Consumption<'db, DB>> {
    let (name, selection, assignments) = match statement {
        Statement::Update(Update {
            table:
                TableWithJoins {
                    relation:
                        TableFactor::Table {
                            name, args: None, ..
                        },
                    ..
                },
            assignments,
            from: None,
            selection: Some(selection),
            returning: None,
            ..
        }) => (name, selection, Some(assignments)),
        Statement::Delete(delete) => {
            let ((name, _), selection) = deleted_table(delete)?;
            (name, selection, None)
        }
        _ => return None,
    };
    let named = stored_table(database, name, path).ok()??;
    if named == table {
        return None;
    }
    let parts = conjuncts(selection);
    let (position, (referenced, column)) = parts
        .iter()
        .enumerate()
        .find_map(|(position, part)| Some((position, key_equality(part, new_rows)?)))?;
    let effect = match assignments {
        Some(assignments) => updated(assignments, &parts, position, new_rows.is_none())?,
        None if parts.len() == 1 => Effect::Delete,
        None => return None,
    };
    Some(Consumption {
        database,
        written: table,
        column: column.into_owned(),
        table: named,
        referenced,
        effect,
    })
}

/// The table `delete` removes rows of, with its alias, and the condition
/// choosing them, when it reads no other relation and returns nothing.
fn deleted_table(delete: &Delete) -> Option<((&ObjectName, &Option<TableAlias>), &Expr)> {
    let Delete {
        from: FromTable::WithFromKeyword(from),
        using: None,
        selection: Some(selection),
        returning: None,
        ..
    } = delete
    else {
        return None;
    };
    let [
        TableWithJoins {
            relation:
                TableFactor::Table {
                    name,
                    alias,
                    args: None,
                    ..
                },
            ..
        },
    ] = from.as_slice()
    else {
        return None;
    };
    Some(((name, alias), selection))
}

/// The effect of an `UPDATE` setting `assignments` on the rows its `WHERE`
/// conjuncts `parts` choose, the one at `position` naming the row, whose
/// values may read `NEW` when `reads_new` is set.
fn updated(
    assignments: &[Assignment],
    parts: &[&Expr],
    position: usize,
    reads_new: bool,
) -> Option<Effect> {
    let guards = parts
        .iter()
        .enumerate()
        .filter(|(other, _)| *other != position)
        .map(|(_, part)| updated_condition(part))
        .collect::<Option<Vec<Expr>>>()?;
    let mut set = Vec::new();
    for assignment in assignments {
        let AssignmentTarget::ColumnName(target) = &assignment.target else {
            return None;
        };
        let assigned = stored_parts(target).pop()?.into_owned();
        if let Some(value) = written_value(&assignment.value, reads_new) {
            set.push((assigned, value));
        }
    }
    if guards
        .iter()
        .any(|guard| substituted(guard, &set).is_none())
    {
        return None;
    }
    Some(Effect::Update {
        assignments: set,
        guards,
    })
}

/// The column of the updated table and the field of the stored row that
/// `conjunct` holds equal, as `column = NEW.key` in a row trigger or
/// `column IN (SELECT key FROM new_rows)` in a statement trigger whose new
/// transition table is `new_rows`.
fn key_equality<'e>(conjunct: &'e Expr, new_rows: Option<&str>) -> Option<(String, Cow<'e, str>)> {
    if let Some(new_rows) = new_rows {
        let Expr::In {
            expr,
            target: InTarget::Subquery(query),
            negated: false,
            ..
        } = unwrapped(conjunct)
        else {
            return None;
        };
        return Some((
            updated_column(expr)?,
            Cow::Owned(stored_field(query, new_rows)?),
        ));
    }
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = unwrapped(conjunct)
    else {
        return None;
    };
    [(left, right), (right, left)]
        .into_iter()
        .find_map(|(referenced, key)| Some((updated_column(referenced)?, new_field(key)?)))
}

/// The stored name of the column `query`, as `SELECT key FROM new_rows`,
/// projects from every row of the transition table `new_rows`.
fn stored_field(query: &Query, new_rows: &str) -> Option<String> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let (
        [
            SelectItem::UnnamedExpr(projected)
            | SelectItem::ExprWithAlias {
                expr: projected, ..
            },
        ],
        [
            TableWithJoins {
                relation:
                    TableFactor::Table {
                        name,
                        alias,
                        args: None,
                        ..
                    },
                joins,
            },
        ],
        None,
        None,
        None,
        None,
        None,
    ) = (
        select.projection.as_slice(),
        select.from.as_slice(),
        &select.selection,
        &select.having,
        &query.with,
        &query.limit_clause,
        &query.fetch,
    )
    else {
        return None;
    };
    let [part] = name.0.as_slice() else {
        return None;
    };
    if !joins.is_empty()
        || stored(part.as_ident()?) != new_rows
        || alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
    {
        return None;
    }
    let exposed = alias
        .as_ref()
        .map_or_else(|| Cow::Borrowed(new_rows), |alias| stored(&alias.name));
    let field = match unwrapped(projected) {
        Expr::Identifier(field) => field,
        Expr::CompoundIdentifier(parts) => match parts.as_slice() {
            [qualifier, field] if stored(qualifier) == exposed => field,
            _ => return None,
        },
        _ => return None,
    };
    Some(stored(field).into_owned())
}

/// `condition` with each column of the updated table written bare by its
/// stored name, or `None` when it reads a trigger row or a query.
fn updated_condition(condition: &Expr) -> Option<Expr> {
    /// Rewrites the updated table's columns, breaking on any other column or
    /// a query.
    struct Columns;

    impl VisitorMut for Columns {
        type Break = ();

        fn pre_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            ControlFlow::Break(())
        }

        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            if !is_column_reference(expression) {
                return ControlFlow::Continue(());
            }
            let Some(column) = updated_column(expression) else {
                return ControlFlow::Break(());
            };
            *expression = Expr::Identifier(Ident::new(column));
            ControlFlow::Continue(())
        }
    }

    let mut rewritten = condition.clone();
    VisitMut::visit(&mut rewritten, &mut Columns)
        .is_continue()
        .then_some(rewritten)
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
/// when it reads another column or a query, or `NEW` unless `reads_new`.
fn written_value(value: &Expr, reads_new: bool) -> Option<Expr> {
    /// Rewrites `NEW`'s fields, breaking on any other column or a query.
    struct Fields {
        reads_new: bool,
    }

    impl VisitorMut for Fields {
        type Break = ();

        fn pre_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            ControlFlow::Break(())
        }

        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            if !is_column_reference(expression) {
                return ControlFlow::Continue(());
            }
            let Some(field) = new_field(expression).filter(|_| self.reads_new) else {
                return ControlFlow::Break(());
            };
            *expression = Expr::Identifier(Ident::new(field));
            ControlFlow::Continue(())
        }
    }

    let mut rewritten = value.clone();
    VisitMut::visit(&mut rewritten, &mut Fields { reads_new })
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
    let deletes = matches!(consumption.effect, Effect::Delete);
    for other in named.triggers(database)? {
        if row_trigger(other, TriggerPeriod::Before)
            && other.events().iter().any(|event| {
                if deletes {
                    matches!(event, TriggerEvent::Delete)
                } else {
                    matches!(event, TriggerEvent::Update(_))
                }
            })
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
    for name in consumption.assigned() {
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
    // A client inserting a row naming a deleted key brings it back.
    if deletes {
        return Ok(!inserts);
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
