//! Walks over the queries of a statement an application sends, shared by the
//! query rules.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinitionScope, ColumnScope, IdentifierCase},
    traits::DatabaseLike,
};
use sqlparser::{
    ast::{
        Delete, Expr, FromTable, Insert, Query, Select, SetExpr, Statement, Update,
        UpdateTableFromKind, Visit, Visitor, With,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::{error::Interruption, traits::Reporter};

/// A `SELECT` over `relations` with `projection` and `selection` under
/// `with`, parsed from its rendering, which gives the expressions of an
/// `UPDATE` or `DELETE` the query scope they resolve in.
fn select_over(
    with: Option<&With>,
    projection: &str,
    relations: &[String],
    selection: Option<&Expr>,
) -> Option<Query> {
    let with = with.map_or_else(String::new, |with| format!("{with} "));
    let filter = selection.map_or_else(String::new, |selection| format!(" WHERE {selection}"));
    let sql = format!(
        "{with}SELECT {projection} FROM {}{filter}",
        relations.join(", ")
    );
    let mut parser = Parser::new(&PostgreSqlDialect {}).try_with_sql(&sql).ok()?;
    parser.parse_query().ok().map(|query| *query)
}

/// The query whose expressions the query rules read. For `SELECT` and
/// `INSERT … SELECT` it is the statement's own query, and for `UPDATE` and
/// `DELETE` a `SELECT` over the same relations, assigned values and
/// `WHERE`, under the `WITH` clause the statement carries.
pub(crate) fn root_query(statement: &Statement) -> Option<Cow<'_, Query>> {
    under(statement, None)
}

/// The query of `statement` written under `with`, the `WITH` clause of a
/// query whose body is the data-modifying statement.
fn under<'s>(statement: &'s Statement, with: Option<&With>) -> Option<Cow<'s, Query>> {
    match statement {
        Statement::Query(query) => match query.body.as_ref() {
            SetExpr::Update(inner) | SetExpr::Delete(inner) | SetExpr::Insert(inner) => {
                under(inner, query.with.as_ref())
            }
            _ => Some(Cow::Borrowed(query)),
        },
        Statement::Insert(Insert {
            source: Some(query),
            ..
        }) => Some(with.map_or(Cow::Borrowed(query.as_ref()), |with| {
            let mut query = query.as_ref().clone();
            query.with.get_or_insert_with(|| with.clone());
            Cow::Owned(query)
        })),
        Statement::Update(Update {
            table,
            assignments,
            from,
            selection,
            ..
        }) => {
            let mut relations = vec![table.to_string()];
            if let Some(
                UpdateTableFromKind::BeforeSet(from) | UpdateTableFromKind::AfterSet(from),
            ) = from
            {
                relations.extend(from.iter().map(ToString::to_string));
            }
            let values: Vec<String> = assignments
                .iter()
                .map(|assignment| assignment.value.to_string())
                .collect();
            select_over(with, &values.join(", "), &relations, selection.as_ref()).map(Cow::Owned)
        }
        Statement::Delete(Delete {
            from: FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables),
            using,
            selection,
            ..
        }) => {
            let relations: Vec<String> = tables
                .iter()
                .chain(using.iter().flatten())
                .map(ToString::to_string)
                .collect();
            select_over(with, "1", &relations, selection.as_ref()).map(Cow::Owned)
        }
        _ => None,
    }
}

/// Calls `check` with every expression a `SELECT` holds at its own level,
/// outside its nested queries, and stops at the first error.
pub(crate) struct OwnLevel<F> {
    depth: usize,
    check: F,
}

impl<F: FnMut(&Expr) -> Result<(), LookupError>> OwnLevel<F> {
    pub(crate) fn new(check: F) -> Self {
        Self { depth: 0, check }
    }

    /// Runs `check` over one clause of the `SELECT`.
    pub(crate) fn over<V: Visit + ?Sized>(&mut self, part: &V) -> Result<(), LookupError> {
        part.visit(self).break_value().map_or(Ok(()), Err)
    }
}

impl<F: FnMut(&Expr) -> Result<(), LookupError>> Visitor for OwnLevel<F> {
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
        if self.depth > 0 {
            return ControlFlow::Continue(());
        }
        (self.check)(expression).map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// The `SELECT`s a query body combines through set operations, leaving
/// parenthesized queries to the visitor that reaches them.
fn selects(body: &SetExpr) -> Vec<&Select> {
    match body {
        SetExpr::Select(select) => vec![select],
        SetExpr::SetOperation { left, right, .. } => {
            let mut found = selects(left);
            found.extend(selects(right));
            found
        }
        _ => Vec::new(),
    }
}

/// Calls its function with every query of a statement's root query.
struct Queries<F>(F);

impl<F: FnMut(&Query) -> Result<(), LookupError>> Visitor for Queries<F> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        (self.0)(query).map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Calls `check` with every expression of every `SELECT` in a statement, at
/// each `SELECT`'s own level, together with the scope its names resolve in.
///
/// # Errors
///
/// Returns the first lookup failure of the scope or of `check`.
pub(crate) fn check_select_expressions<DB: DatabaseLike>(
    database: &DB,
    statement: &Statement,
    mut check: impl FnMut(&ColumnDefinitionScope<'_, '_, '_, DB>, &Expr) -> Result<(), LookupError>,
) -> Result<(), LookupError> {
    let Some(root) = root_query(statement) else {
        return Ok(());
    };
    let scope = ColumnScope::from_query(&root, database, IdentifierCase::Folded)?;
    root.visit(&mut Queries(|query: &Query| {
        selects(&query.body).into_iter().try_for_each(|select| {
            scope.scope_for_select(select).map_or(Ok(()), |local| {
                let mut own = OwnLevel::new(|expression: &Expr| check(&local, expression));
                own.over(&select.projection)?;
                own.over(&select.from)?;
                own.over(&select.selection)?;
                own.over(&select.group_by)?;
                own.over(&select.having)
            })
        })
    }))
    .break_value()
    .map_or(Ok(()), Err)
}

/// A finding of a query rule: the text of the statement it names, what the
/// text does, and how to fix it.
#[derive(PartialEq)]
pub(crate) struct Finding {
    pub(crate) object: String,
    pub(crate) message: String,
    pub(crate) resolution: String,
}

/// Reports every finding `find` pushes while it reads `statement`, in the
/// order it pushes them.
///
/// # Errors
///
/// Returns the first lookup failure of `find`, or the interruption the
/// reporter asks for.
pub(crate) fn report<DB: DatabaseLike>(
    statement: &Statement,
    reporter: &mut Reporter<'_, DB>,
    find: impl FnOnce(&mut Vec<Finding>) -> Result<(), LookupError>,
) -> Result<(), Interruption> {
    let mut found = Vec::new();
    find(&mut found)?;
    for finding in found {
        reporter.statement(
            statement,
            finding.object,
            finding.message,
            finding.resolution,
        )?;
    }
    Ok(())
}
