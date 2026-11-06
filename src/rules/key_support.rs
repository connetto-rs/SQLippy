//! Unique keys, foreign keys and the equalities of a `SELECT`, shared by the
//! query rules that ask whether a query's rows are pinned down.

use std::{iter, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinitionScope, IdentifierCase, TargetName},
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, IndexLike, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{
    BinaryOperator, Distinct, Expr, GroupByExpr, OrderBy, OrderByKind, Query, Select, SelectItem,
    SelectItemQualifiedWildcardKind, TableFactor, Value, ValueWithSpan, Visit, Visitor,
};

use crate::rules::{policy_support::conjuncts, statement_support::OwnLevel};

/// A column a `SELECT` names: the folded name its relation goes by in the
/// query, and the column's stored name.
pub(crate) type Named = (String, String);

/// One relation a `SELECT`'s `FROM` names.
pub(crate) struct Instance<'db, DB: DatabaseLike> {
    /// The folded name the query refers to it by.
    pub(crate) name: String,
    /// The catalog table.
    pub(crate) table: &'db DB::Table,
    /// The position of the comma-separated `FROM` item holding it.
    pub(crate) item: usize,
}

/// The relations a `SELECT`'s `FROM` names, or `None` when one of them is
/// not a plain catalog table, such as a derived table or a function. The
/// statement's scope resolves these names first, so a name that fails to
/// resolve here never reaches a rule.
pub(crate) fn instances<'db, DB: DatabaseLike>(
    database: &'db DB,
    select: &Select,
) -> Option<Vec<Instance<'db, DB>>> {
    let mut found = Vec::new();
    for (item, from) in select.from.iter().enumerate() {
        for factor in iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
        {
            let resolved = match factor {
                TableFactor::Table {
                    name,
                    alias,
                    args: None,
                    ..
                } => {
                    let exposed = alias
                        .as_ref()
                        .map(|alias| &alias.name)
                        .or_else(|| name.0.last().and_then(|part| part.as_ident()));
                    let rendered = name.to_string();
                    TargetName::parse(&rendered)
                        .ok()
                        .and_then(|target| {
                            database
                                .resolve_target_table(target, IdentifierCase::Folded)
                                .ok()
                                .flatten()
                        })
                        .zip(exposed)
                }
                _ => None,
            };
            let (table, exposed) = resolved?;
            found.push(Instance {
                name: normalize_identifier(&exposed.value, exposed.quote_style.is_some())
                    .into_owned(),
                table,
                item,
            });
        }
    }
    Some(found)
}

/// The column `expression` names, resolved in `scope`.
pub(crate) fn named<DB: DatabaseLike>(
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    expression: &Expr,
) -> Result<Option<Named>, LookupError> {
    if !matches!(
        expression,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
    ) {
        return Ok(None);
    }
    Ok(scope
        .resolve_column_binding(expression)?
        .and_then(|(_, binding)| binding.relation().zip(binding.exposed()))
        .map(|((relation, relation_quoted), (column, column_quoted))| {
            (
                normalize_identifier(relation, relation_quoted).into_owned(),
                normalize_identifier(column, column_quoted).into_owned(),
            )
        }))
}

/// The unique keys of a table that tell its rows apart: unconditional,
/// over plain columns, and over columns that cannot hold distinct `NULL`s.
pub(crate) fn unique_keys<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
) -> Result<Vec<Vec<&'db DB::Column>>, LookupError> {
    fn usable<'db, DB: DatabaseLike, I: IndexLike<DB = DB>>(
        database: &'db DB,
        index: &'db I,
    ) -> Result<Option<Vec<&'db DB::Column>>, LookupError> {
        if index.predicate().is_some() || !index.is_simple(database)? {
            return Ok(None);
        }
        let columns: Vec<&DB::Column> = index.columns(database)?.collect();
        let mut nullable = false;
        for column in &columns {
            nullable |= column.is_nullable(database)?;
        }
        Ok((!nullable || !index.nulls_distinct()).then_some(columns))
    }
    let mut keys = Vec::new();
    for index in table.unique_indices(database)? {
        keys.extend(usable(database, index)?);
    }
    for index in table.indices(database)?.filter(|index| index.is_unique()) {
        keys.extend(usable(database, index)?);
    }
    Ok(keys)
}

/// Collects the expressions a node holds at its top, outside the
/// expressions they nest.
#[derive(Default)]
struct TopLevel {
    depth: usize,
    found: Vec<Expr>,
}

impl Visitor for TopLevel {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if self.depth == 0 {
            self.found.push(expression.clone());
        }
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, _expression: &Expr) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }
}

/// The conditions of a `SELECT`: its `WHERE` and its join conditions.
fn conditions(select: &Select) -> Vec<Expr> {
    let mut top = TopLevel::default();
    for from in &select.from {
        for join in &from.joins {
            let _ = join.join_operator.visit(&mut top);
        }
    }
    select.selection.iter().cloned().chain(top.found).collect()
}

/// The column equalities of a `SELECT`'s `WHERE` and join conditions, and
/// the columns they pin to a value.
#[derive(Default)]
pub(crate) struct Equalities {
    pub(crate) pairs: Vec<(Named, Named)>,
    pub(crate) pinned: Vec<Named>,
}

/// Whether `expression` stands for one value for the whole statement.
fn is_value(expression: &Expr) -> bool {
    // Expression evaluator: only literals and bind parameters pin a column.
    // The evaluator decides which expressions are constant for the
    // statement, such as `lower($1)`.
    matches!(expression, Expr::Value(_))
}

/// The equalities of `select`, resolved in `scope`.
pub(crate) fn equalities<DB: DatabaseLike>(
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    select: &Select,
) -> Result<Equalities, LookupError> {
    let mut equalities = Equalities::default();
    for condition in conditions(select) {
        for conjunct in conjuncts(&condition) {
            let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = conjunct
            else {
                continue;
            };
            match (named(scope, left)?, named(scope, right)?) {
                (Some(left), Some(right)) => equalities.pairs.push((left, right)),
                (Some(column), None) if is_value(right) => equalities.pinned.push(column),
                (None, Some(column)) if is_value(left) => equalities.pinned.push(column),
                _ => {}
            }
        }
    }
    Ok(equalities)
}

/// The expressions a query orders by.
pub(crate) fn order_of(query: &Query) -> Vec<&Expr> {
    let Some(OrderBy {
        kind: OrderByKind::Expressions(keys),
        ..
    }) = &query.order_by
    else {
        return Vec::new();
    };
    keys.iter().map(|key| &key.expr).collect()
}

/// Whether every expression of `keys` is ordered by, as written or as a
/// column `known` holds.
fn covers<DB: DatabaseLike>(
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    keys: &[&Expr],
    order: &[&Expr],
    known: &[Named],
) -> Result<bool, LookupError> {
    for key in keys {
        let written = key.to_string();
        if !order.iter().any(|ordered| ordered.to_string() == written)
            && !named(scope, key)?.is_some_and(|column| known.contains(&column))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The select-list expression an `ORDER BY` or `GROUP BY` key names, the
/// way PostgreSQL reads a bare key: an ordinal names the output at that
/// position, and a name an output alias carries names that output. Any other
/// key, and an ordinal past a wildcard, stands for itself.
fn target<'s>(select: &'s Select, key: &'s Expr) -> &'s Expr {
    let output = |item: &'s SelectItem| match item {
        SelectItem::UnnamedExpr(expression)
        | SelectItem::ExprWithAlias {
            expr: expression, ..
        } => Some(expression),
        _ => None,
    };
    match key {
        Expr::Value(ValueWithSpan {
            value: Value::Number(number, _),
            ..
        }) => number
            .parse::<usize>()
            .ok()
            .and_then(|position| select.projection.get(..position))
            .and_then(|before| before.iter().map(output).collect::<Option<Vec<_>>>())
            .and_then(|outputs| outputs.last().copied())
            .unwrap_or(key),
        Expr::Identifier(name) => select
            .projection
            .iter()
            .find_map(|item| match item {
                SelectItem::ExprWithAlias { expr, alias }
                    if normalize_identifier(&alias.value, alias.quote_style.is_some())
                        == normalize_identifier(&name.value, name.quote_style.is_some()) =>
                {
                    Some(expr)
                }
                _ => None,
            })
            .unwrap_or(key),
        _ => key,
    }
}

/// The relations whose columns the select list of `select` reads.
fn projected<DB: DatabaseLike>(
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    select: &Select,
    instances: &[Instance<'_, DB>],
) -> Result<Vec<String>, LookupError> {
    let mut read = Vec::new();
    for item in &select.projection {
        match item {
            SelectItem::Wildcard(_) => {
                read.extend(instances.iter().map(|instance| instance.name.clone()));
            }
            SelectItem::QualifiedWildcard(SelectItemQualifiedWildcardKind::ObjectName(name), _) => {
                read.extend(name.0.last().and_then(|part| part.as_ident()).map(|ident| {
                    normalize_identifier(&ident.value, ident.quote_style.is_some()).into_owned()
                }));
            }
            _ => OwnLevel::new(|expression: &Expr| {
                read.extend(named(scope, expression)?.map(|(relation, _)| relation));
                Ok(())
            })
            .over(item)?,
        }
    }
    Ok(read)
}

/// Whether `order` gives every row of `select` its own position: each
/// relation the select list reads pinned by a unique key that the order or
/// the equalities cover, or the group keys or the `DISTINCT` list covered.
/// Rows that differ only in relations the select list does not read look
/// the same in the result, so those relations need no pin. `None` when a
/// `FROM` item is not a plain catalog table.
pub(crate) fn determined<DB: DatabaseLike>(
    database: &DB,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    select: &Select,
    order: &[&Expr],
) -> Result<Option<bool>, LookupError> {
    let Some(instances) = instances(database, select) else {
        return Ok(None);
    };
    let order: Vec<&Expr> = order.iter().map(|key| target(select, key)).collect();
    let equalities = equalities(scope, select)?;
    let mut known = equalities.pinned;
    for expression in &order {
        known.extend(named(scope, expression)?);
    }
    if let GroupByExpr::Expressions(keys, _) = &select.group_by
        && !keys.is_empty()
    {
        let keys: Vec<&Expr> = keys.iter().map(|key| target(select, key)).collect();
        return covers(scope, &keys, &order, &known).map(Some);
    }
    if let Some(Distinct::Distinct) = select.distinct {
        let listed: Vec<&Expr> = select
            .projection
            .iter()
            .filter_map(|item| match item {
                SelectItem::UnnamedExpr(expression)
                | SelectItem::ExprWithAlias {
                    expr: expression, ..
                } => Some(expression),
                _ => None,
            })
            .collect();
        if listed.len() == select.projection.len() && covers(scope, &listed, &order, &known)? {
            return Ok(Some(true));
        }
    }
    let read = projected(scope, select, &instances)?;
    let mut pinned: Vec<bool> = instances
        .iter()
        .map(|instance| !read.contains(&instance.name))
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for (index, instance) in instances.iter().enumerate() {
            if pinned[index] {
                continue;
            }
            let covered = unique_keys(database, instance.table)?.iter().any(|key| {
                key.iter().all(|column| {
                    known.contains(&(
                        instance.name.clone(),
                        column.stored_column_name().into_owned(),
                    ))
                })
            });
            if covered {
                pinned[index] = true;
                changed = true;
                for column in instance.table.columns(database)? {
                    known.push((
                        instance.name.clone(),
                        column.stored_column_name().into_owned(),
                    ));
                }
            }
        }
        for (left, right) in &equalities.pairs {
            match (known.contains(left), known.contains(right)) {
                (true, false) => known.push(right.clone()),
                (false, true) => known.push(left.clone()),
                _ => continue,
            }
            changed = true;
        }
    }
    Ok(Some(pinned.into_iter().all(|pinned| pinned)))
}

/// The `(child column, parent column)` pairs of one foreign key.
pub(crate) type KeyPairs<'db, DB> = Vec<(
    &'db <DB as DatabaseLike>::Column,
    &'db <DB as DatabaseLike>::Column,
)>;

/// The column pairs of each foreign key of `child` that references
/// `parent`.
pub(crate) fn references<'db, DB: DatabaseLike>(
    database: &'db DB,
    child: &'db DB::Table,
    parent: &'db DB::Table,
) -> Result<Vec<KeyPairs<'db, DB>>, LookupError> {
    let mut found = Vec::new();
    for foreign_key in child.foreign_keys(database)? {
        if foreign_key.referenced_table(database)? == parent {
            found.push(
                foreign_key
                    .host_columns(database)?
                    .zip(foreign_key.referenced_columns(database)?)
                    .collect(),
            );
        }
    }
    Ok(found)
}
