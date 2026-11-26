//! The row a subtype table's foreign key references in its parent table,
//! inserted by a row-level `BEFORE INSERT` trigger of the subtype table from
//! `NEW`'s key, which a deferred constraint trigger on the parent table
//! refuses at commit while no subtype row holds its key.

use std::borrow::Cow;

use sql_traits::{
    errors::LookupError,
    structs::ConstraintDeferral,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike, TriggerLike},
    utils::scalar_family::ScalarFamily,
};
use sqlparser::ast::{
    BinaryOperator, Delete, Expr, FromTable, GroupByExpr, Ident, InTarget, ObjectNamePart,
    OnConflict, OnConflictAction, OnInsert, Query, Select, SelectItem, SetExpr, Statement,
    TableFactor, TableInheritance, TableObject, TriggerEvent, TriggerPeriod, UnaryOperator, Visit,
};
use sqlparser_plpgsql::embedded::{
    AliasTarget, Block, DeclarationKind, Loop, LoopControl, Node, NodeKind, Target,
};

use crate::rules::{
    closed_set_support::{Identity, checked_values, identity, kept_literal},
    cte_support::stored_table,
    function_reach_support::Reach,
    key_support::{KeyPairs, equality_keys, key_pairs},
    null_support::may_hold_null,
    plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
    policy_read_support::reads_every_row,
    policy_support::conjuncts,
    trigger_support::{
        WritesTable, Written, evaluated, fires_for_clients, fires_on_insert, names_record,
        new_field_write, row, row_trigger, stored, stored_parts,
    },
};

/// A referenced column that every row the subtype table references holds
/// one value in.
struct Pinned<'db, DB: DatabaseLike> {
    column: &'db DB::Column,
    /// The text of the one value.
    text: String,
    /// Whether the column is an enum, whose literals may be cast to it.
    enumeration: bool,
}

/// A subtype table's foreign key and the parent table it references.
pub(crate) struct Parent<'db, DB: DatabaseLike> {
    database: &'db DB,
    /// The subtype table holding the foreign key.
    table: &'db DB::Table,
    /// The table the foreign key references.
    referenced: &'db DB::Table,
    /// The referenced table's columns, in the order an insert naming none
    /// fills them.
    order: Vec<&'db DB::Column>,
    /// Each host column with the referenced column it names.
    pairs: KeyPairs<'db, DB>,
    /// The referenced columns whose host column a validated check pins to
    /// one value. A generated column is not read, since `NEW` holds no value
    /// for it before the row is stored.
    pinned: Vec<Pinned<'db, DB>>,
    /// Whether the foreign key checks every subtype row, existing ones
    /// included.
    validated: bool,
}

impl<'db, DB: DatabaseLike> Parent<'db, DB> {
    /// Reads `foreign_key` of `table`.
    pub(crate) fn new(
        database: &'db DB,
        table: &'db DB::Table,
        foreign_key: &'db DB::ForeignKey,
    ) -> Result<Self, LookupError> {
        let referenced = foreign_key.referenced_table(database)?;
        let pairs = key_pairs(database, foreign_key)?;
        let mut pinned = Vec::new();
        for &(host, column) in &pairs {
            let kind = identity(column, database)?;
            let enumeration = match &kind {
                Some(Identity::Enumeration(_)) => true,
                Some(Identity::Family(ScalarFamily::String)) => false,
                _ => continue,
            };
            if host.generation_expression().is_some() || identity(host, database)? != kind {
                continue;
            }
            if let Some(values) = checked_values(database, host)?
                && let [value] = values.as_slice()
                && let Some(text) = kept_literal(value, enumeration)
            {
                pinned.push(Pinned {
                    column,
                    text: text.to_owned(),
                    enumeration,
                });
            }
        }
        Ok(Self {
            database,
            table,
            referenced,
            order: referenced.columns(database)?.collect(),
            pairs,
            pinned,
            validated: foreign_key.is_validated(database)?,
        })
    }

    /// The table the foreign key references.
    pub(crate) const fn referenced(&self) -> &'db DB::Table {
        self.referenced
    }

    /// Whether `statement` inserts one `VALUES` row into the referenced
    /// table holding `NEW`'s value of each host column in its referenced
    /// column, failing when a row already holds the key or, when `skips`,
    /// doing nothing then.
    pub(crate) fn inserts(&self, statement: &Statement, skips: bool) -> bool {
        let Statement::Insert(insert) = statement else {
            return false;
        };
        let conflict = match &insert.on {
            None => true,
            Some(OnInsert::OnConflict(OnConflict {
                action: OnConflictAction::DoNothing,
                ..
            })) => skips,
            Some(_) => false,
        };
        if let TableObject::TableName(name) = &insert.table
            && let Some(source) = insert.source.as_deref()
            && let SetExpr::Values(values) = source.body.as_ref()
            && let [values] = values.rows.as_slice()
            && conflict
            && insert.or.is_none()
            && !insert.ignore
            && source.with.is_none()
            && source.limit_clause.is_none()
            && source.fetch.is_none()
            && matches!(
                stored_table(self.database, name, None),
                Ok(Some(table)) if table == self.referenced
            )
        {
            return self.pairs.iter().all(|&(host, referenced)| {
                let at = if insert.columns.is_empty() {
                    self.order.iter().position(|column| *column == referenced)
                } else {
                    insert.columns.iter().position(|column| {
                        column
                            .0
                            .last()
                            .and_then(ObjectNamePart::as_ident)
                            .is_some_and(|ident| names_column(referenced, ident))
                    })
                };
                at.and_then(|at| values.get(at))
                    .is_some_and(|value| self.field(value, true) == Some(host))
            });
        }
        false
    }

    /// Whether an enabled deferred constraint trigger on the referenced
    /// table, firing for every inserted row the subtype table can reference
    /// and, when `updated`, for every updated one, raises at commit when such
    /// a row survives without a subtype row referencing it.
    pub(crate) fn guarded(&self, updated: bool) -> Result<bool, LookupError> {
        if !self.validated {
            return Ok(false);
        }
        for trigger in self.referenced.triggers(self.database)? {
            if trigger.deferral() == Some(ConstraintDeferral::InitiallyDeferred)
                && row_trigger(trigger, TriggerPeriod::After)
                && fires_on_insert(trigger)
                && (!updated || fires_on_every_update(trigger))
                && trigger
                    .condition()
                    .is_none_or(|condition| self.holds(condition))
                && fires_for_clients(self.database, trigger)?
                && let Some(function) = trigger.function(self.database)
                && let Some(block) = plpgsql_block(function)
            {
                let mut guard = Guard {
                    parent: self,
                    absence: reads_every_row(self.database, function, self.referenced)?,
                    table_writes: Reach::new(
                        self.database,
                        WritesTable::new(self.database, self.table),
                    ),
                    referenced_writes: Reach::new(
                        self.database,
                        WritesTable::new(self.database, self.referenced),
                    ),
                    unchecked: false,
                    followed: true,
                };
                walk_block(&mut guard, &block, Checked(false));
                if guard.followed && !guard.unchecked {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether every enabled `BEFORE INSERT` row trigger of the subtype
    /// table returns `NEW` with its host columns unwritten, so the row a
    /// trigger writes from `NEW`'s key is the row the insert checks and
    /// stores.
    pub(crate) fn settled(&self) -> Result<bool, LookupError> {
        for trigger in self.table.triggers(self.database)? {
            if row_trigger(trigger, TriggerPeriod::Before)
                && fires_on_insert(trigger)
                && fires_for_clients(self.database, trigger)?
            {
                let Some(block) = trigger.function(self.database).and_then(plpgsql_block) else {
                    return Ok(false);
                };
                let mut settles = Settles::<DB> {
                    pairs: &self.pairs,
                    settled: true,
                };
                walk_block(&mut settles, &block, Unit);
                if !settles.settled {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Whether a referenced row can neither outlive the subtype row
    /// referencing it nor be referenced by two. A unique key of the subtype
    /// table lies within the host columns, and enabled `AFTER` row triggers
    /// of the subtype table delete the referenced row of `OLD`'s key, through
    /// a function that sees every referenced row, on every `DELETE` and on
    /// every `UPDATE` changing a host column no check pins.
    pub(crate) fn kept(&self) -> Result<bool, LookupError> {
        let within = |column: &&DB::Column| self.pairs.iter().any(|(host, _)| host == column);
        if !equality_keys(self.database, self.table)?
            .iter()
            .any(|key| key.iter().all(within))
        {
            return Ok(false);
        }
        let unpinned: Vec<&DB::Column> = self
            .pairs
            .iter()
            .filter(|(_, referenced)| !self.pinned.iter().any(|pin| pin.column == *referenced))
            .map(|&(host, _)| host)
            .collect();
        let (mut deleted, mut rekeyed) = (false, unpinned.is_empty());
        for trigger in self.table.triggers(self.database)? {
            if !row_trigger(trigger, TriggerPeriod::After)
                || !fires_for_clients(self.database, trigger)?
            {
                continue;
            }
            let Some(function) = trigger.function(self.database) else {
                continue;
            };
            if !reads_every_row(self.database, function, self.referenced)?
                || !plpgsql_block(function).is_some_and(|block| {
                    always_runs(&block, "old", |statement| self.deletes(statement))
                })
            {
                continue;
            }
            let condition = trigger.condition();
            deleted |= condition.is_none()
                && trigger
                    .events()
                    .iter()
                    .any(|event| matches!(event, TriggerEvent::Delete));
            rekeyed |= fires_on_every_update(trigger)
                && condition.is_none_or(|condition| {
                    let changed = self.changed(condition);
                    unpinned.iter().all(|column| changed.contains(column))
                });
        }
        Ok(deleted && rekeyed)
    }

    /// Whether `statement` deletes the referenced rows whose columns equal
    /// `OLD`'s values of the host columns naming them, under a conjunction
    /// of such equalities.
    fn deletes(&self, statement: &Statement) -> bool {
        let Statement::Delete(Delete {
            tables,
            from: FromTable::WithFromKeyword(from),
            using: None,
            selection: Some(selection),
            limit: None,
            ..
        }) = statement
        else {
            return false;
        };
        let [from] = from.as_slice() else {
            return false;
        };
        let Some(name) = sole_relation(self.database, &from.relation, self.referenced) else {
            return false;
        };
        tables.is_empty()
            && from.joins.is_empty()
            && conjuncts(selection).into_iter().all(|conjunct| {
                equated(conjunct).is_some_and(|(left, right)| {
                    [(left, right), (right, left)]
                        .into_iter()
                        .any(|(column, value)| {
                            self.qualified(column, &name, self.referenced)
                                .zip(self.field(value, false))
                                .is_some_and(|(referenced, host)| {
                                    self.pairs.contains(&(host, referenced))
                                })
                        })
                })
            })
    }

    /// The host columns whose change makes an `UPDATE` trigger's `WHEN`
    /// condition true, read from `OLD.column IS DISTINCT FROM NEW.column`
    /// tests, alone, over rows or under `OR`.
    fn changed(&self, condition: &Expr) -> Vec<&'db DB::Column> {
        match condition {
            Expr::Nested(inner) => self.changed(inner),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
            } => {
                let mut changed = self.changed(left);
                changed.extend(self.changed(right));
                changed
            }
            Expr::IsDistinctFrom(left, right) => match (left.as_ref(), right.as_ref()) {
                (Expr::Tuple(left), Expr::Tuple(right)) if left.len() == right.len() => left
                    .iter()
                    .zip(right)
                    .map(|(left, right)| self.compared(left, right))
                    .collect::<Option<Vec<_>>>()
                    .unwrap_or_default(),
                (left, right) => self.compared(left, right).into_iter().collect(),
            },
            _ => Vec::new(),
        }
    }

    /// The host column `left` and `right` read, one as `OLD` and the other
    /// as `NEW`.
    fn compared(&self, left: &Expr, right: &Expr) -> Option<&'db DB::Column> {
        let (old, new) = match (self.field(left, false), self.field(right, true)) {
            (Some(old), Some(new)) => (old, new),
            _ => (self.field(right, false)?, self.field(left, true)?),
        };
        (old == new).then_some(old)
    }

    /// The host column `expression` reads as a field of `NEW` when `new`, of
    /// `OLD` otherwise, under parentheses.
    fn field(&self, expression: &Expr, new: bool) -> Option<&'db DB::Column> {
        self.pairs
            .iter()
            .map(|&(host, _)| host)
            .find(|host| names_row_field(expression, new, *host))
    }

    /// The referenced column `expression` reads as a field of `NEW`, in the
    /// constraint trigger whose row is the referenced row.
    fn referenced_field(&self, expression: &Expr) -> Option<&'db DB::Column> {
        self.order
            .iter()
            .copied()
            .find(|column| names_row_field(expression, true, *column))
    }

    /// The text and enum flag of the value every referenced row the subtype
    /// table can reference holds in the column `expression` reads from
    /// `NEW`.
    fn pinned_value(&self, expression: &Expr) -> Option<&Pinned<'db, DB>> {
        let column = self.referenced_field(expression)?;
        self.pinned.iter().find(|pin| pin.column == column)
    }

    /// Whether the constraint trigger's `WHEN` condition is true for every
    /// referenced row the subtype table can reference.
    fn holds(&self, condition: &Expr) -> bool {
        match condition {
            Expr::Nested(inner) => self.holds(inner),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => self.holds(left) && self.holds(right),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
            } => self.holds(left) || self.holds(right),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => [(left, right), (right, left)]
                .into_iter()
                .any(|(field, value)| {
                    self.pinned_value(field).is_some_and(|pin| {
                        kept_literal(value, pin.enumeration) == Some(pin.text.as_str())
                    })
                }),
            Expr::In {
                expr,
                target: InTarget::List(list),
                negated: false,
                ..
            } => self.pinned_value(expr).is_some_and(|pin| {
                list.iter()
                    .any(|value| kept_literal(value, pin.enumeration) == Some(pin.text.as_str()))
            }),
            _ => false,
        }
    }

    /// Whether knowing that `expression` has `truth` shows that the
    /// constraint trigger's row is gone or that a subtype row references
    /// it, for every referenced row the subtype table can reference.
    /// `absence` tells whether the trigger reads every referenced row.
    fn implies(&self, expression: &Expr, truth: Truth, absence: bool) -> bool {
        match expression {
            Expr::Nested(inner) => self.implies(inner, truth, absence),
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr,
            } => self.implies(expr, truth.negated(), absence),
            Expr::BinaryOp {
                left,
                op: op @ (BinaryOperator::And | BinaryOperator::Or),
                right,
            } => {
                let (left, right) = (
                    self.implies(left, truth, absence),
                    self.implies(right, truth, absence),
                );
                // `AND` true or not false, and `OR` not true or false, hold
                // when either side does. The other cases hold when both do.
                if (*op == BinaryOperator::And) == truth.affirms() {
                    left || right
                } else {
                    left && right
                }
            }
            Expr::Exists { subquery, negated } => {
                let truth = if *negated { truth.negated() } else { truth };
                if truth.affirms() {
                    self.finds_subtype_row(subquery)
                } else {
                    absence && self.finds_referenced_row(subquery)
                }
            }
            Expr::Case {
                operand: Some(operand),
                conditions,
                else_result,
                ..
            } => {
                let Some(pin) = self.pinned_value(operand) else {
                    return false;
                };
                for branch in conditions {
                    match kept_literal(&branch.condition, pin.enumeration) {
                        Some(label) if label == pin.text => {
                            return self.implies(&branch.result, truth, absence);
                        }
                        Some(_) => {}
                        None => return false,
                    }
                }
                else_result
                    .as_deref()
                    .is_some_and(|result| self.implies(result, truth, absence))
            }
            _ => false,
        }
    }

    /// Whether every row `query` finds is a subtype row referencing the
    /// constraint trigger's row. Its filter equates host columns with
    /// `NEW`'s referenced columns covering a unique key of the referenced
    /// table, the other host columns are `NOT NULL` so the foreign key checks
    /// the row, and other conjuncts only narrow it.
    fn finds_subtype_row(&self, query: &Query) -> bool {
        let Some((select, name)) = self.lone_select(query, self.table) else {
            return false;
        };
        let mut matched = Vec::new();
        for (left, right) in select
            .selection
            .iter()
            .flat_map(conjuncts)
            .filter_map(equated)
        {
            for (column, value) in [(left, right), (right, left)] {
                if let Some(host) = self.qualified(column, &name, self.table)
                    && let Some(referenced) = self.referenced_field(value)
                    && self.pairs.contains(&(host, referenced))
                {
                    matched.push((host, referenced));
                }
            }
        }
        let keyed = equality_keys(self.database, self.referenced).is_ok_and(|keys| {
            keys.iter().any(|key| {
                key.iter()
                    .all(|column| matched.iter().any(|(_, referenced)| referenced == column))
            })
        });
        keyed
            && self.pairs.iter().all(|(host, _)| {
                matched.iter().any(|(matched, _)| matched == host)
                    || may_hold_null(self.database, host).is_ok_and(|nullable| !nullable)
            })
    }

    /// Whether `query` finds the constraint trigger's row whenever it
    /// exists, since each conjunct of its filter equates a column of the
    /// referenced table no row holds `NULL` in with `NEW`'s value of it.
    fn finds_referenced_row(&self, query: &Query) -> bool {
        let Some((select, name)) = self.lone_select(query, self.referenced) else {
            return false;
        };
        select.selection.iter().flat_map(conjuncts).all(|conjunct| {
            equated(conjunct).is_some_and(|(left, right)| {
                [(left, right), (right, left)]
                    .into_iter()
                    .any(|(column, value)| {
                        self.qualified(column, &name, self.referenced)
                            .is_some_and(|column| {
                                self.referenced_field(value) == Some(column)
                                    && may_hold_null(self.database, column)
                                        .is_ok_and(|nullable| !nullable)
                            })
                    })
            })
        })
    }

    /// The `SELECT` of `query` with the name it reads `table` by, when it
    /// reads that table alone, without a child table's rows, and returns a
    /// row for each row its filter keeps, with no grouping, aggregate,
    /// window, set operation or limit.
    fn lone_select<'q>(&self, query: &'q Query, table: &DB::Table) -> Option<(&'q Select, String)> {
        if query.with.is_some() || query.limit_clause.is_some() || query.fetch.is_some() {
            return None;
        }
        let SetExpr::Select(select) = query.body.as_ref() else {
            return None;
        };
        let [from] = select.from.as_slice() else {
            return None;
        };
        let plain = select.top.is_none()
            && select.into.is_none()
            && select.prewhere.is_none()
            && select.having.is_none()
            && select.qualify.is_none()
            && select.lateral_views.is_empty()
            && select.connect_by.is_empty()
            && select.named_window.is_empty()
            && from.joins.is_empty()
            && matches!(&select.group_by, GroupByExpr::Expressions(grouped, modifiers)
                if grouped.is_empty() && modifiers.is_empty())
            && select.projection.iter().all(|item| match item {
                SelectItem::UnnamedExpr(expression)
                | SelectItem::ExprWithAlias {
                    expr: expression, ..
                } => {
                    matches!(
                        expression,
                        Expr::Value(_) | Expr::Identifier(_) | Expr::CompoundIdentifier(_)
                    )
                }
                SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => true,
                SelectItem::ExprWithAliases { .. } => false,
            });
        if !plain {
            return None;
        }
        Some((
            select.as_ref(),
            sole_relation(self.database, &from.relation, table)?,
        ))
    }

    /// The column of `table` that `expression` names, bare or qualified by
    /// `name`.
    fn qualified(
        &self,
        expression: &Expr,
        name: &str,
        table: &'db DB::Table,
    ) -> Option<&'db DB::Column> {
        let column = match expression {
            Expr::Nested(inner) => return self.qualified(inner, name, table),
            Expr::Identifier(column) => column,
            Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                [relation, column] if stored(relation) == name => column,
                _ => return None,
            },
            _ => return None,
        };
        table
            .columns(self.database)
            .ok()?
            .find(|candidate| names_column(candidate, column))
    }
}

/// The name a `FROM` item reading `table` alone goes by, without a child
/// table's rows unless `table` has none.
pub(crate) fn sole_relation<DB: DatabaseLike>(
    database: &DB,
    relation: &TableFactor,
    table: &DB::Table,
) -> Option<String> {
    let TableFactor::Table {
        name,
        alias,
        args: None,
        sample: None,
        with_ordinality: false,
        inheritance,
        ..
    } = relation
    else {
        return None;
    };
    let only = matches!(inheritance, Some(TableInheritance::Only { .. }));
    let childless = table
        .inheritors(database)
        .is_ok_and(|mut inheritors| inheritors.next().is_none());
    if !matches!(stored_table(database, name, None), Ok(Some(read)) if read == table)
        || !(only || childless)
    {
        return None;
    }
    match alias {
        Some(alias) if alias.columns.is_empty() => Some(stored(&alias.name).into_owned()),
        Some(_) => None,
        None => stored_parts(name).pop().map(Cow::into_owned),
    }
}

/// Whether `trigger` fires on every `UPDATE`, naming no columns.
fn fires_on_every_update<T: TriggerLike>(trigger: &T) -> bool {
    trigger
        .events()
        .iter()
        .any(|event| matches!(event, TriggerEvent::Update(columns) if columns.is_empty()))
}

/// Whether `column` is the one `ident` names.
fn names_column<C: ColumnLike>(column: &C, ident: &Ident) -> bool {
    *stored(ident) == *column.stored_column_name()
}

/// Whether `expression`, under parentheses, reads `column` from `NEW` when
/// `new` and from `OLD` otherwise.
fn names_row_field<C: ColumnLike>(expression: &Expr, new: bool, column: &C) -> bool {
    match expression {
        Expr::Nested(inner) => names_row_field(inner, new, column),
        Expr::CompoundIdentifier(parts) => matches!(
            parts.as_slice(),
            [record, field] if row(record) == Some(new) && names_column(column, field)
        ),
        _ => false,
    }
}

/// The two sides of an `=` conjunct.
fn equated(conjunct: &Expr) -> Option<(&Expr, &Expr)> {
    match conjunct {
        Expr::Nested(inner) => equated(inner),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => Some((left, right)),
        _ => None,
    }
}

/// What is known of a condition a path passed.
#[derive(Clone, Copy)]
enum Truth {
    True,
    NotTrue,
    False,
    NotFalse,
}

impl Truth {
    /// What is then known of the condition's negation.
    const fn negated(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::NotTrue => Self::NotFalse,
            Self::NotFalse => Self::NotTrue,
        }
    }

    /// Whether a condition never `NULL` is then true.
    const fn affirms(self) -> bool {
        matches!(self, Self::True | Self::NotFalse)
    }
}

/// Whether every path reaching a step passed a condition showing the
/// constraint trigger's row gone or referenced by a subtype row, writing
/// neither table since.
#[derive(Clone, Copy)]
struct Checked(bool);

impl FlowState for Checked {
    fn join(&mut self, other: Self) {
        self.0 &= other.0;
    }
}

/// Follows a constraint trigger's function to whether every path returning
/// passed the check.
struct Guard<'p, 'db, DB: DatabaseLike> {
    parent: &'p Parent<'db, DB>,
    /// Whether the function reads every referenced row, so a query finding
    /// none shows the trigger's row gone.
    absence: bool,
    table_writes: Reach<'db, DB, WritesTable<'db, DB>>,
    referenced_writes: Reach<'db, DB, WritesTable<'db, DB>>,
    /// Some path returns without the check.
    unchecked: bool,
    /// `NEW` names the trigger row throughout the body.
    followed: bool,
}

impl<DB: DatabaseLike> Guard<'_, '_, DB> {
    /// Whether `node` may write either table.
    fn writes<N: Visit + ?Sized>(&mut self, node: &N) -> bool {
        !self.table_writes.occurrences(node).is_empty()
            || !self.referenced_writes.occurrences(node).is_empty()
    }
}

impl<DB: DatabaseLike> FlowVisitor for Guard<'_, '_, DB> {
    type State = Checked;

    fn enter(&mut self, block: &Block, _state: &mut Checked) {
        self.followed &= !shadows(block, "new");
    }

    fn repeat(&mut self, repeated: &Loop, _state: &mut Checked) {
        self.followed &= !loop_writes(repeated, "new");
    }

    fn query(&mut self, query: &Query, state: &mut Checked) {
        state.0 &= !self.writes(query);
    }

    fn statement(&mut self, statement: &Statement, state: &mut Checked) {
        state.0 &= !self.writes(statement);
    }

    fn step(&mut self, node: &Node, state: &mut Checked) {
        if matches!(node.kind, NodeKind::Return { .. }) {
            self.unchecked |= !state.0;
        }
        self.followed &= !written_targets(node)
            .iter()
            .any(|target| names_row(target, "new"));
    }

    fn assume(&mut self, condition: &Query, holds: bool, state: &mut Checked) {
        let truth = if holds { Truth::True } else { Truth::NotTrue };
        state.0 |= evaluated(condition)
            .is_some_and(|condition| self.parent.implies(condition, truth, self.absence));
    }
}

/// A state no path changes.
#[derive(Clone, Copy)]
struct Unit;

impl FlowState for Unit {
    fn join(&mut self, _other: Self) {}
}

/// Follows a `BEFORE INSERT` trigger's function to whether it returns `NEW`
/// with its host columns unwritten.
struct Settles<'p, 'db, DB: DatabaseLike> {
    pairs: &'p KeyPairs<'db, DB>,
    settled: bool,
}

impl<DB: DatabaseLike> FlowVisitor for Settles<'_, '_, DB> {
    type State = Unit;

    fn enter(&mut self, block: &Block, _state: &mut Unit) {
        self.settled &= !shadows(block, "new");
    }

    fn repeat(&mut self, repeated: &Loop, _state: &mut Unit) {
        self.settled &= !loop_writes(repeated, "new");
    }

    fn query(&mut self, _query: &Query, _state: &mut Unit) {}

    fn statement(&mut self, _statement: &Statement, _state: &mut Unit) {}

    fn step(&mut self, node: &Node, _state: &mut Unit) {
        if let NodeKind::Return { value } = &node.kind {
            self.settled &= value
                .as_deref()
                .and_then(evaluated)
                .is_some_and(|value| names_record(value, "new"));
        }
        let pairs = self.pairs;
        self.settled &= written_targets(node).iter().all(|target| {
            pairs.iter().all(|(host, _)| {
                matches!(
                    new_field_write(target, &host.stored_column_name()),
                    Written::Elsewhere
                )
            })
        });
    }
}

/// Whether every path through a trigger function that returns has run a
/// statement `runs` accepts, with the trigger row `record` names neither
/// written nor shadowed anywhere in the body.
pub(crate) fn always_runs(block: &Block, record: &str, runs: impl Fn(&Statement) -> bool) -> bool {
    always_runs_unless(block, record, runs, |_, _| false)
}

/// [`always_runs`], also accepting a path that has gone on past a condition
/// evaluated to a truth `excused` accepts.
pub(crate) fn always_runs_unless(
    block: &Block,
    record: &str,
    runs: impl Fn(&Statement) -> bool,
    excused: impl Fn(&Expr, bool) -> bool,
) -> bool {
    let mut always = Always {
        runs,
        excused,
        record,
        missed: false,
        unfollowed: false,
    };
    walk_block(&mut always, block, Ran(false));
    !always.missed && !always.unfollowed
}

/// Whether every path reaching a step has run the statement sought.
#[derive(Clone, Copy)]
struct Ran(bool);

impl FlowState for Ran {
    fn join(&mut self, other: Self) {
        self.0 &= other.0;
    }
}

/// Follows a trigger function's paths to whether each one returning has run
/// the statement sought.
struct Always<'r, F, E> {
    runs: F,
    /// Accepts a path past a condition evaluated to the given truth.
    excused: E,
    /// `new` or `old`.
    record: &'r str,
    /// Some path returns without having run it.
    missed: bool,
    /// The function writes or shadows the record.
    unfollowed: bool,
}

impl<F: Fn(&Statement) -> bool, E: Fn(&Expr, bool) -> bool> FlowVisitor for Always<'_, F, E> {
    type State = Ran;

    fn enter(&mut self, block: &Block, _state: &mut Ran) {
        self.unfollowed |= shadows(block, self.record);
    }

    fn repeat(&mut self, repeated: &Loop, _state: &mut Ran) {
        self.unfollowed |= loop_writes(repeated, self.record);
    }

    fn query(&mut self, _query: &Query, _state: &mut Ran) {}

    fn assume(&mut self, condition: &Query, holds: bool, state: &mut Ran) {
        state.0 |= evaluated(condition).is_some_and(|condition| (self.excused)(condition, holds));
    }

    fn statement(&mut self, statement: &Statement, state: &mut Ran) {
        state.0 |= (self.runs)(statement);
    }

    fn step(&mut self, node: &Node, state: &mut Ran) {
        if matches!(node.kind, NodeKind::Return { .. }) {
            self.missed |= !state.0;
        }
        self.unfollowed |= written_targets(node)
            .iter()
            .any(|target| names_row(target, self.record));
    }
}

/// Whether `block` declares a variable or an alias that hides the trigger
/// row `record` names.
fn shadows(block: &Block, record: &str) -> bool {
    block.declarations.iter().any(|declaration| {
        declaration.name == record
            || matches!(&declaration.kind, DeclarationKind::Alias(AliasTarget::Name(name))
                if stored_parts(name).iter().any(|part| part == record))
    })
}

/// Whether a loop assigns the trigger row `record` names, or a part of it,
/// on each iteration.
fn loop_writes(repeated: &Loop, record: &str) -> bool {
    match &repeated.control {
        LoopControl::Range { variable, .. } | LoopControl::Cursor { variable, .. } => {
            variable == record
        }
        LoopControl::Query { targets, .. }
        | LoopControl::Dynamic { targets, .. }
        | LoopControl::Array { targets, .. } => {
            targets.iter().any(|target| names_row(target, record))
        }
        LoopControl::Unconditional | LoopControl::While(_) => false,
    }
}

/// Whether a part of `target`'s name is the trigger row `record` names.
fn names_row(target: &Target, record: &str) -> bool {
    stored_parts(&target.name).iter().any(|part| part == record)
}

/// The targets a step assigns.
fn written_targets(node: &Node) -> Vec<&Target> {
    match &node.kind {
        NodeKind::Assignment(assignment) => vec![&assignment.target],
        NodeKind::Statement {
            into: Some(into), ..
        }
        | NodeKind::Dynamic {
            into: Some(into), ..
        } => into.targets.iter().collect(),
        NodeKind::Fetch(fetch) => fetch.targets.iter().collect(),
        NodeKind::Diagnostics(diagnostics) => {
            diagnostics.items.iter().map(|item| &item.target).collect()
        }
        _ => Vec::new(),
    }
}
