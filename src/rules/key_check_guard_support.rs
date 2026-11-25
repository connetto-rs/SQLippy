//! The conditions a referencing table's `BEFORE` row triggers hold every row
//! to before PostgreSQL checks its foreign key.
//!
//! PostgreSQL runs the `BEFORE` row triggers of a write before the key check,
//! and checks no key holding a `NULL` nor, on `UPDATE`, a key the update
//! leaves unchanged. A trigger that raises or skips the row unless `NEW`
//! meets a condition, on every path that keeps the row, holds every checked
//! row to that condition.

use std::{borrow::Cow, mem};

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, TableLike, TriggerLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionSecurity, Query, Statement, TriggerEvent, TriggerPeriod,
    UnaryOperator,
};
use sqlparser_plpgsql::embedded::{Block, Loop, LoopControl, Node, NodeKind, Target};

use crate::rules::{
    existence_oracle_support::resolves_alike,
    expression_site_support::is_null_literal,
    plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
    policy_support::sets_only_search_path,
    trigger_support::{
        Written, evaluated, fires_for_clients, names_record, new_field, new_field_write,
        new_fields_as_columns, row, row_trigger, shadows_new, stored,
    },
};

/// What reaches a foreign key's check through one command.
pub(crate) enum KeyCheck {
    /// No row the command writes reaches the check.
    Skipped,
    /// Every row reaching the check meets each condition, written over the
    /// referencing table's columns by their stored names.
    Meeting(Vec<Expr>),
}

/// What the `BEFORE` row triggers of the table holding `foreign_key` let
/// reach its check through an `UPDATE` when `update` is set and an `INSERT`
/// otherwise.
///
/// A trigger counts when it runs a PL/pgSQL function with its caller's rights
/// setting no parameter but its search path, fires on every write of a key
/// column, and skips by its `WHEN` only rows the check skips. Every other
/// trigger firing on the command must return `NEW` or `NULL` with the key
/// columns unwritten, since a trigger may change the key after another
/// tested it, and a key column must not be generated, which `NEW` holds no
/// value for before the row is stored. A condition counts only when it reads
/// `NEW`'s key columns and no other column, variable or query, and resolves
/// its names on the function's search path as on the schema's. An `ASSERT`
/// holds nothing, since a session may turn assertions off.
pub(crate) fn key_check<DB: DatabaseLike>(
    database: &DB,
    foreign_key: &DB::ForeignKey,
    update: bool,
) -> Result<KeyCheck, LookupError> {
    let unguarded = Ok(KeyCheck::Meeting(Vec::new()));
    let mut keys = Vec::new();
    for column in foreign_key.host_columns(database)? {
        if column.generation_expression().is_some() {
            return unguarded;
        }
        keys.push(column.stored_column_name());
    }
    let guard = Guard { keys, update };
    let mut readings = Vec::new();
    for trigger in foreign_key.host_table(database).triggers(database)? {
        if !row_trigger(trigger, TriggerPeriod::Before)
            || !guard.fires(trigger)
            || !fires_for_clients(database, trigger)?
        {
            continue;
        }
        let Some(function) = trigger.function(database) else {
            return unguarded;
        };
        let Some(block) = plpgsql_block(function) else {
            return unguarded;
        };
        let reading = guard.read(trigger.condition(), &block);
        if !reading.kept {
            return unguarded;
        }
        if guard.fires_on_every_checked_row(trigger)
            && function.security_mode() != FunctionSecurity::Definer
            && sets_only_search_path(function)
        {
            readings.push((function, reading.checked));
        }
    }
    let mut facts = Vec::new();
    for (function, checked) in readings {
        let Some(found) = checked else {
            return Ok(KeyCheck::Skipped);
        };
        let path = function.search_path(database)?;
        for fact in found {
            if let Some(path) = &path
                && !resolves_alike(database, &fact, path)?
            {
                continue;
            }
            if !facts.contains(&fact) {
                facts.push(fact);
            }
        }
    }
    Ok(KeyCheck::Meeting(facts))
}

/// The key columns of a foreign key and the command writing them.
struct Guard<'k> {
    /// The stored names of the referencing columns.
    keys: Vec<Cow<'k, str>>,
    update: bool,
}

/// What one trigger function does to the rows reaching the key check.
struct Reading {
    /// Whether it returns `NEW` or `NULL` with the key columns unwritten on
    /// every path.
    kept: bool,
    /// The conditions every row it returns into the check meets, `None`
    /// when it returns none.
    checked: Option<Vec<Expr>>,
}

impl Guard<'_> {
    /// Whether `trigger` fires on the command at all.
    fn fires<T: TriggerLike>(&self, trigger: &T) -> bool {
        trigger.events().iter().any(|event| match event {
            TriggerEvent::Insert => !self.update,
            TriggerEvent::Update(_) => self.update,
            TriggerEvent::Delete | TriggerEvent::Truncate => false,
        })
    }

    /// Whether `trigger` fires on every row whose key the command writes and
    /// PostgreSQL checks. An `UPDATE` changes a key column only by naming it,
    /// so a column list must name every key column.
    fn fires_on_every_checked_row<T: TriggerLike>(&self, trigger: &T) -> bool {
        trigger.events().iter().any(|event| match event {
            TriggerEvent::Insert => !self.update,
            TriggerEvent::Update(columns) => {
                self.update
                    && (columns.is_empty()
                        || self
                            .keys
                            .iter()
                            .all(|key| columns.iter().any(|column| stored(column) == *key)))
            }
            TriggerEvent::Delete | TriggerEvent::Truncate => false,
        }) && trigger
            .condition()
            .is_none_or(|condition| self.unchecked(condition, false))
    }

    /// Follows `block`, entered on rows meeting the trigger's `condition`.
    fn read(&self, condition: Option<&Expr>, block: &Block) -> Reading {
        let mut entry = Known::Facts(Vec::new());
        if let Some(condition) = condition {
            self.assume(condition, true, &mut entry);
        }
        let mut flow = Flow {
            guard: self,
            returned: None,
            kept: true,
            asserting: false,
        };
        walk_block(&mut flow, block, entry);
        Reading {
            kept: flow.kept,
            checked: match flow.returned {
                None | Some(Known::Unchecked) => None,
                Some(Known::Facts(facts)) => Some(facts),
            },
        }
    }

    /// Narrows `state` to a path on which `condition` evaluated to true when
    /// `holds` is set, and to false or `NULL` otherwise.
    fn assume(&self, condition: &Expr, holds: bool, state: &mut Known) {
        if self.unchecked(condition, holds) {
            *state = Known::Unchecked;
        } else if let Known::Facts(facts) = state {
            for fact in self.facts(condition, holds) {
                if !facts.contains(&fact) {
                    facts.push(fact);
                }
            }
        }
    }

    /// Whether every row on which `condition` evaluated to true when `holds`
    /// is set, and to false or `NULL` otherwise, skips the key check, by a
    /// `NULL` key column or, on `UPDATE`, by an unchanged key.
    fn unchecked(&self, condition: &Expr, holds: bool) -> bool {
        match (condition, holds) {
            (Expr::Nested(inner), _) => self.unchecked(inner, holds),
            (
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::And,
                    right,
                },
                true,
            )
            | (
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Or,
                    right,
                },
                false,
            ) => self.unchecked(left, holds) || self.unchecked(right, holds),
            (
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Or,
                    right,
                },
                true,
            )
            | (
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::And,
                    right,
                },
                false,
            ) => self.unchecked(left, holds) && self.unchecked(right, holds),
            (
                Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    expr,
                },
                true,
            ) => self.unchecked(expr, false),
            (Expr::IsNull(field), true) | (Expr::IsNotNull(field), false) => {
                self.key_position(field).is_some()
            }
            (Expr::IsNotDistinctFrom(left, right), true)
            | (Expr::IsDistinctFrom(left, right), false) => self.compares_key_with_old(left, right),
            _ => false,
        }
    }

    /// The conditions every checked row on which `condition` evaluated to
    /// true when `holds` is set, and to false or `NULL` otherwise, meets.
    fn facts(&self, condition: &Expr, holds: bool) -> Vec<Expr> {
        match (condition, holds) {
            (Expr::Nested(inner), _) => self.facts(inner, holds),
            (
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::And,
                    right,
                },
                true,
            )
            | (
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Or,
                    right,
                },
                false,
            ) => {
                let mut facts = self.facts(left, holds);
                facts.extend(self.facts(right, holds));
                facts
            }
            (
                Expr::BinaryOp {
                    left,
                    op: op @ (BinaryOperator::Or | BinaryOperator::And),
                    right,
                },
                _,
            ) => {
                if self.unchecked(left, holds) {
                    self.facts(right, holds)
                } else if self.unchecked(right, holds) {
                    self.facts(left, holds)
                } else if *op == BinaryOperator::Or {
                    self.columns(condition).into_iter().collect()
                } else {
                    Vec::new()
                }
            }
            (
                Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    expr,
                },
                true,
            ) => {
                // A negation is true where its operand is false.
                let mut facts = self.facts(expr, false);
                facts.extend(self.columns(condition));
                facts
            }
            (Expr::IsNotDistinctFrom(left, right), true)
            | (Expr::IsDistinctFrom(left, right), false) => self.key_equality(left, right),
            (_, true) => self.columns(condition).into_iter().collect(),
            (_, false) => Vec::new(),
        }
    }

    /// `key = value` for `left` and `right` known not distinct, which a
    /// checked row's key column, never `NULL`, makes equal, when one names a
    /// key column of `NEW`.
    fn key_equality(&self, left: &Expr, right: &Expr) -> Vec<Expr> {
        for (key, value) in [(left, right), (right, left)] {
            if self.key_position(key).is_some()
                && let Some(equality) = self.columns(&Expr::BinaryOp {
                    left: Box::new(key.clone()),
                    op: BinaryOperator::Eq,
                    right: Box::new(value.clone()),
                })
            {
                return vec![equality];
            }
        }
        Vec::new()
    }

    /// `condition` with `NEW`'s key columns written bare, or `None` when it
    /// reads another column, a variable or a query.
    fn columns(&self, condition: &Expr) -> Option<Expr> {
        new_fields_as_columns(condition, |field| self.keys.iter().any(|key| key == field))
    }

    /// The position of the key column `expression` names as a field of
    /// `NEW`.
    fn key_position(&self, expression: &Expr) -> Option<usize> {
        let field = new_field(expression)?;
        self.keys.iter().position(|key| *key == field)
    }

    /// Whether `left` and `right` compare the one key column of `NEW` with
    /// the same column of `OLD`, which on `UPDATE` tests whether the key
    /// changed.
    fn compares_key_with_old(&self, left: &Expr, right: &Expr) -> bool {
        let [key] = self.keys.as_slice() else {
            return false;
        };
        self.update
            && [(left, right), (right, left)]
                .into_iter()
                .any(|(new, old)| {
                    self.key_position(new).is_some()
                        && old_field(old).is_some_and(|field| field == *key)
                })
    }
}

/// The stored name of the field of `OLD` the expression, under parentheses,
/// names.
fn old_field(expression: &Expr) -> Option<Cow<'_, str>> {
    match expression {
        Expr::Nested(inner) => old_field(inner),
        Expr::CompoundIdentifier(parts) => match parts.as_slice() {
            [record, field] if row(record) == Some(false) => Some(stored(field)),
            _ => None,
        },
        _ => None,
    }
}

/// What a path knows of the rows on it that reach the key check.
#[derive(Clone)]
enum Known {
    /// No row on the path reaches the check.
    Unchecked,
    /// Every row on the path reaching the check meets each condition.
    Facts(Vec<Expr>),
}

impl FlowState for Known {
    fn join(&mut self, other: Self) {
        match (&mut *self, other) {
            (_, Self::Unchecked) => {}
            (Self::Unchecked, other) => *self = other,
            (Self::Facts(facts), Self::Facts(others)) => {
                facts.retain(|fact| others.contains(fact));
            }
        }
    }
}

/// Follows a trigger function's paths to the rows it returns.
struct Flow<'g, 'k> {
    guard: &'g Guard<'k>,
    /// What every path returning `NEW` knows, `None` until one returns it.
    returned: Option<Known>,
    /// Whether every path returns `NEW` or `NULL` with the key columns
    /// unwritten.
    kept: bool,
    /// Whether the condition assumed next is an `ASSERT`'s.
    asserting: bool,
}

impl Flow<'_, '_> {
    /// Whether writing `targets` may change a key column of `NEW`.
    fn rewrites<'t>(&self, targets: impl IntoIterator<Item = &'t Target>) -> bool {
        targets.into_iter().any(|target| {
            self.guard
                .keys
                .iter()
                .any(|key| !matches!(new_field_write(target, key), Written::Elsewhere))
        })
    }
}

impl FlowVisitor for Flow<'_, '_> {
    type State = Known;

    fn enter(&mut self, block: &Block, _state: &mut Known) {
        self.kept &= !shadows_new(block);
    }

    fn repeat(&mut self, repeated: &Loop, _state: &mut Known) {
        self.kept &= match &repeated.control {
            LoopControl::Range { variable, .. } | LoopControl::Cursor { variable, .. } => {
                variable != "new"
            }
            LoopControl::Query { targets, .. }
            | LoopControl::Dynamic { targets, .. }
            | LoopControl::Array { targets, .. } => !self.rewrites(targets),
            LoopControl::Unconditional | LoopControl::While(_) => true,
        };
    }

    fn query(&mut self, _query: &Query, _state: &mut Known) {}

    fn statement(&mut self, _statement: &Statement, _state: &mut Known) {}

    fn step(&mut self, node: &Node, state: &mut Known) {
        let unkept = match &node.kind {
            NodeKind::Assignment(assignment) => self.rewrites([&assignment.target]),
            NodeKind::Statement { into, .. } => into
                .as_ref()
                .is_some_and(|into| self.rewrites(&into.targets)),
            NodeKind::Dynamic { .. } => true,
            NodeKind::Fetch(fetch) => self.rewrites(&fetch.targets),
            NodeKind::Diagnostics(diagnostics) => {
                self.rewrites(diagnostics.items.iter().map(|item| &item.target))
            }
            NodeKind::Assert(_) => {
                self.asserting = true;
                false
            }
            NodeKind::Return { value } => {
                let value = value.as_deref().and_then(evaluated);
                if value.is_some_and(|value| names_record(value, "new")) {
                    // The path ends here, so its state moves into the returns.
                    let mut returned = mem::replace(state, Known::Unchecked);
                    if let Some(earlier) = self.returned.take() {
                        returned.join(earlier);
                    }
                    self.returned = Some(returned);
                    false
                } else {
                    !value.is_some_and(is_null_literal)
                }
            }
            _ => false,
        };
        self.kept &= !unkept;
    }

    fn assume(&mut self, condition: &Query, holds: bool, state: &mut Known) {
        if mem::take(&mut self.asserting) {
            return;
        }
        if let Some(condition) = evaluated(condition) {
            self.guard.assume(condition, holds, state);
        }
    }
}
