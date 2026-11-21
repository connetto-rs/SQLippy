//! Functions that take a lock and then read rows the transaction's snapshot
//! may predate.

use std::{
    collections::{HashMap, HashSet},
    ops::ControlFlow,
};

use sql_traits::{
    structs::{IdentifierCase, WrittenCall},
    traits::{DatabaseLike, FunctionLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionBehavior, InTarget, ObjectName, Query, SetExpr, Statement,
    TableFactor, UnaryOperator, Visit, Visitor,
};
use sqlparser_plpgsql::embedded::{Node, NodeKind};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::stored_table,
        expression_site_support::body_statements,
        function_reach_support::{literal_key, split},
        literal_support::text_literal,
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        trigger_support::evaluated,
        walk_support::walk,
    },
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports a function taking an advisory,
    /// table or row lock and then reading a table, itself or through the
    /// functions it calls, with no check before the lock that refuses a
    /// transaction-wide snapshot.
    ///
    /// Under `REPEATABLE READ` and `SERIALIZABLE` the snapshot is taken by
    /// the transaction's first statement, so a read after waiting for the
    /// lock misses what the previous holder committed. A guard counts when
    /// a condition on `current_setting('transaction_isolation')` before the
    /// lock leaves every `REPEATABLE READ` path through an error, written
    /// in the body or in a PL/pgSQL function called by a statement or an
    /// expression made of that call alone. Re-reading the rows a
    /// `SELECT ... FOR UPDATE` locked, by the same filter, is
    /// exempt. A `STABLE` or `IMMUTABLE` function reads with its caller's
    /// snapshot at every level and is reported whatever it checks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = SnapshotBeforeLock::default().into();
    /// let schema = |guard: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE TABLE slots (id INT PRIMARY KEY);
    ///          CREATE FUNCTION reserve(slot INT) RETURNS void LANGUAGE plpgsql AS $$ BEGIN
    ///            {guard}
    ///            PERFORM pg_advisory_xact_lock(1);
    ///            IF (SELECT count(*) FROM slots) >= 10 THEN RAISE EXCEPTION 'full'; END IF;
    ///            INSERT INTO slots VALUES (slot);
    ///          END $$;"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("")).is_err());
    /// let guarded = schema(
    ///     "IF current_setting('transaction_isolation') <> 'read committed' THEN RAISE EXCEPTION 'read committed required'; END IF;",
    /// );
    /// assert!(constrainer.validate_schema(&guarded).is_ok());
    /// ```
    SnapshotBeforeLock,
    register_function_rule,
    LintGroup::Suspicious,
    "Under REPEATABLE READ or SERIALIZABLE a transaction reads from the snapshot its first statement took, so a check that reads rows after waiting for a lock misses what the previous holder committed and can admit a write the lock was meant to refuse.",
    Some("https://www.postgresql.org/docs/18/transaction-iso.html#XACT-REPEATABLE-READ"),
    RuleExample {
        bad: "CREATE TABLE slots (id integer PRIMARY KEY);\n\
CREATE FUNCTION reserve_slot(slot_id integer) RETURNS void LANGUAGE plpgsql VOLATILE AS $$\n\
BEGIN\n  PERFORM pg_advisory_xact_lock(41001);\n  IF (SELECT count(*) FROM slots) >= 10 THEN\n    RAISE EXCEPTION 'capacity reached';\n  END IF;\n  INSERT INTO slots VALUES (slot_id);\nEND $$;",
        good: "CREATE TABLE slots (id integer PRIMARY KEY);\n\
CREATE FUNCTION reserve_slot(slot_id integer) RETURNS void LANGUAGE plpgsql VOLATILE AS $$\n\
BEGIN\n  IF current_setting('transaction_isolation') <> 'read committed' THEN\n    RAISE EXCEPTION 'read committed required';\n  END IF;\n  PERFORM pg_advisory_xact_lock(41001);\n  IF (SELECT count(*) FROM slots) >= 10 THEN\n    RAISE EXCEPTION 'capacity reached';\n  END IF;\n  INSERT INTO slots VALUES (slot_id);\nEND $$;",
    }
);

/// The catalog functions taking an advisory lock.
const ADVISORY_LOCKS: [&str; 8] = [
    "pg_advisory_lock",
    "pg_advisory_lock_shared",
    "pg_advisory_xact_lock",
    "pg_advisory_xact_lock_shared",
    "pg_try_advisory_lock",
    "pg_try_advisory_lock_shared",
    "pg_try_advisory_xact_lock",
    "pg_try_advisory_xact_lock_shared",
];

/// A lock a path holds.
#[derive(Clone, PartialEq, Eq, Hash)]
enum Held {
    /// An advisory lock, as the call taking it is written.
    Advisory(String),
    /// A `LOCK TABLE`, as written.
    Table(String),
    /// The rows of `table` a `SELECT ... FOR UPDATE` or `FOR SHARE` locked
    /// by `filter`.
    Rows {
        table: String,
        filter: Option<String>,
    },
    /// A lock a called function may take, as the call is written.
    Called(String),
}

impl Held {
    fn describe(&self) -> String {
        match self {
            Self::Advisory(call) => format!("the advisory lock `{call}`"),
            Self::Table(lock) => format!("`{lock}`"),
            Self::Rows { table, .. } => format!("a row lock on '{table}'"),
            Self::Called(call) => format!("a lock through `{call}`"),
        }
    }
}

/// What a path knows about locks and the isolation level.
#[derive(Clone, Default)]
struct Snapshot {
    /// The path runs only under an isolation level taking a new snapshot per
    /// statement.
    guarded: bool,
    /// Locks the path took while unguarded.
    held: Vec<Held>,
    /// Variables the path assigned the isolation level to.
    isolation: HashSet<String>,
}

impl FlowState for Snapshot {
    fn join(&mut self, other: Self) {
        self.guarded &= other.guarded;
        for held in other.held {
            if !self.held.contains(&held) {
                self.held.push(held);
            }
        }
        self.isolation.retain(|name| other.isolation.contains(name));
    }
}

/// Whether `expression` calls one of `names` in `pg_catalog`.
fn calls_catalog(expression: &Expr, names: &[&str]) -> bool {
    let Expr::Function(function) = expression else {
        return false;
    };
    split(&function.name).is_some_and(|(schema, name)| {
        schema.is_none_or(|schema| schema.eq_ignore_ascii_case("pg_catalog"))
            && names.iter().any(|sought| sought.eq_ignore_ascii_case(name))
    })
}

/// Whether `expression` reads the transaction's isolation level, directly
/// or through a variable assigned it.
fn reads_isolation(expression: &Expr, variables: &HashSet<String>) -> bool {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => reads_isolation(inner, variables),
        Expr::Identifier(ident) => variables.contains(&ident.value.to_lowercase()),
        Expr::Function(function) => {
            calls_catalog(expression, &["current_setting"])
                && literal_key(function)
                    .is_some_and(|key| key.eq_ignore_ascii_case("transaction_isolation"))
        }
        _ => false,
    }
}

/// What `expression` evaluates to under `REPEATABLE READ`, `None` when it
/// depends on anything else.
fn under_repeatable_read(expression: &Expr, variables: &HashSet<String>) -> Option<bool> {
    const LEVEL: &str = "repeatable read";
    let compared = |left: &Expr, right: &Expr| {
        let level = |side: &Expr, other: &Expr| {
            reads_isolation(side, variables)
                .then(|| text_literal(other))
                .flatten()
                .map(|text| text.eq_ignore_ascii_case(LEVEL))
        };
        level(left, right).or_else(|| level(right, left))
    };
    match expression {
        Expr::Nested(inner) => under_repeatable_read(inner, variables),
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => under_repeatable_read(expr, variables).map(|value| !value),
        Expr::BinaryOp { left, op, right } => match op {
            BinaryOperator::Eq => compared(left, right),
            BinaryOperator::NotEq => compared(left, right).map(|equal| !equal),
            BinaryOperator::And => {
                let (left, right) = (
                    under_repeatable_read(left, variables),
                    under_repeatable_read(right, variables),
                );
                match (left, right) {
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                }
            }
            BinaryOperator::Or => {
                let (left, right) = (
                    under_repeatable_read(left, variables),
                    under_repeatable_read(right, variables),
                );
                match (left, right) {
                    (Some(true), _) | (_, Some(true)) => Some(true),
                    (Some(false), Some(false)) => Some(false),
                    _ => None,
                }
            }
            _ => None,
        },
        Expr::IsDistinctFrom(left, right) => compared(left, right).map(|equal| !equal),
        Expr::IsNotDistinctFrom(left, right) => compared(left, right),
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated,
            ..
        } if reads_isolation(expr, variables) => {
            let mut levels = list.iter().map(text_literal);
            let found = levels
                .clone()
                .flatten()
                .any(|level| level.eq_ignore_ascii_case(LEVEL));
            levels
                .all(|level| level.is_some())
                .then_some(found != *negated)
        }
        _ => None,
    }
}

/// The table a plain `FROM` item names, rendered.
fn factor_table(factor: &TableFactor) -> Option<&ObjectName> {
    match factor {
        TableFactor::Table { name, .. } => Some(name),
        _ => None,
    }
}

/// A table a statement reads.
struct Read {
    table: String,
    /// The filter of a `SELECT` reading the table alone.
    filter: Option<String>,
    /// The call reading it, for a read in a called function.
    through: Option<String>,
}

impl Read {
    fn describe(&self) -> String {
        match &self.through {
            Some(call) => format!("'{}' through `{call}`", self.table),
            None => format!("'{}'", self.table),
        }
    }
}

/// The locks, table reads and calls of one statement or query, in that
/// order of interest: reads are judged against the locks taken before it.
struct Fragment<'db, DB: DatabaseLike> {
    database: &'db DB,
    locks: Vec<Held>,
    reads: Vec<Read>,
    /// Each function a call may reach, with the call as written.
    calls: Vec<(String, &'db DB::Function)>,
}

impl<DB: DatabaseLike> Fragment<'_, DB> {
    fn called(&mut self, call: WrittenCall<'_>) {
        let Ok(functions) = self
            .database
            .functions_reached_by(call, IdentifierCase::Folded)
        else {
            return;
        };
        let written = call.to_string();
        self.calls.extend(
            functions
                .filter(|function| function.target_name().schema() != Some("pg_catalog"))
                .map(|function| (written.clone(), function)),
        );
    }
}

impl<DB: DatabaseLike> Visitor for Fragment<'_, DB> {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        let SetExpr::Select(select) = query.body.as_ref() else {
            return ControlFlow::Continue(());
        };
        let tables: Vec<&ObjectName> = select
            .from
            .iter()
            .flat_map(|from| {
                std::iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
            })
            .filter_map(factor_table)
            .filter(|name| matches!(stored_table(self.database, name, None), Ok(Some(_))))
            .collect();
        let filter = select.selection.as_ref().map(ToString::to_string);
        if !query.locks.is_empty() {
            if let [table] = tables.as_slice() {
                self.locks.push(Held::Rows {
                    table: table.to_string(),
                    filter,
                });
            } else {
                self.locks.extend(tables.iter().map(|table| Held::Rows {
                    table: table.to_string(),
                    filter: None,
                }));
            }
            return ControlFlow::Continue(());
        }
        let alone = tables.len() == 1;
        self.reads.extend(tables.into_iter().map(|table| Read {
            table: table.to_string(),
            filter: alone.then(|| filter.clone()).flatten(),
            through: None,
        }));
        ControlFlow::Continue(())
    }

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        if let Statement::Lock(lock) = statement {
            self.locks.push(Held::Table(lock.to_string()));
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<()> {
        if let Some(call) = WrittenCall::relation(factor) {
            self.called(call);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if calls_catalog(expression, &ADVISORY_LOCKS) {
            self.locks.push(Held::Advisory(expression.to_string()));
        } else if let Expr::Function(call) = expression {
            self.called(call.into());
        }
        ControlFlow::Continue(())
    }
}

/// A read after a lock that the lock does not refresh.
struct StaleRead {
    lock: String,
    read: String,
}

/// What a call to a function does to its caller's snapshot.
#[derive(Default)]
struct Callee {
    /// Every path returning from it passed a guard, so it raises under
    /// `REPEATABLE READ`.
    refuses: bool,
    /// Whether it may take a lock.
    locks: bool,
    /// The tables it may read.
    reads: Vec<String>,
}

/// Follows locks and reads along the paths of a body.
struct Locks<'db, DB: DatabaseLike> {
    database: &'db DB,
    /// Whether a guard on the isolation level can protect the function.
    guards: bool,
    found: Option<StaleRead>,
    /// Whether a `RETURN` leaves the body on a path no guard narrowed.
    returns_unguarded: bool,
    /// Whether the body may take a lock, on any path.
    takes_lock: bool,
    /// Every table the body may read, on any path.
    reads: Vec<String>,
    /// What each called function read so far does, nothing while its body
    /// is being read.
    callees: HashMap<&'db DB::Function, Callee>,
}

impl<'db, DB: DatabaseLike> Locks<'db, DB> {
    fn new(database: &'db DB, guards: bool, callees: HashMap<&'db DB::Function, Callee>) -> Self {
        Self {
            database,
            guards,
            found: None,
            returns_unguarded: false,
            takes_lock: false,
            reads: Vec::new(),
            callees,
        }
    }

    /// Walks the body of `function`, answering whether every path returning
    /// from it passed a guard, never for a body in another language than
    /// PL/pgSQL.
    fn body(&mut self, function: &DB::Function) -> bool {
        if let Some(block) = plpgsql_block(function) {
            let ended = walk_block(self, &block, Snapshot::default());
            !self.returns_unguarded && ended.is_none_or(|state| state.guarded)
        } else {
            let mut state = Snapshot::default();
            for statement in body_statements(function) {
                self.statement(&statement, &mut state);
            }
            false
        }
    }

    /// What a call to `function` does, read from its body once.
    fn callee(&mut self, function: &'db DB::Function) -> &Callee {
        if !self.callees.contains_key(function) {
            self.callees.insert(function, Callee::default());
            let mut body = Locks::new(self.database, true, std::mem::take(&mut self.callees));
            let refuses = body.body(function);
            // A call that raises under `REPEATABLE READ` leaves no stale snapshot.
            let callee = if refuses {
                Callee {
                    refuses,
                    ..Callee::default()
                }
            } else {
                Callee {
                    refuses,
                    locks: body.takes_lock,
                    reads: body.reads,
                }
            };
            self.callees = body.callees;
            self.callees.insert(function, callee);
        }
        &self.callees[function]
    }

    /// Guards `state` when `query` is a call whose every reached function
    /// refuses `REPEATABLE READ`.
    fn call(&mut self, query: &Query, state: &mut Snapshot) {
        if !self.guards || state.guarded {
            return;
        }
        let Some(Expr::Function(call)) = evaluated(query) else {
            return;
        };
        let Ok(called) = self
            .database
            .functions_reached_by(call, IdentifierCase::Folded)
        else {
            return;
        };
        let called: Vec<&'db DB::Function> = called.collect();
        if !called.is_empty()
            && called
                .into_iter()
                .all(|function| self.callee(function).refuses)
        {
            state.guarded = true;
        }
    }

    fn fragment<V: Visit + ?Sized>(&mut self, node: &V, state: &mut Snapshot) {
        let mut fragment = Fragment {
            database: self.database,
            locks: Vec::new(),
            reads: Vec::new(),
            calls: Vec::new(),
        };
        let _ = walk(node, &mut fragment);
        for (call, function) in fragment.calls {
            let callee = self.callee(function);
            fragment.reads.extend(callee.reads.iter().map(|table| Read {
                table: table.clone(),
                filter: None,
                through: Some(call.clone()),
            }));
            if callee.locks {
                fragment.locks.push(Held::Called(call));
            }
        }
        self.takes_lock |= !fragment.locks.is_empty();
        if self.found.is_none() {
            for read in &fragment.reads {
                let exempt = state.held.iter().any(|held| {
                    matches!(held, Held::Rows { table: locked, filter: locked_by }
                        if *locked == read.table && locked_by.is_some() && *locked_by == read.filter)
                });
                if let (false, Some(held)) = (exempt, state.held.first()) {
                    self.found = Some(StaleRead {
                        lock: held.describe(),
                        read: read.describe(),
                    });
                    break;
                }
            }
        }
        self.reads
            .extend(fragment.reads.into_iter().map(|read| read.table));
        if !state.guarded {
            for lock in fragment.locks {
                if !state.held.contains(&lock) {
                    state.held.push(lock);
                }
            }
        }
    }
}

impl<DB: DatabaseLike> FlowVisitor for Locks<'_, DB> {
    type State = Snapshot;

    fn query(&mut self, query: &Query, state: &mut Snapshot) {
        self.fragment(query, state);
        self.call(query, state);
    }

    fn statement(&mut self, statement: &Statement, state: &mut Snapshot) {
        self.fragment(statement, state);
        if let Statement::Query(query) = statement {
            self.call(query, state);
        }
    }

    fn step(&mut self, node: &Node, state: &mut Snapshot) {
        match &node.kind {
            NodeKind::Assignment(assignment) => {
                let target = assignment.target.name.to_string().to_lowercase();
                if evaluated(&assignment.value)
                    .is_some_and(|value| reads_isolation(value, &state.isolation))
                {
                    state.isolation.insert(target);
                } else {
                    state.isolation.remove(&target);
                }
            }
            // The next transaction's snapshot follows every lock taken so
            // far, and only `AND CHAIN` keeps the isolation level a guard
            // checked.
            NodeKind::Commit { chain } | NodeKind::Rollback { chain } => {
                state.held.clear();
                state.guarded &= *chain;
            }
            NodeKind::Return { .. } => self.returns_unguarded |= !state.guarded,
            _ => {}
        }
    }

    fn assume(&mut self, condition: &Query, holds: bool, state: &mut Snapshot) {
        if self.guards
            && evaluated(condition)
                .and_then(|condition| under_repeatable_read(condition, &state.isolation))
                .is_some_and(|value| value != holds)
        {
            state.guarded = true;
        }
    }
}

impl<DB: DatabaseLike> FunctionRule for SnapshotBeforeLock<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if function.target_name().schema() == Some("pg_catalog") {
            return Ok(());
        }
        let volatility = function.volatility();
        let volatile = volatility == FunctionBehavior::Volatile;
        let mut locks = Locks::new(database, volatile, HashMap::new());
        locks.body(function);
        let Some(StaleRead { lock, read }) = locks.found else {
            return Ok(());
        };
        let signature = signature(function, database);
        if volatile {
            reporter.function(
                function,
                format!(
                    "Function '{signature}' takes {lock} and then reads {read}, but under REPEATABLE READ or SERIALIZABLE the read uses the snapshot taken before the lock was granted, so it misses what the previous holder committed."
                ),
                "Raise unless current_setting('transaction_isolation') is 'read committed' before taking the lock, or have callers retry the whole transaction on serialization failure."
                    .to_owned(),
            )?;
        } else {
            reporter.function(
                function,
                format!(
                    "Function '{signature}' is declared {volatility} and reads {read} after taking {lock}, but a non-volatile function reads with its caller's snapshot at every isolation level, so the read misses what the previous holder committed."
                ),
                "Declare the function VOLATILE, and raise unless current_setting('transaction_isolation') is 'read committed' before taking the lock."
                    .to_owned(),
            )?;
        }
        Ok(())
    }
}
