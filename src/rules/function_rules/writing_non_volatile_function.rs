//! Statements a non-volatile function cannot run.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::traits::{DatabaseLike, FunctionLike};
use sqlparser::ast::{FunctionBehavior, LockType, Query, SetExpr, Statement, Visitor};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{expression_site_support::body_statements, walk_support::walk},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Reports `STABLE` or `IMMUTABLE` functions whose bodies run a statement
/// other than a query without row locks, such as `INSERT`, `UPDATE`,
/// `DELETE`, `MERGE`, `TRUNCATE`, `SET`, `NOTIFY`, `LOCK`, `CALL`, a DDL
/// command, `SELECT INTO` or a locking read.
///
/// PostgreSQL refuses every call that reaches the statement, naming the
/// command, or the statement around it when a write sits in a `WITH` item.
/// The rule reads SQL, `BEGIN ATOMIC` and PL/pgSQL bodies, writes inside
/// `WITH` items included, and skips bodies that do not parse. It sits beside
/// `impure_immutable_function`, which judges reads.
///
/// The rule does not run on SQLite, which has no stored functions.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = WritingNonVolatileFunction::default().into();
/// let schema = "CREATE TABLE audit (n INT);";
/// let stable = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE FUNCTION f() RETURNS VOID LANGUAGE sql STABLE
///        AS $$ INSERT INTO audit VALUES (5) $$;"
/// )).unwrap();
/// assert!(constrainer.validate_schema(&stable).is_err());
/// let volatile = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE FUNCTION f() RETURNS VOID LANGUAGE sql VOLATILE
///        AS $$ INSERT INTO audit VALUES (5) $$;"
/// )).unwrap();
/// assert!(constrainer.validate_schema(&volatile).is_ok());
/// ```
pub struct WritingNonVolatileFunction<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for WritingNonVolatileFunction<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<WritingNonVolatileFunction<DB>> for GenericConstrainer<DB> {
    fn from(rule: WritingNonVolatileFunction<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for WritingNonVolatileFunction<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(WritingNonVolatileFunction),
            group: LintGroup::Correctness,
            rationale: "PostgreSQL refuses every call that reaches a statement other than a query without row locks in a STABLE or IMMUTABLE function, such as a write, directly or inside a WITH item, a setting change, a lock, a notification or a DDL command.",
            source: Some("https://www.postgresql.org/docs/18/xfunc-volatility.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE audit (n INT);\nCREATE FUNCTION f() RETURNS VOID LANGUAGE sql STABLE AS 'INSERT INTO audit VALUES (5)';",
                good: "CREATE TABLE audit (n INT);\nCREATE FUNCTION f() RETURNS VOID LANGUAGE sql VOLATILE AS 'INSERT INTO audit VALUES (5)';",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

/// Stops at the first statement a non-volatile function cannot run, naming
/// its command, or quoting a statement without a fixed name.
struct FirstRefused;

/// The rank PostgreSQL gives `lock_type` when one table is locked more than
/// once, naming the statement after the strongest.
fn strength(lock_type: LockType) -> u8 {
    match lock_type {
        LockType::KeyShare => 0,
        LockType::Share => 1,
        LockType::NoKeyUpdate => 2,
        LockType::Update => 3,
    }
}

impl Visitor for FirstRefused {
    type Break = Cow<'static, str>;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        if matches!(query.body.as_ref(), SetExpr::Select(select) if select.into.is_some()) {
            return ControlFlow::Break(Cow::Borrowed("SELECT INTO"));
        }
        match query
            .locks
            .iter()
            .map(|lock| lock.lock_type)
            .max_by_key(|lock_type| strength(*lock_type))
        {
            Some(lock_type) => ControlFlow::Break(Cow::Owned(format!("SELECT FOR {lock_type}"))),
            None => ControlFlow::Continue(()),
        }
    }

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        let named = match statement {
            Statement::Query(_) => return ControlFlow::Continue(()),
            Statement::Insert(_) => "INSERT",
            Statement::Update(_) => "UPDATE",
            Statement::Delete(_) => "DELETE",
            Statement::Merge(_) => "MERGE",
            Statement::Truncate { .. } => "TRUNCATE TABLE",
            other => return ControlFlow::Break(Cow::Owned(format!("`{other}`"))),
        };
        ControlFlow::Break(Cow::Borrowed(named))
    }
}

impl<DB: DatabaseLike> FunctionRule for WritingNonVolatileFunction<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let volatility = function.volatility();
        if !matches!(
            volatility,
            FunctionBehavior::Stable | FunctionBehavior::Immutable
        ) || function.target_name().schema() == Some("pg_catalog")
        {
            return Ok(());
        }
        let statements = body_statements(function);
        let atomic = function.atomic_statements(database)?;
        for statement in statements
            .iter()
            .chain(atomic.as_deref().into_iter().flatten())
        {
            if let ControlFlow::Break(kind) = walk(statement, &mut FirstRefused) {
                let signature = signature(function, database);
                reporter.function(
                    function,
                    format!("Function '{signature}' is declared {volatility} but runs {kind}, which PostgreSQL refuses in a non-volatile function on every call that reaches the statement."),
                    "Declare the function VOLATILE, or move the statement out of it.".to_owned(),
                )?;
                break;
            }
        }
        Ok(())
    }
}
