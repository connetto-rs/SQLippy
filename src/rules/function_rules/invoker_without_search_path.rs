//! Invoker functions whose schema callers inherit a mutable search path.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    traits::{
        CheckConstraintLike, ColumnLike, DatabaseLike, DomainLike, FunctionLike, IndexLike,
        PolicyLike, TableLike,
    },
};
use sqlparser::ast::{Expr, Function, FunctionSecurity, Visitor};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{function_reach_support::reaches_function, walk_support::walk},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Reports invoker functions whose unqualified names are reached by stored schema expressions.
///
/// Policies, checks, defaults, generated columns and indexes can invoke these bodies under a caller's path or a restricted index-build path.
/// Views and exclusion constraints are not entry sites, and unreadable bodies are skipped.
///
/// The rule does not run on SQLite, which has no stored functions.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let rule: GenericConstrainer<ParserDB> = InvokerWithoutSearchPath::default().into();
/// let schema = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE allowed (v INT);
///      CREATE FUNCTION ok(x INT) RETURNS BOOLEAN LANGUAGE sql
///        AS 'SELECT EXISTS (SELECT FROM allowed WHERE v = x)';
///      CREATE TABLE docs (v INT CHECK (ok(v)));",
/// ).unwrap();
/// assert!(rule.validate_schema(&schema).is_err());
/// ```
pub struct InvokerWithoutSearchPath<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for InvokerWithoutSearchPath<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<InvokerWithoutSearchPath<DB>> for GenericConstrainer<DB> {
    fn from(rule: InvokerWithoutSearchPath<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for InvokerWithoutSearchPath<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(InvokerWithoutSearchPath),
            group: LintGroup::Correctness,
            rationale: "An invoker function reached by a policy, check, default, generated column or index resolves unqualified names under the session's `search_path`, allowing temporary tables to replace its reads or a restricted index-build path to break its calls.",
            source: Some(
                "https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATH",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE allowed (v INT);\nCREATE FUNCTION ok(x INT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT EXISTS (SELECT FROM allowed WHERE v = x)';\nCREATE TABLE docs (v INT CHECK (ok(v)));",
                good: "CREATE TABLE allowed (v INT);\nCREATE FUNCTION ok(x INT) RETURNS BOOLEAN LANGUAGE sql SET search_path = pg_catalog, pg_temp AS 'SELECT EXISTS (SELECT FROM public.allowed WHERE v = x)';\nCREATE TABLE docs (v INT CHECK (ok(v)));",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

/// Tests each call using the binding supplied by its owning schema object.
struct BoundCalls<F>(F);

impl<F: FnMut(&Function) -> Result<bool, LookupError>> Visitor for BoundCalls<F> {
    type Break = Result<(), LookupError>;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(call) = expression {
            match (self.0)(call) {
                Ok(true) => return ControlFlow::Break(Ok(())),
                Err(error) => return ControlFlow::Break(Err(error)),
                Ok(false) => {}
            }
        }
        ControlFlow::Continue(())
    }
}

/// Whether one of an expression's bound calls reaches the target function.
fn expression_reaches(
    expression: &Expr,
    reaches: impl FnMut(&Function) -> Result<bool, LookupError>,
) -> Result<bool, LookupError> {
    match walk(expression, &mut BoundCalls(reaches)) {
        ControlFlow::Continue(()) => Ok(false),
        ControlFlow::Break(result) => result.map(|()| true),
    }
}

/// Whether any bound callee reaches the target function.
fn callees_reach<'db, DB: DatabaseLike>(
    database: &'db DB,
    target: &DB::Function,
    callees: impl Iterator<Item = &'db DB::Function>,
) -> Result<bool, LookupError> {
    for callee in callees {
        if reaches_function(database, callee, target)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Names the first stored schema expression that reaches the function.
fn reaching_site<DB: DatabaseLike>(
    database: &DB,
    target: &DB::Function,
) -> Result<Option<String>, LookupError> {
    for table in database.tables() {
        for policy in table.policies(database)? {
            for expression in [
                policy.using_expression(database)?,
                policy.check_expression(database)?,
            ]
            .into_iter()
            .flatten()
            {
                if expression_reaches(expression, |call| {
                    callees_reach(
                        database,
                        target,
                        policy.functions_reached_by(call, database)?,
                    )
                })? {
                    return Ok(Some(format!("a policy on '{}'", table.table_name())));
                }
            }
        }
        for check in table
            .check_constraints(database)?
            .filter(|check| check.is_enforced())
        {
            if expression_reaches(check.expression(database), |call| {
                callees_reach(
                    database,
                    target,
                    check.functions_reached_by(call, database)?,
                )
            })? {
                return Ok(Some(format!("a check on '{}'", table.table_name())));
            }
        }
        for column in table.columns(database)? {
            for (kind, expression) in [
                ("default", column.default_expression()),
                ("generation expression", column.generation_expression()),
            ] {
                if let Some(expression) = expression
                    && expression_reaches(expression, |call| {
                        callees_reach(
                            database,
                            target,
                            column.functions_reached_by(call, database)?,
                        )
                    })?
                {
                    return Ok(Some(format!(
                        "the {kind} of '{}.{}'",
                        table.table_name(),
                        column.column_name()
                    )));
                }
            }
        }
        for index in table.indices(database)? {
            for expression in [Some(index.expression(database)?), index.predicate()]
                .into_iter()
                .flatten()
            {
                if expression_reaches(expression, |call| {
                    callees_reach(
                        database,
                        target,
                        index.functions_reached_by(call, database)?,
                    )
                })? {
                    return Ok(Some(format!("an index on '{}'", table.table_name())));
                }
            }
        }
    }
    for domain in database.domains() {
        for expression in domain.check_expressions() {
            if expression_reaches(expression, |call| {
                callees_reach(
                    database,
                    target,
                    domain.functions_reached_by(call, database)?,
                )
            })? {
                return Ok(Some(format!("a check on domain '{}'", domain.name())));
            }
        }
    }
    Ok(None)
}

/// Names the stored schema expression reaching an invoker function that sets
/// no `search_path` and names a relation or function without its schema in a
/// body resolved when it runs, the function this rule reports.
pub(super) fn unpinned_reaching_site<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
) -> Result<Option<String>, LookupError> {
    if function.security_mode() == FunctionSecurity::Definer
        || function.body_is_bound()
        || function.search_path(database)?.is_some()
    {
        return Ok(None);
    }
    if super::readable(function.unqualified_names(database))?.is_empty() {
        return Ok(None);
    }
    reaching_site(database, function)
}

impl<DB: DatabaseLike> FunctionRule for InvokerWithoutSearchPath<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if let Some(site) = unpinned_reaching_site(database, function)? {
            let signature = signature(function, database);
            reporter.function(
                function,
                format!("Invoker function '{signature}' is reached by {site} and resolves unqualified names under the calling session's `search_path`."),
                format!("ALTER FUNCTION {signature} SET search_path = pg_catalog, pg_temp; and qualify every other name its body uses."),
            )?;
        }
        Ok(())
    }
}
