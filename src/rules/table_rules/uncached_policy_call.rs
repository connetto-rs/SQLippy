//! Submodule providing the `UncachedPolicyCall` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, FunctionLike, PolicyLike, TableLike},
};
use sqlparser::{
    ast::{
        Expr, FunctionArguments, FunctionBehavior, FunctionSecurity, Query, SetExpr, Statement,
        Visit, Visitor,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Whether an expression reads a column, conservatively counting every name.
fn reads_a_column(expression: &Expr) -> bool {
    struct Names;
    impl Visitor for Names {
        type Break = ();
        fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            match expression {
                Expr::Identifier(_) | Expr::CompoundIdentifier(_) => ControlFlow::Break(()),
                _ => ControlFlow::Continue(()),
            }
        }
    }
    expression.visit(&mut Names).is_break()
}

/// Whether a parsed body is one `SELECT` of one expression and nothing else.
fn scalar_select(statements: &[Statement]) -> bool {
    matches!(statements, [Statement::Query(query)]
        if query.with.is_none()
            && query.order_by.is_none()
            && query.limit_clause.is_none()
            && matches!(query.body.as_ref(), SetExpr::Select(select)
                if select.projection.len() == 1
                    && select.from.is_empty()
                    && select.selection.is_none()
                    && select.having.is_none()))
}

/// Whether PostgreSQL inlines a call to the function into the calling query,
/// which a `RETURN` body or a body of one `SELECT` of one expression allows.
fn inlinable<F: FunctionLike>(function: &F) -> bool {
    function
        .stored_language()
        .is_none_or(|language| language == "sql")
        && function.security_mode() != FunctionSecurity::Definer
        && function.configuration_parameters().is_empty()
        && !function.returns_set()
        && (function.body_expression().is_some()
            || function
                .body()
                .and_then(|body| Parser::parse_sql(&PostgreSqlDialect {}, body).ok())
                .is_some_and(|statements| scalar_select(&statements)))
}

/// One call the rule reports.
struct Finding {
    call: String,
    volatile: bool,
}

/// Collects the outermost calls outside sublinks whose arguments read no
/// column and whose functions are not all `IMMUTABLE`.
struct RowIndependentCalls<'db, DB: DatabaseLike> {
    database: &'db DB,
    policy: &'db DB::Policy,
    depth: usize,
    within: Option<*const Expr>,
    findings: Vec<Finding>,
}

impl<DB: DatabaseLike> RowIndependentCalls<'_, DB> {
    fn call(&mut self, expression: &Expr) -> Result<(), LookupError> {
        let Expr::Function(call) = expression else {
            return Ok(());
        };
        if matches!(call.args, FunctionArguments::None) || reads_a_column(expression) {
            return Ok(());
        }
        let mut immutable = true;
        let mut volatile = false;
        let mut reached = false;
        for function in self.policy.functions_reached_by(call, self.database)? {
            reached = true;
            match function.volatility() {
                FunctionBehavior::Immutable => {}
                FunctionBehavior::Stable => immutable = false,
                FunctionBehavior::Volatile => {
                    immutable = false;
                    volatile |= !inlinable(function);
                }
            }
        }
        if !reached || !immutable {
            self.within = Some(std::ptr::from_ref(expression));
            self.findings.push(Finding {
                call: expression.to_string(),
                volatile,
            });
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for RowIndependentCalls<'_, DB> {
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
        if self.depth > 0 || self.within.is_some() {
            return ControlFlow::Continue(());
        }
        self.call(expression)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if self
            .within
            .is_some_and(|within| std::ptr::eq(within, expression))
        {
            self.within = None;
        }
        ControlFlow::Continue(())
    }
}

/// Struct defining a rule that reports a call in a policy whose arguments read
/// nothing from the row, written where PostgreSQL evaluates it per row.
///
/// Wrapped as `(SELECT call)`, the planner evaluates it once per statement
/// as an initPlan. Built-in calls such as `current_setting` count, calls to
/// `IMMUTABLE` functions are folded by the planner and do not, and the SQL
/// value functions written without parentheses (`current_user`) do not. A
/// `VOLATILE` call that PostgreSQL cannot inline also keeps an index from
/// serving the comparison.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UncachedPolicyCall::default().into();
/// let schema = "CREATE TABLE docs (owner TEXT); ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";
///
/// let per_row = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY p ON docs USING (owner = current_setting('app.user_id', true));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&per_row).is_err());
///
/// let once = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY p ON docs USING (owner = (SELECT current_setting('app.user_id', true)));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&once).is_ok());
/// ```
pub struct UncachedPolicyCall<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UncachedPolicyCall<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UncachedPolicyCall<DB>> for GenericConstrainer<DB> {
    fn from(rule: UncachedPolicyCall<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UncachedPolicyCall<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "UncachedPolicyCall",
            group: LintGroup::Perf,
            rationale: "PostgreSQL evaluates a policy against each candidate row, so a call that reads nothing from the row runs once per row unless it is wrapped as `(SELECT call)`, which the planner evaluates once.",
            source: Some(
                "https://supabase.com/docs/guides/database/postgres/row-level-security#call-functions-with-select",
            ),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for UncachedPolicyCall<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            let clauses = [
                (PolicyClause::Using, policy.using_expression(database)),
                (PolicyClause::WithCheck, policy.check_expression(database)),
            ];
            for (clause, expression) in clauses {
                let Some(expression) = expression else {
                    continue;
                };
                let mut calls = RowIndependentCalls {
                    database,
                    policy,
                    depth: 0,
                    within: None,
                    findings: Vec::new(),
                };
                expression
                    .visit(&mut calls)
                    .break_value()
                    .map_or(Ok(()), Err)?;
                for Finding { call, volatile } in calls.findings {
                    let (name, table_name) = (policy.name(), table.table_name());
                    let index = if volatile {
                        ", and being VOLATILE it keeps an index from serving the comparison"
                    } else {
                        ""
                    };
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: call.clone(),
                        }],
                        format!(
                            "Policy '{name}' on '{table_name}' calls `{call}` in its {clause} clause with nothing from the row, so PostgreSQL calls it once per row it checks{index}."
                        ),
                        format!(
                            "Wrap the call as `(SELECT {call})`, which PostgreSQL evaluates once per statement."
                        ),
                    )?;
                }
            }
        }
        Ok(())
    }
}
