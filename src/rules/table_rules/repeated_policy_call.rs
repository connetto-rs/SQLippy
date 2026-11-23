//! Submodule providing the `RepeatedPolicyCall` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, FunctionLike, PolicyLike, TableLike},
};
use sqlparser::ast::{Expr, FunctionBehavior, Query, Visitor};

use crate::{
    engine::Engine,
    error::{Interruption, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{policy_support::walked_clauses, walk_support::walk},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Detects row references outside queries.
#[derive(Default)]
struct RowReference {
    depth: usize,
    found: bool,
}

impl Visitor for RowReference {
    type Break = ();

    fn pre_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        self.found |= self.depth == 0
            && matches!(
                expression,
                Expr::Identifier(_) | Expr::CompoundIdentifier(_)
            );
        ControlFlow::Continue(())
    }
}

/// Finds volatile or unresolved argument calls in their policy's scope.
struct VolatileArguments<'database, DB: DatabaseLike> {
    database: &'database DB,
    policy: &'database DB::Policy,
    found: bool,
}

impl<DB: DatabaseLike> Visitor for VolatileArguments<'_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if let Expr::Function(call) = expression {
            let mut reached = match self.policy.functions_reached_by(call, self.database) {
                Ok(reached) => reached.peekable(),
                Err(error) => return ControlFlow::Break(error),
            };
            self.found |= reached.peek().is_none()
                || reached.any(|function| function.volatility() == FunctionBehavior::Volatile);
        }
        ControlFlow::Continue(())
    }
}

/// Collects eligible calls outside sublinks.
struct Calls<'database, DB: DatabaseLike> {
    database: &'database DB,
    policy: &'database DB::Policy,
    depth: usize,
    within: Option<*const Expr>,
    expressions: Vec<String>,
}

impl<DB: DatabaseLike> Calls<'_, DB> {
    /// Retains calls with row arguments and nonvolatile user-defined targets.
    fn consider(&mut self, expression: &Expr) -> Result<(), LookupError> {
        let Expr::Function(call) = expression else {
            return Ok(());
        };
        let mut reached = self
            .policy
            .functions_reached_by(call, self.database)?
            .peekable();
        if reached.peek().is_none()
            || reached.any(|function| {
                function.volatility() == FunctionBehavior::Volatile
                    || matches!(
                        function.target_name().schema(),
                        Some("pg_catalog" | "information_schema")
                    )
            })
        {
            return Ok(());
        }
        let mut row = RowReference::default();
        let _ = walk(&call.args, &mut row);
        let mut arguments = VolatileArguments {
            database: self.database,
            policy: self.policy,
            found: false,
        };
        walk(&call.args, &mut arguments)
            .break_value()
            .map_or(Ok(()), Err)?;
        if row.found && !arguments.found {
            self.within = Some(std::ptr::from_ref(expression));
            self.expressions.push(expression.to_string());
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for Calls<'_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, _: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if self.depth == 0 && self.within.is_none() {
            self.consider(expression)
                .map_or_else(ControlFlow::Break, ControlFlow::Continue)
        } else {
            ControlFlow::Continue(())
        }
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

/// Reports repeated row-dependent `STABLE` or `IMMUTABLE` helper calls within
/// one policy clause because each call repeats work for the candidate row.
///
/// Row-independent calls are left to [`super::UncachedPolicyCall`]. Built-ins,
/// calls inside sublinks and calls with volatile arguments are not reported.
///
/// A `STABLE` PL/pgSQL helper over 300,000 rows took 156.852 ms with two calls
/// and 90.343 ms with one on PostgreSQL 17, and 150.870 ms and 89.093 ms on
/// PostgreSQL 18.
///
/// The rule does not run on SQLite, which has no row-level security policies.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = RepeatedPolicyCall::default().into();
/// let schema = "CREATE TABLE docs(owner_id INT);
///     CREATE FUNCTION can_read(owner_id INT) RETURNS BOOLEAN
///       LANGUAGE plpgsql STABLE AS $$ BEGIN RETURN owner_id > 0; END $$;";
///
/// let bad = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY own ON docs
///        USING(can_read(owner_id) AND can_read(owner_id));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&bad).is_err());
///
/// let good = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY own ON docs USING(can_read(owner_id));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&good).is_ok());
/// ```
pub struct RepeatedPolicyCall<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RepeatedPolicyCall<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RepeatedPolicyCall<DB>> for GenericConstrainer<DB> {
    fn from(rule: RepeatedPolicyCall<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for RepeatedPolicyCall<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RepeatedPolicyCall),
            group: LintGroup::Perf,
            rationale: "Repeated row-dependent helper calls repeat work per row. A STABLE PL/pgSQL helper over 300,000 rows took 156.852 ms with two calls and 90.343 ms with one on PostgreSQL 17, and 150.870 ms and 89.093 ms on PostgreSQL 18.",
            source: Some("https://www.postgresql.org/docs/17/sql-createpolicy.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs(owner_id INT);\n\
CREATE FUNCTION can_read(owner_id INT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$ BEGIN RETURN owner_id > 0; END $$;\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs USING(can_read(owner_id) AND can_read(owner_id));",
                good: "CREATE TABLE docs(owner_id INT);\n\
CREATE FUNCTION can_read(owner_id INT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$ BEGIN RETURN owner_id > 0; END $$;\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs USING(can_read(owner_id));",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

impl<DB: DatabaseLike> TableRule for RepeatedPolicyCall<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &DB,
        table: &DB::Table,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            for (clause, expression) in walked_clauses(database, policy)? {
                let Some(expression) = expression else {
                    continue;
                };
                let mut calls = Calls {
                    database,
                    policy,
                    depth: 0,
                    within: None,
                    expressions: Vec::new(),
                };
                walk(expression, &mut calls)
                    .break_value()
                    .map_or(Ok(()), Err)?;
                calls.expressions.sort_unstable();
                let mut remaining = calls.expressions.as_slice();
                while let Some((first, rest)) = remaining.split_first() {
                    let duplicates = rest.iter().take_while(|other| *other == first).count();
                    if duplicates > 0 {
                        let (name, table_name) = (policy.name(), table.table_name());
                        reporter.policies(
                            vec![PolicySite {
                                table: Box::new(table.clone()),
                                policy: Box::new(policy.clone()),
                                clause,
                                expression: first.clone(),
                            }],
                            format!(
                                "Policy '{name}' on '{table_name}' calls `{first}` more than once per row in its {clause} clause."
                            ),
                            "Evaluate the repeated helper call once per row.".to_owned(),
                        )?;
                    }
                    remaining = &rest[duplicates..];
                }
            }
        }
        Ok(())
    }
}
