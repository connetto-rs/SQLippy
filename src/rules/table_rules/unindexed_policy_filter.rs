//! Submodule providing the `UnindexedPolicyFilter` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, PolicyLike, TableLike},
};
use sqlparser::ast::{Expr, Query, Visit, Visitor};

use crate::{
    deployment::Deployment,
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::{
        index_support::{Side, comparison_sides, indexed},
        policy_support::{derives_from_caller, holds_caller, is_column_reference},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Finds a column reference.
struct ColumnReference;

impl Visitor for ColumnReference {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if is_column_reference(expression) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// A column a policy filters on by the caller with no index leading with it.
struct Unindexed {
    table: String,
    column: String,
    comparison: String,
}

/// The policy table and deployment comparisons are judged against.
struct Judge<'a, 'db, DB: DatabaseLike> {
    database: &'db DB,
    table: &'db DB::Table,
    deployment: &'a Deployment,
}

impl<DB: DatabaseLike> Judge<'_, '_, DB> {
    /// Whether a side derives from the caller, judged against the policy's
    /// row outside sublinks and with no column reference inside them.
    fn derives<V: Visit>(&self, node: &V, in_sublink: bool) -> Result<bool, LookupError> {
        if in_sublink {
            return Ok(holds_caller(self.deployment, node)
                && node.visit(&mut ColumnReference).is_continue());
        }
        derives_from_caller(self.database, self.table, self.deployment, node)
    }

    fn caller_side(&self, side: Side<'_>, in_sublink: bool) -> Result<bool, LookupError> {
        match side {
            Side::Expr(expression) => self.derives(expression, in_sublink),
            Side::List(list) => self.derives(list, in_sublink),
            Side::Query(query) => self.derives(query, in_sublink),
        }
    }

    /// Records the unindexed columns, resolved through `scope`, that
    /// `expression` compares with the caller.
    fn consider(
        &self,
        scope: &ColumnScope<'_, '_, DB>,
        expression: &Expr,
        in_sublink: bool,
        found: &mut Vec<Unindexed>,
    ) -> Result<(), LookupError> {
        comparison_sides(expression, |column, side| {
            if !is_column_reference(column) {
                return Ok(());
            }
            let Some(ColumnDefinition::Base { table, column, .. }) =
                scope.resolve_column_definition(column)?
            else {
                return Ok(());
            };
            if !self.caller_side(side, in_sublink)? || indexed(self.database, table, column)? {
                return Ok(());
            }
            let (table, column) = (table.table_name(), column.column_name());
            if !found
                .iter()
                .any(|seen| seen.table == table && seen.column == column)
            {
                found.push(Unindexed {
                    table: table.to_owned(),
                    column: column.to_owned(),
                    comparison: expression.to_string(),
                });
            }
            Ok(())
        })
    }
}

/// Unindexed columns a policy expression filters on, outside sublinks.
struct Filters<'a, 'db, DB: DatabaseLike> {
    judge: Judge<'a, 'db, DB>,
    scope: ColumnScope<'db, 'db, DB>,
    depth: usize,
    found: Vec<Unindexed>,
}

/// Unindexed columns in the top-level query of one sublink.
struct SublinkFilters<'f, 'a, 'db, 'q, DB: DatabaseLike> {
    judge: &'f Judge<'a, 'db, DB>,
    found: &'f mut Vec<Unindexed>,
    local: ColumnScope<'q, 'db, DB>,
    depth: usize,
}

impl<DB: DatabaseLike> Visitor for SublinkFilters<'_, '_, '_, '_, DB> {
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
        if self.depth != 1 {
            return ControlFlow::Continue(());
        }
        self.judge
            .consider(&self.local, expression, true, self.found)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

impl<DB: DatabaseLike> Visitor for Filters<'_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        ColumnScope::from_query(query, self.judge.database, IdentifierCase::Folded).map_or_else(
            ControlFlow::Break,
            |local| {
                query.visit(&mut SublinkFilters {
                    judge: &self.judge,
                    found: &mut self.found,
                    local,
                    depth: 0,
                })
            },
        )
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if self.depth != 0 {
            return ControlFlow::Continue(());
        }
        self.judge
            .consider(&self.scope, expression, false, &mut self.found)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Struct defining a rule that reports a column a policy filters on by the
/// caller when no index leads with it.
///
/// The rule reads `USING` clauses, where PostgreSQL filters existing rows. A
/// column is reported when it is compared (`=`, `<`, `<=`, `>`, `>=`, `IN`,
/// `= ANY`) with a side derived from the caller alone: a declared credential,
/// a `current_setting` call, a read of the current role, or a set computed
/// from them. That holds for the policy's own table and for the table a
/// policy subquery filters. A column counts as indexed when an index without
/// a predicate, a unique constraint or the primary key leads with it. A small
/// or rarely read table is a legitimate exception.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UnindexedPolicyFilter::default().into();
/// let schema = "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY own ON docs USING (owner = current_user);";
///
/// let unindexed = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&unindexed).is_err());
///
/// let indexed = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE INDEX docs_owner ON docs (owner);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&indexed).is_ok());
/// ```
pub struct UnindexedPolicyFilter<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnindexedPolicyFilter<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnindexedPolicyFilter<DB>> for GenericConstrainer<DB> {
    fn from(rule: UnindexedPolicyFilter<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UnindexedPolicyFilter<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "UnindexedPolicyFilter",
            group: LintGroup::Perf,
            rationale: "PostgreSQL evaluates the policy against each candidate row, so a column the policy filters on without an index led by it turns a read into a sequential scan.",
            source: Some(
                "https://supabase.com/docs/guides/database/postgres/row-level-security#add-indexes",
            ),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for UnindexedPolicyFilter<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            let Some(expression) = policy.using_expression(database) else {
                continue;
            };
            let mut filters = Filters {
                judge: Judge {
                    database,
                    table,
                    deployment: reporter.deployment(),
                },
                scope: ColumnScope::for_table(table, database, IdentifierCase::Folded),
                depth: 0,
                found: Vec::new(),
            };
            expression
                .visit(&mut filters)
                .break_value()
                .map_or(Ok(()), Err)?;
            for Unindexed {
                table: filtered,
                column,
                comparison,
            } in filters.found
            {
                let name = policy.name();
                reporter.policies(
                    vec![PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new(policy.clone()),
                        clause: PolicyClause::Using,
                        expression: comparison,
                    }],
                    format!(
                        "Policy '{name}' on '{}' filters '{filtered}' on column '{column}' by the caller, and no index on '{filtered}' leads with '{column}'.",
                        table.table_name()
                    ),
                    format!("Create an index led by '{column}', such as `CREATE INDEX ON {filtered} ({column})`."),
                )?;
            }
        }
        Ok(())
    }
}
