//! Submodule providing the `NestedPolicySubquery` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    traits::{DataStatementLike, DatabaseLike, PolicyLike, Relation, TableLike},
};
use sqlparser::ast::{Expr, Query, Visit, Visitor};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::policy_support::{Command, held_by_name, policy_roles},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Whether an expression holds a sublink.
fn holds_subquery(expression: &Expr) -> bool {
    struct Sublink;
    impl Visitor for Sublink {
        type Break = ();
        fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
            ControlFlow::Break(())
        }
    }
    expression.visit(&mut Sublink).is_break()
}

/// The tables the outermost query of each sublink reads directly, with the
/// sublink rendered as SQL.
struct SublinkTables<'db, DB: DatabaseLike> {
    database: &'db DB,
    depth: usize,
    reads: Vec<(String, &'db DB::Table)>,
}

impl<DB: DatabaseLike> SublinkTables<'_, DB> {
    fn query(&mut self, query: &Query) -> Result<(), LookupError> {
        for relation in DataStatementLike::<DB>::referenced_relations(query, self.database)? {
            if let Relation::Table(table) = relation {
                self.reads.push((query.to_string(), table));
            }
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for SublinkTables<'_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        self.query(query)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }
}

/// Whether the two policies can apply to one querying role.
fn share_a_role<DB: DatabaseLike>(database: &DB, outer: &DB::Policy, inner: &DB::Policy) -> bool {
    match (policy_roles(database, outer), policy_roles(database, inner)) {
        (None, _) | (_, None) => true,
        (Some(outer), Some(inner)) => outer.iter().any(|role| {
            inner
                .iter()
                .any(|name| held_by_name(database, role).contains(name))
        }),
    }
}

/// A `SELECT` policy of `table` holding a subquery that applies with `outer`.
fn nested_policy<'db, DB: DatabaseLike>(
    database: &'db DB,
    outer: &DB::Policy,
    table: &'db DB::Table,
) -> Result<Option<&'db DB::Policy>, LookupError> {
    if !table.has_row_level_security(database)? {
        return Ok(None);
    }
    Ok(table.policies(database)?.find(|policy| {
        Command::Select.covered_by(policy.command())
            && share_a_role(database, outer, policy)
            && policy
                .using_expression(database)
                .is_some_and(holds_subquery)
    }))
}

/// Struct defining a rule that reports a policy subquery reading a table with
/// row-level security whose own applicable `SELECT` policy holds a subquery.
///
/// PostgreSQL applies the read table's policies inside the subquery each time
/// the outer policy is evaluated, so a subquery there expands again, and the
/// plan grows with every level. A read through a function call is not a direct
/// read, and a table whose `SELECT` policies compare the row to the caller
/// without a subquery is cheap to read and is not reported.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NestedPolicySubquery::default().into();
/// let schema = "CREATE TABLE docs (team INT); CREATE TABLE members (team INT, member TEXT);
///     CREATE TABLE admins (member TEXT);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY; ALTER TABLE members ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY docs_p ON docs USING (team IN (SELECT team FROM members WHERE member = current_user));";
///
/// let nested = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY members_p ON members USING (member IN (SELECT member FROM admins));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&nested).is_err());
///
/// let flat = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY members_p ON members USING (member = current_user);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&flat).is_ok());
/// ```
pub struct NestedPolicySubquery<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NestedPolicySubquery<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NestedPolicySubquery<DB>> for GenericConstrainer<DB> {
    fn from(rule: NestedPolicySubquery<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for NestedPolicySubquery<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NestedPolicySubquery",
            group: LintGroup::Perf,
            rationale: "PostgreSQL applies a read table's own policies inside a policy subquery, so a subquery in them expands again on every evaluation, while a `SECURITY DEFINER` helper reads the table once without them.",
            source: Some(
                "https://supabase.com/docs/guides/database/postgres/row-level-security#use-security-definer-functions",
            ),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for NestedPolicySubquery<DB> {
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
                let mut sublinks = SublinkTables {
                    database,
                    depth: 0,
                    reads: Vec::new(),
                };
                expression
                    .visit(&mut sublinks)
                    .break_value()
                    .map_or(Ok(()), Err)?;
                for (subquery, read) in sublinks.reads {
                    let Some(nested) = nested_policy(database, policy, read)? else {
                        continue;
                    };
                    let (name, table_name, read_name) =
                        (policy.name(), table.table_name(), read.table_name());
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: subquery,
                        }],
                        format!(
                            "Policy '{name}' on '{table_name}' reads '{read_name}' in a subquery of its {clause} clause, and policy '{}' on '{read_name}' holds a subquery of its own, so PostgreSQL expands it inside every evaluation.",
                            nested.name()
                        ),
                        format!(
                            "Read '{read_name}' through a `STABLE SECURITY DEFINER` function owned by a role that bypasses its policies, called as `(SELECT fn())`."
                        ),
                    )?;
                }
            }
        }
        Ok(())
    }
}
