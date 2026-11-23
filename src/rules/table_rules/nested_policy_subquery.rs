//! Submodule providing the `NestedPolicySubquery` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    traits::{DataStatementLike, DatabaseLike, PolicyLike, Relation, TableLike},
};
use sqlparser::ast::{Expr, Query, Visitor};

use crate::rules::walk_support::walk;
use crate::{
    engine::Engine,
    error::{Interruption, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{Command, held_by_name, policy_roles, reads_row, walked_clauses},
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
    walk(expression, &mut Sublink).is_break()
}

/// The tables the outermost query of each sublink joined to the row of
/// `table` reads directly, with the sublink rendered as SQL.
struct SublinkTables<'db, DB: DatabaseLike> {
    database: &'db DB,
    table: &'db DB::Table,
    depth: usize,
    reads: Vec<(String, &'db DB::Table)>,
}

impl<DB: DatabaseLike> SublinkTables<'_, DB> {
    fn query(&mut self, query: &Query) -> Result<(), LookupError> {
        if !reads_row(self.database, self.table, None, query)? {
            return Ok(());
        }
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
    for policy in table.policies(database)? {
        if Command::Select.covered_by(policy.command())
            && share_a_role(database, outer, policy)
            && policy
                .using_clause(database)?
                .as_ref()
                .is_some_and(|clause| holds_subquery(clause.expression()))
        {
            return Ok(Some(policy));
        }
    }
    Ok(None)
}

/// Struct defining a rule that reports a policy subquery joined to the
/// checked row that reads a table with row-level security whose own applicable
/// `SELECT` policy holds a subquery.
///
/// PostgreSQL runs a subquery joined to the row again for each candidate row
/// and applies the read table's policies on each run, so their subquery is
/// consulted again for every candidate row. A subquery that does not reference
/// the row runs once per statement and is not reported. A read through a
/// function call is not a direct read, and a table whose `SELECT` policies
/// compare the row to the caller without a subquery is cheap to read and is
/// not reported.
///
/// The rule does not run on SQLite, which has no row-level security policies.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NestedPolicySubquery::default().into();
/// let schema = "CREATE TABLE docs (team INT, owner TEXT); CREATE TABLE members (team INT, member TEXT);
///     CREATE TABLE admins (member TEXT);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY; ALTER TABLE members ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY members_p ON members USING (member IN (SELECT member FROM admins));";
///
/// let joined = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY docs_p ON docs USING (
///        owner IN (SELECT member FROM members WHERE members.team = docs.team));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&joined).is_err());
///
/// let set = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY docs_p ON docs USING (
///        team IN (SELECT team FROM members WHERE member = current_user));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&set).is_ok());
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
            name: rule_name!(NestedPolicySubquery),
            group: LintGroup::Perf,
            rationale: "PostgreSQL runs a policy subquery joined to the checked row once per candidate row and applies the read table's own policies on each run, so a subquery in them is consulted again for every row, while a `SECURITY DEFINER` helper reads the table without them.",
            source: Some(
                "https://supabase.com/docs/guides/database/postgres/row-level-security#use-security-definer-functions",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (team INT, owner TEXT);\n\
CREATE TABLE members (team INT, member TEXT);\n\
CREATE TABLE admins (member TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
ALTER TABLE members ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY docs_p ON docs USING (owner IN (SELECT member FROM members WHERE members.team = docs.team));\n\
CREATE POLICY members_p ON members USING (member IN (SELECT member FROM admins));",
                good: "CREATE TABLE docs (team INT, owner TEXT);\n\
CREATE TABLE members (team INT, member TEXT);\n\
CREATE TABLE admins (member TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
ALTER TABLE members ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY docs_p ON docs USING (owner IN (SELECT member FROM members WHERE members.team = docs.team));\n\
CREATE POLICY members_p ON members USING (member = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
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
            let clauses = walked_clauses(database, policy)?;
            for (clause, expression) in clauses {
                let Some(expression) = expression else {
                    continue;
                };
                let mut sublinks = SublinkTables {
                    database,
                    table,
                    depth: 0,
                    reads: Vec::new(),
                };
                walk(expression, &mut sublinks)
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
                            "Policy '{name}' on '{table_name}' reads '{read_name}' in a subquery joined to the checked row in its {clause} clause, so PostgreSQL reads '{read_name}' again for every checked row and applies policy '{}' on '{read_name}', which holds a subquery of its own, on each read.",
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
