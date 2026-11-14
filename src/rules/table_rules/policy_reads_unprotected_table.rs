//! Submodule providing the `PolicyReadsUnprotectedTable` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::{LookupError, RowSecurityError},
    structs::{ActingRole, RowSecurity, RowSecurityExemption, RowStatement},
    traits::{DataStatementLike, DatabaseLike, PolicyLike, Relation, RoleLike, TableLike},
};
use sqlparser::ast::{
    BinaryOperator, Distinct, Expr, FunctionArguments, GroupByExpr, InTarget, JoinOperator, Query,
    SetExpr, TableFactor, UnaryOperator, Visitor,
};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        policy_read_support::sublink_reads,
        policy_support::{may_aggregate, walked_clauses},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// The row changes of a read table that can make a policy pass more rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Needs {
    /// Adding rows, through `INSERT` or `UPDATE`.
    add: bool,
    /// Removing rows, through `DELETE`, `UPDATE` or `TRUNCATE`.
    remove: bool,
}

impl Needs {
    const EITHER: Self = Self {
        add: true,
        remove: true,
    };

    fn of(negated: bool) -> Self {
        Self {
            add: !negated,
            remove: negated,
        }
    }

    fn join(&mut self, other: Self) {
        self.add |= other.add;
        self.remove |= other.remove;
    }
}

/// A part of a policy clause together with the row changes of the tables it
/// reads that let more rows pass.
enum Part<'e> {
    /// The query of an `EXISTS` or `IN` sublink whose result only grows as
    /// its tables gain rows.
    Monotone(&'e Query, Needs),
    /// Any other expression, whose reads can move the outcome either way.
    Other(&'e Expr),
}

/// Splits `expression` through `AND`, `OR` and `NOT` into its parts.
fn parts<'e, DB: DatabaseLike>(
    database: &DB,
    policy: &DB::Policy,
    expression: &'e Expr,
    negated: bool,
    found: &mut Vec<Part<'e>>,
) -> Result<(), LookupError> {
    match expression {
        Expr::Nested(inner) => parts(database, policy, inner, negated, found)?,
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => parts(database, policy, expr, !negated, found)?,
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And | BinaryOperator::Or,
            right,
        } => {
            parts(database, policy, left, negated, found)?;
            parts(database, policy, right, negated, found)?;
        }
        Expr::Exists {
            subquery,
            negated: inner,
        } if monotone(database, policy, subquery)? => {
            found.push(Part::Monotone(subquery, Needs::of(negated != *inner)));
        }
        Expr::In {
            expr,
            target: InTarget::Subquery(subquery),
            negated: inner,
            ..
        } if monotone(database, policy, subquery)? => {
            found.push(Part::Other(expr));
            found.push(Part::Monotone(subquery, Needs::of(negated != *inner)));
        }
        other => found.push(Part::Other(other)),
    }
    Ok(())
}

/// Whether the rows `query` returns can only grow as the tables it reads gain
/// rows: one `SELECT` over base tables joined by inner or cross joins, with no
/// view, grouping, aggregate, window, limit, sample or nested query.
fn monotone<DB: DatabaseLike>(
    database: &DB,
    policy: &DB::Policy,
    query: &Query,
) -> Result<bool, LookupError> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Ok(false);
    };
    let plain = |factor: &TableFactor| {
        matches!(
            factor,
            TableFactor::Table {
                args: None,
                sample: None,
                ..
            }
        )
    };
    let shaped = query.with.is_none()
        && query.limit_clause.is_none()
        && query.fetch.is_none()
        && query.pipe_operators.is_empty()
        && matches!(
            select.distinct,
            None | Some(Distinct::All | Distinct::Distinct)
        )
        && select.top.is_none()
        && matches!(&select.group_by, GroupByExpr::Expressions(keys, modifiers) if keys.is_empty() && modifiers.is_empty())
        && select.having.is_none()
        && select.qualify.is_none()
        && select.named_window.is_empty()
        && select.connect_by.is_empty()
        && select.lateral_views.is_empty()
        && select.from.iter().all(|from| {
            plain(&from.relation)
                && from.joins.iter().all(|join| {
                    plain(&join.relation)
                        && matches!(
                            join.join_operator,
                            JoinOperator::Join(_)
                                | JoinOperator::Inner(_)
                                | JoinOperator::CrossJoin(_)
                        )
                })
        });
    if !shaped
        || DataStatementLike::<DB>::referenced_relations(query, database)?
            .iter()
            .any(|relation| !matches!(relation, Relation::Table(_)))
    {
        return Ok(false);
    }
    let mut calls = Calls {
        database,
        policy,
        depth: 0,
    };
    Ok(match walk(query, &mut calls) {
        ControlFlow::Continue(()) => true,
        ControlFlow::Break(outcome) => outcome?,
    })
}

/// Stops at a nested query, a window or a call that may aggregate.
struct Calls<'a, DB: DatabaseLike> {
    database: &'a DB,
    policy: &'a DB::Policy,
    depth: usize,
}

impl<DB: DatabaseLike> Visitor for Calls<'_, DB> {
    /// `Ok(false)` when the query is not monotone, or a lookup failure.
    type Break = Result<bool, LookupError>;

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Break(Ok(false));
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        let Expr::Function(call) = expression else {
            return ControlFlow::Continue(());
        };
        if call.over.is_some() {
            return ControlFlow::Break(Ok(false));
        }
        if matches!(call.args, FunctionArguments::None) {
            return ControlFlow::Continue(());
        }
        let aggregates = self
            .policy
            .functions_reached_by(call, self.database)
            .and_then(|reached| may_aggregate(self.database, reached));
        match aggregates {
            Ok(false) => ControlFlow::Continue(()),
            outcome => ControlFlow::Break(outcome.map(|_| false)),
        }
    }
}

/// The acting role for a declared role, or `PUBLIC` for `None`.
fn acting<R>(role: Option<&R>) -> ActingRole<'_, R> {
    role.map_or(ActingRole::Public, ActingRole::Declared)
}

/// Why `role`, `PUBLIC` for `None`, reads or writes `table` past its
/// policies, if it does.
fn exemption<'db, T: TableLike>(
    table: &'db T,
    role: Option<&'db <T::DB as DatabaseLike>::Role>,
    database: &'db T::DB,
) -> Result<Option<RowSecurityExemption>, LookupError> {
    match table.row_security(
        RowStatement::Insert { returning: false },
        acting(role),
        database,
    ) {
        Ok(RowSecurity::Exempt(exemption)) => Ok(Some(exemption)),
        Err(RowSecurityError::Lookup(error)) => Err(error),
        Ok(_) | Err(_) => Ok(None),
    }
}

/// Whether `role`, `PUBLIC` for `None`, may change `table` in a way `needs`
/// asks for, past the table's row-level security.
fn rewrites<'db, T: TableLike>(
    table: &'db T,
    role: Option<&'db <T::DB as DatabaseLike>::Role>,
    needs: Needs,
    database: &'db T::DB,
) -> Result<bool, LookupError> {
    let held = table.possible_privileges(acting(role), database)?;
    if needs.remove && held.truncate {
        return Ok(true);
    }
    let writes = (needs.add && held.insert.on_any_column())
        || held.update.on_any_column()
        || (needs.remove && held.delete);
    Ok(writes && exemption(table, role, database)?.is_some())
}

rule_definition!(
    /// Struct defining a rule that reports a policy deciding on the rows of
    /// another table that a role the policy restricts may rewrite past that
    /// table's row-level security.
    ///
    /// The policy's sublinks, the views they read and the functions it calls
    /// are followed to their tables, whoever reads them, since the writer
    /// changes the rows every reader sees. A sublink that only finds more
    /// rows as its tables gain rows, an `EXISTS` or `IN` over a plain join,
    /// needs `INSERT` or `UPDATE` to pass more rows, and once negated
    /// `DELETE`, `UPDATE` or `TRUNCATE`. Every other read needs any of them.
    /// `TRUNCATE` ignores row-level security, and the other writes count when
    /// the table does not enable it or the role is exempt from it. Privileges
    /// count unless revoked, since defaults may grant them outside the schema.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     PolicyReadsUnprotectedTable::default().into();
    /// let schema = "CREATE ROLE app;
    ///     CREATE TABLE docs (team INT);
    ///     CREATE TABLE members (uid TEXT, team INT);
    ///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    ///     CREATE POLICY team ON docs TO app
    ///       USING (team IN (SELECT team FROM members WHERE uid = current_user));";
    ///
    /// let open = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    /// assert!(constrainer.validate_schema(&open).is_err());
    ///
    /// let protected = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} ALTER TABLE members ENABLE ROW LEVEL SECURITY;"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&protected).is_ok());
    /// ```
    PolicyReadsUnprotectedTable,
    register_table_rule,
    LintGroup::Suspicious,
    "A policy expression runs with the querying role's privileges, so a role it restricts that may insert, update, delete or truncate rows of a table the policy reads, past that table's row-level security, can grant itself the rows the policy guards.",
    Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
    RuleExample {
        bad: "CREATE ROLE authenticated;\n\
CREATE TABLE docs (team INT);\n\
CREATE TABLE members (uid TEXT, team INT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY team ON docs TO authenticated USING (team IN (SELECT team FROM members WHERE uid = current_user));",
        good: "CREATE ROLE authenticated;\n\
CREATE TABLE docs (team INT);\n\
CREATE TABLE members (uid TEXT, team INT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
ALTER TABLE members ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON members FOR SELECT TO authenticated USING (uid = current_user);\n\
CREATE POLICY team ON docs TO authenticated USING (team IN (SELECT team FROM members WHERE uid = current_user));",
    }
);

/// A table a policy reads, the row changes that let more rows pass and the
/// clause and sublink or call that first reads it.
struct ReadTable<'db, DB: DatabaseLike> {
    table: &'db DB::Table,
    needs: Needs,
    clause: PolicyClause,
    via: String,
}

impl<DB: DatabaseLike> TableRule for PolicyReadsUnprotectedTable<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !table.has_row_level_security(database)? {
            return Ok(());
        }
        for policy in table.policies(database)? {
            let mut writers = Vec::new();
            if policy.applies_to_public() {
                writers.push(None);
            }
            for role in database.roles() {
                if policy.applies_to_role(role, database)
                    && exemption(table, Some(role), database)?.is_none()
                {
                    writers.push(Some(role));
                }
            }
            if writers.is_empty() {
                continue;
            }
            let mut read: Vec<ReadTable<'_, DB>> = Vec::new();
            for (clause, expression) in walked_clauses(database, policy)? {
                let Some(expression) = expression else {
                    continue;
                };
                let mut found = Vec::new();
                parts(database, policy, expression, false, &mut found)?;
                for part in found {
                    let (reads, needs) = match part {
                        Part::Monotone(query, needs) => {
                            (sublink_reads(database, policy, Some(query))?.1, needs)
                        }
                        Part::Other(expression) => (
                            sublink_reads(database, policy, Some(expression))?.1,
                            Needs::EITHER,
                        ),
                    };
                    for each in reads {
                        if each.table == table {
                            continue;
                        }
                        let needs = if each.call { Needs::EITHER } else { needs };
                        match read.iter_mut().find(|known| known.table == each.table) {
                            Some(known) => known.needs.join(needs),
                            None => read.push(ReadTable {
                                table: each.table,
                                needs,
                                clause,
                                via: each.via,
                            }),
                        }
                    }
                }
            }
            for target in read {
                let mut names = Vec::new();
                for &writer in &writers {
                    if rewrites(target.table, writer, target.needs, database)? {
                        names.push(writer.map_or_else(
                            || "PUBLIC".to_owned(),
                            |role| format!("'{}'", role.stored_name()),
                        ));
                    }
                }
                if names.is_empty() {
                    continue;
                }
                let (name, table_name, read_name) =
                    (policy.name(), table.table_name(), target.table.table_name());
                let writers = names.join(", ");
                reporter.policies(
                    vec![PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new(policy.clone()),
                        clause: target.clause,
                        expression: target.via,
                    }],
                    format!(
                        "Policy '{name}' on '{table_name}' decides on rows of '{read_name}', which {writers} may rewrite past its row-level security, so they can widen the rows the policy lets through."
                    ),
                    format!(
                        "Enable row-level security on '{read_name}' with policies that keep {writers} from changing it and revoke TRUNCATE on it from them, or revoke the privileges they write it with."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
