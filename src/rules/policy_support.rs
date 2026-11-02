//! Facts about row-level security policies shared by the policy rules.

use std::{collections::BTreeSet, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{ColumnScope, IdentifierCase},
    traits::{DatabaseLike, PolicyLike, RoleLike, RoleMembershipLike, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{CreatePolicyCommand, Expr, Owner, Query, Visit, Visitor};

use crate::error::PolicyClause;

/// Statement command whose policies PostgreSQL applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Select,
    Insert,
    Update,
    Delete,
}

impl Command {
    pub(crate) const ALL: [Self; 4] = [Self::Select, Self::Insert, Self::Update, Self::Delete];

    /// Returns whether a policy declared `FOR command` applies to `self`.
    pub(crate) fn covered_by(self, command: CreatePolicyCommand) -> bool {
        matches!(
            (command, self),
            (CreatePolicyCommand::All, _)
                | (CreatePolicyCommand::Select, Self::Select)
                | (CreatePolicyCommand::Insert, Self::Insert)
                | (CreatePolicyCommand::Update, Self::Update)
                | (CreatePolicyCommand::Delete, Self::Delete)
        )
    }
}

/// Stage of a command at which a policy expression is evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Existing rows are filtered.
    Filter,
    /// New rows are checked.
    Check,
}

/// One expression PostgreSQL evaluates for a policy and a command.
pub(crate) struct Applied<'db> {
    pub(crate) stage: Stage,
    pub(crate) clause: PolicyClause,
    pub(crate) expression: &'db Expr,
}

/// Expressions of `policy` PostgreSQL evaluates for `command`, following
/// "Policies Applied by Command Type" in the `CREATE POLICY` documentation.
pub(crate) fn applied<'db, DB: DatabaseLike>(
    database: &'db DB,
    policy: &'db DB::Policy,
    command: Command,
) -> Vec<Applied<'db>> {
    let using = policy.using_expression(database);
    let check = policy.check_expression(database);
    let filter = using.map(|expression| Applied {
        stage: Stage::Filter,
        clause: PolicyClause::Using,
        expression,
    });
    let new_rows = match check {
        Some(expression) => Some(Applied {
            stage: Stage::Check,
            clause: PolicyClause::WithCheck,
            expression,
        }),
        None => using.map(|expression| Applied {
            stage: Stage::Check,
            clause: PolicyClause::Using,
            expression,
        }),
    };
    match command {
        Command::Select | Command::Delete => filter.into_iter().collect(),
        Command::Insert => new_rows.into_iter().collect(),
        Command::Update => filter.into_iter().chain(new_rows).collect(),
    }
}

/// Normalized name of a policy role.
pub(crate) fn owner_name(owner: &Owner) -> String {
    match owner {
        Owner::Ident(ident) => {
            normalize_identifier(&ident.value, ident.quote_style.is_some()).into_owned()
        }
        Owner::CurrentRole => "CURRENT_ROLE".to_owned(),
        Owner::CurrentUser => "CURRENT_USER".to_owned(),
        Owner::SessionUser => "SESSION_USER".to_owned(),
    }
}

/// Normalized roles a policy applies to, or `None` for `PUBLIC`.
pub(crate) fn policy_roles<DB: DatabaseLike>(
    database: &DB,
    policy: &DB::Policy,
) -> Option<Vec<String>> {
    (!policy.applies_to_public()).then(|| policy.roles(database).map(owner_name).collect())
}

/// Roles whose privileges `role` holds, itself included, following the
/// memberships granted with the `INHERIT` option.
pub(crate) fn held_roles<DB: DatabaseLike>(database: &DB, role: &DB::Role) -> BTreeSet<String> {
    let mut held = BTreeSet::from([role.stored_name().into_owned()]);
    let mut frontier = vec![role];
    while let Some(member) = frontier.pop() {
        for membership in member.memberships(database) {
            if membership.inherit_option()
                && held.insert(membership.stored_role_name().into_owned())
                && let Some(parent) = membership.role(database)
            {
                frontier.push(parent);
            }
        }
    }
    held
}

/// Roles whose privileges the named role holds, or the name alone when the
/// schema does not declare it.
pub(crate) fn held_by_name<DB: DatabaseLike>(database: &DB, role: &str) -> BTreeSet<String> {
    database.role(role).map_or_else(
        || BTreeSet::from([role.to_owned()]),
        |role| held_roles(database, role),
    )
}

/// Finds column references to the policy's table, outside sublinks or in the
/// top-level query of a sublink that its own relations do not resolve.
struct RowReferences<'db, DB: DatabaseLike> {
    database: &'db DB,
    table: ColumnScope<'db, 'db, DB>,
    depth: usize,
}

impl<DB: DatabaseLike> RowReferences<'_, DB> {
    fn reads_table(&self, expression: &Expr) -> Result<bool, LookupError> {
        Ok(self.table.resolve_column_definition(expression)?.is_some())
    }
}

/// References in the top-level query of one sublink.
struct SublinkReferences<'outer, 'db, 'query, DB: DatabaseLike> {
    outer: &'outer RowReferences<'db, DB>,
    local: ColumnScope<'query, 'db, DB>,
    depth: usize,
}

impl<DB: DatabaseLike> Visitor for SublinkReferences<'_, '_, '_, DB> {
    type Break = Result<(), LookupError>;

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if self.depth != 1 || !is_column_reference(expression) {
            return ControlFlow::Continue(());
        }
        decide(
            self.local
                .resolve_column_definition(expression)
                .and_then(|local| match local {
                    Some(_) => Ok(false),
                    None => self.outer.reads_table(expression),
                }),
        )
    }
}

/// Stops the traversal on a row reference or a lookup failure.
fn decide(reads_row: Result<bool, LookupError>) -> ControlFlow<Result<(), LookupError>> {
    match reads_row {
        Ok(false) => ControlFlow::Continue(()),
        Ok(true) => ControlFlow::Break(Ok(())),
        Err(error) => ControlFlow::Break(Err(error)),
    }
}

impl<DB: DatabaseLike> Visitor for RowReferences<'_, DB> {
    type Break = Result<(), LookupError>;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        match ColumnScope::from_query(query, self.database, IdentifierCase::Folded) {
            Ok(local) => query.visit(&mut SublinkReferences {
                outer: self,
                local,
                depth: 0,
            }),
            Err(error) => decide(Err(error)),
        }
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if self.depth != 0 || !is_column_reference(expression) {
            return ControlFlow::Continue(());
        }
        decide(self.reads_table(expression))
    }
}

fn is_column_reference(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
    )
}

/// Returns whether a policy expression on `table` depends on the row it is
/// evaluated for.
pub(crate) fn reads_row<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    expression: &Expr,
) -> Result<bool, LookupError> {
    let mut references = RowReferences {
        database,
        table: ColumnScope::for_table(table, database, IdentifierCase::Folded),
        depth: 0,
    };
    match expression.visit(&mut references) {
        ControlFlow::Continue(()) => Ok(false),
        ControlFlow::Break(outcome) => outcome.map(|()| true),
    }
}

/// Returns whether PostgreSQL can prove the expression true for every row.
pub(crate) fn is_tautology<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    expression: &Expr,
) -> Result<bool, LookupError> {
    Ok(table.expression_truth(database, expression, IdentifierCase::AsWritten)? == Some(true))
}
