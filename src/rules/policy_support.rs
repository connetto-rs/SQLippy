//! Facts about row-level security policies shared by the policy rules.

use std::{collections::BTreeSet, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnScope, FunctionKind, IdentifierCase, PolicyExpression},
    traits::{DatabaseLike, FunctionLike, PolicyLike, RoleLike, RoleMembershipLike, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::{
    ast::{
        BinaryOperator, CreatePolicyCommand, Expr, FunctionArguments, Owner, Query, Statement,
        Visit, Visitor,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::rules::walk_support::walk;
use crate::{deployment::Deployment, error::PolicyClause};

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
) -> Result<Vec<Applied<'db>>, LookupError> {
    let using = policy.using_expression(database)?;
    let check = policy.check_expression(database)?;
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
        Command::Select | Command::Delete => Ok(filter.into_iter().collect()),
        Command::Insert => Ok(new_rows.into_iter().collect()),
        Command::Update => Ok(filter.into_iter().chain(new_rows).collect()),
    }
}

/// The `USING` and `WITH CHECK` clauses of `policy`, each for a walk of the
/// relations, subqueries and calls it holds, stored when every literal of it
/// could be read and written when one could not.
pub(crate) fn walked_clauses<'db, DB: DatabaseLike>(
    database: &'db DB,
    policy: &'db DB::Policy,
) -> Result<[(PolicyClause, Option<&'db Expr>); 2], LookupError> {
    Ok([
        (
            PolicyClause::Using,
            policy
                .using_clause(database)?
                .as_ref()
                .map(PolicyExpression::expression),
        ),
        (
            PolicyClause::WithCheck,
            policy
                .check_clause(database)?
                .as_ref()
                .map(PolicyExpression::expression),
        ),
    ])
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

/// Returns whether a policy for `deciding` roles applies to every role of
/// `policy`, either role list being `None` for `PUBLIC`.
pub(crate) fn covers<DB: DatabaseLike>(
    database: &DB,
    deciding: Option<&[String]>,
    policy: Option<&[String]>,
) -> bool {
    match (deciding, policy) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(deciding), Some(policy)) => policy.iter().all(|role| {
            held_by_name(database, role)
                .iter()
                .any(|held| deciding.contains(held))
        }),
    }
}

/// The query a set-returning `LANGUAGE sql` function runs, when its body is
/// one query.
pub(crate) fn sql_set_body<F: FunctionLike>(function: &F) -> Option<Query> {
    if !function.returns_set()
        || function
            .stored_language()
            .is_some_and(|language| language != "sql")
    {
        return None;
    }
    let mut statements = Parser::parse_sql(&PostgreSqlDialect {}, function.body()?).ok()?;
    match (statements.pop(), statements.is_empty()) {
        (Some(Statement::Query(query)), true) => Some(*query),
        _ => None,
    }
}

/// Whether the expression holds a sublink or a call with arguments.
pub(crate) fn holds_sublink_or_call(expression: &Expr) -> bool {
    struct Found;
    impl Visitor for Found {
        type Break = ();
        fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
            ControlFlow::Break(())
        }
        fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            match expression {
                Expr::Function(call) if !matches!(call.args, FunctionArguments::None) => {
                    ControlFlow::Break(())
                }
                _ => ControlFlow::Continue(()),
            }
        }
    }
    walk(expression, &mut Found).is_break()
}

/// Finds column references to the policy's table, or to one of its columns,
/// outside sublinks or in the top-level query of a sublink that its own
/// relations do not resolve.
struct RowReferences<'db, DB: DatabaseLike> {
    database: &'db DB,
    table: ColumnScope<'db, 'db, DB>,
    column: Option<&'db DB::Column>,
    depth: usize,
    until_first: bool,
    outside: bool,
    correlated: Vec<String>,
}

impl<DB: DatabaseLike> RowReferences<'_, DB> {
    fn reads_table(&self, expression: &Expr) -> Result<bool, LookupError> {
        Ok(self
            .table
            .resolve_column_definition(expression)?
            .is_some_and(|definition| {
                self.column.is_none_or(|wanted| {
                    matches!(definition, ColumnDefinition::Base { column, .. } if column == wanted)
                })
            }))
    }

    /// Lets `mark` record a row reference, then stops after the first one when
    /// only its existence matters.
    fn record(
        &mut self,
        reads: Result<bool, LookupError>,
        mark: impl FnOnce(&mut Self),
    ) -> ControlFlow<Option<LookupError>> {
        match reads {
            Ok(false) => ControlFlow::Continue(()),
            Ok(true) => {
                mark(self);
                if self.until_first {
                    ControlFlow::Break(None)
                } else {
                    ControlFlow::Continue(())
                }
            }
            Err(error) => ControlFlow::Break(Some(error)),
        }
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
    /// A lookup failure, or `None` after the first row reference.
    type Break = Option<LookupError>;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        let reads = match ColumnScope::from_query(query, self.database, IdentifierCase::Folded) {
            Ok(local) => match walk(
                query,
                &mut SublinkReferences {
                    outer: self,
                    local,
                    depth: 0,
                },
            ) {
                ControlFlow::Continue(()) => Ok(false),
                ControlFlow::Break(outcome) => outcome.map(|()| true),
            },
            Err(error) => Err(error),
        };
        self.record(reads, |references| {
            references.correlated.push(query.to_string());
        })
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if self.depth != 0 || !is_column_reference(expression) {
            return ControlFlow::Continue(());
        }
        let reads = self.reads_table(expression);
        self.record(reads, |references| references.outside = true)
    }
}

/// Whether a call that reaches the functions `reached` may run an aggregate:
/// one of them is an aggregate, or it reaches no known function.
///
/// # Errors
///
/// Returns the first lookup failure of a function's kind.
pub(crate) fn may_aggregate<'db, DB: DatabaseLike>(
    database: &DB,
    reached: impl IntoIterator<Item = &'db DB::Function>,
) -> Result<bool, LookupError>
where
    DB::Function: 'db,
{
    let mut known = false;
    for function in reached {
        known = true;
        if function.kind(database)? == FunctionKind::Aggregate {
            return Ok(true);
        }
    }
    Ok(!known)
}

/// Strips the parentheses around an expression.
pub(crate) fn unnested(mut expression: &Expr) -> &Expr {
    while let Expr::Nested(inner) = expression {
        expression = inner;
    }
    expression
}

/// The operands of the `AND` chain of an expression.
pub(crate) fn conjuncts(expression: &Expr) -> Vec<&Expr> {
    match expression {
        Expr::Nested(inner) => conjuncts(inner),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            let mut operands = conjuncts(left);
            operands.extend(conjuncts(right));
            operands
        }
        _ => vec![expression],
    }
}

pub(crate) fn is_column_reference(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
    )
}

/// Whether the expression reads the current or session role.
pub(crate) fn is_role_read(expression: &Expr) -> bool {
    is_call_to(
        expression,
        &["current_user", "current_role", "session_user"],
        true,
    )
}

/// Whether the expression calls one of `names`, written without parentheses
/// when `bare`.
fn is_call_to(expression: &Expr, names: &[&str], bare: bool) -> bool {
    let Expr::Function(function) = expression else {
        return false;
    };
    matches!(function.args, FunctionArguments::None) == bare
        && function
            .name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .is_some_and(|ident| {
                names
                    .iter()
                    .any(|name| ident.value.eq_ignore_ascii_case(name))
            })
}

/// Finds a term identifying the caller.
struct CallerTerm<'a>(&'a Deployment);

impl Visitor for CallerTerm<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if self.0.is_credential(expression)
            || is_role_read(expression)
            || is_call_to(expression, &["current_setting"], false)
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Whether the node holds a term identifying the caller: a declared
/// credential, a `current_setting` call or a read of the current role.
pub(crate) fn holds_caller<V: Visit>(deployment: &Deployment, node: &V) -> bool {
    walk(node, &mut CallerTerm(deployment)).is_break()
}

/// Whether a policy operand on `table` is derived from the caller alone,
/// holding a caller term and no reference to the row being checked.
pub(crate) fn derives_from_caller<DB: DatabaseLike, V: Visit>(
    database: &DB,
    table: &DB::Table,
    deployment: &Deployment,
    node: &V,
) -> Result<bool, LookupError> {
    Ok(holds_caller(deployment, node) && !reads_row(database, table, None, node)?)
}

/// Row references of a policy expression on `table`, to `column` alone when
/// given.
fn row_references<'db, DB: DatabaseLike, V: Visit>(
    database: &'db DB,
    table: &'db DB::Table,
    column: Option<&'db DB::Column>,
    node: &V,
    until_first: bool,
) -> Result<RowReferences<'db, DB>, LookupError> {
    let mut references = RowReferences {
        database,
        table: ColumnScope::for_table(table, database, IdentifierCase::Folded),
        column,
        depth: 0,
        until_first,
        outside: false,
        correlated: Vec::new(),
    };
    match walk(node, &mut references) {
        ControlFlow::Break(Some(error)) => Err(error),
        ControlFlow::Continue(()) | ControlFlow::Break(None) => Ok(references),
    }
}

/// Returns whether a policy expression on `table` depends on the row it is
/// evaluated for, or on its `column` alone when given.
pub(crate) fn reads_row<'db, DB: DatabaseLike, V: Visit>(
    database: &'db DB,
    table: &'db DB::Table,
    column: Option<&'db DB::Column>,
    node: &V,
) -> Result<bool, LookupError> {
    let references = row_references(database, table, column, node, true)?;
    Ok(references.outside || !references.correlated.is_empty())
}

/// Returns every sublink of a policy expression on `table` whose top-level
/// query references the row being checked, rendered as SQL.
pub(crate) fn correlated_subqueries<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    expression: &Expr,
) -> Result<Vec<String>, LookupError> {
    Ok(row_references(database, table, None, expression, false)?.correlated)
}

/// Returns whether PostgreSQL can prove the expression true for every row.
pub(crate) fn is_tautology<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    expression: &Expr,
) -> Result<bool, LookupError> {
    Ok(table.expression_truth(database, expression, IdentifierCase::AsWritten)? == Some(true))
}
