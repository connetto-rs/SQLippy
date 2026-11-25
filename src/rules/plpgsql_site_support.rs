//! The sites of a PL/pgSQL body, and the conditions and values it evaluates
//! with their truth where it evaluates them, for the rules reading it.

use sql_traits::{
    structs::{
        EmbeddedSql, ExpressionTruth, IdentifierCase, PlPgSqlSite, PlPgSqlSiteRole, PlPgSqlSites,
    },
    traits::{DatabaseLike, FunctionLike},
};
use sqlparser::ast::{Expr, Query, SelectItem, SetExpr};

use crate::{error::Interruption, rules::function_rules::readable};

/// How the rules reading PL/pgSQL truth compare identifiers.
pub(crate) const CASE: IdentifierCase = IdentifierCase::Folded;

/// The PL/pgSQL body of `function`, none for a body that does not parse or
/// is written in another language, and for a function of `pg_catalog`.
///
/// # Errors
///
/// Returns the lookup errors reading the body runs into.
pub(crate) fn plpgsql_body<'db, DB: DatabaseLike>(
    database: &'db DB,
    function: &'db DB::Function,
) -> Result<Option<PlPgSqlSites<'db, DB>>, Interruption> {
    if function.target_name().schema() == Some("pg_catalog") {
        return Ok(None);
    }
    Ok(readable(function.plpgsql_sites(database).map(Some))?)
}

/// Calls `visit` with each site of the PL/pgSQL body of `function`, in body
/// order, none for a body [`plpgsql_body`] leaves out.
///
/// # Errors
///
/// Returns the lookup errors reading the body runs into, and the errors
/// `visit` returns.
pub(crate) fn plpgsql_sites<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
    mut visit: impl FnMut(&PlPgSqlSite<'_, '_, DB>) -> Result<(), Interruption>,
) -> Result<(), Interruption> {
    let Some(body) = plpgsql_body(database, function)? else {
        return Ok(());
    };
    for site in readable(body.sites())? {
        visit(&site)?;
    }
    Ok(())
}

/// A condition, an assigned value or a default a PL/pgSQL body evaluates on
/// a path reaching it.
pub(crate) struct EvaluatedSite {
    /// What the body does with the expression.
    pub(crate) role: PlPgSqlSiteRole,
    /// The expression as a message names it, such as the IF condition
    /// `` `n > 5` ``.
    pub(crate) described: String,
    /// What the expression is where the body evaluates it, a condition
    /// converted to `boolean` as PL/pgSQL converts it.
    pub(crate) truth: ExpressionTruth,
}

/// Calls `found` with each condition, assigned value and declared default
/// the PL/pgSQL body of `function` evaluates on a path reaching it, in body
/// order, as [`plpgsql_sites`] visits the body.
///
/// # Errors
///
/// Returns the errors [`plpgsql_sites`] returns, and the lookup errors
/// reading what an expression is.
pub(crate) fn evaluated_sites<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
    mut found: impl FnMut(EvaluatedSite) -> Result<(), Interruption>,
) -> Result<(), Interruption> {
    plpgsql_sites(database, function, |site| {
        let role = site.role();
        let EmbeddedSql::Expression(query) = site.sql() else {
            return Ok(());
        };
        let (described, truth) = match (condition_keyword(role), role, selected(query)) {
            (Some(keyword), _, _) => (
                format!("the {keyword} condition `{}`", written(query)),
                readable(site.condition(CASE))?,
            ),
            (None, PlPgSqlSiteRole::Assigned, Some(value)) => (
                format!("the assigned value `{value}`"),
                readable(site.truth_under(value, CASE))?,
            ),
            (None, PlPgSqlSiteRole::Default, Some(value)) => (
                format!("the declared default `{value}`"),
                readable(site.truth_under(value, CASE))?,
            ),
            (None, _, _) => return Ok(()),
        };
        let Some(truth) = truth else {
            return Ok(());
        };
        found(EvaluatedSite {
            role,
            described,
            truth,
        })
    })
}

/// Names the clause a condition site of `role` belongs to, `None` for a site
/// whose role is no condition.
pub(crate) const fn condition_keyword(role: PlPgSqlSiteRole) -> Option<&'static str> {
    match role {
        PlPgSqlSiteRole::IfCondition { .. } => Some("IF"),
        PlPgSqlSiteRole::ElsifCondition { .. } => Some("ELSIF"),
        PlPgSqlSiteRole::CaseWhen { .. } => Some("WHEN"),
        PlPgSqlSiteRole::WhileCondition => Some("WHILE"),
        PlPgSqlSiteRole::ExitWhen => Some("EXIT WHEN"),
        PlPgSqlSiteRole::ContinueWhen => Some("CONTINUE WHEN"),
        PlPgSqlSiteRole::AssertCondition => Some("ASSERT"),
        PlPgSqlSiteRole::Statement
        | PlPgSqlSiteRole::CaseSubject
        | PlPgSqlSiteRole::CaseValue
        | PlPgSqlSiteRole::Assigned
        | PlPgSqlSiteRole::Default
        | PlPgSqlSiteRole::Expression => None,
    }
}

/// The expression `query`, the `SELECT` PL/pgSQL evaluates an expression
/// as, selects alone.
pub(crate) fn selected(query: &Query) -> Option<&Expr> {
    let SetExpr::Select(select) = &*query.body else {
        return None;
    };
    match select.projection.as_slice() {
        [SelectItem::UnnamedExpr(expression)] => Some(expression),
        _ => None,
    }
}

/// Renders the expression the body wrote, which `query` selects alone, or
/// the whole query when it selects anything else.
pub(crate) fn written(query: &Query) -> String {
    selected(query).map_or_else(|| query.to_string(), ToString::to_string)
}
