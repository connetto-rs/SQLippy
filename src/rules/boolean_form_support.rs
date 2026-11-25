//! The minimal forms of the boolean conditions and values that tables,
//! domains, views, function bodies and statements write, for the rules
//! reporting a form that reads fewer terms.

use sql_traits::{
    errors::LookupError,
    structs::{
        Assumption, EmbeddedSql, ExpressionContext, ExpressionScope, ExpressionTruth,
        IdentifierCase, Outcomes, PlPgSqlSiteRole, Raising,
    },
    traits::{
        CheckConstraintLike, ColumnLike, DatabaseLike, DomainLike, FunctionLike, IndexLike,
        PolicyLike, TableLike, ViewLike,
    },
};
use sqlparser::ast::{BinaryOperator, Expr, Statement, UnaryOperator, Visit};
use sqlparser_expr_eval::{Atom, Minimal, Site, Volatility, minimal};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    rules::{
        clause_support::{Clause, visit_clauses},
        expression_site_support::is_null_literal,
        function_body_support::{BodyNode, function_body},
        function_rules::readable,
        plpgsql_site_support::{CASE, condition_keyword, plpgsql_sites, selected},
        table_rules::redundant_term::{Site as TermSite, assumed, guaranteed_checks},
        volatility_support::runs_volatile,
    },
    traits::{Reporter, reporter::signature},
};

/// Reads what an expression is where its site evaluates it, `None` where no
/// path reaches it.
type Read<'r> = dyn Fn(&Expr) -> Result<Option<ExpressionTruth>, LookupError> + 'r;

/// Whether `redundant_term` reports a term of a filter, which then gets no
/// finding of its own here.
type Judged<'r> = dyn Fn(&Expr) -> Result<bool, LookupError> + 'r;

/// Which simpler forms a rule reports, after clippy's two boolean lints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// A form that drops a term, clippy's `overly_complex_bool_expr`.
    DropsTerms,
    /// A shorter form that reads every term, clippy's `nonminimal_bool`.
    KeepsTerms,
}

impl Shape {
    /// Whether a rule reporting this shape reports `form`.
    fn wants(self, form: &SimplerForm) -> bool {
        form.dropped.is_empty() == (self == Self::KeepsTerms)
    }
}

/// A form of a written expression that agrees with it where it sits and is
/// shorter.
pub(crate) struct SimplerForm {
    /// The expression as written.
    written: String,
    /// The minimal form.
    form: String,
    /// The terms the written expression reads and the form does not.
    dropped: Vec<String>,
}

impl SimplerForm {
    /// The message of the finding on `place` of `subject`, such as the CHECK
    /// of table 't'.
    fn message(&self, subject: &str, place: &str) -> String {
        let Self {
            written,
            form,
            dropped,
        } = self;
        if dropped.is_empty() {
            return format!(
                "{subject} has {place} `{written}`, which `{form}` says with fewer operators."
            );
        }
        let dropped = dropped
            .iter()
            .map(|term| format!("`{term}`"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{subject} has {place} `{written}`, which means the same as `{form}` without reading {dropped}."
        )
    }

    /// The resolution of the finding.
    fn resolution(&self) -> String {
        format!("Replace `{}` with `{}`.", self.written, self.form)
    }
}

/// Whether `expression` is an `AND`, an `OR` or a `NOT`, under parentheses.
fn is_connective(mut expression: &Expr) -> bool {
    while let Expr::Nested(inner) = expression {
        expression = inner;
    }
    matches!(
        expression,
        Expr::BinaryOp {
            op: BinaryOperator::And | BinaryOperator::Or,
            ..
        } | Expr::UnaryOp {
            op: UnaryOperator::Not,
            ..
        }
    )
}

/// Whether `expression` has a simpler form at `site` when every term it
/// reads is never `NULL`, never raises and is immutable. It has one whenever
/// it has one under the reading of its terms where it sits, which only adds
/// rows to the truth table and terms the form must keep, so an expression
/// failing this needs no term read.
fn may_simplify(expression: &Expr, site: Site) -> bool {
    let plain = Atom {
        may_be_null: false,
        may_raise: false,
        volatility: Volatility::Immutable,
    };
    is_connective(expression) && minimal(expression, site, |_| plain).is_some()
}

/// Whether a clause within `node` may have a simpler form, a `WHERE` or an
/// `ON` only when `filters` holds, and a select-list value at any of
/// `value_sites`.
fn clauses_may_simplify<N: Visit + ?Sized>(node: &N, filters: bool, value_sites: &[Site]) -> bool {
    let mut found = false;
    let visited = visit_clauses(node, |clause, expression| {
        found = found
            || match clause {
                Clause::Where | Clause::On => filters && may_simplify(expression, Site::Filter),
                Clause::Selected => value_sites
                    .iter()
                    .any(|&site| may_simplify(expression, site)),
            };
        Ok(())
    });
    found && visited.is_ok()
}

/// The minimal form of `expression` at `site`, reading each term through
/// `read`. None for an expression already minimal, one whose minimal form
/// is a constant, which the tautology and contradiction rules report, and
/// one no path reaches.
///
/// # Errors
///
/// Returns the lookup errors reading a term.
fn simpler_form<DB: DatabaseLike>(
    database: &DB,
    expression: &Expr,
    site: Site,
    read: &Read<'_>,
) -> Result<Option<SimplerForm>, LookupError> {
    if !may_simplify(expression, site) {
        return Ok(None);
    }
    let mut failure = Ok(());
    let mut reached = true;
    let found = minimal(expression, site, |term| {
        if failure.is_err() || !reached {
            return Atom::OPAQUE;
        }
        match read(term) {
            Ok(Some(truth)) => Atom {
                may_be_null: truth.outcomes.null,
                may_raise: truth.raising != Raising::Never,
                volatility: if runs_volatile(database, term) {
                    Volatility::Volatile
                } else {
                    Volatility::Stable
                },
            },
            Ok(None) => {
                reached = false;
                Atom::OPAQUE
            }
            Err(error) => {
                failure = Err(error);
                Atom::OPAQUE
            }
        }
    });
    failure?;
    let Some(Minimal { form, dropped }) = found.filter(|_| reached) else {
        return Ok(None);
    };
    let dropped: Vec<String> = dropped
        .into_iter()
        .filter(|term| !is_null_literal(term))
        .map(ToString::to_string)
        .collect();
    if matches!(form, Expr::Value(_)) {
        return Ok(None);
    }
    Ok(Some(SimplerForm {
        written: expression.to_string(),
        form: form.to_string(),
        dropped,
    }))
}

/// The simpler forms of the `WHERE` and `ON` clauses within `node` that
/// `judged` leaves to this rule, none when `judged` is `None`, and of its
/// select-list values when `values` holds, each with the clause it sits in.
///
/// # Errors
///
/// Returns the lookup errors reading a clause.
fn clause_forms<N: Visit + ?Sized, DB: DatabaseLike>(
    database: &DB,
    node: &N,
    read: &Read<'_>,
    judged: Option<&Judged<'_>>,
    values: bool,
) -> Result<Vec<(&'static str, SimplerForm)>, LookupError> {
    let mut found = Vec::new();
    visit_clauses(node, |clause, expression| {
        let (place, site) = match clause {
            Clause::Where => ("a WHERE clause", Site::Filter),
            Clause::On => ("an ON clause", Site::Filter),
            Clause::Selected => ("a select-list value", Site::Value),
        };
        let wanted = if site == Site::Filter {
            judged.is_some()
        } else {
            values
        };
        if !wanted {
            return Ok(());
        }
        let Some(form) = simpler_form(database, expression, site, read)? else {
            return Ok(());
        };
        if let Some(judged) = judged
            && site == Site::Filter
            && judged(expression)?
        {
            return Ok(());
        }
        found.push((place, form));
        Ok(())
    })?;
    Ok(found)
}

/// The simpler forms of the clauses `context` roots, the redundant terms of
/// a filter judged as `redundant_term` judges them.
///
/// # Errors
///
/// Returns the lookup errors reading a clause.
fn context_forms<N: Visit + ?Sized, DB: DatabaseLike>(
    database: &DB,
    context: &ExpressionContext<'_, '_, DB>,
    node: &N,
    values: bool,
) -> Result<Vec<(&'static str, SimplerForm)>, LookupError> {
    let read = |expression: &Expr| context.truth_under(expression, &[]).map(Some);
    let judged = |expression: &Expr| {
        let site = TermSite::new(
            |expression, assumptions| context.truth_under(expression, assumptions),
            Vec::new(),
        );
        Ok(!site.redundant_terms(expression, Outcomes::TRUE)?.is_empty())
    };
    clause_forms(database, node, &read, Some(&judged), values)
}

/// Reports the simpler forms of the checks of `table`, each read under the
/// other checks of `checks` that every stored row satisfies.
///
/// # Errors
///
/// Returns the lookup errors reading a check, and the interruption the
/// reporter raises.
fn report_checks<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    checks: &[(&DB::CheckConstraint, bool)],
    shape: Shape,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    let subject = format!("Table '{}'", table.table_name());
    let case = database.identifier_case();
    for (position, &(check, _)) in checks.iter().enumerate() {
        let base = assumed(checks, Some(position));
        let expression = check.expression(database);
        let read = |expression: &Expr| {
            table
                .truth_under(database, expression, case, &base)
                .map(Some)
        };
        let Some(form) = simpler_form(database, expression, Site::Check, &read)?
            .filter(|form| shape.wants(form))
        else {
            continue;
        };
        let site = TermSite::new(
            |expression, assumptions| table.truth_under(database, expression, case, assumptions),
            base.clone(),
        );
        if site
            .redundant_terms(expression, Outcomes::NOT_FALSE)?
            .is_empty()
        {
            reporter.table(
                table,
                form.message(&subject, "the CHECK"),
                form.resolution(),
            )?;
        }
    }
    Ok(())
}

/// Reports the simpler forms of the checks, column defaults and generated
/// columns, policy clauses and partial index predicates of `table`.
///
/// # Errors
///
/// Returns the lookup errors reading an expression, and the interruption
/// the reporter raises.
pub(crate) fn report_table<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    shape: Shape,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    let checks = guaranteed_checks(database, table)?;
    report_checks(database, table, &checks, shape, reporter)?;
    let table_name = table.table_name();
    let base = assumed(&checks, None);
    let read = |expression: &Expr| {
        table
            .truth_under(database, expression, IdentifierCase::AsWritten, &base)
            .map(Some)
    };
    let judged = |expression: &Expr| {
        let site = TermSite::new(
            |expression, assumptions| {
                table.truth_under(database, expression, IdentifierCase::AsWritten, assumptions)
            },
            base.clone(),
        );
        Ok::<_, LookupError>(!site.redundant_terms(expression, Outcomes::TRUE)?.is_empty())
    };
    for column in table.columns(database)? {
        for (place, expression) in [
            ("its default", column.default_expression()),
            ("its generation expression", column.generation_expression()),
        ] {
            let Some(expression) = expression else {
                continue;
            };
            if let Some(form) = simpler_form(database, expression, Site::Value, &read)?
                .filter(|form| shape.wants(form))
            {
                let subject = format!("Column '{table_name}.{}'", column.column_name());
                reporter.column(column, form.message(&subject, place), form.resolution())?;
            }
        }
    }
    for policy in table.policies(database)? {
        let name = policy.name();
        for (clause, expression) in [
            (PolicyClause::Using, policy.using_expression(database)?),
            (PolicyClause::WithCheck, policy.check_expression(database)?),
        ] {
            let Some(expression) = expression else {
                continue;
            };
            let Some(form) = simpler_form(database, expression, Site::Filter, &read)?
                .filter(|form| shape.wants(form))
            else {
                continue;
            };
            if judged(expression)? {
                continue;
            }
            reporter.policies(
                vec![PolicySite {
                    table: Box::new(table.clone()),
                    policy: Box::new(policy.clone()),
                    clause,
                    expression: expression.to_string(),
                }],
                form.message(
                    &format!("Policy '{name}' on '{table_name}'"),
                    &format!("its {clause} clause"),
                ),
                form.resolution(),
            )?;
        }
    }
    for index in table.indices(database)? {
        let Some(predicate) = index.predicate() else {
            continue;
        };
        let Some(form) = simpler_form(database, predicate, Site::Filter, &read)?
            .filter(|form| shape.wants(form))
        else {
            continue;
        };
        if judged(predicate)? {
            continue;
        }
        let index_name = index.name().unwrap_or("the partial index");
        reporter.index(
            index,
            form.message(
                &format!("Index '{index_name}' on '{table_name}'"),
                "its predicate",
            ),
            form.resolution(),
        )?;
    }
    Ok(())
}

/// Reports the simpler forms of the domain checks, of the clauses of views
/// and materialized views, and of the clauses, conditions and values of
/// function bodies.
///
/// # Errors
///
/// Returns the lookup errors reading an expression, and the interruption
/// the reporter raises.
pub(crate) fn report_schema<DB: DatabaseLike>(
    database: &DB,
    shape: Shape,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    let case = database.identifier_case();
    for domain in database.domains() {
        let checks = domain.check_expressions().collect::<Vec<_>>();
        for (position, &expression) in checks.iter().enumerate() {
            let others: Vec<_> = checks
                .iter()
                .enumerate()
                .filter(|&(other, _)| other != position)
                .map(|(_, &other)| Assumption::Expression {
                    expression: other,
                    outcomes: Outcomes::NOT_FALSE,
                })
                .collect();
            let read = |expression: &Expr| {
                domain
                    .truth_under(database, expression, case, &others)
                    .map(Some)
            };
            let Some(form) = simpler_form(database, expression, Site::Check, &read)?
                .filter(|form| shape.wants(form))
            else {
                continue;
            };
            let site = TermSite::new(
                |expression, assumptions| {
                    domain.truth_under(database, expression, case, assumptions)
                },
                others.clone(),
            );
            if site
                .redundant_terms(expression, Outcomes::NOT_FALSE)?
                .is_empty()
            {
                let subject = format!("Domain '{}'", domain.name());
                reporter.domain(domain, form.message(&subject, "a CHECK"), form.resolution())?;
            }
        }
    }
    for view in database.views() {
        if !clauses_may_simplify(view.definition(), true, &[Site::Value]) {
            continue;
        }
        let context = ExpressionContext::new(view.definition(), database, IdentifierCase::Folded)?;
        let subject = format!("View '{}'", view.view_name());
        for (place, form) in context_forms(database, &context, view.definition(), true)? {
            if !shape.wants(&form) {
                continue;
            }
            reporter.view(view, form.message(&subject, place), form.resolution())?;
        }
    }
    for view in database.materialized_views() {
        if !clauses_may_simplify(view.definition(), true, &[Site::Value]) {
            continue;
        }
        let context = ExpressionContext::new(view.definition(), database, IdentifierCase::Folded)?;
        let subject = format!("Materialized view '{}'", view.view_name());
        for (place, form) in context_forms(database, &context, view.definition(), true)? {
            if !shape.wants(&form) {
                continue;
            }
            reporter.materialized_view(view, form.message(&subject, place), form.resolution())?;
        }
    }
    for function in database.functions().filter(|function| {
        !matches!(
            function.target_name().schema(),
            Some("pg_catalog" | "information_schema")
        )
    }) {
        report_function(database, function, shape, reporter)?;
    }
    Ok(())
}

/// Reports the simpler forms of the clauses, conditions and values of the
/// body of `function`.
///
/// # Errors
///
/// Returns the lookup errors reading the body, and the interruption the
/// reporter raises.
fn report_function<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
    shape: Shape,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    let plpgsql = function.stored_language().as_deref() == Some("plpgsql");
    let value_sites: &[Site] = if plpgsql { &[] } else { &[Site::Value] };
    let scope = ExpressionScope::FunctionBody(function);
    let mut found: Vec<(String, SimplerForm)> = Vec::new();
    let mut plpgsql_candidate = false;
    function_body(database, function, |node| -> Result<(), LookupError> {
        let forms = match node {
            BodyNode::Statement(statement) => {
                plpgsql_candidate = plpgsql_candidate
                    || (plpgsql
                        && clauses_may_simplify(statement, false, &[Site::Filter, Site::Value]));
                if !clauses_may_simplify(statement, true, value_sites) {
                    return Ok(());
                }
                let context = ExpressionContext::for_statement(
                    statement,
                    &scope,
                    database,
                    IdentifierCase::Folded,
                )?;
                context_forms(database, &context, statement, !plpgsql)?
            }
            BodyNode::Expression(expression) => {
                if !may_simplify(expression, Site::Value)
                    && !clauses_may_simplify(expression, true, &[Site::Value])
                {
                    return Ok(());
                }
                let context = ExpressionContext::for_expression(
                    expression,
                    &scope,
                    database,
                    IdentifierCase::Folded,
                )?;
                let read = |expression: &Expr| context.truth_under(expression, &[]).map(Some);
                let mut forms = Vec::new();
                if let Some(form) = simpler_form(database, expression, Site::Value, &read)? {
                    forms.push(("its returned value", form));
                }
                forms.extend(context_forms(database, &context, expression, true)?);
                forms
            }
        };
        found.extend(
            forms
                .into_iter()
                .map(|(place, form)| (place.to_owned(), form)),
        );
        Ok(())
    })?;
    if plpgsql_candidate {
        plpgsql_forms(database, function, &mut found)?;
    }
    let subject = format!("Function '{}'", signature(function, database));
    for (place, form) in found.into_iter().filter(|(_, form)| shape.wants(form)) {
        reporter.function(function, form.message(&subject, &place), form.resolution())?;
    }
    Ok(())
}

/// Pushes onto `found` the simpler forms of the conditions and values the
/// PL/pgSQL body of `function` evaluates, and of the select-list values of
/// the queries it runs, each read where the body evaluates it.
///
/// # Errors
///
/// Returns the lookup errors reading the body.
fn plpgsql_forms<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
    found: &mut Vec<(String, SimplerForm)>,
) -> Result<(), Interruption> {
    plpgsql_sites(database, function, |site| {
        let read = |expression: &Expr| readable(site.truth_under(expression, CASE));
        let values = match site.sql() {
            EmbeddedSql::Expression(query) => {
                let Some(expression) = selected(query) else {
                    return Ok(());
                };
                let role = site.role();
                let (place, kind) = match (condition_keyword(role), role) {
                    (Some(keyword), _) => (format!("the {keyword} condition"), Site::Filter),
                    (None, PlPgSqlSiteRole::Assigned) => {
                        ("an assigned value".to_owned(), Site::Value)
                    }
                    (None, PlPgSqlSiteRole::Default) => {
                        ("a declared default".to_owned(), Site::Value)
                    }
                    (None, _) => ("a value".to_owned(), Site::Value),
                };
                if let Some(form) = simpler_form(database, expression, kind, &read)? {
                    found.push((place, form));
                }
                clause_forms(database, expression, &read, None, true)?
            }
            EmbeddedSql::Statement(statement) => {
                clause_forms(database, statement, &read, None, true)?
            }
        };
        found.extend(
            values
                .into_iter()
                .map(|(place, form)| (place.to_owned(), form)),
        );
        Ok(())
    })
}

/// Reports the simpler forms of the clauses of the script statement
/// `statement`.
///
/// # Errors
///
/// Returns the lookup errors reading a clause, and the interruption the
/// reporter raises.
pub(crate) fn report_statement<DB: DatabaseLike>(
    database: &DB,
    statement: &Statement,
    shape: Shape,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    if !clauses_may_simplify(statement, true, &[Site::Value]) {
        return Ok(());
    }
    let context = ExpressionContext::for_statement(
        statement,
        &ExpressionScope::Empty,
        database,
        IdentifierCase::Folded,
    )?;
    for (place, form) in context_forms(database, &context, statement, true)? {
        if !shape.wants(&form) {
            continue;
        }
        let message = form.message("The statement", place);
        let resolution = form.resolution();
        reporter.statement(statement, form.written, message, resolution)?;
    }
    Ok(())
}
