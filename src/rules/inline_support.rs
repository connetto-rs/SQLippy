//! Whether PostgreSQL 18 inlines a call to a `LANGUAGE sql` function into the
//! query calling it, as `inline_function` and `inline_set_returning_function`
//! in `src/backend/optimizer/util/clauses.c` decide.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::FunctionKind,
    traits::{DatabaseLike, FunctionLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::{
    ast::{
        BinaryOperator, Expr, FunctionBehavior, FunctionCalledOnNull, FunctionSecurity, Query,
        SelectItem, SetExpr, Statement, Visitor,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use super::{
    function_body_support::parameter,
    policy_support::sql_set_body,
    volatility_support::runs_volatile,
    walk_support::{stop_on, stopped, walk},
};

/// Whether `function` is `LANGUAGE sql`, runs as its caller and sets no
/// configuration parameter, which both kinds of inlining require.
fn plain_sql<F: FunctionLike>(function: &F) -> bool {
    function
        .stored_language()
        .is_none_or(|language| language == "sql")
        && function.security_mode() != FunctionSecurity::Definer
        && function.configuration_parameters().is_empty()
}

/// The one expression a query computes, when it is a `SELECT` of one
/// expression with no other clause.
fn selected_expression(query: &Query) -> Option<&Expr> {
    if query.with.is_some()
        || query.order_by.is_some()
        || query.limit_clause.is_some()
        || query.fetch.is_some()
    {
        return None;
    }
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let [
        SelectItem::UnnamedExpr(expression)
        | SelectItem::ExprWithAlias {
            expr: expression, ..
        },
    ] = select.projection.as_slice()
    else {
        return None;
    };
    (select.from.is_empty()
        && select.selection.is_none()
        && select.having.is_none()
        && select.distinct.is_none()
        && select.named_window.is_empty()
        && select.into.is_none()
        && matches!(&select.group_by, sqlparser::ast::GroupByExpr::Expressions(keys, modifiers) if keys.is_empty() && modifiers.is_empty()))
    .then_some(expression)
}

/// The functions a call names, by its last name part, among the database's
/// functions.
fn named<'db, DB: DatabaseLike>(
    database: &'db DB,
    call: &sqlparser::ast::Function,
) -> Vec<&'db DB::Function> {
    call.name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .map_or_else(Vec::new, |name| {
            database
                .functions_named(&normalize_identifier(
                    &name.value,
                    name.quote_style.is_some(),
                ))
                .collect()
        })
}

/// Finds a term that keeps PostgreSQL from inlining an expression body: a
/// sublink, an aggregate, a window function or a set-returning call, a call
/// an `IMMUTABLE` function may not make, and, for a `STRICT` function, a
/// construct that does not return `NULL` on a `NULL` input.
struct Showstopper<'db, DB: DatabaseLike> {
    database: &'db DB,
    immutable: bool,
    strict: bool,
}

impl<DB: DatabaseLike> Showstopper<'_, DB> {
    fn stops(&mut self, expression: &Expr) -> Result<bool, LookupError> {
        Ok(match expression {
            Expr::Function(call) => {
                if call.over.is_some() || call.filter.is_some() || !call.within_group.is_empty() {
                    return Ok(true);
                }
                let reached = named(self.database, call);
                if reached.is_empty() {
                    return Ok(self.immutable || self.strict);
                }
                for function in reached {
                    if function.returns_set()
                        || function.kind(self.database)? != FunctionKind::Normal
                        || (self.immutable && function.volatility() != FunctionBehavior::Immutable)
                        || (self.strict
                            && function.null_input_behavior()
                                == FunctionCalledOnNull::CalledOnNullInput)
                    {
                        return Ok(true);
                    }
                }
                false
            }
            Expr::Case { .. }
            | Expr::Array(_)
            | Expr::Tuple(_)
            | Expr::IsNull(_)
            | Expr::IsNotNull(_)
            | Expr::IsTrue(_)
            | Expr::IsNotTrue(_)
            | Expr::IsFalse(_)
            | Expr::IsNotFalse(_)
            | Expr::IsUnknown(_)
            | Expr::IsNotUnknown(_)
            | Expr::IsDistinctFrom(..)
            | Expr::IsNotDistinctFrom(..)
            | Expr::BinaryOp {
                op: BinaryOperator::And | BinaryOperator::Or,
                ..
            } => self.strict,
            _ => false,
        })
    }
}

impl<DB: DatabaseLike> Visitor for Showstopper<'_, DB> {
    type Break = Option<LookupError>;

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<Option<LookupError>> {
        ControlFlow::Break(None)
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Option<LookupError>> {
        stop_on(self.stops(expression))
    }
}

/// Whether `expression` reads the input parameter of `function` at
/// `position`.
fn reads_parameter<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
    expression: &Expr,
    position: usize,
) -> bool {
    struct Reads<'a, DB: DatabaseLike> {
        database: &'a DB,
        function: &'a DB::Function,
        position: usize,
    }
    impl<DB: DatabaseLike> Visitor for Reads<'_, DB> {
        type Break = ();
        fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            if parameter(self.database, self.function, expression) == Some(self.position) {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        }
    }
    walk(
        expression,
        &mut Reads {
            database,
            function,
            position,
        },
    )
    .is_break()
}

/// Whether PostgreSQL inlines a call to `function` written in an
/// expression: a `LANGUAGE sql` function of kind `f` running as its caller
/// with no `SET`, returning one value of a type other than `record`, whose
/// body is `RETURN` of an expression or one `SELECT` of one expression with
/// no other clause. The expression holds no sublink, aggregate, window
/// function or set-returning call, makes only `IMMUTABLE` calls in an
/// `IMMUTABLE` function and no `VOLATILE` one in a `STABLE` function, and in
/// a `STRICT` function reads every parameter and holds no construct that
/// returns a value on a `NULL` input.
///
/// # Errors
///
/// Returns the lookup errors reading the body or a called function's kind.
pub(crate) fn inlined_in_expression<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
) -> Result<bool, LookupError> {
    if !plain_sql(function)
        || function.returns_set()
        || function.kind(database)? != FunctionKind::Normal
        || function
            .return_type_name(database)
            .is_some_and(|returned| returned.eq_ignore_ascii_case("record"))
    {
        return Ok(false);
    }
    let returned = function.body_expression(database)?;
    let parsed = function
        .body()
        .and_then(|body| Parser::parse_sql(&PostgreSqlDialect {}, body).ok());
    let atomic = function.atomic_statements(database)?;
    let statements = parsed.as_deref().or(atomic.as_deref());
    let expression = match (&returned, statements) {
        (Some(returned), _) => returned.as_ref(),
        (None, Some([Statement::Query(query)])) => match selected_expression(query) {
            Some(expression) => expression,
            None => return Ok(false),
        },
        (None, _) => return Ok(false),
    };
    let volatility = function.volatility();
    let strict = function.null_input_behavior() != FunctionCalledOnNull::CalledOnNullInput;
    if volatility != FunctionBehavior::Volatile && runs_volatile(database, expression) {
        return Ok(false);
    }
    let mut showstopper = Showstopper {
        database,
        immutable: volatility == FunctionBehavior::Immutable,
        strict,
    };
    if stopped(walk(expression, &mut showstopper))? {
        return Ok(false);
    }
    Ok(!strict
        || (0..function.argument_names(database).count())
            .all(|position| reads_parameter(database, function, expression, position)))
}

/// Whether PostgreSQL inlines a call to the set-returning `function` written
/// as a `FROM` item: a `LANGUAGE sql` function running as its caller with no
/// `SET`, not `VOLATILE`, whose body is one query.
///
/// # Errors
///
/// Returns the lookup errors reading a `BEGIN ATOMIC` body.
pub(crate) fn inlined_in_from<F: FunctionLike>(
    database: &F::DB,
    function: &F,
) -> Result<bool, LookupError> {
    Ok(plain_sql(function)
        && function.volatility() != FunctionBehavior::Volatile
        && sql_set_body(database, function)?.is_some())
}
