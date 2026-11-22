//! Whether a filter implies the conditions of row-level-security policies,
//! compared as written once the columns each tests go by one name.

use std::{borrow::Cow, convert::Infallible, mem, ops::ControlFlow, slice};

use sql_traits::{errors::LookupError, structs::RowGate, traits::DatabaseLike};
use sqlparser::ast::{
    BinaryOperator, Distinct, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArgumentList,
    FunctionArguments, Ident, InTarget, Query, Select, SelectItem, SetExpr, TableFactor, Value,
    Visit, VisitMut, Visitor, VisitorMut, WildcardAdditionalOptions, visit_expressions,
    visit_expressions_mut,
};

use crate::{
    deployment::Deployment,
    rules::{
        closed_set_support::stored_name,
        policy_support::{
            conjuncts, disjuncts, is_column_reference, is_tautology, unnested, unwrapped,
        },
        walk_support::walk,
    },
};

/// What a name a filter writes like a column's stands for.
pub(crate) enum Term {
    /// The column of this stored name.
    Column(String),
    /// The input parameter at this position, counted from zero, of the
    /// function whose body holds the filter.
    Parameter(usize),
}

/// The values an input parameter of an enum type may hold.
pub(crate) struct ParameterValues {
    /// Each label of the enum, as a string literal.
    pub(crate) labels: Vec<Expr>,
    /// Whether the parameter may also be `NULL`, as in a function that runs
    /// on `NULL` input.
    pub(crate) null: bool,
}

/// One value of the row a policy condition tests against a set.
pub(crate) enum Operand<'e, T> {
    /// The condition columns this column names.
    Tested(T),
    /// A value that reads no column, met as written.
    Value(&'e Expr),
}

/// How the columns a policy condition tests map onto those a filter tests.
pub(crate) trait Columns {
    /// The condition columns a set membership tests.
    type Tested;

    /// The deployment declaring which sets lie within which.
    fn deployment(&self) -> &Deployment;

    /// The name the filter gives the condition column stored as `column`.
    fn rename(&self, column: Cow<'_, str>) -> Option<String>;

    /// The condition columns `column` names, when it names one the filter can
    /// test.
    fn tested(&self, column: &Expr) -> Option<Self::Tested>;

    /// Whether the filter column `column` is one of `tested`.
    fn tests(&self, column: &Expr, tested: &Self::Tested) -> bool;

    /// Whether `clause` alone meets every condition.
    fn settles(&self, _clause: &Expr) -> bool {
        false
    }

    /// The values the input parameter at `ordinal` may hold, `None` for one
    /// whose type is no enum.
    fn parameter_values(&self, _ordinal: usize) -> Option<&ParameterValues> {
        None
    }

    /// Whether every function `call` may reach returns `NULL` when its
    /// positional argument at `index`, counted from zero, is `NULL`.
    fn returns_null_on_null_argument(&self, _call: &Function, _index: usize) -> bool {
        false
    }

    /// Whether `clause` draws the row it tests from rows that each meet
    /// `condition`, when the row also meets every one of `context`.
    ///
    /// # Errors
    ///
    /// Returns the lookup error reading the rows' source raised.
    fn draws_implied(
        &self,
        _clause: &Expr,
        _condition: &Condition<'_, Self::Tested>,
        _context: &[&Expr],
    ) -> Result<bool, LookupError> {
        Ok(false)
    }
}

/// A policy condition as a filter would state it.
pub(crate) struct Condition<'e, T> {
    /// The condition as the policy writes it.
    pub(crate) original: &'e Expr,
    /// The condition with each column it tests named as the filter names it,
    /// when the filter names every one.
    renamed: Option<Expr>,
    /// The row the condition tests against a set, value by value, and the
    /// expression yielding the members of the set.
    pub(crate) membership: Option<(Vec<Operand<'e, T>>, Cow<'e, Expr>)>,
    /// The conjuncts of an `AND`, each implied for the whole.
    pub(crate) parts: Vec<Self>,
    /// The arms of an `OR`, one implied for the whole.
    arms: Vec<Self>,
}

impl<'e, T> Condition<'e, T> {
    /// `condition` as a filter naming columns as `columns` does would state
    /// it, split into its conjuncts and arms.
    pub(crate) fn new<C: Columns<Tested = T>>(columns: &C, condition: &'e Expr) -> Self {
        let condition = unnested(condition);
        let split = |operands: Vec<&'e Expr>| {
            if operands.len() > 1 {
                operands
                    .into_iter()
                    .map(|operand| Self::new(columns, operand))
                    .collect()
            } else {
                Vec::new()
            }
        };
        Self {
            original: condition,
            renamed: renamed(condition, |column| {
                stored_name(column)
                    .and_then(|name| columns.rename(name))
                    .map(Term::Column)
            }),
            membership: membership(condition).and_then(|(row, members)| {
                let operands = row
                    .iter()
                    .map(|operand| {
                        if is_column(operand) {
                            columns.tested(operand).map(Operand::Tested)
                        } else {
                            Some(Operand::Value(operand))
                        }
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some((operands, members))
            }),
            parts: split(conjuncts(condition)),
            arms: split(disjuncts(condition)),
        }
    }
}

/// Whether every row `clause` admits meets `condition`, when the row also
/// meets every one of `context`. That holds when the clause settles it,
/// states it, tests the same row against a set within the condition's, or
/// draws its row from rows meeting it, when it implies the condition in
/// every arm or for every value of an `IN` list or in one of its conjuncts,
/// or when it implies each conjunct or one arm of `condition`.
///
/// # Errors
///
/// Returns the lookup error [`Columns::draws_implied`] raised.
pub(crate) fn clause_implies<C: Columns>(
    columns: &C,
    clause: &Expr,
    condition: &Condition<'_, C::Tested>,
    context: &[&Expr],
) -> Result<bool, LookupError> {
    let clause = unnested(clause);
    if columns.settles(clause) {
        return Ok(true);
    }
    if let Some(stated) = &condition.renamed
        && renamed(clause, |column| {
            stored_name(column).map(|name| Term::Column(name.into_owned()))
        })
        .as_ref()
            == Some(stated)
    {
        return Ok(true);
    }
    if let Some((operands, wider)) = &condition.membership
        && let Some((row, members)) = membership(clause)
        && row.len() == operands.len()
        && row
            .iter()
            .zip(operands)
            .all(|(value, operand)| match operand {
                Operand::Tested(tested) => is_column(value) && columns.tests(value, tested),
                Operand::Value(stated) => value == *stated,
            })
        && is_within(columns, &members, wider)
    {
        return Ok(true);
    }
    if columns.draws_implied(clause, condition, context)? {
        return Ok(true);
    }
    let arms = disjuncts(clause);
    if arms.len() > 1
        && every(&arms, |arm| {
            clause_implies(columns, arm, condition, context)
        })?
    {
        return Ok(true);
    }
    if let Expr::In {
        expr,
        target: InTarget::List(list),
        negated: false,
        ..
    } = clause
    {
        let arms: Vec<Expr> = list
            .iter()
            .map(|value| Expr::BinaryOp {
                left: expr.clone(),
                op: BinaryOperator::Eq,
                right: Box::new(value.clone()),
            })
            .collect();
        if every(&arms, |arm| {
            clause_implies(columns, arm, condition, context)
        })? {
            return Ok(true);
        }
    }
    if !condition.parts.is_empty()
        && every(&condition.parts, |part| {
            clause_implies(columns, clause, part, context)
        })?
    {
        return Ok(true);
    }
    let parts = conjuncts(clause);
    if parts.len() > 1 {
        for (index, part) in parts.iter().enumerate() {
            let mut beside = context.to_vec();
            beside.extend(
                parts
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .flat_map(|(_, other)| conjuncts(other)),
            );
            if clause_implies(columns, part, condition, &beside)? {
                return Ok(true);
            }
        }
    }
    for arm in &condition.arms {
        if clause_implies(columns, clause, arm, context)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `holds` accepts every one of `items`, stopping at the first it
/// refuses or the first error it raises.
fn every<T, E>(items: &[T], mut holds: impl FnMut(&T) -> Result<bool, E>) -> Result<bool, E> {
    for item in items {
        if !holds(item)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `gates` admit every row of `table` that meets each condition
/// `implied` accepts, which holds when every restrictive term and one
/// permissive term of each gate is a tautology or accepted.
///
/// # Errors
///
/// Returns the lookup error reading a policy or `implied` raised.
pub(crate) fn admits<DB: DatabaseLike, C: Columns>(
    database: &DB,
    table: &DB::Table,
    gates: &[RowGate<'_, DB::Policy>],
    columns: &C,
    implied: impl Fn(&Condition<'_, C::Tested>) -> Result<bool, LookupError>,
) -> Result<bool, LookupError> {
    let holds = |condition: &Expr| -> Result<bool, LookupError> {
        Ok(is_tautology(database, table, condition)?
            || implied(&Condition::new(columns, condition))?)
    };
    for gate in gates {
        for term in gate.restrictive() {
            if !holds(term.expression().expression())? {
                return Ok(false);
            }
        }
        let mut admitted = false;
        for term in gate.permissive() {
            if holds(term.expression().expression())? {
                admitted = true;
                break;
            }
        }
        if !admitted {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `expression` is a column reference, bare or qualified.
pub(crate) fn is_column(expression: &Expr) -> bool {
    is_column_reference(unwrapped(expression))
}

/// Whether `node` mentions a column, which in a policy can be one of the
/// row's.
fn references_column<V: Visit>(node: &V) -> bool {
    visit_expressions(node, |expression| {
        if is_column(expression) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .is_break()
}

/// The numbered placeholder `$n` PostgreSQL reads as the input parameter at
/// `ordinal`, counted from zero.
pub(crate) fn parameter(ordinal: usize) -> Expr {
    Expr::Value(Value::Placeholder(format!("${}", ordinal + 1)).into())
}

/// The position, counted from zero, of the input parameter `expression`
/// reads as `$n`.
fn parameter_ordinal(expression: &Expr) -> Option<usize> {
    let Expr::Value(value) = expression else {
        return None;
    };
    let Value::Placeholder(placeholder) = &value.value else {
        return None;
    };
    let digits = placeholder.strip_prefix('$')?;
    digits.parse::<usize>().ok()?.checked_sub(1)
}

/// `expression` with every column reference named, quoted, by the column
/// `rename` resolves it to and every parameter reference written as `$n`,
/// and every scalar subquery that reads no relation, such as
/// `(SELECT auth.uid())`, replaced by the value it projects. `rename` is
/// called on the references of `expression` itself. `None` when `rename`
/// resolves a reference to nothing or a subquery reads a column, which may
/// resolve to another table's.
pub(crate) fn renamed(expression: &Expr, rename: impl Fn(&Expr) -> Option<Term>) -> Option<Expr> {
    /// Resolves each reference, in the order [`Renamer`] meets them.
    struct Resolver<F> {
        rename: F,
        depth: usize,
        resolved: Vec<Expr>,
    }

    impl<F: Fn(&Expr) -> Option<Term>> Visitor for Resolver<F> {
        type Break = ();

        fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
            self.depth += 1;
            ControlFlow::Continue(())
        }

        fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
            self.depth -= 1;
            ControlFlow::Continue(())
        }

        fn post_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            if !is_column_reference(expression) {
                return ControlFlow::Continue(());
            }
            let resolved = match (self.rename)(expression) {
                Some(Term::Column(name)) if self.depth == 0 => {
                    Expr::Identifier(Ident::with_quote('"', name))
                }
                Some(Term::Parameter(ordinal)) => parameter(ordinal),
                _ => return ControlFlow::Break(()),
            };
            self.resolved.push(resolved);
            ControlFlow::Continue(())
        }
    }

    /// Writes the resolved references and inlines the scalar subqueries.
    struct Renamer<I> {
        resolved: I,
    }

    impl<I: Iterator<Item = Expr>> VisitorMut for Renamer<I> {
        type Break = Infallible;

        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<Infallible> {
            if let Expr::Subquery(query) = expression
                && sole_item(query).is_some()
                && let SetExpr::Select(select) = query.body.as_mut()
                && let [
                    SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. },
                ] = select.projection.as_mut_slice()
            {
                *expression = mem::replace(value, Expr::Value(Value::Null.into()));
            } else if is_column_reference(expression)
                && let Some(resolved) = self.resolved.next()
            {
                *expression = resolved;
            }
            ControlFlow::Continue(())
        }
    }

    let mut resolver = Resolver {
        rename,
        depth: 0,
        resolved: Vec::new(),
    };
    if walk(expression, &mut resolver).is_break() {
        return None;
    }
    let mut renamed = expression.clone();
    let ControlFlow::Continue(()) = VisitMut::visit(
        &mut renamed,
        &mut Renamer {
            resolved: resolver.resolved.into_iter(),
        },
    );
    Some(renamed)
}

/// Whether every value `narrower` yields is one `wider` yields, whatever
/// value each input parameter it reads holds. A parameter of an enum type
/// takes each label in turn, and a `NULL` one passes only to a call returning
/// `NULL` on `NULL` input, which yields no value. A parameter of any other
/// type proves nothing.
fn is_within<C: Columns>(columns: &C, narrower: &Expr, wider: &Expr) -> bool {
    let mut ordinals = Vec::new();
    let _ = visit_expressions(narrower, |expression| {
        if let Some(ordinal) = parameter_ordinal(expression)
            && !ordinals.contains(&ordinal)
        {
            ordinals.push(ordinal);
        }
        ControlFlow::<()>::Continue(())
    });
    if ordinals.is_empty() {
        return columns.deployment().is_set_within(narrower, wider);
    }
    let Some(values) = ordinals
        .iter()
        .map(|&ordinal| columns.parameter_values(ordinal))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if ordinals
        .iter()
        .zip(&values)
        .any(|(&ordinal, values)| values.null && !nothing_on_null(columns, narrower, ordinal))
    {
        return false;
    }
    let mut choice = vec![0; ordinals.len()];
    loop {
        let mut expanded = narrower.clone();
        let _ = visit_expressions_mut(&mut expanded, |expression| {
            if let Some(ordinal) = parameter_ordinal(expression)
                && let Some(position) = ordinals.iter().position(|&seen| seen == ordinal)
                && let Some(label) = values[position].labels.get(choice[position])
            {
                *expression = label.clone();
            }
            ControlFlow::<()>::Continue(())
        });
        if !columns.deployment().is_set_within(&expanded, wider) {
            return false;
        }
        let Some(position) = (0..choice.len())
            .find(|&position| choice[position] + 1 < values[position].labels.len())
        else {
            return true;
        };
        choice[position] += 1;
        choice[..position].fill(0);
    }
}

/// Whether `narrower` yields no value while the input parameter at
/// `ordinal` is `NULL`, as a call does that takes it, through parentheses
/// and casts, as a positional argument it returns `NULL` for.
fn nothing_on_null<C: Columns>(columns: &C, narrower: &Expr, ordinal: usize) -> bool {
    let Expr::Function(
        call @ Function {
            args: FunctionArguments::List(list),
            ..
        },
    ) = unwrapped(narrower)
    else {
        return false;
    };
    list.args.iter().enumerate().any(|(index, argument)| {
        matches!(
            argument,
            FunctionArg::Unnamed(FunctionArgExpr::Expr(argument))
                if parameter_ordinal(unwrapped(argument)) == Some(ordinal)
        ) && columns.returns_null_on_null_argument(call, index)
    })
}

/// The expression yielding the values `value` holds as the operand of `=`,
/// when it reads no column.
fn value_members(value: &Expr) -> Option<Cow<'_, Expr>> {
    match unwrapped(value) {
        Expr::Subquery(query) => query_members(query),
        value => (!references_column(value)).then_some(Cow::Borrowed(value)),
    }
}

/// The expression yielding the rows of `query`, when the query projects it
/// alone or selects every column of one call, and filters and limits
/// nothing.
fn query_members(query: &Query) -> Option<Cow<'_, Expr>> {
    match sole_item(query) {
        Some(value) => value_members(value),
        None => sole_call(query).map(Cow::Owned),
    }
}

/// The `SELECT` of `query`, when it filters, limits and draws on nothing
/// and keeps every distinct row, so it yields every row its `FROM` list
/// does.
fn unfiltered(query: &Query) -> Option<&Select> {
    if let SetExpr::Select(select) = query.body.as_ref()
        && query.with.is_none()
        && query.limit_clause.is_none()
        && query.fetch.is_none()
        && query.pipe_operators.is_empty()
        && !matches!(select.distinct, Some(Distinct::On(_)))
        && select.top.is_none()
        && select.prewhere.is_none()
        && select.selection.is_none()
        && select.connect_by.is_empty()
        && select.having.is_none()
        && select.qualify.is_none()
    {
        Some(select)
    } else {
        None
    }
}

/// The one expression `query` projects, when it reads, filters and limits
/// nothing, so it yields that value in one row.
fn sole_item(query: &Query) -> Option<&Expr> {
    let select = unfiltered(query)?;
    if let [SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. }] =
        select.projection.as_slice()
        && select.from.is_empty()
    {
        Some(value)
    } else {
        None
    }
}

/// The call `query` selects every column of, written as an expression, when
/// the query reads that call alone, without ordinality, and filters and
/// limits nothing, so it yields every row of the call.
fn sole_call(query: &Query) -> Option<Expr> {
    let select = unfiltered(query)?;
    let ([SelectItem::Wildcard(options)], [from]) =
        (select.projection.as_slice(), select.from.as_slice())
    else {
        return None;
    };
    if *options != WildcardAdditionalOptions::default() || !from.joins.is_empty() {
        return None;
    }
    let (name, args) = match &from.relation {
        TableFactor::Table {
            name,
            args: Some(args),
            with_ordinality: false,
            sample: None,
            ..
        } if args.settings.is_none() => (name, &args.args),
        TableFactor::Function {
            name,
            args,
            with_ordinality: false,
            ..
        } => (name, args),
        _ => return None,
    };
    Some(Expr::Function(Function {
        name: name.clone(),
        uses_odbc_syntax: false,
        parameters: FunctionArguments::None,
        args: FunctionArguments::List(FunctionArgumentList {
            duplicate_treatment: None,
            args: args.clone(),
            clauses: Vec::new(),
        }),
        filter: None,
        null_treatment: None,
        over: None,
        within_group: Vec::new(),
    }))
}

/// The expression yielding the elements of `array` as the operand of
/// `= ANY`, when it reads no column.
fn array_members(array: &Expr) -> Option<Cow<'_, Expr>> {
    let array = unwrapped(array);
    if let Expr::Function(function) = array
        && function.name.to_string().eq_ignore_ascii_case("array")
        && let FunctionArguments::Subquery(query) = &function.args
    {
        return query_members(query);
    }
    (!references_column(array)).then_some(Cow::Borrowed(array))
}

/// The row `condition` tests against a set with `=`, `= ANY` or `IN`, one
/// column or a row value of columns and values reading none, and the
/// expression yielding the members of the set. Column types keep one
/// expression from yielding a value in one spelling and an array in another.
pub(crate) fn membership(condition: &Expr) -> Option<(&[Expr], Cow<'_, Expr>)> {
    match unwrapped(condition) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => [(left, right), (right, left)]
            .into_iter()
            .find_map(|(column, value)| {
                if is_column(column) {
                    Some((slice::from_ref(column.as_ref()), value_members(value)?))
                } else {
                    None
                }
            }),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } if is_column(left) => Some((slice::from_ref(left.as_ref()), array_members(right)?)),
        Expr::In {
            expr,
            target: InTarget::Subquery(query),
            negated: false,
            ..
        } => {
            let row = match unwrapped(expr) {
                Expr::Tuple(values)
                    if values
                        .iter()
                        .all(|value| is_column(value) || !references_column(value)) =>
                {
                    values.as_slice()
                }
                _ if is_column(expr) => slice::from_ref(expr.as_ref()),
                _ => return None,
            };
            Some((row, query_members(query)?))
        }
        _ => None,
    }
}
