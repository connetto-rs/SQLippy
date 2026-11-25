//! Whether a filter implies the conditions of row-level-security policies,
//! compared as written once the columns each tests go by one name.

use std::{borrow::Cow, convert::Infallible, iter, mem, ops::ControlFlow, ptr, slice};

use sql_traits::{
    errors::LookupError, structs::RowGate, traits::DatabaseLike,
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{
    AccessExpr, BinaryOperator, Distinct, Expr, Function, FunctionArg, FunctionArgExpr,
    FunctionArgumentList, FunctionArguments, GroupByExpr, Ident, InTarget, ObjectName, Query,
    Select, SelectItem, SetExpr, TableAlias, TableFactor, Value, Visit, VisitMut, Visitor,
    VisitorMut, WildcardAdditionalOptions, visit_expressions, visit_expressions_mut,
};

use crate::rules::{
    closed_set_support::stored_name,
    literal_support::literal,
    policy_support::{
        conjuncts, disjuncts, is_column_reference, is_tautology, unnested, unwrapped,
    },
    walk_support::walk,
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

    /// Whether every value the set expression `narrower` yields is one
    /// `wider` yields.
    ///
    /// # Errors
    ///
    /// Returns the lookup error reading what either expression yields raised.
    fn is_set_within(&self, narrower: &Expr, wider: &Expr) -> Result<bool, LookupError>;

    /// The name the filter gives the condition column stored as `column`.
    fn rename(&self, column: Cow<'_, str>) -> Option<String>;

    /// The condition columns `column` names, when it names one the filter can
    /// test.
    fn tested(&self, column: &Expr) -> Option<Self::Tested>;

    /// Whether the filter column `column` is one of `tested`.
    fn tests(&self, column: &Expr, tested: &Self::Tested) -> bool;

    /// The stored table `name` names in a subquery of a condition, `None`
    /// for any other relation, whose columns are unknown.
    fn relation(&self, _name: &ObjectName) -> Option<StoredRelation> {
        None
    }

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
            renamed: renamed(
                condition,
                |column| {
                    stored_name(column)
                        .and_then(|name| columns.rename(name))
                        .map(Term::Column)
                },
                |name| columns.relation(name),
            ),
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
        && renamed(
            clause,
            |column| stored_name(column).map(|name| Term::Column(name.into_owned())),
            |name| columns.relation(name),
        )
        .as_ref()
            == Some(stated)
    {
        return Ok(true);
    }
    if let Some((operands, wider)) = &condition.membership
        && let Some((row, members)) = membership(clause)
        && row.len() == operands.len()
        && row_meets(columns, row, operands, context)
        && is_within(columns, &members, wider)?
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

/// Whether `expression` mentions a column or reads an input parameter as
/// `$n`, either of which may hold another value where it is read again.
pub(crate) fn reads_column_or_parameter(expression: &Expr) -> bool {
    visit_expressions(expression, |expression| {
        if is_column(expression) || parameter_ordinal(expression).is_some() {
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
pub(crate) fn parameter_ordinal(expression: &Expr) -> Option<usize> {
    let Expr::Value(value) = expression else {
        return None;
    };
    let Value::Placeholder(placeholder) = &value.value else {
        return None;
    };
    let digits = placeholder.strip_prefix('$')?;
    digits.parse::<usize>().ok()?.checked_sub(1)
}

/// A stored table a subquery of a condition reads, as [`renamed`] names it.
pub(crate) struct StoredRelation {
    /// The schema-qualified name the table resolves to.
    pub(crate) name: ObjectName,
    /// The stored names of the table's columns.
    pub(crate) columns: Vec<String>,
}

/// `expression` with every column reference of the row it tests named,
/// quoted, by the column `rename` resolves it to, every parameter reference
/// written as `$n`, and every scalar subquery that reads no relation, such
/// as `(SELECT auth.uid())`, replaced by the value it projects. A subquery
/// reading stored tables, which `relation` resolves, reads each under its
/// resolved name and the alias `"depth.position"`, names their columns
/// through that alias and the columns of the tested row through `"0"`, so
/// that two spellings of one subquery rename alike and renaming the result
/// again yields it unchanged. `rename` is called on the references resolving
/// to no relation of a subquery. `None` when `rename` resolves a reference
/// to nothing, a reference is ambiguous, or a reference other than a
/// parameter is read inside a subquery that reads anything but stored
/// tables or may name its output where a column is expected.
pub(crate) fn renamed(
    expression: &Expr,
    rename: impl Fn(&Expr) -> Option<Term>,
    relation: impl Fn(&ObjectName) -> Option<StoredRelation>,
) -> Option<Expr> {
    let mut resolver = Resolver {
        rename,
        relation,
        scopes: Vec::new(),
        inlining: None,
        resolved: Vec::new(),
        relations: Vec::new(),
    };
    if walk(expression, &mut resolver).is_break() {
        return None;
    }
    let mut renamed = expression.clone();
    let ControlFlow::Continue(()) = VisitMut::visit(
        &mut renamed,
        &mut Renamer {
            resolved: resolver.resolved.into_iter(),
            relations: resolver.relations.into_iter(),
        },
    );
    Some(renamed)
}

/// A query around a node of a renamed condition.
struct Scope {
    /// The stored tables the query reads, each under the name its references
    /// qualify it by, or `None` when a column read inside does not resolve.
    bound: Option<Vec<Bound>>,
    /// How many of `bound` the walk has met.
    met: usize,
    /// Whether the query is a scalar subquery reading nothing, which renames
    /// to the value it projects.
    inlined: bool,
}

/// A stored table a subquery reads.
struct Bound {
    /// The alias, or the table's own name without its schema, normalized.
    name: String,
    relation: StoredRelation,
    /// The alias the renamed subquery reads the table under.
    alias: Ident,
}

/// The stored tables `query`, nested `depth` queries deep, reads in its
/// `FROM` list, when it reads nothing else, has no `WITH`, and names no
/// output column where PostgreSQL also looks for a column, as `ORDER BY`,
/// `GROUP BY` and `DISTINCT ON` do.
fn bound(
    query: &Query,
    depth: usize,
    relation: impl Fn(&ObjectName) -> Option<StoredRelation>,
) -> Option<Vec<Bound>> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    if query.with.is_some()
        || query.order_by.is_some()
        || !query.pipe_operators.is_empty()
        || matches!(select.distinct, Some(Distinct::On(_)))
        || !matches!(&select.group_by, GroupByExpr::Expressions(grouped, _) if grouped.is_empty())
        || !select.lateral_views.is_empty()
        || select
            .projection
            .iter()
            .any(|item| matches!(item, SelectItem::QualifiedWildcard(..)))
    {
        return None;
    }
    let mut bound = Vec::new();
    for from in &select.from {
        for factor in iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
        {
            let TableFactor::Table {
                name,
                alias,
                args: None,
                with_hints,
                version: None,
                with_ordinality: false,
                partitions,
                json_path: None,
                sample: None,
                index_directives,
                ..
            } = factor
            else {
                return None;
            };
            if !with_hints.is_empty()
                || !partitions.is_empty()
                || !index_directives.is_empty()
                || alias
                    .as_ref()
                    .is_some_and(|alias| !alias.columns.is_empty())
            {
                return None;
            }
            let named = match alias {
                Some(alias) => &alias.name,
                None => name.0.last()?.as_ident()?,
            };
            bound.push(Bound {
                name: normalize_identifier(&named.value, named.quote_style.is_some()).into_owned(),
                relation: relation(name)?,
                alias: Ident::with_quote('"', format!("{depth}.{}", bound.len())),
            });
        }
    }
    Some(bound)
}

/// Resolves each reference and each relation of a subquery, in the order
/// [`Renamer`] meets them.
struct Resolver<F, R> {
    rename: F,
    relation: R,
    /// The queries around the walked node, innermost last.
    scopes: Vec<Scope>,
    /// The scalar subquery about to be walked, when it reads nothing and
    /// renames to the value it projects.
    inlining: Option<*const Query>,
    resolved: Vec<Expr>,
    /// The name and alias each table factor renames to, `None` for one left
    /// as written.
    relations: Vec<Option<(ObjectName, Ident)>>,
}

impl<F: Fn(&Expr) -> Option<Term>, R: Fn(&ObjectName) -> Option<StoredRelation>> Resolver<F, R> {
    /// `reference`, written as `parts`, as the renamed condition writes it,
    /// resolved first against the tables of the innermost query and last
    /// against the tested row.
    fn resolve(&self, reference: &Expr, parts: &[Ident]) -> Option<Expr> {
        if self.scopes.is_empty() {
            return self.outer(reference);
        }
        let normalized = |name: &Ident| {
            normalize_identifier(&name.value, name.quote_style.is_some()).into_owned()
        };
        let (qualifier, column) = match parts {
            [column] => (None, normalized(column)),
            [qualifier, column] => (Some(normalized(qualifier)), normalized(column)),
            _ => return None,
        };
        for scope in self.scopes.iter().rev() {
            let Some(bound) = &scope.bound else {
                return match (self.rename)(reference)? {
                    Term::Parameter(ordinal) => Some(parameter(ordinal)),
                    Term::Column(_) => None,
                };
            };
            let mut found = bound.iter().filter(|bound| match &qualifier {
                Some(qualifier) => bound.name == *qualifier,
                None => bound.relation.columns.contains(&column),
            });
            if let Some(bound) = found.next() {
                return (found.next().is_none() && bound.relation.columns.contains(&column)).then(
                    || {
                        Expr::CompoundIdentifier(vec![
                            bound.alias.clone(),
                            Ident::with_quote('"', column),
                        ])
                    },
                );
            }
        }
        self.outer(reference)
    }

    /// How many queries around the walked node remain once the scalar
    /// subqueries are inlined.
    fn depth(&self) -> usize {
        self.scopes.iter().filter(|scope| !scope.inlined).count()
    }

    /// `reference`, resolving to no relation of a subquery, as `rename`
    /// resolves it, qualified by `"0"` inside a subquery.
    fn outer(&self, reference: &Expr) -> Option<Expr> {
        Some(match (self.rename)(reference)? {
            Term::Column(name) if self.depth() == 0 => {
                Expr::Identifier(Ident::with_quote('"', name))
            }
            Term::Column(name) => Expr::CompoundIdentifier(vec![
                Ident::with_quote('"', "0"),
                Ident::with_quote('"', name),
            ]),
            Term::Parameter(ordinal) => parameter(ordinal),
        })
    }
}

impl<F: Fn(&Expr) -> Option<Term>, R: Fn(&ObjectName) -> Option<StoredRelation>> Visitor
    for Resolver<F, R>
{
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if let Expr::Subquery(query) = expression
            && sole_item(query).is_some()
        {
            self.inlining = Some(ptr::from_ref(query.as_ref()));
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        let inlined = self
            .inlining
            .is_some_and(|inlining| ptr::eq(inlining, query));
        let depth = self.depth() + usize::from(!inlined);
        let bound = bound(query, depth, &self.relation);
        self.scopes.push(Scope {
            bound,
            met: 0,
            inlined,
        });
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
        self.scopes.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, _factor: &TableFactor) -> ControlFlow<()> {
        let renamed = self.scopes.last_mut().and_then(|scope| {
            let bound = scope.bound.as_ref()?.get(scope.met)?;
            scope.met += 1;
            Some((bound.relation.name.clone(), bound.alias.clone()))
        });
        self.relations.push(renamed);
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        let parts = match expression {
            Expr::Identifier(column) => slice::from_ref(column),
            Expr::CompoundIdentifier(parts) => parts.as_slice(),
            _ => return ControlFlow::Continue(()),
        };
        let Some(resolved) = self.resolve(expression, parts) else {
            return ControlFlow::Break(());
        };
        self.resolved.push(resolved);
        ControlFlow::Continue(())
    }
}

/// Writes the resolved references and relations and inlines the scalar
/// subqueries.
struct Renamer<I, T> {
    resolved: I,
    relations: T,
}

impl<I: Iterator<Item = Expr>, T: Iterator<Item = Option<(ObjectName, Ident)>>> VisitorMut
    for Renamer<I, T>
{
    type Break = Infallible;

    fn pre_visit_table_factor(&mut self, factor: &mut TableFactor) -> ControlFlow<Infallible> {
        if let Some(Some((stored, renamed))) = self.relations.next()
            && let TableFactor::Table { name, alias, .. } = factor
        {
            *name = stored;
            *alias = Some(TableAlias {
                explicit: true,
                name: renamed,
                columns: Vec::new(),
                at: None,
            });
        }
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<Infallible> {
        if let Expr::Subquery(query) = expression
            && sole_item(query).is_some()
            && let SetExpr::Select(select) = query.body.as_mut()
            && let [SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. }] =
                select.projection.as_mut_slice()
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

/// Whether `row`, tested against a set by a clause, holds the values each
/// of `operands` asks of a condition's row, a column matching a column the
/// condition tests, a value matching it as written, and a column `context`
/// fixes to a literal matching that literal either way.
fn row_meets<C: Columns>(
    columns: &C,
    row: &[Expr],
    operands: &[Operand<'_, C::Tested>],
    context: &[&Expr],
) -> bool {
    row.iter()
        .zip(operands)
        .all(|(value, operand)| match operand {
            Operand::Tested(tested) => {
                if is_column(value) {
                    columns.tests(value, tested)
                } else {
                    literal(value).is_some_and(|fixed| {
                        pinned(context, |column| columns.tests(column, tested), fixed)
                    })
                }
            }
            Operand::Value(stated) => {
                value == *stated
                    || is_column(value)
                        && columns.tested(value).is_some_and(|tested| {
                            literal(stated).is_some_and(|fixed| {
                                pinned(context, |column| columns.tests(column, &tested), fixed)
                            })
                        })
            }
        })
}

/// Whether a conjunct of `context` fixes a column `tested` accepts to the
/// literal `fixed` with `=`, written on either side.
fn pinned(context: &[&Expr], tested: impl Fn(&Expr) -> bool, fixed: &Value) -> bool {
    context.iter().any(|conjunct| {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = unnested(conjunct)
        else {
            return false;
        };
        [(left, right), (right, left)]
            .into_iter()
            .any(|(column, value)| {
                is_column(column) && tested(column) && literal(value) == Some(fixed)
            })
    })
}

/// Whether every value `narrower` yields is one `wider` yields, whatever
/// value each input parameter it reads holds. A parameter of an enum type
/// takes each label in turn, and a `NULL` one passes only to a call returning
/// `NULL` on `NULL` input, which yields no value. A parameter of any other
/// type proves nothing.
fn is_within<C: Columns>(columns: &C, narrower: &Expr, wider: &Expr) -> Result<bool, LookupError> {
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
        return columns.is_set_within(narrower, wider);
    }
    let Some(values) = ordinals
        .iter()
        .map(|&ordinal| columns.parameter_values(ordinal))
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(false);
    };
    if ordinals
        .iter()
        .zip(&values)
        .any(|(&ordinal, values)| values.null && !nothing_on_null(columns, narrower, ordinal))
    {
        return Ok(false);
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
        if !columns.is_set_within(&expanded, wider)? {
            return Ok(false);
        }
        let Some(position) = (0..choice.len())
            .find(|&position| choice[position] + 1 < values[position].labels.len())
        else {
            return Ok(true);
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
/// alone, selects every column of one call or one column of one call, and
/// filters and limits nothing.
pub(crate) fn query_members(query: &Query) -> Option<Cow<'_, Expr>> {
    match sole_item(query) {
        Some(value) => value_members(value),
        None => sole_call(query)
            .or_else(|| sole_column(query))
            .map(Cow::Owned),
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
    let [SelectItem::Wildcard(options)] = select.projection.as_slice() else {
        return None;
    };
    if *options != WildcardAdditionalOptions::default() {
        return None;
    }
    sole_relation_call(select).map(|(call, _)| call)
}

/// The column of one call `query` projects, written `(call).column`, when
/// the query reads that call alone under an alias renaming no column, names
/// the column through the alias, and filters and limits nothing, so it
/// yields every value of the column. The call reads no column or parameter,
/// which could stand for another row's value.
fn sole_column(query: &Query) -> Option<Expr> {
    let select = unfiltered(query)?;
    let [
        SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts))
        | SelectItem::ExprWithAlias {
            expr: Expr::CompoundIdentifier(parts),
            ..
        },
    ] = select.projection.as_slice()
    else {
        return None;
    };
    let [relation, column] = parts.as_slice() else {
        return None;
    };
    let (call, Some(alias)) = sole_relation_call(select)? else {
        return None;
    };
    if !alias.columns.is_empty()
        || normalize_identifier(&alias.name.value, alias.name.quote_style.is_some())
            != normalize_identifier(&relation.value, relation.quote_style.is_some())
        || reads_column_or_parameter(&call)
    {
        return None;
    }
    Some(column_of(
        call,
        &normalize_identifier(&column.value, column.quote_style.is_some()),
    ))
}

/// The values the column stored as `column` takes among the rows `call`
/// yields, written `(call).column`, the column quoted unless its stored name
/// is folded.
pub(crate) fn column_of(call: Expr, column: &str) -> Expr {
    let field = if normalize_identifier(column, false) == column {
        Ident::new(column)
    } else {
        Ident::with_quote('"', column)
    };
    Expr::CompoundFieldAccess {
        root: Box::new(Expr::Nested(Box::new(call))),
        access_chain: vec![AccessExpr::Dot(Expr::Identifier(field))],
    }
}

/// The call `select` reads alone, without ordinality, written as an
/// expression, with the alias it reads the call under.
fn sole_relation_call(select: &Select) -> Option<(Expr, Option<&TableAlias>)> {
    let [from] = select.from.as_slice() else {
        return None;
    };
    if !from.joins.is_empty() {
        return None;
    }
    let (name, args, alias) = match &from.relation {
        TableFactor::Table {
            name,
            args: Some(args),
            with_ordinality: false,
            sample: None,
            alias,
            ..
        } if args.settings.is_none() => (name, &args.args, alias),
        TableFactor::Function {
            name,
            args,
            with_ordinality: false,
            alias,
            ..
        } => (name, args, alias),
        _ => return None,
    };
    let call = Expr::Function(Function {
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
    });
    Some((call, alias.as_ref()))
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
