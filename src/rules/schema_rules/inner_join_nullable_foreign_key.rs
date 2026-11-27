//! Submodule providing the `InnerJoinNullableForeignKey` rule.

use std::{cell::Cell, collections::BTreeSet, ops::ControlFlow, ptr, rc::Rc};

use sql_traits::{
    errors::LookupError,
    structs::{
        ColumnDefinition, ColumnScope, ExpressionContext, IdentifierCase, QueryOutput,
        RangeTableEntry, TargetName,
    },
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike, ViewLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, JoinConstraint, JoinOperator, ObjectNamePart, Query, Select, SetExpr,
    Statement, TableFactor, TableWithJoins, Visit, Visitor,
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::{WithScopes, output_expression},
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        implication_support::{Term, renamed},
        key_support::key_pairs,
        not_in_support::{extends_left, factors, null_extended},
        null_support::{may_hold_null, may_hold_null_where, rejects_null},
        policy_support::{conjuncts, disjuncts, is_column_reference, unnested},
        statement_support::{OwnLevel, root_query},
        trigger_support::stored,
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Struct defining a rule that reports an inner join over a foreign key
/// whose referencing column can be `NULL` where the join reads it.
///
/// A row whose reference is `NULL` matches no parent row, so the inner join
/// drops it, and a caller expecting every child silently loses the children
/// without a parent. The rule reads views, materialized views, policies, SQL
/// and PL/pgSQL function bodies and, as a query rule, statements.
///
/// A join is read when `JOIN`, `INNER JOIN` or `JOIN LATERAL` equates
/// referencing columns with the columns they reference through `ON`, `USING`
/// or `NATURAL`, or when a `WHERE` equality does so across comma-separated
/// `FROM` items or a `CROSS JOIN`. Only the referencing columns the join
/// equates are judged. A column is nullable unless it is declared `NOT NULL`,
/// a validated check holds it `IS NOT NULL`, or a validated `MATCH FULL` key
/// with a `NOT NULL` column forces it. A column read through a derived table,
/// a `WITH` item or a view is followed to the column it projects, and an
/// outer join on the way makes it nullable.
///
/// The join is accepted when a conjunct that a `LEFT JOIN` rewrite could not
/// escape rejects the `NULL`, since a `LEFT JOIN` would then return the same
/// rows. Those conjuncts are the `WHERE` conjuncts and the `ON` conjuncts of
/// the other inner joins of the same `SELECT`, rejecting `NULL` in the
/// referencing column or in any column of the parent, and the `WHERE` of the
/// derived table, `WITH` item or view the column comes through. An `OR`
/// rejects the `NULL` when every branch does. Those conjuncts reading only
/// the stored table holding the referencing column also reject the `NULL`
/// when, with the table's column declarations and validated checks, they
/// rule it out, as `kind = 'folder'` does under `CHECK ((kind =
/// 'organization') = (parent_id IS NULL))`. The link between the target of
/// an `UPDATE` or `DELETE` and its `FROM` or `USING` items is not reported,
/// since those statements have no outer variant.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = InnerJoinNullableForeignKey::default().into();
/// let schema = "CREATE TABLE d (id INT PRIMARY KEY); CREATE TABLE e (d_id INT REFERENCES d (id));";
/// let inner = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS SELECT d.id FROM e JOIN d ON e.d_id = d.id;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&inner).is_err());
/// let left = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW v AS SELECT d.id FROM e LEFT JOIN d ON e.d_id = d.id;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&left).is_ok());
/// ```
pub struct InnerJoinNullableForeignKey<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for InnerJoinNullableForeignKey<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<InnerJoinNullableForeignKey<DB>> for GenericConstrainer<DB> {
    fn from(rule: InnerJoinNullableForeignKey<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(InnerJoinNullableForeignKey::default()));
        constrainer
    }
}

impl<DB> Rule for InnerJoinNullableForeignKey<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(InnerJoinNullableForeignKey),
            group: LintGroup::Pedantic,
            rationale: "A row whose foreign key is NULL has no parent to match, so an inner join over that key silently drops it.",
            source: Some("https://search.worldcat.org/isbn/9780133970777"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE departments (id BIGINT PRIMARY KEY);\n\
CREATE TABLE employees (id BIGINT PRIMARY KEY, department_id BIGINT REFERENCES departments (id));\n\
CREATE VIEW employee_departments AS SELECT employees.id AS employee_id, departments.id AS department_id FROM employees INNER JOIN departments ON employees.department_id = departments.id;",
                good: "CREATE TABLE departments (id BIGINT PRIMARY KEY);\n\
CREATE TABLE employees (id BIGINT PRIMARY KEY, department_id BIGINT REFERENCES departments (id));\n\
CREATE VIEW employee_departments AS SELECT employees.id AS employee_id, departments.id AS department_id FROM employees LEFT JOIN departments ON employees.department_id = departments.id;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for InnerJoinNullableForeignKey<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&InnerJoins, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for InnerJoinNullableForeignKey<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&InnerJoins, database, statement, reporter)
    }
}

/// Finds the inner joins over a nullable foreign key.
struct InnerJoins;

impl ExpressionFinder for InnerJoins {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let mut roots = Roots {
            database,
            views: Vec::new(),
            found: Vec::new(),
            depth: 0,
            opened: Vec::new(),
        };
        walk(node, &mut roots).break_value().map_or(Ok(()), Err)?;
        Ok(roots.found)
    }

    fn problem(&self) -> &'static str {
        "which drops every row whose reference is NULL"
    }

    fn resolution(&self) -> &'static str {
        "Use a LEFT JOIN to keep the rows without a parent, or filter the reference with IS NOT NULL when only rows with a parent are meant."
    }
}

/// One column of one `FROM` item, compared by the item's address.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Entry {
    factor: *const TableFactor,
    ordinal: usize,
}

impl Entry {
    fn of(entry: RangeTableEntry<'_>) -> Self {
        Self {
            factor: ptr::from_ref(entry.factor()),
            ordinal: entry.ordinal(),
        }
    }
}

/// What a `FROM` item reads.
enum Reads<'db, DB: DatabaseLike> {
    Table(&'db DB::Table),
    /// A plain or materialized view, by its stored definition.
    View(&'db Query),
    /// A derived table or a `WITH` item, by the address of its query.
    Query(*const Query),
    Other,
}

/// A conjunct that a `LEFT JOIN` rewrite of a join of its `SELECT` cannot
/// escape, with the columns and `FROM` items whose `NULL` keeps it from
/// being true.
struct Conjunct {
    node: *const Expr,
    entries: Vec<Entry>,
    factors: Vec<*const TableFactor>,
    /// The columns paired with another `FROM` item such that the column
    /// being `NULL` and the item being null-extended together keep the
    /// conjunct from being true.
    pairs: Vec<(Entry, *const TableFactor)>,
    /// The stored table the conjunct reads alone, with the conjunct naming
    /// its columns as [`may_hold_null_where`] reads them.
    local: Option<(*const TableFactor, Expr)>,
}

/// What the rule needs of one `SELECT`.
struct Block<'db, DB: DatabaseLike> {
    items: Vec<(*const TableFactor, Reads<'db, DB>)>,
    extended: Vec<*const TableFactor>,
    conjuncts: Vec<Conjunct>,
}

impl<DB: DatabaseLike> Block<'_, DB> {
    /// Whether a conjunct outside `skip` satisfies `rejected`.
    fn rejects(&self, skip: &[*const Expr], rejected: impl Fn(&Conjunct) -> bool) -> bool {
        self.conjuncts
            .iter()
            .any(|conjunct| !skip.contains(&conjunct.node) && rejected(conjunct))
    }
}

/// What the rule needs of one query and every query it holds, kept by
/// address so that it outlives the walk collecting it.
struct Facts<'db, DB: DatabaseLike> {
    blocks: Vec<Block<'db, DB>>,
    /// The column each output of a query projects, by output position, up to
    /// the first output that projects none.
    outputs: Vec<(*const Query, Vec<Option<Entry>>)>,
}

impl<'db, DB: DatabaseLike> Facts<'db, DB> {
    /// The facts of `root`, whose nodes `types` resolves.
    fn of(
        database: &'db DB,
        types: &ExpressionContext<'_, 'db, DB>,
        root: &Query,
    ) -> Result<Self, LookupError> {
        let scope = ColumnScope::from_query(root, database, IdentifierCase::Folded)?;
        let mut collect = Collect {
            database,
            types,
            scope: &scope,
            scopes: WithScopes::default(),
            bodies: Vec::new(),
            facts: Self {
                blocks: Vec::new(),
                outputs: Vec::new(),
            },
        };
        walk(root, &mut collect).break_value().map_or(Ok(()), Err)?;
        Ok(collect.facts)
    }

    /// The `SELECT` whose `FROM` holds `factor`.
    fn block(&self, factor: *const TableFactor) -> Option<&Block<'db, DB>> {
        self.blocks
            .iter()
            .find(|block| block.items.iter().any(|(item, _)| *item == factor))
    }

    /// The `SELECT` whose `FROM` holds `factor`, a `FROM` item of the query
    /// these facts describe.
    fn holding(&self, factor: *const TableFactor) -> &Block<'db, DB> {
        self.block(factor)
            .expect("every FROM item of a query belongs to one of its SELECTs")
    }

    /// The column the output at `ordinal` of `query` projects.
    fn output(&self, query: *const Query, ordinal: usize) -> Option<Entry> {
        self.outputs
            .iter()
            .find(|(held, _)| *held == query)
            .and_then(|(_, outputs)| outputs.get(ordinal).copied().flatten())
    }
}

/// Collects the facts of a query.
struct Collect<'c, 'q, 'db, DB: DatabaseLike> {
    database: &'db DB,
    types: &'c ExpressionContext<'q, 'db, DB>,
    scope: &'c ColumnScope<'q, 'db, DB>,
    scopes: WithScopes,
    /// The bodies of the `WITH` items of each query holding a `WITH`.
    bodies: Vec<(*const Query, Vec<*const Query>)>,
    facts: Facts<'db, DB>,
}

impl<'db, DB: DatabaseLike> Collect<'_, '_, 'db, DB> {
    /// The column each output of `query` projects.
    fn outputs(&self, query: &Query) -> Result<Vec<Option<Entry>>, LookupError> {
        let (Some(scope), SetExpr::Select(select)) =
            (self.scope.scope_for_query(query), query.body.as_ref())
        else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for output in scope.outputs() {
            let QueryOutput::Column { item, wildcard, .. } = output else {
                break;
            };
            found.push(match wildcard {
                Some(binding) => binding.entry().map(Entry::of),
                None => select
                    .projection
                    .get(item)
                    .and_then(output_expression)
                    .map_or(Ok(None), |expression| self.entry(expression))?,
            });
        }
        Ok(found)
    }

    /// The column the column reference `expression` reads.
    fn entry(&self, expression: &Expr) -> Result<Option<Entry>, LookupError> {
        if !is_column_reference(expression) {
            return Ok(None);
        }
        Ok(self
            .types
            .reference(expression)?
            .and_then(|(_, binding)| binding.entry())
            .map(Entry::of))
    }

    /// What `factor` reads, as the `WITH` items visible where it stands
    /// bind its name.
    fn reads(&self, factor: &TableFactor) -> Reads<'db, DB> {
        match factor {
            TableFactor::Derived { subquery, .. } => Reads::Query(ptr::from_ref(subquery.as_ref())),
            TableFactor::Table {
                name, args: None, ..
            } => {
                if let Some(binding) = self.scopes.binding(name) {
                    return self
                        .bodies
                        .iter()
                        .find(|(owner, _)| *owner == binding.owner)
                        .and_then(|(_, bodies)| bodies.get(binding.item))
                        .map_or(Reads::Other, |body| Reads::Query(*body));
                }
                let rendered = name.to_string();
                let database = self.database;
                TargetName::parse(&rendered)
                    .ok()
                    .map_or(Reads::Other, |target| {
                        database
                            .resolve_target_table(target.clone(), IdentifierCase::Folded)
                            .ok()
                            .flatten()
                            .map(Reads::Table)
                            .or_else(|| {
                                database
                                    .resolve_target_view(target.clone(), IdentifierCase::Folded)
                                    .ok()
                                    .flatten()
                                    .map(|view| Reads::View(view.definition()))
                            })
                            .or_else(|| {
                                database
                                    .resolve_target_materialized_view(
                                        target,
                                        IdentifierCase::Folded,
                                    )
                                    .ok()
                                    .flatten()
                                    .map(|view| Reads::View(view.definition()))
                            })
                            .unwrap_or(Reads::Other)
                    })
            }
            _ => Reads::Other,
        }
    }

    /// The facts of `select`.
    fn block(&self, select: &Select) -> Result<Block<'db, DB>, LookupError> {
        let leaves: Vec<&TableFactor> = select.from.iter().flat_map(factors).collect();
        let extended = leaves
            .iter()
            .filter(|factor| {
                select
                    .from
                    .iter()
                    .any(|joined| null_extended(joined, factor, false))
            })
            .map(|factor| ptr::from_ref(*factor))
            .collect();
        let items: Vec<(*const TableFactor, Reads<'db, DB>)> = leaves
            .iter()
            .map(|factor| (ptr::from_ref(*factor), self.reads(factor)))
            .collect();
        let mut conditions: Vec<&Expr> = select.selection.iter().flat_map(conjuncts).collect();
        for joined in &select.from {
            surviving(joined, &mut conditions);
        }
        let mut found = Vec::with_capacity(conditions.len());
        for condition in conditions {
            found.push(self.conjunct(condition, &items)?);
        }
        Ok(Block {
            items,
            extended,
            conjuncts: found,
        })
    }

    /// The columns and `FROM` items whose `NULL` keeps `condition` from
    /// being true, among the `FROM` items `sources` of its `SELECT`.
    fn conjunct(
        &self,
        condition: &Expr,
        sources: &[(*const TableFactor, Reads<'db, DB>)],
    ) -> Result<Conjunct, LookupError> {
        let mut read: Vec<Entry> = Vec::new();
        OwnLevel::new(|expression: &Expr| {
            if let Some(entry) = self.entry(expression)?
                && !read.contains(&entry)
            {
                read.push(entry);
            }
            Ok(())
        })
        .over(condition)?;
        let mut items: Vec<*const TableFactor> = Vec::new();
        for entry in &read {
            if !items.contains(&entry.factor) {
                items.push(entry.factor);
            }
        }
        let mut entries = Vec::new();
        let mut factors = Vec::new();
        let mut pairs = Vec::new();
        for &entry in &read {
            let column = |expression: &Expr| Ok(self.entry(expression)? == Some(entry));
            if rejects(self.database, self.types, condition, &column)? {
                entries.push(entry);
            }
            let item = |expression: &Expr| {
                Ok(self
                    .entry(expression)?
                    .is_some_and(|found| found.factor == entry.factor))
            };
            if !factors.contains(&entry.factor)
                && rejects(self.database, self.types, condition, &item)?
            {
                factors.push(entry.factor);
            }
            for &factor in &items {
                let either = |expression: &Expr| {
                    Ok(self
                        .entry(expression)?
                        .is_some_and(|found| found == entry || found.factor == factor))
                };
                if factor != entry.factor && rejects(self.database, self.types, condition, &either)?
                {
                    pairs.push((entry, factor));
                }
            }
        }
        let local = match items.as_slice() {
            [factor] => self.local(condition, *factor, sources)?,
            _ => None,
        };
        Ok(Conjunct {
            node: ptr::from_ref(condition),
            entries,
            factors,
            pairs,
            local,
        })
    }

    /// `condition`, reading columns of `factor` alone, with each named by
    /// its stored name, when `factor` is a stored table among `sources` and
    /// every reference of the condition resolves to one of its columns.
    fn local(
        &self,
        condition: &Expr,
        factor: *const TableFactor,
        sources: &[(*const TableFactor, Reads<'db, DB>)],
    ) -> Result<Option<(*const TableFactor, Expr)>, LookupError> {
        let Some(table) = sources.iter().find_map(|(item, reads)| match reads {
            Reads::Table(table) if *item == factor => Some(*table),
            _ => None,
        }) else {
            return Ok(None);
        };
        let names: Vec<String> = table
            .columns(self.database)?
            .map(|column| column.stored_column_name().into_owned())
            .collect();
        let failure = Cell::new(None);
        let rename = |expression: &Expr| match self.entry(expression) {
            Ok(entry) => entry
                .filter(|entry| entry.factor == factor)
                .and_then(|entry| names.get(entry.ordinal).cloned())
                .map(Term::Column),
            Err(error) => {
                failure.set(Some(error));
                None
            }
        };
        let written = renamed(condition, rename, |_| None, |_| None);
        failure
            .into_inner()
            .map_or(Ok(written.map(|written| (factor, written))), Err)
    }
}

impl<DB: DatabaseLike> Visitor for Collect<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.scopes.enter(query);
        if let Some(with) = &query.with {
            self.bodies.push((
                ptr::from_ref(query),
                with.cte_tables
                    .iter()
                    .map(|item| ptr::from_ref(item.query.as_ref()))
                    .collect(),
            ));
        }
        let outputs = self.outputs(query);
        outputs
            .map(|outputs| self.facts.outputs.push((ptr::from_ref(query), outputs)))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.scopes.leave(query);
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<LookupError> {
        let block = self.block(select);
        block
            .map(|block| self.facts.blocks.push(block))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Whether `condition` cannot be true while a column `bound` accepts is
/// `NULL`, an `OR` only when every branch cannot.
fn rejects<DB: DatabaseLike>(
    database: &DB,
    types: &ExpressionContext<'_, '_, DB>,
    condition: &Expr,
    bound: &impl Fn(&Expr) -> Result<bool, LookupError>,
) -> Result<bool, LookupError> {
    let condition = unnested(condition);
    let branches = disjuncts(condition);
    if branches.len() > 1 {
        for branch in branches {
            if !rejects(database, types, branch, bound)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    let parts = conjuncts(condition);
    if parts.len() > 1 {
        for part in parts {
            if rejects(database, types, part, bound)? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    rejects_null(condition, bound, database, types)
}

/// Appends the `ON` conjuncts of the inner joins of `joined` that no later
/// `RIGHT` or `FULL` join undoes, inside parenthesized joins no outer join
/// null-extends.
fn surviving<'s>(joined: &'s TableWithJoins, found: &mut Vec<&'s Expr>) {
    if let TableFactor::NestedJoin {
        table_with_joins, ..
    } = &joined.relation
        && !null_extended(joined, &joined.relation, false)
    {
        surviving(table_with_joins, found);
    }
    for (position, join) in joined.joins.iter().enumerate() {
        let undone = joined.joins[position + 1..]
            .iter()
            .any(|later| extends_left(&later.join_operator));
        if !undone
            && let JoinOperator::Join(JoinConstraint::On(condition))
            | JoinOperator::Inner(JoinConstraint::On(condition)) = &join.join_operator
        {
            found.extend(conjuncts(condition));
        }
        if let TableFactor::NestedJoin {
            table_with_joins, ..
        } = &join.relation
            && !null_extended(joined, &join.relation, false)
        {
            surviving(table_with_joins, found);
        }
    }
}

/// The `FROM` items `factor` names, itself unless it is a parenthesized join.
fn leaves(factor: &TableFactor) -> Vec<&TableFactor> {
    match factor {
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => factors(table_with_joins),
        _ => vec![factor],
    }
}

/// The `FROM` items the parenthesized join `factor` null-extends.
fn within(factor: &TableFactor) -> Vec<*const TableFactor> {
    match factor {
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => factors(table_with_joins)
            .into_iter()
            .filter(|leaf| null_extended(table_with_joins, leaf, false))
            .map(ptr::from_ref)
            .collect(),
        _ => Vec::new(),
    }
}

/// How the judgment of a referencing column ends.
enum Judgment {
    NotNull,
    Nullable,
    /// The reference reads a stored column that may hold `NULL` on the rows
    /// it reads, unless the foreign key forces every referencing column.
    Stored,
    Unknown,
}

/// The longest chain of derived tables, `WITH` items and views a column is
/// followed through.
const FOLLOWED_RELATIONS: usize = 16;

/// Walks a node for the queries no other query holds, and checks the joins
/// of each.
struct Roots<'db, DB: DatabaseLike> {
    database: &'db DB,
    /// The facts of each view definition followed so far.
    views: Vec<(*const Query, Rc<Facts<'db, DB>>)>,
    found: Vec<(String, String)>,
    depth: usize,
    /// Whether each statement the walk stands in was checked as a whole.
    opened: Vec<bool>,
}

impl<'db, DB: DatabaseLike> Roots<'db, DB> {
    /// Checks the joins of `root`, whose first `FROM` item is the target of
    /// an `UPDATE` or `DELETE` when `target` holds.
    fn inspect(&mut self, root: &Query, target: bool) -> Result<(), LookupError> {
        let types = ExpressionContext::new(root, self.database, IdentifierCase::Folded)?;
        let facts = Facts::of(self.database, &types, root)?;
        let target = match root.body.as_ref() {
            SetExpr::Select(select) if target => select.from.first().map(ptr::from_ref),
            _ => None,
        };
        let mut joins = Joins {
            roots: self,
            types: &types,
            facts: &facts,
            target,
        };
        walk(root, &mut joins).break_value().map_or(Ok(()), Err)
    }

    /// The facts of `definition`, the stored definition of a view.
    fn view(&mut self, definition: &'db Query) -> Result<Rc<Facts<'db, DB>>, LookupError> {
        if let Some((_, facts)) = self
            .views
            .iter()
            .find(|(held, _)| ptr::eq(*held, definition))
        {
            return Ok(Rc::clone(facts));
        }
        let types = ExpressionContext::new(definition, self.database, IdentifierCase::Folded)?;
        let facts = Rc::new(Facts::of(self.database, &types, definition)?);
        self.views
            .push((ptr::from_ref(definition), Rc::clone(&facts)));
        Ok(facts)
    }

    /// Whether the column `entry` can be `NULL` where `facts` reads it,
    /// leaving out the conjuncts `skip` holds, following the relation it
    /// comes from through at most `remaining` more relations. The `FROM`
    /// items `site` holds are those null-extended where the column is read,
    /// every null-extended item of its `SELECT` when `None`.
    fn judge(
        &mut self,
        facts: &Facts<'db, DB>,
        entry: Entry,
        skip: &[*const Expr],
        site: Option<&[*const TableFactor]>,
        remaining: usize,
    ) -> Result<Judgment, LookupError> {
        let block = facts.holding(entry.factor);
        if block.rejects(skip, |conjunct| conjunct.entries.contains(&entry)) {
            return Ok(Judgment::NotNull);
        }
        if site.unwrap_or(&block.extended).contains(&entry.factor) {
            return Ok(Judgment::Nullable);
        }
        let Some(remaining) = remaining.checked_sub(1) else {
            return Ok(Judgment::Unknown);
        };
        let (_, reads) = block
            .items
            .iter()
            .find(|(item, _)| *item == entry.factor)
            .expect("the SELECT holding a FROM item lists what the item reads");
        let (inner, column) = match reads {
            Reads::Table(table) => {
                let table: &'db DB::Table = table;
                let Some(column) = table.columns(self.database)?.nth(entry.ordinal) else {
                    return Ok(Judgment::Unknown);
                };
                let filters: Vec<&Expr> = block
                    .conjuncts
                    .iter()
                    .filter(|conjunct| !skip.contains(&conjunct.node))
                    .filter_map(|conjunct| match &conjunct.local {
                        Some((factor, written)) if *factor == entry.factor => Some(written),
                        _ => None,
                    })
                    .collect();
                return Ok(if may_hold_null_where(self.database, column, &filters)? {
                    Judgment::Stored
                } else {
                    Judgment::NotNull
                });
            }
            Reads::Query(query) => (None, facts.output(*query, entry.ordinal)),
            Reads::View(definition) => {
                let definition: &'db Query = definition;
                let inner = self.view(definition)?;
                let column = inner.output(ptr::from_ref(definition), entry.ordinal);
                (Some(inner), column)
            }
            Reads::Other => (None, None),
        };
        column.map_or(Ok(Judgment::Unknown), |column| {
            self.judge(
                inner.as_deref().unwrap_or(facts),
                column,
                &[],
                None,
                remaining,
            )
        })
    }
}

/// Whether `statement` writes the first `FROM` item of its
/// [`root_query`].
fn targets_first_item(statement: &Statement) -> bool {
    match statement {
        Statement::Update(_) | Statement::Delete(_) => true,
        Statement::Query(query) => matches!(
            query.body.as_ref(),
            SetExpr::Update(inner) | SetExpr::Delete(inner) if targets_first_item(inner)
        ),
        _ => false,
    }
}

impl<DB: DatabaseLike> Visitor for Roots<'_, DB> {
    type Break = LookupError;

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<LookupError> {
        let root = if self.depth == 0 {
            root_query(statement)
        } else {
            None
        };
        self.opened.push(root.is_some());
        let checked = root.map_or(Ok(()), |root| {
            self.depth += 1;
            self.inspect(&root, targets_first_item(statement))
        });
        checked.map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_statement(&mut self, _statement: &Statement) -> ControlFlow<LookupError> {
        if self.opened.pop() == Some(true) {
            self.depth -= 1;
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        let checked = if self.depth == 0 {
            self.inspect(query, false)
        } else {
            Ok(())
        };
        self.depth += 1;
        checked.map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }
}

/// One column an equality of a join reads, with the stored column its
/// definition reaches.
struct Side<'t, DB: DatabaseLike> {
    entry: Entry,
    table: &'t DB::Table,
    column: &'t DB::Column,
    text: String,
}

/// An equality between a column of the left side of a join and one of its
/// right side, with the conjunct that writes it unless a `USING` or
/// `NATURAL` join implies it.
struct Equality<'t, DB: DatabaseLike> {
    left: Side<'t, DB>,
    right: Side<'t, DB>,
    node: Option<*const Expr>,
    text: String,
}

/// Checks the joins of every `SELECT` of a query.
struct Joins<'r, 'c, 'q, 'db, DB: DatabaseLike> {
    roots: &'r mut Roots<'db, DB>,
    types: &'c ExpressionContext<'q, 'db, DB>,
    facts: &'c Facts<'db, DB>,
    /// The `FROM` item an `UPDATE` or `DELETE` writes.
    target: Option<*const TableWithJoins>,
}

impl<'c, 'db: 'c, DB: DatabaseLike> Joins<'_, 'c, '_, 'db, DB> {
    /// The column `expression` reads and the stored column it reaches.
    fn side(&self, expression: &Expr) -> Result<Option<Side<'c, DB>>, LookupError> {
        let expression = unnested(expression);
        if !is_column_reference(expression) {
            return Ok(None);
        }
        let types = self.types;
        let Some((ColumnDefinition::Base { table, column, .. }, binding)) =
            types.reference(expression)?
        else {
            return Ok(None);
        };
        Ok(binding.entry().map(|entry| Side {
            entry: Entry::of(entry),
            table,
            column,
            text: expression.to_string(),
        }))
    }

    /// The stored table `factor` reads.
    fn table(&self, factor: &TableFactor) -> Option<&'db DB::Table> {
        let address = ptr::from_ref(factor);
        self.facts.block(address).and_then(|block| {
            block.items.iter().find_map(|(item, reads)| match reads {
                Reads::Table(table) if *item == address => Some(*table),
                _ => None,
            })
        })
    }

    /// The column named `name` of `factor`, a stored table.
    fn named(&self, factor: &TableFactor, name: &str) -> Result<Option<Side<'c, DB>>, LookupError> {
        let (
            Some(table),
            TableFactor::Table {
                name: relation,
                alias,
                ..
            },
        ) = (self.table(factor), factor)
        else {
            return Ok(None);
        };
        let exposed = alias
            .as_ref()
            .map(|alias| &alias.name)
            .or_else(|| relation.0.last().and_then(ObjectNamePart::as_ident));
        let prefix = exposed.map_or_else(String::new, |ident| format!("{ident}."));
        Ok(table
            .columns(self.roots.database)?
            .enumerate()
            .find(|(_, column)| column.stored_column_name() == name)
            .map(|(ordinal, column)| Side {
                entry: Entry {
                    factor: ptr::from_ref(factor),
                    ordinal,
                },
                table,
                column,
                text: format!("{prefix}{}", column.column_name()),
            }))
    }

    /// The column named `name` of the first stored table of `factors`
    /// holding one, which is the column a merged column of an inner join
    /// reads.
    fn holder(
        &self,
        factors: &[&TableFactor],
        name: &str,
    ) -> Result<Option<Side<'c, DB>>, LookupError> {
        for factor in factors {
            if let Some(side) = self.named(factor, name)? {
                return Ok(Some(side));
            }
        }
        Ok(None)
    }

    /// The equality the merged column `name` stands for, when a stored
    /// table of `left` and one of `right` hold it.
    fn merged(
        &self,
        name: &str,
        left: &[&TableFactor],
        right: &[&TableFactor],
    ) -> Result<Option<Equality<'c, DB>>, LookupError> {
        let (Some(left), Some(right)) = (self.holder(left, name)?, self.holder(right, name)?)
        else {
            return Ok(None);
        };
        let text = format!("{} = {}", left.text, right.text);
        Ok(Some(Equality {
            left,
            right,
            node: None,
            text,
        }))
    }

    /// The names of the columns the `USING` or `NATURAL` join `constraint`
    /// merges, for `NATURAL` every column of the stored tables of `right`.
    fn merged_names(
        &self,
        constraint: &JoinConstraint,
        right: &[&TableFactor],
    ) -> Result<BTreeSet<String>, LookupError> {
        let mut names = BTreeSet::new();
        match constraint {
            JoinConstraint::Using(columns) | JoinConstraint::UsingAlias(columns, _) => {
                names.extend(
                    columns
                        .iter()
                        .filter_map(|column| column.0.last().and_then(ObjectNamePart::as_ident))
                        .map(|ident| stored(ident).into_owned()),
                );
            }
            JoinConstraint::Natural => {
                for table in right.iter().filter_map(|factor| self.table(factor)) {
                    names.extend(
                        table
                            .columns(self.roots.database)?
                            .map(|column| column.stored_column_name().into_owned()),
                    );
                }
            }
            JoinConstraint::On(_) | JoinConstraint::None => {}
        }
        Ok(names)
    }

    /// Checks the inner joins of `select`.
    fn select(&mut self, select: &Select) -> Result<(), LookupError> {
        for joined in &select.from {
            self.explicit(joined)?;
        }
        self.linked(select)
    }

    /// Checks the inner joins `joined` writes out, inside parenthesized
    /// joins.
    fn explicit(&mut self, joined: &TableWithJoins) -> Result<(), LookupError> {
        if let TableFactor::NestedJoin {
            table_with_joins, ..
        } = &joined.relation
        {
            self.explicit(table_with_joins)?;
        }
        let mut left = leaves(&joined.relation);
        let mut extended = within(&joined.relation);
        for join in &joined.joins {
            if let TableFactor::NestedJoin {
                table_with_joins, ..
            } = &join.relation
            {
                self.explicit(table_with_joins)?;
            }
            let right = leaves(&join.relation);
            if let JoinOperator::Join(constraint) | JoinOperator::Inner(constraint) =
                &join.join_operator
            {
                let mut equalities = Vec::new();
                let mut skip = Vec::new();
                if let JoinConstraint::On(condition) = constraint {
                    for part in conjuncts(condition) {
                        skip.push(ptr::from_ref(part));
                        if let Some(equality) = self.equality(part, &left, &right)? {
                            equalities.push(equality);
                        }
                    }
                }
                for name in self.merged_names(constraint, &right)? {
                    if let Some(equality) = self.merged(&name, &left, &right)? {
                        equalities.push(equality);
                    }
                }
                self.report(&equalities, &skip, Some(&extended), |_| join.to_string())?;
            }
            if extends_left(&join.join_operator) {
                extended.extend(left.iter().map(|factor| ptr::from_ref(*factor)));
            }
            if matches!(
                join.join_operator,
                JoinOperator::Left(_) | JoinOperator::LeftOuter(_) | JoinOperator::FullOuter(_)
            ) {
                extended.extend(right.iter().map(|factor| ptr::from_ref(*factor)));
            }
            extended.extend(within(&join.relation));
            left.extend(right);
        }
        Ok(())
    }

    /// The equality `part` writes between a column of `left` and one of
    /// `right`, left first.
    fn equality(
        &self,
        part: &Expr,
        left: &[&TableFactor],
        right: &[&TableFactor],
    ) -> Result<Option<Equality<'c, DB>>, LookupError> {
        let Expr::BinaryOp {
            left: first,
            op: BinaryOperator::Eq,
            right: second,
        } = unnested(part)
        else {
            return Ok(None);
        };
        let (Some(first), Some(second)) = (self.side(first)?, self.side(second)?) else {
            return Ok(None);
        };
        let holds = |factors: &[&TableFactor], side: &Side<'c, DB>| {
            factors
                .iter()
                .any(|factor| ptr::eq(*factor, side.entry.factor))
        };
        let node = Some(ptr::from_ref(part));
        let text = part.to_string();
        Ok(if holds(left, &first) && holds(right, &second) {
            Some(Equality {
                left: first,
                right: second,
                node,
                text,
            })
        } else if holds(left, &second) && holds(right, &first) {
            Some(Equality {
                left: second,
                right: first,
                node,
                text,
            })
        } else {
            None
        })
    }

    /// Checks the `WHERE` equalities linking comma-separated `FROM` items
    /// or the two sides of a `CROSS JOIN`, other than those reaching the
    /// target of an `UPDATE` or `DELETE`.
    fn linked(&mut self, select: &Select) -> Result<(), LookupError> {
        let mut units: Vec<(Vec<&TableFactor>, bool)> = Vec::new();
        for joined in &select.from {
            let target = self.target == Some(ptr::from_ref(joined));
            let mut unit = leaves(&joined.relation);
            for join in &joined.joins {
                if matches!(join.join_operator, JoinOperator::CrossJoin(_)) {
                    units.push((std::mem::take(&mut unit), target));
                }
                unit.extend(leaves(&join.relation));
            }
            units.push((unit, target));
        }
        if units.len() < 2 {
            return Ok(());
        }
        let unit_of = |side: &Side<'c, DB>| {
            units.iter().position(|(unit, _)| {
                unit.iter()
                    .any(|factor| ptr::eq(*factor, side.entry.factor))
            })
        };
        let mut equalities = Vec::new();
        for part in select.selection.iter().flat_map(conjuncts) {
            let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = unnested(part)
            else {
                continue;
            };
            let (Some(left), Some(right)) = (self.side(left)?, self.side(right)?) else {
                continue;
            };
            let (Some(first), Some(second)) = (unit_of(&left), unit_of(&right)) else {
                continue;
            };
            if first == second || units[first].1 || units[second].1 {
                continue;
            }
            let node = Some(ptr::from_ref(part));
            let text = part.to_string();
            equalities.push(if first < second {
                Equality {
                    left,
                    right,
                    node,
                    text,
                }
            } else {
                Equality {
                    left: right,
                    right: left,
                    node,
                    text,
                }
            });
        }
        self.report(&equalities, &[], None, |matched| {
            matched
                .iter()
                .map(|equality| equality.text.as_str())
                .collect::<Vec<_>>()
                .join(" AND ")
        })
    }

    /// Reports each pair of `FROM` items `equalities` join through a
    /// foreign key whose equated referencing column can be `NULL`, leaving
    /// out the conjuncts `skip` holds and those equating the pair, with the
    /// `FROM` items `site` holds null-extended at the join, and rendering
    /// the join with `render`.
    fn report(
        &mut self,
        equalities: &[Equality<'c, DB>],
        skip: &[*const Expr],
        site: Option<&[*const TableFactor]>,
        render: impl Fn(&[&Equality<'c, DB>]) -> String,
    ) -> Result<(), LookupError> {
        for child_left in [true, false] {
            let orient = |equality| oriented(equality, child_left);
            let mut groups: Vec<Vec<&Equality<'c, DB>>> = Vec::new();
            for equality in equalities {
                let (child, parent) = orient(equality);
                let group = groups.iter_mut().find(|group| {
                    let (held_child, held_parent) = orient(group[0]);
                    held_child.entry.factor == child.entry.factor
                        && held_parent.entry.factor == parent.entry.factor
                        && held_child.table == child.table
                        && held_parent.table == parent.table
                });
                match group {
                    Some(group) => group.push(equality),
                    None => groups.push(vec![equality]),
                }
            }
            for group in groups {
                let pairs: Vec<_> = group.iter().map(|equality| orient(equality)).collect();
                let skip: Vec<*const Expr> = skip
                    .iter()
                    .copied()
                    .chain(group.iter().filter_map(|equality| equality.node))
                    .collect();
                if let Some((description, positions)) = self.finding(&pairs, &skip, site)? {
                    let matched: Vec<&Equality<'c, DB>> = positions
                        .into_iter()
                        .map(|position| group[position])
                        .collect();
                    self.roots.found.push((description, render(&matched)));
                }
            }
        }
        Ok(())
    }

    /// The description of the inner join `pairs` of child and parent
    /// columns make over a foreign key whose equated referencing column can
    /// be `NULL`, with the positions of the pairs over that key, or `None`
    /// when no such key exists.
    fn finding(
        &mut self,
        pairs: &[(&Side<'c, DB>, &Side<'c, DB>)],
        skip: &[*const Expr],
        site: Option<&[*const TableFactor]>,
    ) -> Result<Option<(String, Vec<usize>)>, LookupError> {
        let (child, parent) = pairs[0];
        let facts = self.facts;
        let block = facts.holding(child.entry.factor);
        if block.rejects(skip, |conjunct| {
            conjunct.factors.contains(&parent.entry.factor)
        }) {
            return Ok(None);
        }
        let database = self.roots.database;
        for foreign_key in child.table.foreign_keys(database)? {
            if foreign_key.referenced_table(database)? != parent.table {
                continue;
            }
            let key = key_pairs(database, foreign_key)?;
            let mut nullable = Vec::new();
            let mut referenced = Vec::new();
            let mut matched = Vec::new();
            for (position, (host, target)) in pairs.iter().enumerate() {
                if !key
                    .iter()
                    .any(|(column, parent)| *column == host.column && *parent == target.column)
                {
                    continue;
                }
                matched.push(position);
                if block.rejects(skip, |conjunct| {
                    conjunct.pairs.contains(&(host.entry, target.entry.factor))
                }) {
                    continue;
                }
                let judged = self
                    .roots
                    .judge(facts, host.entry, skip, site, FOLLOWED_RELATIONS)?;
                if match judged {
                    Judgment::Nullable => true,
                    Judgment::Stored => !forced(database, foreign_key)?,
                    Judgment::NotNull | Judgment::Unknown => false,
                } {
                    nullable.push(format!("`{}`", host.text));
                    referenced.push(format!("`{}`", target.text));
                }
            }
            if !nullable.is_empty() {
                return Ok(Some((
                    format!(
                        "an inner join from nullable {} to {}",
                        nullable.join(", "),
                        referenced.join(", ")
                    ),
                    matched,
                )));
            }
        }
        Ok(None)
    }
}

/// The child and parent sides of `equality`, the child on its left side
/// when `child_left` holds.
fn oriented<'e, 't, DB: DatabaseLike>(
    equality: &'e Equality<'t, DB>,
    child_left: bool,
) -> (&'e Side<'t, DB>, &'e Side<'t, DB>) {
    if child_left {
        (&equality.left, &equality.right)
    } else {
        (&equality.right, &equality.left)
    }
}

impl<DB: DatabaseLike> Visitor for Joins<'_, '_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<LookupError> {
        self.select(select)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Whether `foreign_key` holds every referencing column non-null, which a
/// validated `MATCH FULL` key with a column that cannot hold `NULL` does.
fn forced<DB: DatabaseLike>(
    database: &DB,
    foreign_key: &DB::ForeignKey,
) -> Result<bool, LookupError> {
    if foreign_key.match_full(database)
        && foreign_key.is_enforced(database)
        && foreign_key.is_validated(database)?
    {
        for host in foreign_key.host_columns(database)? {
            if !may_hold_null(database, host)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
