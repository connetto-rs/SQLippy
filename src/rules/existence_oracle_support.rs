//! Whether a key a client role writes tells it if a row it cannot read
//! exists, shared by the foreign key and unique key existence oracles.

use std::{borrow::Cow, cell::RefCell, collections::HashMap, ops::ControlFlow, ptr, rc::Rc, slice};

use sql_traits::{
    errors::{LookupError, RowSecurityError},
    structs::{
        Assumption, ColumnDefinitionScope, ColumnPrivilege, ColumnScope, GateTerm, IdentifierCase,
        Outcomes, RowGate, RowSecurity, RowStatement, RowVersion, TargetName, WrittenCall,
    },
    traits::{
        CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, TableLike,
    },
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::{
    ast::{
        BinaryOperator, Expr, Function, FunctionArguments, FunctionSecurity, Ident, InTarget,
        JoinConstraint, JoinOperator, ObjectName, Query, Select, SelectItem, SetExpr, SetOperator,
        TableAlias, TableFactor, Visit, VisitMut, VisitorMut, visit_expressions,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::{
    deployment::Deployment,
    rules::{
        closed_set_support::{names_cast_column, names_column, same_identity, stored_name},
        consumed_key_support::Consumption,
        cte_support::stored_table,
        grant_support::schema_of,
        helper_set_support::HelperSets,
        implication_support::{
            Columns, Condition, Operand, admits, clause_implies, column_of, is_column, membership,
            reads_column_or_parameter,
        },
        key_support::{binds, equality_keys, instances, key_pairs, named, no_inheritors},
        ladder_support::called,
        policy_read_support::{reads_every_row, sublink_reads},
        policy_support::{
            acting, client_roles, conjuncts, disjuncts, evaluates_every_term, is_column_reference,
            is_contradiction, is_tautology, sets_only_search_path, sql_set_body, unwrapped,
        },
    },
};

/// The row security `role` meets running `statement` on `table`, or `None`
/// when the schema cannot settle it for the role.
pub(crate) fn row_security<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
    statement: RowStatement,
    role: Option<&'db DB::Role>,
) -> Result<Option<RowSecurity<'db, DB::Policy>>, LookupError> {
    match table.row_security(statement, acting(role), database) {
        Ok(security) => Ok(Some(security)),
        Err(RowSecurityError::Lookup(error)) => Err(error),
        Err(_) => Ok(None),
    }
}

/// Whether the `SELECT` policies of `table` in `security`, which `role`
/// meets, leave some row out. Policies the role may not evaluate leave out
/// every row.
pub(crate) fn hides_rows<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    role: Option<&DB::Role>,
    security: &RowSecurity<'_, DB::Policy>,
) -> Result<bool, LookupError> {
    let Some(gates) = security.gates() else {
        // An exempt role reads every row, and a refused read reads none.
        return Ok(security.infinite_recursion().is_some());
    };
    if !evaluates_every_term(database, role, gates)? {
        return Ok(true);
    }
    for gate in gates {
        let mut admitted = false;
        for term in gate.permissive() {
            if is_tautology(database, table, term.expression().expression())? {
                admitted = true;
                break;
            }
        }
        for term in gate.restrictive() {
            if !is_tautology(database, table, term.expression().expression())? {
                admitted = false;
            }
        }
        if !admitted {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What one arm of a query yields in a column of its output.
#[derive(Clone, Default)]
struct Origin {
    /// The row of the arm the value is a column of, and the stored name of
    /// that column.
    row: Option<(usize, String)>,
    /// Sets the value is one of.
    members: Vec<Expr>,
}

/// A row an arm of a query reads, with what its filters state of it.
struct Row<'db, DB: DatabaseLike> {
    table: &'db DB::Table,
    /// Conditions the row meets, over the stored names of its columns.
    facts: Vec<Expr>,
    /// Whether the row was read under the writer's own policies.
    read_by_writer: bool,
    /// Each column of the row whose value the arm keeps only when no row of
    /// the parent holds it, with the stored name of that column of the
    /// parent.
    unheld: Vec<(String, String)>,
}

/// One arm of a query, with where each output column comes from and the
/// rows the arm reads.
struct Arm<'db, DB: DatabaseLike> {
    outputs: Vec<Origin>,
    rows: Vec<Row<'db, DB>>,
}

/// A relation the `FROM` of an arm reads.
struct Source<'db, DB: DatabaseLike> {
    /// The name the arm reads the relation under.
    name: String,
    /// The stored names of its columns, in order.
    columns: Vec<String>,
    /// Whether `columns` names every column the relation yields.
    counted: bool,
    /// The set each column's values lie in, by position, which a call
    /// yielding there what it yields to the writer names.
    sets: Vec<Expr>,
    kind: SourceKind<'db, DB>,
}

/// What an arm learns of a value it reads from a source.
enum SourceKind<'db, DB: DatabaseLike> {
    /// A table, whose row the arm reads at this position among its rows.
    Table(usize),
    /// A helper whose body the arm reads as its arms.
    Helper(Vec<Arm<'db, DB>>),
    /// A relation the arm learns nothing of.
    Opaque,
}

/// The arms of the helper a check reads the written row from, with the
/// position of each written item among the helper's outputs.
struct HelperArms<'db, DB: DatabaseLike> {
    /// For each key column, the position of the item naming it.
    positions: Vec<Option<usize>>,
    arms: Vec<Arm<'db, DB>>,
}

/// A condition admitting referenced columns into the values columns of one
/// row of a table take.
struct Sublink<'db, DB: DatabaseLike> {
    /// The position in the key of each key column the condition admits, with
    /// the stored name of the column the subquery projects in its place.
    columns: Vec<(usize, String)>,
    table: &'db DB::Table,
    /// The subquery's filters, stated of the table's columns.
    filters: Vec<Expr>,
}

/// What the checks of a written table force on the nullable key columns of
/// its rows.
struct NullForcing<'a, DB: DatabaseLike> {
    written: &'a DB::Table,
    /// The enforced and validated checks of `written` that read a column of
    /// `linked`, which every written row meets.
    checks: Vec<Assumption<'a, DB>>,
    /// `IS NULL` over the nullable key columns, joined with `OR`.
    test: Expr,
    /// The stored names of the nullable key columns and of every column a
    /// check of `checks` reads, one of which a clause must read to force a
    /// key column `NULL`.
    linked: Vec<Cow<'a, str>>,
    /// The answer for each clause read so far.
    answers: RefCell<HashMap<Expr, bool>>,
}

impl<'a, DB: DatabaseLike> NullForcing<'a, DB> {
    /// The forcing on the `key_columns` of rows of `written`, `None` when
    /// every key column is `NOT NULL`.
    fn new(
        database: &'a DB,
        written: &'a DB::Table,
        key_columns: &[Cow<'a, str>],
    ) -> Result<Option<Self>, LookupError> {
        let mut linked = Vec::new();
        let mut test: Option<Expr> = None;
        for column in written.columns(database)? {
            let name = column.stored_column_name();
            if key_columns.contains(&name) && column.is_nullable(database)? {
                let null = Expr::IsNull(Box::new(Expr::Identifier(Ident::with_quote(
                    '"',
                    name.as_ref(),
                ))));
                test = Some(match test {
                    Some(left) => Expr::BinaryOp {
                        left: Box::new(left),
                        op: BinaryOperator::Or,
                        right: Box::new(null),
                    },
                    None => null,
                });
                linked.push(name);
            }
        }
        let Some(test) = test else {
            return Ok(None);
        };
        let mut reads = Vec::new();
        for check in written.check_constraints(database)? {
            if check.is_enforced() && check.is_validated(database)? {
                let read: Vec<Cow<'a, str>> = check
                    .columns(database)?
                    .map(ColumnLike::stored_column_name)
                    .collect();
                reads.push((check, read));
            }
        }
        // A check reading a linked column ties every column it reads to it.
        let mut checks = Vec::new();
        while let Some(index) = reads
            .iter()
            .position(|(_, read)| read.iter().any(|column| linked.contains(column)))
        {
            let (check, read) = reads.swap_remove(index);
            for column in read {
                if !linked.contains(&column) {
                    linked.push(column);
                }
            }
            checks.push(Assumption::Check(check));
        }
        Ok(Some(Self {
            written,
            checks,
            test,
            linked,
            answers: RefCell::new(HashMap::new()),
        }))
    }

    /// Whether every written row meeting `clause` holds a key column `NULL`
    /// under the checks, which a clause the checks leave no row for does.
    fn forces(&self, database: &DB, clause: &Expr) -> Result<bool, LookupError> {
        let reads_linked = visit_expressions(clause, |expression| {
            if stored_name(expression).is_some_and(|name| self.linked.contains(&name)) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .is_break();
        if !reads_linked {
            return Ok(false);
        }
        if let Some(&forced) = self.answers.borrow().get(clause) {
            return Ok(forced);
        }
        let mut assumptions = self.checks.clone();
        assumptions.push(Assumption::Expression {
            expression: clause,
            outcomes: Outcomes::TRUE,
        });
        let forced = !self
            .written
            .truth_under(
                database,
                &self.test,
                IdentifierCase::AsWritten,
                &assumptions,
            )?
            .outcomes
            .falsity;
        self.answers.borrow_mut().insert(clause.clone(), forced);
        Ok(forced)
    }
}

/// Decides whether the check on a written row confines a key to rows its
/// writer may point at. A set of key columns is a bit mask over their
/// positions in the key, which PostgreSQL caps at 32.
pub(crate) struct Confinement<'a, DB: DatabaseLike> {
    database: &'a DB,
    deployment: &'a Deployment,
    parent: &'a DB::Table,
    key_columns: Vec<Cow<'a, str>>,
    /// The referenced column each key column maps onto, by position.
    referenced_columns: Vec<Cow<'a, str>>,
    /// The key columns mapped onto each unique key of the referenced table
    /// whose columns the key references.
    row_keys: Vec<u64>,
    /// Whether a `NULL` key column skips the check, as it does for a foreign
    /// key and for a unique key whose `NULL` values are distinct.
    null_skips: bool,
    /// What the written table's checks force on the nullable key columns,
    /// when `NULL` skips the check.
    null_forcing: Option<NullForcing<'a, DB>>,
    /// The key columns whose values only rows of their writer's principal
    /// hold, which a check pinning one to a principal accessor confines.
    principal_columns: u64,
    /// The helper arms each clause reads, by the clause's address.
    helpers: RefCell<HashMap<*const Expr, Option<Rc<HelperArms<'a, DB>>>>>,
    /// Which sets lie within which.
    sets: HelperSets<'a, DB>,
    /// Triggers taking each held key out of the sets a check may draw it
    /// from.
    consumptions: Vec<Consumption<'a, DB>>,
    /// The helpers whose bodies are being read, outermost first, so that a
    /// helper reaching itself is read as opaque.
    reading: RefCell<Vec<&'a DB::Function>>,
}

impl<'a, DB: DatabaseLike> Confinement<'a, DB> {
    /// A confinement of the `key_columns` of rows written to `written` onto
    /// `referenced_columns` of `parent`, by position, under a check that a
    /// `NULL` key column skips when `null_skips` is set.
    pub(crate) fn new(
        database: &'a DB,
        deployment: &'a Deployment,
        written: &'a DB::Table,
        key_columns: Vec<Cow<'a, str>>,
        parent: &'a DB::Table,
        referenced_columns: Vec<Cow<'a, str>>,
        null_skips: bool,
    ) -> Result<Self, LookupError> {
        let row_keys = equality_keys(database, parent)?
            .into_iter()
            .filter_map(|key| {
                key.iter().try_fold(0, |mask, column| {
                    let name = column.stored_column_name();
                    let position = referenced_columns
                        .iter()
                        .position(|mapped| *mapped == name)?;
                    Some(mask | 1 << position)
                })
            })
            .collect();
        let null_forcing = if null_skips {
            NullForcing::new(database, written, &key_columns)?
        } else {
            None
        };
        Ok(Self {
            database,
            deployment,
            parent,
            key_columns,
            referenced_columns,
            row_keys,
            null_skips,
            null_forcing,
            principal_columns: 0,
            helpers: RefCell::new(HashMap::new()),
            sets: HelperSets::new(database),
            consumptions: Vec::new(),
            reading: RefCell::new(Vec::new()),
        })
    }

    /// This confinement, also settling a key column a check draws from a
    /// set that `consumptions` take every held key out of.
    pub(crate) fn with_consumptions(self, consumptions: Vec<Consumption<'a, DB>>) -> Self {
        Self {
            consumptions,
            ..self
        }
    }

    /// This confinement, also settling a key whose check pins one of
    /// `columns`, by stored name, to a declared principal accessor. Only
    /// rows of the writer's principal hold its value in such a column, or in
    /// the referenced column a foreign key maps it onto, so a key meeting a
    /// row there names a row of that principal.
    pub(crate) fn with_principal_columns(
        self,
        columns: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        let principal_columns = columns.into_iter().fold(0, |mask, column| {
            self.key_columns
                .iter()
                .position(|key| *key == column.as_ref())
                .map_or(mask, |position| mask | 1 << position)
        });
        Self {
            principal_columns,
            ..self
        }
    }

    /// Whether `gate` pins a principal column of the key to a declared
    /// principal accessor for every row it admits.
    fn pins_principal_column(&self, gate: &RowGate<'_, DB::Policy>) -> bool {
        self.key_columns
            .iter()
            .enumerate()
            .any(|(position, column)| {
                self.principal_columns & 1 << position != 0
                    && pins_principal(self.deployment, gate, column)
            })
    }

    /// Every key column.
    fn whole_key(&self) -> u64 {
        (1 << self.key_columns.len()) - 1
    }

    /// The key columns `expression` names.
    fn key_columns_named(&self, expression: &Expr) -> u64 {
        positions(&self.key_columns, expression)
    }

    /// The position in the key of the key column `expression` names.
    fn key_position(&self, expression: &Expr) -> Option<usize> {
        self.key_columns
            .iter()
            .position(|column| names_cast_column(expression, column))
    }

    /// Whether every written row meeting `clause` holds a key column `NULL`,
    /// which a check that `NULL` skips then looks up nothing for. The clause
    /// tests the column `IS NULL` itself, or the written table's checks
    /// force it under the clause.
    fn forces_null(&self, clause: &Expr) -> Result<bool, LookupError> {
        if !self.null_skips {
            return Ok(false);
        }
        if let Expr::IsNull(column) = unwrapped(clause)
            && self.key_position(column).is_some()
        {
            return Ok(true);
        }
        match &self.null_forcing {
            Some(forcing) => forcing.forces(self.database, clause),
            None => Ok(false),
        }
    }

    /// Whether `query`, a plain `SELECT`, gives every column of a unique key
    /// of the referenced table from one row it reads under the writer's
    /// policies, so the key matches that row or none. `pairs` lists each key
    /// column with the expression of the query that gives its value, and a
    /// pair counts when that expression names the column the key maps the
    /// key column onto.
    fn draws_row_key<'e>(
        &self,
        query: &'e Query,
        pairs: impl FnOnce(
            &'e Select,
            &ColumnDefinitionScope<'_, '_, '_, DB>,
        ) -> Result<Vec<(&'e Expr, &'e Expr)>, LookupError>,
    ) -> Result<bool, LookupError> {
        let SetExpr::Select(select) = query.body.as_ref() else {
            return Ok(false);
        };
        let local = ColumnScope::from_query(query, self.database, IdentifierCase::Folded)?;
        let (Some(instances), Some(scope)) = (
            instances(self.database, select).filter(|_| query.with.is_none()),
            local.scope_for_select(select),
        ) else {
            return Ok(false);
        };
        // The key columns each instance of the referenced table gives, by its name.
        let mut rows: Vec<(String, u64)> = Vec::new();
        for (key, referenced) in pairs(select, &scope)? {
            let (Some(position), Some((relation, column))) =
                (self.key_position(key), named(&scope, referenced)?)
            else {
                continue;
            };
            if column != self.referenced_columns[position]
                || !instances
                    .iter()
                    .any(|instance| instance.name == relation && instance.table == self.parent)
            {
                continue;
            }
            match rows.iter_mut().find(|(row, _)| *row == relation) {
                Some((_, mask)) => *mask |= 1 << position,
                None => rows.push((relation, 1 << position)),
            }
        }
        Ok(rows.iter().any(|(_, mask)| self.covers_row_key(*mask)))
    }

    /// Whether the key columns in `mask` include every column of a unique
    /// key of the referenced table.
    fn covers_row_key(&self, mask: u64) -> bool {
        self.row_keys.iter().any(|key| mask & key == *key)
    }

    /// Whether every row of `query` gives `items` the values of one row of
    /// the referenced table it reads under the writer's policies, over the
    /// columns of a unique key the key maps them onto. Items pair with the
    /// select list up to its first wildcard, which shifts every later column.
    fn yields_readable_row<'e>(
        &self,
        items: &'e [Expr],
        query: &'e Query,
    ) -> Result<bool, LookupError> {
        self.draws_row_key(query, |select, _| {
            Ok(items
                .iter()
                .zip(&select.projection)
                .map_while(|(item, projected)| match projected {
                    SelectItem::UnnamedExpr(value)
                    | SelectItem::ExprWithAlias { expr: value, .. } => Some((item, value)),
                    _ => None,
                })
                .collect())
        })
    }

    /// Whether an `EXISTS` over `query` equates every column of a unique key
    /// of one row of the referenced table it reads under the writer's
    /// policies with the key column the key maps onto it.
    fn matches_readable_row(&self, query: &Query) -> Result<bool, LookupError> {
        self.draws_row_key(query, |select, scope| {
            let mut pairs = Vec::new();
            for conjunct in select.selection.iter().flat_map(conjuncts) {
                if let Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Eq,
                    right,
                } = unwrapped(conjunct)
                    && is_column(left)
                    && is_column(right)
                {
                    for (inner, outer) in [(left, right), (right, left)] {
                        if scope.resolve_column_binding(outer)?.is_none() {
                            pairs.push((outer.as_ref(), inner.as_ref()));
                        }
                    }
                }
            }
            Ok(pairs)
        })
    }

    /// Whether the conjunct leaves the key check nothing hidden to find. It
    /// forces a key column `NULL`, alone or under the written table's
    /// checks, under a check that `NULL` skips, so PostgreSQL looks up no
    /// row, it ties the key to one row the writer reads, or it draws a key
    /// column from a set no held key is in.
    fn settles_key(&self, conjunct: &Expr) -> Result<bool, LookupError> {
        if self.excludes_held(conjunct)? || self.forces_null(conjunct)? {
            return Ok(true);
        }
        match unwrapped(conjunct) {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => {
                for (column, value) in [(left, right), (right, left)] {
                    if let Expr::Subquery(query) = unwrapped(value)
                        && self.yields_readable_row(slice::from_ref(column), query)?
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Expr::AnyOp {
                left,
                compare_op: BinaryOperator::Eq,
                right,
                ..
            } => match unwrapped(right) {
                Expr::Subquery(query) => self.yields_readable_row(slice::from_ref(left), query),
                Expr::Function(Function {
                    name,
                    args: FunctionArguments::Subquery(query),
                    ..
                }) if name.to_string().eq_ignore_ascii_case("array") => {
                    self.yields_readable_row(slice::from_ref(left), query)
                }
                _ => Ok(false),
            },
            Expr::In {
                expr,
                target: InTarget::Subquery(query),
                negated: false,
                ..
            } => match unwrapped(expr) {
                Expr::Tuple(items) => self.yields_readable_row(items, query),
                item => self.yields_readable_row(slice::from_ref(item), query),
            },
            Expr::Exists {
                subquery,
                negated: false,
            } => self.matches_readable_row(subquery),
            _ => Ok(false),
        }
    }

    /// Whether `conjunct` draws a key column from the rows of a
    /// set-returning helper, as `IN (SELECT helper())`, `= ANY
    /// (ARRAY(SELECT helper()))` or `IN (SELECT ... FROM helper())`, every
    /// arm of whose body yields only values no row of the parent holds, or
    /// rows a consumption leaves rejected by the arm's filters once a row
    /// holds their key.
    fn excludes_held(&self, conjunct: &Expr) -> Result<bool, LookupError> {
        let Some(helper) = self.helper_arms(conjunct)? else {
            return Ok(false);
        };
        for (position, output) in helper.positions.iter().enumerate() {
            if let Some(output) = output
                && self.arms_exclude_held(position, *output, &helper.arms)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether every one of `arms` gives the key column at `position` in its
    /// output at `output` from a row it keeps only when no row of the parent
    /// holds that value in the column the key maps the key column onto, or
    /// from the row a consumption of that key column writes, read under a
    /// filter the written row fails.
    fn arms_exclude_held(
        &self,
        position: usize,
        output: usize,
        arms: &[Arm<'a, DB>],
    ) -> Result<bool, LookupError> {
        let column = &self.key_columns[position];
        let referenced = &self.referenced_columns[position];
        for arm in arms {
            let Some(Origin {
                row: Some((index, drawn)),
                ..
            }) = arm.outputs.get(output)
            else {
                return Ok(false);
            };
            let row = &arm.rows[*index];
            if row
                .unheld
                .iter()
                .any(|(own, held)| own == drawn && held == referenced)
            {
                continue;
            }
            if !self.consumed(column, row, drawn)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether a consumption of the key column `column` writes the row of
    /// `row`'s table its column `drawn` names, and leaves it failing one of
    /// `row`'s facts.
    fn consumed(&self, column: &str, row: &Row<'a, DB>, drawn: &str) -> Result<bool, LookupError> {
        for consumption in &self.consumptions {
            if consumption.column() != column || !consumption.names(row.table, drawn) {
                continue;
            }
            for fact in &row.facts {
                if consumption.rejects(&normalized(fact))? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether `query` yields only rows of the referenced table read under
    /// the writer's policies.
    fn confining_query(&self, policy: &DB::Policy, query: &Query) -> Result<bool, LookupError> {
        let SetExpr::Select(select) = query.body.as_ref() else {
            return Ok(false);
        };
        if select.from.is_empty()
            && let [SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. }] =
                select.projection.as_slice()
        {
            return self.confining_value(policy, value);
        }
        let (_, reads) = sublink_reads(self.database, policy, Some(query))?;
        Ok(reads.iter().any(|read| read.table == self.parent))
    }

    /// Whether `value` holds only keys of rows the writer reads.
    fn confining_value(&self, policy: &DB::Policy, value: &Expr) -> Result<bool, LookupError> {
        match unwrapped(value) {
            Expr::Subquery(query) => self.confining_query(policy, query),
            Expr::Function(function) => match &function.args {
                FunctionArguments::Subquery(query)
                    if function.name.to_string().eq_ignore_ascii_case("array") =>
                {
                    self.confining_query(policy, query)
                }
                _ => Ok(false),
            },
            _ => Ok(false),
        }
    }

    /// The key columns an `EXISTS` over `query` ties to a column of the
    /// referenced table it reads under the writer's policies.
    fn columns_matched_by_exists(
        &self,
        policy: &DB::Policy,
        query: &Query,
    ) -> Result<u64, LookupError> {
        let SetExpr::Select(select) = query.body.as_ref() else {
            return Ok(0);
        };
        let Some(selection) = &select.selection else {
            return Ok(0);
        };
        let (_, reads) = sublink_reads(self.database, policy, Some(query))?;
        if !reads.iter().any(|read| read.table == self.parent) {
            return Ok(0);
        }
        Ok(conjuncts(selection)
            .into_iter()
            .filter_map(|conjunct| match unwrapped(conjunct) {
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Eq,
                    right,
                } if is_column(left) && is_column(right) => {
                    Some(self.key_columns_named(left) | self.key_columns_named(right))
                }
                _ => None,
            })
            .fold(0, |mask, matched| mask | matched))
    }

    /// The key columns the conjunct confines, every one when it settles the
    /// key.
    fn columns_confined_by_conjunct(
        &self,
        policy: &DB::Policy,
        conjunct: &Expr,
    ) -> Result<u64, LookupError> {
        if self.settles_key(conjunct)? {
            return Ok(self.whole_key());
        }
        match unwrapped(conjunct) {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => {
                let mut confined = 0;
                for (column, value) in [(left, right), (right, left)] {
                    let named = self.key_columns_named(column);
                    if named != 0 && self.confining_value(policy, value)? {
                        confined |= named;
                    }
                }
                Ok(confined)
            }
            Expr::AnyOp {
                left,
                compare_op: BinaryOperator::Eq,
                right,
                ..
            } => {
                let named = self.key_columns_named(left);
                Ok(if named != 0 && self.confining_value(policy, right)? {
                    named
                } else {
                    0
                })
            }
            Expr::In {
                expr,
                target: InTarget::Subquery(query),
                negated: false,
                ..
            } => {
                let items = match unwrapped(expr) {
                    Expr::Tuple(items) => items.as_slice(),
                    item => std::slice::from_ref(item),
                };
                if let SetExpr::Select(select) = query.body.as_ref()
                    && select.from.is_empty()
                {
                    // The query yields one row, so each item takes the value in its position.
                    let mut confined = 0;
                    for (item, projected) in items.iter().zip(&select.projection) {
                        let named = self.key_columns_named(item);
                        if named != 0
                            && let SelectItem::UnnamedExpr(value)
                            | SelectItem::ExprWithAlias { expr: value, .. } = projected
                            && self.confining_value(policy, value)?
                        {
                            confined |= named;
                        }
                    }
                    return Ok(confined);
                }
                let named = items
                    .iter()
                    .fold(0, |mask, item| mask | self.key_columns_named(item));
                Ok(if named != 0 && self.confining_query(policy, query)? {
                    named
                } else {
                    0
                })
            }
            Expr::Exists {
                subquery,
                negated: false,
            } => self.columns_matched_by_exists(policy, subquery),
            _ => Ok(0),
        }
    }

    /// The key columns the clause confines, which are those one of its
    /// conjuncts confines or every arm of a disjunction does.
    fn columns_confined_by_clause(
        &self,
        policy: &DB::Policy,
        clause: &Expr,
    ) -> Result<u64, LookupError> {
        let arms = disjuncts(clause);
        if arms.len() > 1 {
            let mut confined = self.whole_key();
            for arm in arms {
                confined &= self.columns_confined_by_clause(policy, arm)?;
            }
            return Ok(confined);
        }
        let mut confined = 0;
        for conjunct in conjuncts(clause) {
            confined |= if disjuncts(conjunct).len() > 1 {
                self.columns_confined_by_clause(policy, conjunct)?
            } else {
                self.columns_confined_by_conjunct(policy, conjunct)?
            };
        }
        Ok(confined)
    }

    /// Whether the gate confines every key column for every row it admits:
    /// each column confined by a restrictive term or by every permissive one.
    fn confining_gate(&self, gate: &RowGate<'_, DB::Policy>) -> Result<bool, LookupError> {
        let mut restricted = 0;
        for term in gate.restrictive() {
            restricted |=
                self.columns_confined_by_clause(term.policy(), term.expression().expression())?;
        }
        let mut permitted = self.whole_key();
        for term in gate.permissive() {
            permitted &=
                self.columns_confined_by_clause(term.policy(), term.expression().expression())?;
        }
        Ok((restricted | permitted) == self.whole_key())
    }

    /// Whether every row of the referenced table the key can match passes
    /// the `SELECT` policies `read`, for every row `written` admits, or every
    /// row when no gate applies, meeting each of `guards`. Policies `role`
    /// may not evaluate pass no row.
    fn reads_matched_rows(
        &self,
        written: Option<&RowGate<'_, DB::Policy>>,
        read: &RowSecurity<'_, DB::Policy>,
        role: Option<&'a DB::Role>,
        guards: &[Expr],
    ) -> Result<bool, LookupError> {
        let Some(gates) = read.gates() else {
            return Ok(false);
        };
        if !evaluates_every_term(self.database, role, gates)? {
            return Ok(false);
        }
        let reading = Reading {
            confinement: self,
            role,
            guards,
        };
        admits(self.database, self.parent, gates, &reading, |condition| {
            reading.gate_implies(written, condition)
        })
    }

    /// Whether `clause` draws the key from the rows of a set-returning
    /// helper every arm of whose body meets `condition`, given `context`.
    fn helper_implies(
        &self,
        clause: &Expr,
        condition: &Condition<'_, u64>,
        context: &[&Expr],
        role: Option<&'a DB::Role>,
    ) -> Result<bool, LookupError> {
        let Some(helper) = self.helper_arms(clause)? else {
            return Ok(false);
        };
        for arm in &helper.arms {
            let origins: Vec<Option<&Origin>> = helper
                .positions
                .iter()
                .map(|position| position.and_then(|position| arm.outputs.get(position)))
                .collect();
            if !self.arm_implies(arm, &origins, condition, context, role)? {
                return Ok(false);
            }
        }
        Ok(!helper.arms.is_empty())
    }

    /// Whether every row of the referenced table a key drawn from `arm`
    /// matches meets `condition`. `origins` holds the origin of each key
    /// column in the arm. The key column is drawn from a set within the one
    /// the condition tests, or the arm reads the matched row itself and its
    /// filters imply the condition, or a foreign key of the matched row pins
    /// what the condition reads to a row the arm reads whose filters imply
    /// it, or the condition admits key columns from rows of a table the
    /// writer reads and the arm draws every one of them from one such row.
    fn arm_implies(
        &self,
        arm: &Arm<'a, DB>,
        origins: &[Option<&Origin>],
        condition: &Condition<'_, u64>,
        context: &[&Expr],
        role: Option<&'a DB::Role>,
    ) -> Result<bool, LookupError> {
        if let Some((operands, wider)) = &condition.membership
            && let [Operand::Tested(mapped)] = operands.as_slice()
        {
            for (position, origin) in origins.iter().enumerate() {
                if mapped & (1 << position) == 0 {
                    continue;
                }
                for members in origin.iter().flat_map(|origin| &origin.members) {
                    if self.is_set_within(members, wider)? {
                        return Ok(true);
                    }
                }
            }
        }
        for (index, row) in arm.rows.iter().enumerate() {
            if row.table != self.parent {
                continue;
            }
            let drawn = origins
                .iter()
                .enumerate()
                .filter(|(position, origin)| {
                    origin
                        .and_then(|origin| origin.row.as_ref())
                        .is_some_and(|(drawn, column)| {
                            *drawn == index && *column == self.referenced_columns[*position]
                        })
                })
                .fold(0, |mask, (position, _)| mask | 1 << position);
            if self.covers_row_key(drawn)
                && (row.read_by_writer
                    || self.entails(
                        &self.row_facts(row, index, origins, context),
                        condition.original,
                    )?)
            {
                return Ok(true);
            }
        }
        if self.pinned_implies(arm, origins, condition, context)? {
            return Ok(true);
        }
        let Some(Sublink {
            columns,
            table,
            filters,
        }) = self.sublink_membership(condition.original)?
        else {
            return Ok(false);
        };
        // Columns of two rows can combine into the key of a row neither admits.
        let mut index = None;
        for (position, column) in &columns {
            let Some(Some((drawn_from, drawn))) = origins
                .get(*position)
                .map(|origin| origin.and_then(|origin| origin.row.as_ref()))
            else {
                return Ok(false);
            };
            if drawn != column || index.is_some_and(|first| first != *drawn_from) {
                return Ok(false);
            }
            index = Some(*drawn_from);
        }
        let Some(index) = index else {
            return Ok(false);
        };
        let row = &arm.rows[index];
        if row.table != table {
            return Ok(false);
        }
        let facts = self.row_facts(row, index, origins, context);
        for filter in &filters {
            if !self.entails(&facts, filter)? {
                return Ok(false);
            }
        }
        Ok(row.read_by_writer || self.row_readable(table, &facts, role)?)
    }

    /// Whether a foreign key of the referenced table pins every column
    /// `condition` reads in the matched row to a column of one row `arm`
    /// reads, whose facts imply the condition so stated. The key columns the
    /// arm draws from that row through the foreign key cover a unique key of
    /// its table, so the foreign key references that very row from the
    /// matched row, which it binds since those key columns hold a value. Each
    /// column pair of the foreign key compares by identity, so the pinned
    /// values are the same values.
    fn pinned_implies(
        &self,
        arm: &Arm<'a, DB>,
        origins: &[Option<&Origin>],
        condition: &Condition<'_, u64>,
        context: &[&Expr],
    ) -> Result<bool, LookupError> {
        let database = self.database;
        for foreign_key in self.parent.foreign_keys(database)? {
            let referenced = foreign_key.referenced_table(database)?;
            let pairs = key_pairs(database, foreign_key)?;
            for (index, row) in arm.rows.iter().enumerate() {
                if row.table != referenced {
                    continue;
                }
                // The columns of `row` the arm draws key columns from through
                // the foreign key, and one host column holding such a key column.
                let mut drawn = Vec::new();
                let mut bound = None;
                for &(host, target) in &pairs {
                    let name = host.stored_column_name();
                    if self
                        .referenced_columns
                        .iter()
                        .position(|column| *column == name)
                        .and_then(|position| origins.get(position).copied().flatten())
                        .and_then(|origin| origin.row.as_ref())
                        .is_some_and(|(from, column)| {
                            *from == index && *column == target.stored_column_name()
                        })
                    {
                        drawn.push(target);
                        bound = Some(host);
                    }
                }
                let Some(bound) = bound else {
                    continue;
                };
                if !binds(database, foreign_key, bound)?
                    || !no_inheritors(database, referenced)?
                    || !equality_keys(database, referenced)?
                        .iter()
                        .any(|key| key.iter().all(|column| drawn.contains(column)))
                {
                    continue;
                }
                let mut alike = true;
                for &(host, target) in &pairs {
                    alike &= same_identity(database, host, target)?;
                }
                if !alike {
                    continue;
                }
                let Some(stated) = requalified(condition.original, |reference| {
                    let name = stored_name(reference)?;
                    pairs
                        .iter()
                        .find(|(host, _)| host.stored_column_name() == name)
                        .map(|(_, target)| target.stored_column_name().into_owned())
                }) else {
                    continue;
                };
                if self.entails(&self.row_facts(row, index, origins, context), &stated)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// What `row`, at `index` among the rows of its arm, is known to meet:
    /// the filters the arm reads it under, and the conditions of `context`
    /// on key columns the arm draws from the row, stated of its columns.
    fn row_facts(
        &self,
        row: &Row<'a, DB>,
        index: usize,
        origins: &[Option<&Origin>],
        context: &[&Expr],
    ) -> Vec<Expr> {
        let mut facts: Vec<Expr> = row.facts.iter().map(normalized).collect();
        for condition in context {
            let Some(stated) = requalified(condition, |reference| {
                let column = stored_name(reference)?;
                let position = self.key_columns.iter().position(|key| *key == column)?;
                let (drawn, source) = origins
                    .get(position)?
                    .and_then(|origin| origin.row.as_ref())?;
                (*drawn == index).then(|| source.clone())
            }) else {
                continue;
            };
            facts.extend(conjuncts(&normalized(&stated)).into_iter().cloned());
        }
        facts
    }

    /// The condition admitting referenced columns into the values columns of
    /// one row of a table take, as `column = ANY (ARRAY(SELECT ...))`,
    /// `column IN (SELECT ...)` or a row value of columns `IN (SELECT ...)`
    /// pairing them by position with as many projected columns, over one
    /// table with no other clause.
    fn sublink_membership(&self, condition: &Expr) -> Result<Option<Sublink<'a, DB>>, LookupError> {
        let Some((tested, query)) = sublink_operands(condition) else {
            return Ok(None);
        };
        let tested = match tested {
            Expr::Tuple(items) => items.as_slice(),
            item => slice::from_ref(item),
        };
        let Some(select) = plain_select(query) else {
            return Ok(None);
        };
        if query.limit_clause.is_some() || query.fetch.is_some() || select.having.is_some() {
            return Ok(None);
        }
        let Some(instances) = instances(self.database, select) else {
            return Ok(None);
        };
        let ([instance], [from]) = (instances.as_slice(), select.from.as_slice()) else {
            return Ok(None);
        };
        if !from.joins.is_empty() {
            return Ok(None);
        }
        let columns: Vec<String> = instance
            .table
            .columns(self.database)?
            .map(|column| column.stored_column_name().into_owned())
            .collect();
        let resolve = |expression: &Expr| -> Option<String> {
            match expression {
                Expr::Identifier(name) => Some(normalize_identifier(
                    &name.value,
                    name.quote_style.is_some(),
                )),
                Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                    [relation, name]
                        if normalize_identifier(
                            &relation.value,
                            relation.quote_style.is_some(),
                        ) == instance.name =>
                    {
                        Some(normalize_identifier(
                            &name.value,
                            name.quote_style.is_some(),
                        ))
                    }
                    _ => None,
                },
                _ => None,
            }
            .map(Cow::into_owned)
            .filter(|name| columns.contains(name))
        };
        if select.projection.len() != tested.len() {
            return Ok(None);
        }
        let mut admitted = Vec::with_capacity(tested.len());
        for (item, projected) in tested.iter().zip(&select.projection) {
            let Some(position) = self
                .referenced_columns
                .iter()
                .position(|referenced| names_cast_column(item, referenced))
            else {
                return Ok(None);
            };
            let (SelectItem::UnnamedExpr(projected)
            | SelectItem::ExprWithAlias {
                expr: projected, ..
            }) = projected
            else {
                return Ok(None);
            };
            let Some(projected) = resolve(without_parentheses(projected)) else {
                return Ok(None);
            };
            admitted.push((position, projected));
        }
        let mut filters = Vec::new();
        for filter in select.selection.iter().flat_map(conjuncts) {
            let Some(stated) = requalified(filter, |reference| resolve(reference)) else {
                return Ok(None);
            };
            filters.push(normalized(&stated));
        }
        Ok(Some(Sublink {
            columns: admitted,
            table: instance.table,
            filters,
        }))
    }

    /// Whether a row of `table` meeting `facts` passes the `SELECT`
    /// policies `role` meets on the table.
    fn row_readable(
        &self,
        table: &'a DB::Table,
        facts: &[Expr],
        role: Option<&'a DB::Role>,
    ) -> Result<bool, LookupError> {
        let Some(security) = row_security(self.database, table, RowStatement::Select, role)? else {
            return Ok(false);
        };
        let Some(gates) = security.gates() else {
            return Ok(security.exemption().is_some());
        };
        for gate in gates {
            for term in gate.restrictive() {
                let condition = term.expression().expression();
                if !is_tautology(self.database, table, condition)?
                    && !self.entails(facts, condition)?
                {
                    return Ok(false);
                }
            }
            let mut admitted = false;
            for term in gate.permissive() {
                let condition = term.expression().expression();
                if is_tautology(self.database, table, condition)?
                    || self.entails(facts, condition)?
                {
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

    /// Whether a row meeting every one of `facts`, stated of its columns,
    /// meets `target`.
    fn entails(&self, facts: &[Expr], target: &Expr) -> Result<bool, LookupError> {
        let facts: Vec<Expr> = facts
            .iter()
            .flat_map(|fact| conjuncts(fact).into_iter().map(normalized))
            .collect();
        self.entails_normalized(&facts, &normalized(target))
    }

    /// [`Self::entails`] over normalized facts and target.
    fn entails_normalized(&self, facts: &[Expr], target: &Expr) -> Result<bool, LookupError> {
        let target = without_parentheses(target);
        if facts.iter().any(|fact| without_parentheses(fact) == target) {
            return Ok(true);
        }
        let parts = conjuncts(target);
        if parts.len() > 1 {
            for part in parts {
                if !self.entails_normalized(facts, part)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        let arms = disjuncts(target);
        if arms.len() > 1 {
            for arm in arms {
                if self.entails_normalized(facts, arm)? {
                    return Ok(true);
                }
            }
        }
        if let Some((items, wider)) = membership(target) {
            for fact in facts {
                if let Some((stated, members)) = membership(fact)
                    && stated == items
                    && self.is_set_within(&members, &wider)?
                {
                    return Ok(true);
                }
            }
        }
        for (index, fact) in facts.iter().enumerate() {
            let arms = disjuncts(fact);
            if arms.len() < 2 {
                continue;
            }
            let mut every = true;
            for arm in arms {
                let mut assumed: Vec<Expr> = facts
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .map(|(_, other)| other.clone())
                    .collect();
                assumed.extend(conjuncts(arm).into_iter().cloned());
                if !self.entails_normalized(&assumed, target)? {
                    every = false;
                    break;
                }
            }
            if every {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether every value the set expression `narrower` yields is one
    /// `wider` yields, as [`HelperSets::is_set_within`] reads them.
    fn is_set_within(&self, narrower: &Expr, wider: &Expr) -> Result<bool, LookupError> {
        self.sets.is_set_within(self.deployment, narrower, wider)
    }

    /// The arms of the helper `clause` reads the written key from, cached by
    /// the clause. The clause draws one column from a call to a
    /// set-returning `LANGUAGE sql` function, as `column IN (SELECT
    /// helper())` or `column = ANY (ARRAY(SELECT helper()))`, or draws
    /// `(items) IN (SELECT ... FROM helper() alias)` over one such call.
    fn helper_arms(&self, clause: &Expr) -> Result<Option<Rc<HelperArms<'a, DB>>>, LookupError> {
        let address: *const Expr = clause;
        if let Some(cached) = self.helpers.borrow().get(&address) {
            return Ok(cached.clone());
        }
        let found = self.read_helper_arms(clause)?.map(Rc::new);
        self.helpers.borrow_mut().insert(address, found.clone());
        Ok(found)
    }

    /// [`Self::helper_arms`] uncached.
    fn read_helper_arms(&self, clause: &Expr) -> Result<Option<HelperArms<'a, DB>>, LookupError> {
        if let Some(([item], set)) = membership(clause)
            && let Expr::Function(call) = set.as_ref()
        {
            let Some(function) =
                called(self.database, call)?.filter(|function| function.returns_set())
            else {
                return Ok(None);
            };
            return Ok(self
                .helper_body_arms(function, Reader::Writer)?
                .filter(|arms| arms.iter().all(|arm| arm.outputs.len() == 1))
                .map(|arms| HelperArms {
                    positions: self
                        .key_columns
                        .iter()
                        .map(|column| names_cast_column(item, column).then_some(0))
                        .collect(),
                    arms,
                }));
        }
        let Expr::In {
            expr,
            target: InTarget::Subquery(query),
            negated: false,
            ..
        } = without_parentheses(clause)
        else {
            return Ok(None);
        };
        let items = match without_parentheses(expr) {
            Expr::Tuple(items) => items.as_slice(),
            item => slice::from_ref(item),
        };
        let Some(select) = plain_select(query) else {
            return Ok(None);
        };
        let [from] = select.from.as_slice() else {
            return Ok(None);
        };
        if !from.joins.is_empty() || WrittenCall::relation(&from.relation).is_none() {
            return Ok(None);
        }
        let Some(arms) = self.select_arms(select, Reader::Writer)? else {
            return Ok(None);
        };
        // Each left item pairs with the output at its position, which every
        // arm must yield.
        let positions = self
            .key_columns
            .iter()
            .map(|column| {
                items
                    .iter()
                    .position(|item| names_cast_column(item, column))
                    .filter(|position| arms.iter().all(|arm| *position < arm.outputs.len()))
            })
            .collect();
        Ok(Some(HelperArms { positions, arms }))
    }

    /// The arms of `select`, read by `reader`, or `None` when one of its
    /// relations cannot be read.
    fn select_arms(
        &self,
        select: &Select,
        reader: Reader,
    ) -> Result<Option<Vec<Arm<'a, DB>>>, LookupError> {
        let mut rows: Vec<Row<'a, DB>> = Vec::new();
        let Some(mut sources) = self.read_sources(select, reader, &mut rows)? else {
            return Ok(None);
        };
        let resolve = |expression: &Expr| resolve_in(&sources, expression);
        // Filters on one row become its facts, and memberships of a column
        // become members of the values the arm draws from it.
        let mut members: Vec<(usize, String, Expr)> = Vec::new();
        for filter in filters(select) {
            if let Some((source, column, held)) = self.unheld(filter, &sources, reader)?
                && let SourceKind::Table(index) = sources[source].kind
            {
                rows[index].unheld.push((column, held));
            }
            if let Some((items, set)) = membership(filter)
                && let [item] = items
                && let Some((source, column)) = resolve(without_parentheses(item))
                && self.admissible(&set, reader)?
            {
                members.push((source, column, set.into_owned()));
            }
            let mut row = None;
            let Some(stated) = requalified(filter, |reference| {
                let (source, column) = resolve(reference)?;
                let SourceKind::Table(index) = sources[source].kind else {
                    return None;
                };
                if row.is_some_and(|row| row != index) {
                    return None;
                }
                row = Some(index);
                Some(column)
            }) else {
                continue;
            };
            if let Some(index) = row
                && self.admissible(&stated, reader)?
            {
                rows[index].facts.push(stated);
            }
        }
        // The source and column of each output, when it names one.
        let Some(projected) = projected_columns(&sources, select) else {
            return Ok(None);
        };
        // A helper the select reads yields one arm per arm of its body, when
        // the select reads no other helper and no table, and is opaque
        // otherwise.
        let mut helper = None;
        for source in &mut sources {
            if let SourceKind::Helper(arms) = &mut source.kind {
                if helper.is_none() && rows.is_empty() {
                    helper = Some(std::mem::take(arms));
                } else {
                    source.kind = SourceKind::Opaque;
                }
            }
        }
        let origin = |entry: &Option<(usize, String)>, arm: Option<&Arm<'a, DB>>| {
            let Some((index, column)) = entry else {
                return Origin::default();
            };
            let source = &sources[*index];
            let position = source.columns.iter().position(|name| name == column);
            let mut origin = match (&source.kind, arm) {
                (SourceKind::Table(row), _) => Origin {
                    row: Some((*row, column.clone())),
                    members: Vec::new(),
                },
                (SourceKind::Helper(_), Some(arm)) => position
                    .and_then(|position| arm.outputs.get(position))
                    .cloned()
                    .unwrap_or_default(),
                _ => Origin::default(),
            };
            origin.members.extend(
                position
                    .and_then(|position| source.sets.get(position))
                    .cloned(),
            );
            origin.members.extend(
                members
                    .iter()
                    .filter(|(from, name, _)| from == index && name == column)
                    .map(|(_, _, set)| set.clone()),
            );
            origin
        };
        Ok(Some(match helper {
            None => vec![Arm {
                outputs: projected.iter().map(|entry| origin(entry, None)).collect(),
                rows,
            }],
            Some(arms) => arms
                .into_iter()
                .map(|arm| Arm {
                    outputs: projected
                        .iter()
                        .map(|entry| origin(entry, Some(&arm)))
                        .collect(),
                    rows: arm.rows,
                })
                .collect(),
        }))
    }

    /// The source and column of the row `filter` keeps only when no row of
    /// the parent holds the column's value, with the stored name of the
    /// parent's column holding it, as `NOT EXISTS (SELECT ... FROM parent p
    /// WHERE p.held = row.column)` or `row.column NOT IN (SELECT held FROM
    /// parent)`, besides which the subquery may only test `held IS NOT
    /// NULL`. `reader` reads the subquery, and must read every row of the
    /// parent.
    fn unheld(
        &self,
        filter: &Expr,
        sources: &[Source<'a, DB>],
        reader: Reader,
    ) -> Result<Option<(usize, String, String)>, LookupError> {
        let (outer, query) = match without_parentheses(filter) {
            Expr::Exists {
                subquery,
                negated: true,
            } => (None, subquery.as_ref()),
            Expr::In {
                expr,
                target: InTarget::Subquery(query),
                negated: true,
                ..
            } => (Some(expr.as_ref()), query.as_ref()),
            _ => return Ok(None),
        };
        let Some((select, inner)) = self.parent_read(query, reader)? else {
            return Ok(None);
        };
        let inner_column = |expression: &Expr| {
            resolve_in(slice::from_ref(&inner), without_parentheses(expression))
                .map(|(_, column)| column)
        };
        // The inner columns the subquery tests `IS NOT NULL`, and its other
        // conjuncts.
        let mut tested = Vec::new();
        let mut others = Vec::new();
        for conjunct in select.selection.iter().flat_map(conjuncts) {
            match without_parentheses(conjunct) {
                Expr::IsNotNull(column) if let Some(column) = inner_column(column) => {
                    tested.push(column);
                }
                other => others.push(other),
            }
        }
        let found = if let Some(outer) = outer {
            let (
                [
                    SelectItem::UnnamedExpr(projected)
                    | SelectItem::ExprWithAlias {
                        expr: projected, ..
                    },
                ],
                [],
            ) = (select.projection.as_slice(), others.as_slice())
            else {
                return Ok(None);
            };
            inner_column(projected).zip(resolve_in(sources, without_parentheses(outer)))
        } else {
            let [
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Eq,
                    right,
                },
            ] = others.as_slice()
            else {
                return Ok(None);
            };
            // An outer column is qualified by a relation the subquery
            // does not read, so that it names no inner column.
            let outer_column = |expression: &Expr| match without_parentheses(expression) {
                qualified @ Expr::CompoundIdentifier(parts)
                    if parts.len() == 2 && identifier(&parts[0]) != inner.name =>
                {
                    resolve_in(sources, qualified)
                }
                _ => None,
            };
            [(left, right), (right, left)]
                .into_iter()
                .find_map(|(held, own)| inner_column(held).zip(outer_column(own)))
        };
        let Some((held, (source, column))) = found else {
            return Ok(None);
        };
        if tested.iter().any(|tested| *tested != held) || !self.reads_every_parent_row(reader)? {
            return Ok(None);
        }
        Ok(Some((source, column, held)))
    }

    /// The select `query` runs and its source, when it reads the parent and
    /// nothing else under no limit, sample or column renaming, so that every
    /// row of the parent its reader sees reaches its filter.
    fn parent_read<'q>(
        &self,
        query: &'q Query,
        reader: Reader,
    ) -> Result<Option<(&'q Select, Source<'a, DB>)>, LookupError> {
        let Some(select) = plain_select(query) else {
            return Ok(None);
        };
        let ([from], None, None, None) = (
            select.from.as_slice(),
            &query.limit_clause,
            &query.fetch,
            &select.having,
        ) else {
            return Ok(None);
        };
        let TableFactor::Table {
            name,
            alias,
            args: None,
            sample: None,
            ..
        } = &from.relation
        else {
            return Ok(None);
        };
        if !from.joins.is_empty() {
            return Ok(None);
        }
        let renamed_columns = renamed(alias.as_ref());
        let mut read = Vec::new();
        let Some(source) =
            self.table_source(name, alias.as_ref(), &renamed_columns, reader, &mut read)?
        else {
            return Ok(None);
        };
        Ok(read
            .first()
            .is_some_and(|row| row.table == self.parent)
            .then_some((select, source)))
    }

    /// Whether `reader` reads every row of the parent, under the rights of
    /// the innermost definer it reads within, or else as the writer past no
    /// row security.
    fn reads_every_parent_row(&self, reader: Reader) -> Result<bool, LookupError> {
        let definer = match reader {
            Reader::Body { definer: true } => self
                .reading
                .borrow()
                .iter()
                .rev()
                .copied()
                .find(|function| function.security_mode() == FunctionSecurity::Definer),
            _ => None,
        };
        match definer {
            Some(function) => reads_every_row(self.database, function, self.parent),
            None => Ok(!self.parent.has_row_level_security(self.database)?),
        }
    }

    /// The relations the `FROM` of `select` reads, read by `reader`, with
    /// the rows they add to `rows`, or `None` when one joins other than by a
    /// cross join or an inner join on a condition, or cannot be followed.
    fn read_sources(
        &self,
        select: &Select,
        reader: Reader,
        rows: &mut Vec<Row<'a, DB>>,
    ) -> Result<Option<Vec<Source<'a, DB>>>, LookupError> {
        let mut sources = Vec::new();
        for from in &select.from {
            if from.joins.iter().any(|join| {
                !matches!(
                    join.join_operator,
                    JoinOperator::CrossJoin(_)
                        | JoinOperator::Join(JoinConstraint::On(_))
                        | JoinOperator::Inner(JoinConstraint::On(_))
                )
            }) {
                return Ok(None);
            }
            for factor in
                std::iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
            {
                let Some(source) = self.source(factor, reader, rows)? else {
                    return Ok(None);
                };
                sources.push(source);
            }
        }
        Ok(Some(sources))
    }

    /// The relation `factor` reads, with the rows it adds to `rows`, or
    /// `None` when it is one the arm cannot follow.
    fn source(
        &self,
        factor: &TableFactor,
        reader: Reader,
        rows: &mut Vec<Row<'a, DB>>,
    ) -> Result<Option<Source<'a, DB>>, LookupError> {
        let alias = match factor {
            TableFactor::Table { alias, .. }
            | TableFactor::Function { alias, .. }
            | TableFactor::Derived { alias, .. }
            | TableFactor::UNNEST { alias, .. } => alias.as_ref(),
            _ => return Ok(None),
        };
        let renamed_columns = renamed(alias);
        // A subquery or an array expansion yields rows the arm learns nothing
        // of.
        if let TableFactor::Derived { .. } | TableFactor::UNNEST { .. } = factor {
            let Some(alias) = alias else {
                return Ok(None);
            };
            return Ok(Some(Source {
                name: identifier(&alias.name),
                columns: renamed_columns,
                counted: false,
                sets: Vec::new(),
                kind: SourceKind::Opaque,
            }));
        }
        if let TableFactor::Table {
            name, args: None, ..
        } = factor
        {
            return self.table_source(name, alias, &renamed_columns, reader, rows);
        }
        let Some(call) = WrittenCall::relation(factor) else {
            return Ok(None);
        };
        let called: Vec<&DB::Function> = self
            .database
            .functions_reached_by(call, IdentifierCase::Folded)?
            .collect();
        let function = match called.as_slice() {
            [function] => Some(*function),
            _ => None,
        };
        let name = call.to_string();
        let exposed = alias.map(|alias| identifier(&alias.name)).or_else(|| {
            let (TableFactor::Table { name, .. } | TableFactor::Function { name, .. }) = factor
            else {
                return None;
            };
            name.0
                .last()
                .and_then(|part| part.as_ident())
                .map(identifier)
        });
        let Some(exposed) = exposed else {
            return Ok(None);
        };
        let mut columns: Vec<String> = function.map_or_else(Vec::new, |function| {
            function
                .returned_columns(self.database)
                .map(|(name, _)| {
                    normalize_identifier(name.name(), name.name_is_quoted()).into_owned()
                })
                .collect()
        });
        if columns.is_empty() && function.is_some_and(FunctionLike::returns_set) {
            columns.push(exposed.clone());
        }
        let counted =
            function.is_some() && !columns.is_empty() && renamed_columns.len() <= columns.len();
        let width = if counted {
            columns.len()
        } else {
            renamed_columns.len()
        };
        let sets = self.call_sets(&name, counted.then_some(columns.as_slice()), width, reader)?;
        for (column, renamed) in columns.iter_mut().zip(&renamed_columns) {
            column.clone_from(renamed);
        }
        if !counted {
            columns = renamed_columns;
        }
        let kind = match function {
            Some(function) => match self.helper_body_arms(function, reader)? {
                Some(arms) => SourceKind::Helper(arms),
                None => SourceKind::Opaque,
            },
            None => SourceKind::Opaque,
        };
        Ok(Some(Source {
            name: exposed,
            columns,
            counted,
            sets,
            kind,
        }))
    }

    /// The set each column of the call written `call` takes its values in,
    /// by position. The call itself is the set of its only column when
    /// `width`, the number of its columns, is one, and `(call).column` the
    /// set of each column `names` lists by stored name otherwise. None when
    /// the call reads a column or parameter, or yields to `reader` what it
    /// does not yield the writer.
    fn call_sets(
        &self,
        call: &str,
        names: Option<&[String]>,
        width: usize,
        reader: Reader,
    ) -> Result<Vec<Expr>, LookupError> {
        let Ok(call) = Parser::new(&PostgreSqlDialect {})
            .try_with_sql(call)
            .and_then(|mut parser| parser.parse_expr())
        else {
            return Ok(Vec::new());
        };
        if reads_column_or_parameter(&call) || !self.admissible(&call, reader)? {
            return Ok(Vec::new());
        }
        Ok(match names {
            _ if width == 1 => vec![call],
            Some(names) => names
                .iter()
                .map(|column| column_of(call.clone(), column))
                .collect(),
            None => Vec::new(),
        })
    }

    /// The table `name` reads under `alias`, renaming its leading columns
    /// to `renamed_columns`, with the row it adds to `rows`, or `None` when
    /// it names no table. A table read with a column renamed to another name
    /// yields rows the arm learns nothing of, since facts and origins name
    /// the stored columns.
    fn table_source(
        &self,
        name: &ObjectName,
        alias: Option<&TableAlias>,
        renamed_columns: &[String],
        reader: Reader,
        rows: &mut Vec<Row<'a, DB>>,
    ) -> Result<Option<Source<'a, DB>>, LookupError> {
        let rendered = name.to_string();
        let Some(table) = TargetName::parse(&rendered).ok().and_then(|target| {
            self.database
                .resolve_target_table(target, IdentifierCase::Folded)
                .ok()
                .flatten()
        }) else {
            return Ok(None);
        };
        let mut columns: Vec<String> = table
            .columns(self.database)?
            .map(|column| column.stored_column_name().into_owned())
            .collect();
        let renames = columns
            .iter()
            .zip(renamed_columns)
            .any(|(column, renamed)| column != renamed);
        for (column, alias) in columns.iter_mut().zip(renamed_columns) {
            alias.clone_into(column);
        }
        let exposed = alias.map_or_else(
            || {
                name.0
                    .last()
                    .and_then(|part| part.as_ident())
                    .map(identifier)
            },
            |alias| Some(identifier(&alias.name)),
        );
        let Some(exposed) = exposed else {
            return Ok(None);
        };
        let kind = if renames {
            SourceKind::Opaque
        } else {
            rows.push(Row {
                table,
                facts: Vec::new(),
                read_by_writer: reader == Reader::Writer,
                unheld: Vec::new(),
            });
            SourceKind::Table(rows.len() - 1)
        };
        Ok(Some(Source {
            name: exposed,
            columns,
            counted: true,
            sets: Vec::new(),
            kind,
        }))
    }

    /// The arms of the body of the set-returning `LANGUAGE sql` `function`,
    /// called by `reader`, read as its owner when it or a helper enclosing
    /// the call is a definer, or `None` when its body is not one query of
    /// plain selects, it sets a parameter other than the search path, which
    /// may change what its expressions yield, a name in its body reaches
    /// another object on the search path it sets than on the schema's own,
    /// or the call is within its own body.
    fn helper_body_arms(
        &self,
        function: &'a DB::Function,
        reader: Reader,
    ) -> Result<Option<Vec<Arm<'a, DB>>>, LookupError> {
        if !sets_only_search_path(function)
            || self
                .reading
                .borrow()
                .iter()
                .any(|reading| ptr::eq(*reading, function))
        {
            return Ok(None);
        }
        let Some(body) = sql_set_body(self.database, function)? else {
            return Ok(None);
        };
        if body.with.is_some() {
            return Ok(None);
        }
        if let Some(path) = function.search_path(self.database)?
            && !resolves_alike(self.database, body.as_ref(), &path)?
        {
            return Ok(None);
        }
        let reader = Reader::Body {
            definer: function.security_mode() == FunctionSecurity::Definer
                || reader == Reader::Body { definer: true },
        };
        self.reading.borrow_mut().push(function);
        let arms = self.set_arms(&body.body, reader);
        self.reading.borrow_mut().pop();
        arms
    }

    /// The arms of a `UNION` of plain selects.
    fn set_arms(
        &self,
        body: &SetExpr,
        reader: Reader,
    ) -> Result<Option<Vec<Arm<'a, DB>>>, LookupError> {
        match body {
            SetExpr::Select(select) => self.select_arms(select, reader),
            SetExpr::Query(query) if query.with.is_none() => self.set_arms(&query.body, reader),
            SetExpr::SetOperation {
                op: SetOperator::Union,
                left,
                right,
                ..
            } => {
                let (Some(mut left), Some(right)) =
                    (self.set_arms(left, reader)?, self.set_arms(right, reader)?)
                else {
                    return Ok(None);
                };
                left.extend(right);
                Ok(Some(left))
            }
            _ => Ok(None),
        }
    }

    /// Whether `expression`, read by `reader`, yields what it yields in a
    /// policy the writer meets, as [`HelperSets::admissible`] reads a helper
    /// body.
    fn admissible(&self, expression: &Expr, reader: Reader) -> Result<bool, LookupError> {
        match reader {
            Reader::Writer => Ok(true),
            Reader::Body { definer } => self.sets.admissible(expression, definer),
        }
    }
}

/// A confinement read for `role`, which states a condition of the referenced
/// row through the key columns the key maps onto the referenced ones, a set
/// of key columns as a mask.
struct Reading<'c, 'a, DB: DatabaseLike> {
    confinement: &'c Confinement<'a, DB>,
    /// The role the helpers a check calls run for, or `None` for no role.
    role: Option<&'a DB::Role>,
    /// Conditions every written row whose key is checked meets besides its
    /// gate, as restrictive terms do.
    guards: &'c [Expr],
}

impl<DB: DatabaseLike> Reading<'_, '_, DB> {
    /// Whether every row `gate` admits meets `condition`, because a guard,
    /// a restrictive term or every permissive one implies it, or each of its
    /// conjuncts. A term may assume the guards and restrictive terms beside
    /// it. Without a gate, only the guards hold the row.
    fn gate_implies(
        &self,
        gate: Option<&RowGate<'_, DB::Policy>>,
        condition: &Condition<'_, u64>,
    ) -> Result<bool, LookupError> {
        let restrictive: Vec<&Expr> = gate
            .into_iter()
            .flat_map(RowGate::restrictive)
            .map(|term| term.expression().expression())
            .chain(self.guards)
            .collect();
        let context: Vec<&Expr> = restrictive
            .iter()
            .flat_map(|clause| conjuncts(clause))
            .collect();
        for clause in &restrictive {
            if clause_implies(self, clause, condition, &context)? {
                return Ok(true);
            }
        }
        if let Some(gate) = gate
            && !gate.permissive().is_empty()
        {
            let mut every = true;
            for term in gate.permissive() {
                if !clause_implies(self, term.expression().expression(), condition, &context)? {
                    every = false;
                    break;
                }
            }
            if every {
                return Ok(true);
            }
        }
        if condition.parts.is_empty() {
            return Ok(false);
        }
        for part in &condition.parts {
            if !self.gate_implies(gate, part)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl<DB: DatabaseLike> Columns for Reading<'_, '_, DB> {
    type Tested = u64;

    fn is_set_within(&self, narrower: &Expr, wider: &Expr) -> Result<bool, LookupError> {
        self.confinement.is_set_within(narrower, wider)
    }

    fn rename(&self, column: Cow<'_, str>) -> Option<String> {
        let confinement = self.confinement;
        confinement
            .referenced_columns
            .iter()
            .position(|referenced| *referenced == column)
            .map(|position| confinement.key_columns[position].to_string())
    }

    fn tested(&self, column: &Expr) -> Option<u64> {
        Some(positions(&self.confinement.referenced_columns, column)).filter(|mapped| *mapped != 0)
    }

    fn tests(&self, column: &Expr, tested: &u64) -> bool {
        self.confinement.key_columns_named(column) & tested != 0
    }

    /// A clause leaving a key column `NULL`, alone or under the written
    /// table's checks, skips a check that `NULL` skips.
    fn settles(&self, clause: &Expr) -> Result<bool, LookupError> {
        self.confinement.forces_null(clause)
    }

    /// A clause drawing the key from a set-returning helper whose every arm
    /// meets the condition.
    fn draws_implied(
        &self,
        clause: &Expr,
        condition: &Condition<'_, u64>,
        context: &[&Expr],
    ) -> Result<bool, LookupError> {
        self.confinement
            .helper_implies(clause, condition, context, self.role)
    }
}

/// Who reads a query, which is the writer under its own policies or the
/// body of a helper it calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reader {
    Writer,
    Body {
        /// Whether the helper runs as its owner.
        definer: bool,
    },
}

/// Whether every unqualified relation and function `body` names reaches on
/// `path` what it reaches on the schema's own search path. A function name
/// declared in more than one schema counts as reaching another, since
/// overloads resolve by argument types the paths may order differently.
pub(crate) fn resolves_alike<DB: DatabaseLike, V: Visit>(
    database: &DB,
    body: &V,
    path: &[(Cow<'_, str>, bool)],
) -> Result<bool, LookupError> {
    let mut names: Vec<ObjectName> = Vec::new();
    let _ = sqlparser::ast::visit_relations(body, |relation| {
        names.push(relation.clone());
        ControlFlow::<()>::Continue(())
    });
    let _ = visit_expressions(body, |expression| {
        if let Expr::Function(call) = expression {
            names.push(call.name.clone());
        }
        ControlFlow::<()>::Continue(())
    });
    for name in names.iter().filter(|name| name.0.len() == 1) {
        let own = stored_table(database, name, None)?;
        if own.is_some() {
            if stored_table(database, name, Some(path))? != own {
                return Ok(false);
            }
            continue;
        }
        let Some(called) = name.0[0].as_ident().map(identifier) else {
            return Ok(false);
        };
        let mut declaring = database.functions_named(&called).map(|function| {
            schema_of(database, function.target_name().schema().map(Cow::Borrowed)).into_owned()
        });
        let Some(schema) = declaring.next() else {
            continue;
        };
        if declaring.any(|other| other != schema) {
            return Ok(false);
        }
        let session = database
            .search_path()
            .any(|(listed, quoted)| normalize_identifier(listed, quoted) == schema);
        let own = path
            .iter()
            .any(|(listed, quoted)| normalize_identifier(listed, *quoted) == schema);
        // PostgreSQL searches `pg_catalog` on every path.
        if schema != "pg_catalog" && session != own {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The column `condition` admits into the values a subquery yields, as
/// `column = ANY (ARRAY(SELECT ...))` or `column IN (SELECT ...)`, with the
/// subquery.
fn sublink_operands(condition: &Expr) -> Option<(&Expr, &Query)> {
    match unwrapped(condition) {
        Expr::In {
            expr,
            target: InTarget::Subquery(query),
            negated: false,
            ..
        } => Some((expr.as_ref(), query.as_ref())),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => match unwrapped(right) {
            Expr::Function(Function {
                name,
                args: FunctionArguments::Subquery(query),
                ..
            }) if name.to_string().eq_ignore_ascii_case("array") => {
                Some((left.as_ref(), query.as_ref()))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The source and column of each output of `select` over `sources`, when
/// the output names one, or `None` when the outputs cannot be counted.
fn projected_columns<DB: DatabaseLike>(
    sources: &[Source<'_, DB>],
    select: &Select,
) -> Option<Vec<Option<(usize, String)>>> {
    /// The columns of the source at `index`, as outputs, or `None` when the
    /// source does not list them all.
    fn source_columns<'s, DB: DatabaseLike>(
        (index, source): (usize, &'s Source<'_, DB>),
    ) -> Option<impl Iterator<Item = Option<(usize, String)>> + 's> {
        source.counted.then(|| {
            source
                .columns
                .iter()
                .map(move |column| Some((index, column.clone())))
        })
    }
    let mut projected = Vec::new();
    for item in &select.projection {
        match item {
            SelectItem::Wildcard(_) => {
                for source in sources.iter().enumerate() {
                    projected.extend(source_columns(source)?);
                }
            }
            SelectItem::QualifiedWildcard(kind, _) => {
                let name = normalize_relation(&kind.to_string());
                let found = sources
                    .iter()
                    .enumerate()
                    .find(|(_, source)| source.name == name)?;
                projected.extend(source_columns(found)?);
            }
            SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. } => {
                projected.push(resolve_in(sources, without_parentheses(value)));
            }
            SelectItem::ExprWithAliases { .. } => return None,
        }
    }
    Some(projected)
}

/// The source and column `expression` names among `sources`.
fn resolve_in<DB: DatabaseLike>(
    sources: &[Source<'_, DB>],
    expression: &Expr,
) -> Option<(usize, String)> {
    match expression {
        Expr::Identifier(name) => {
            let column = identifier(name);
            let mut found = sources
                .iter()
                .enumerate()
                .filter(|(_, source)| source.columns.contains(&column));
            let (index, _) = found.next()?;
            found.next().is_none().then_some((index, column))
        }
        Expr::CompoundIdentifier(parts) => match parts.as_slice() {
            [relation, name] => {
                let relation = identifier(relation);
                let column = identifier(name);
                sources
                    .iter()
                    .position(|source| source.name == relation && source.columns.contains(&column))
                    .map(|index| (index, column))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The stored name of an identifier.
pub(crate) fn identifier(name: &Ident) -> String {
    normalize_identifier(&name.value, name.quote_style.is_some()).into_owned()
}

/// The stored name of a relation written `name`, unquoted.
fn normalize_relation(name: &str) -> String {
    normalize_identifier(name, false).into_owned()
}

/// The names `alias` gives the leading columns of the relation it names.
fn renamed(alias: Option<&TableAlias>) -> Vec<String> {
    alias.map_or_else(Vec::new, |alias| {
        alias
            .columns
            .iter()
            .map(|column| identifier(&column.name))
            .collect()
    })
}

/// The conjuncts that keep the rows `select` yields, from its `WHERE` and
/// from the condition of each inner join, which keeps rows as a filter does.
fn filters(select: &Select) -> impl Iterator<Item = &Expr> {
    let joined = select
        .from
        .iter()
        .flat_map(|from| &from.joins)
        .filter_map(|join| match &join.join_operator {
            JoinOperator::Join(JoinConstraint::On(condition))
            | JoinOperator::Inner(JoinConstraint::On(condition)) => Some(condition),
            _ => None,
        });
    select.selection.iter().chain(joined).flat_map(conjuncts)
}

/// The plain `SELECT` a query runs, when it has no `WITH`.
fn plain_select(query: &Query) -> Option<&Select> {
    match query.body.as_ref() {
        SetExpr::Select(select) if query.with.is_none() => Some(select),
        _ => None,
    }
}

/// `expression` with every column reference outside its subqueries named by
/// `rename` of the reference, or `None` when `rename` names none for one or
/// a subquery mentions a column.
fn requalified(expression: &Expr, rename: impl FnMut(&Expr) -> Option<String>) -> Option<Expr> {
    struct Renamer<F> {
        rename: F,
        depth: usize,
    }

    impl<F: FnMut(&Expr) -> Option<String>> VisitorMut for Renamer<F> {
        type Break = ();

        fn pre_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            self.depth += 1;
            ControlFlow::Continue(())
        }

        fn post_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            self.depth -= 1;
            ControlFlow::Continue(())
        }

        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            if !is_column_reference(expression) {
                return ControlFlow::Continue(());
            }
            if self.depth > 0 {
                return ControlFlow::Break(());
            }
            match (self.rename)(expression) {
                Some(name) => {
                    *expression = Expr::Identifier(Ident::new(name));
                    ControlFlow::Continue(())
                }
                None => ControlFlow::Break(()),
            }
        }
    }

    let mut renamed = expression.clone();
    VisitMut::visit(&mut renamed, &mut Renamer { rename, depth: 0 })
        .is_continue()
        .then_some(renamed)
}

/// `expression` without parentheses, with a scalar subquery selecting one
/// expression from nothing written as that expression and a qualified
/// column reference outside subqueries written bare, so that conditions on
/// one row compare as written.
fn normalized(expression: &Expr) -> Expr {
    struct Normalizer {
        depth: usize,
    }

    impl VisitorMut for Normalizer {
        type Break = ();

        fn pre_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            self.depth += 1;
            ControlFlow::Continue(())
        }

        fn post_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            self.depth -= 1;
            ControlFlow::Continue(())
        }

        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            let replaced = match expression {
                Expr::Nested(inner) => Some(inner.as_ref().clone()),
                Expr::Subquery(query) => scalar(query).cloned(),
                Expr::CompoundIdentifier(parts) if self.depth == 0 => {
                    parts.last().cloned().map(Expr::Identifier)
                }
                _ => None,
            };
            if let Some(replaced) = replaced {
                *expression = replaced;
            }
            ControlFlow::Continue(())
        }
    }

    let mut normalized = expression.clone();
    let _ = VisitMut::visit(&mut normalized, &mut Normalizer { depth: 0 });
    normalized
}

/// The one expression a query selects from nothing, with no other clause.
fn scalar(query: &Query) -> Option<&Expr> {
    let select = plain_select(query)?;
    match select.projection.as_slice() {
        [SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. }]
            if select.from.is_empty()
                && select.selection.is_none()
                && select.having.is_none()
                && query.limit_clause.is_none()
                && query.fetch.is_none() =>
        {
            Some(value)
        }
        _ => None,
    }
}

/// Whether `role` may write a key of its choosing through `statement` on
/// `child`, past its policies and unconfined by them, while `read` holds
/// the `SELECT` policies it meets on the referenced table, when it may read
/// it. Every written row whose key is checked also meets each of `guards`.
pub(crate) fn writes_free_key<'a, DB: DatabaseLike>(
    confinement: &Confinement<'a, DB>,
    child: &'a DB::Table,
    statement: RowStatement,
    written: RowVersion,
    role: Option<&'a DB::Role>,
    read: Option<&RowSecurity<'_, DB::Policy>>,
    guards: &[Expr],
) -> Result<bool, LookupError> {
    let Some(security) = row_security(confinement.database, child, statement, role)? else {
        return Ok(false);
    };
    let reads_matched_rows = |gate| match read {
        Some(read) => confinement.reads_matched_rows(gate, read, role, guards),
        None => Ok(false),
    };
    let Some(gates) = security.gates() else {
        return Ok(security.exemption().is_some() && !reads_matched_rows(None)?);
    };
    for gate in gates {
        if admits_nothing(confinement.database, child, gate)? {
            return Ok(false);
        }
    }
    for gate in gates.iter().filter(|gate| gate.row() == written) {
        if confinement.confining_gate(gate)?
            || confinement.pins_principal_column(gate)
            || reads_matched_rows(Some(gate))?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The stored names of `columns` of `table` that every client role writes
/// only with the value a declared principal accessor yields for it, so that
/// only rows of one principal hold each value.
pub(crate) fn principal_columns<'db, DB: DatabaseLike>(
    database: &'db DB,
    deployment: &Deployment,
    table: &'db DB::Table,
    columns: &[&'db DB::Column],
) -> Result<Vec<Cow<'db, str>>, LookupError> {
    let mut pinned = Vec::new();
    if deployment.principal_accessors().is_empty() {
        return Ok(pinned);
    }
    let mut roles = Vec::new();
    for (_, role) in client_roles(database, deployment) {
        roles.push((role, table.privileges(acting(role), database)?));
    }
    'columns: for &column in columns {
        let name = column.stored_column_name();
        for (role, held) in &roles {
            for (privilege, statement, written) in [
                (
                    &held.insert,
                    RowStatement::Insert { returning: false },
                    RowVersion::Inserted,
                ),
                (
                    &held.update,
                    RowStatement::Update { reads: false },
                    RowVersion::Updated,
                ),
            ] {
                if privilege.on_column(column)
                    && !writes_only_pinned(
                        database, deployment, table, statement, written, *role, &name,
                    )?
                {
                    continue 'columns;
                }
            }
        }
        pinned.push(name);
    }
    Ok(pinned)
}

/// Whether every row `role` writes through `statement` on `table` holds in
/// `column` the value a declared principal accessor yields for it, or the
/// statement writes nothing.
fn writes_only_pinned<'a, DB: DatabaseLike>(
    database: &'a DB,
    deployment: &Deployment,
    table: &'a DB::Table,
    statement: RowStatement,
    written: RowVersion,
    role: Option<&'a DB::Role>,
    column: &str,
) -> Result<bool, LookupError> {
    let Some(security) = row_security(database, table, statement, role)? else {
        return Ok(false);
    };
    let Some(gates) = security.gates() else {
        // An exempt role writes any value, and a refused write writes none.
        return Ok(security.infinite_recursion().is_some());
    };
    for gate in gates {
        if admits_nothing(database, table, gate)? {
            return Ok(true);
        }
    }
    Ok(gates
        .iter()
        .filter(|gate| gate.row() == written)
        .all(|gate| pins_principal(deployment, gate, column)))
}

/// Whether every row `gate` admits holds in `column` the value a declared
/// principal accessor yields, through a top-level `AND` term of a
/// restrictive policy or of every permissive one.
fn pins_principal<P>(deployment: &Deployment, gate: &RowGate<'_, P>, column: &str) -> bool {
    let pinned = |term: &GateTerm<'_, P>| {
        conjuncts(term.expression().expression())
            .into_iter()
            .any(|conjunct| pins_to_principal(deployment, conjunct, column))
    };
    gate.restrictive().iter().any(pinned)
        || (!gate.permissive().is_empty() && gate.permissive().iter().all(pinned))
}

/// Whether `conjunct` is `column = accessor`, either way round, for a
/// declared principal accessor reading no column.
fn pins_to_principal(deployment: &Deployment, conjunct: &Expr, column: &str) -> bool {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = unwrapped(conjunct)
    else {
        return false;
    };
    [(left, right), (right, left)]
        .into_iter()
        .any(|(tested, value)| {
            names_column(tested, column) && !reads_any_column(value) && {
                let value = selected(value);
                deployment
                    .principal_accessors()
                    .iter()
                    .any(|accessor| selected(accessor) == value)
            }
        })
}

/// `expression` under parentheses and scalar subqueries selecting one
/// expression from nothing.
fn selected(mut expression: &Expr) -> &Expr {
    loop {
        expression = match expression {
            Expr::Nested(inner) => inner,
            Expr::Subquery(query) => match scalar(query) {
                Some(value) => value,
                None => return expression,
            },
            _ => return expression,
        };
    }
}

/// Whether `expression` names a column anywhere, its subqueries included.
fn reads_any_column(expression: &Expr) -> bool {
    visit_expressions(expression, |inner| {
        if is_column_reference(inner) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .is_break()
}

/// Whether `gate` admits no row of `table`, holding no permissive policy, a
/// restrictive one PostgreSQL proves false, or only permissive ones it
/// proves false.
fn admits_nothing<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    gate: &RowGate<'_, DB::Policy>,
) -> Result<bool, LookupError> {
    for term in gate.restrictive() {
        if is_contradiction(database, table, term.expression().expression())? {
            return Ok(true);
        }
    }
    for term in gate.permissive() {
        if !is_contradiction(database, table, term.expression().expression())? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `privilege` lets its holder write a whole key over `columns` for
/// PostgreSQL to check. An insert must name every key column, since an
/// unnamed one takes its default. An update must set one, and every other
/// column it leaves must be `NOT NULL` when `kept` is set, so that the
/// stored value completes the key. A generated column follows the others.
pub(crate) fn writes_whole_key<'db, DB: DatabaseLike>(
    database: &'db DB,
    columns: impl IntoIterator<Item = &'db DB::Column>,
    privilege: &ColumnPrivilege<&'db DB::Column>,
    kept: bool,
) -> Result<bool, LookupError> {
    let mut sets_one = false;
    for column in columns {
        if privilege.on_column(column) {
            sets_one = true;
        } else if !column.is_generated(database) && (!kept || column.is_nullable(database)?) {
            return Ok(false);
        }
    }
    Ok(sets_one)
}

/// The positions among `columns` of the column `expression` names.
fn positions(columns: &[Cow<'_, str>], expression: &Expr) -> u64 {
    columns
        .iter()
        .enumerate()
        .filter(|(_, column)| names_cast_column(expression, column))
        .fold(0, |mask, (position, _)| mask | 1 << position)
}

/// Removes parentheses from an expression.
fn without_parentheses(mut expression: &Expr) -> &Expr {
    while let Expr::Nested(inner) = expression {
        expression = inner;
    }
    expression
}
