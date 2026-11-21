//! Submodule providing the `ForeignKeyExistenceOracle` rule.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::{LookupError, RowSecurityError},
    structs::{ColumnPrivilege, GateTerm, RowGate, RowSecurity, RowStatement, RowVersion},
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArguments, Ident, InTarget, Query, SelectItem, SetExpr, Visit,
    VisitMut, VisitorMut, visit_expressions,
};

use crate::{
    deployment::Deployment,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::{names_cast_column, stored_name},
        policy_read_support::sublink_reads,
        policy_support::{
            acting, client_roles, conjuncts, disjuncts, is_column_reference, is_tautology,
            unwrapped,
        },
    },
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports a foreign key into a row-level-security
/// table whose referencing columns a client role may write while the
/// referenced table hides rows from it.
///
/// PostgreSQL checks a foreign key past row-level security, so the role learns
/// whether a key it cannot read exists from whether its write succeeds or fails
/// with `23503`. The roles are the declared app and anonymous roles and
/// `PUBLIC`. A role writes the key when it may insert every referencing column,
/// or update one while every other is updatable or `NOT NULL`, and the
/// referencing table's policies let the write through. The referenced table
/// hides rows when its `SELECT` policies for the role do not admit every row.
/// A write is excused when the check the referencing table applies to the
/// written row confines every key column, each in a restrictive policy or in
/// every permissive one, with `=`, `= ANY` or `IN` to a subquery reading the
/// referenced table, or with an `EXISTS` over the referenced table equating
/// its column with the key column. Such a subquery runs under the role's own
/// policies and fails alike for a hidden and a missing key. A write is also
/// excused when the check makes every row the key can match readable, which
/// holds when every restrictive and at least one permissive `SELECT` policy
/// of the referenced table tests the columns the key maps onto as the check
/// tests their key columns, or tests one against a set the check confines its
/// key column within, as written or declared with
/// [`Deployment::with_set_within`]. The rule does not run on SQLite, which
/// has no row-level security.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = ForeignKeyExistenceOracle::default().into();
/// constrainer.set_deployment(Deployment::default().with_app_role("app"));
/// let schema = "CREATE ROLE app;
///     CREATE TABLE secrets (id INT PRIMARY KEY);
///     ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
///     CREATE TABLE notes (id INT PRIMARY KEY, secret_id INT REFERENCES secrets (id));
///     GRANT INSERT ON notes TO app;";
/// let probing = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&probing).is_err());
/// let confined = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
///      CREATE POLICY notes_insert ON notes FOR INSERT TO app
///        WITH CHECK (secret_id IN (SELECT id FROM secrets));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&confined).is_ok());
/// ```
pub struct ForeignKeyExistenceOracle<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ForeignKeyExistenceOracle<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ForeignKeyExistenceOracle<DB>> for GenericConstrainer<DB> {
    fn from(rule: ForeignKeyExistenceOracle<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ForeignKeyExistenceOracle<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(ForeignKeyExistenceOracle),
            group: LintGroup::Pedantic,
            rationale: "Referential integrity checks bypass row-level security, so a role that may write a foreign key learns whether a row it cannot read exists from whether its write fails.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE authenticated;\n\
CREATE TABLE secrets (id INT PRIMARY KEY);\n\
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;\n\
CREATE TABLE notes (id INT PRIMARY KEY, secret_id INT REFERENCES secrets (id));\n\
GRANT INSERT ON notes TO authenticated;",
                good: "CREATE ROLE authenticated;\n\
CREATE TABLE secrets (id INT PRIMARY KEY);\n\
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;\n\
CREATE TABLE notes (id INT PRIMARY KEY, secret_id INT REFERENCES secrets (id));\n\
GRANT INSERT ON notes TO authenticated;\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY notes_insert ON notes FOR INSERT TO authenticated WITH CHECK (secret_id IN (SELECT id FROM secrets));",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

/// The row security `role` meets running `statement` on `table`, or `None`
/// when the schema cannot settle it for the role.
fn row_security<'db, DB: DatabaseLike>(
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

/// Whether the `SELECT` policies of `parent` in `security` leave some row out.
fn hides_rows<DB: DatabaseLike>(
    database: &DB,
    parent: &DB::Table,
    security: &RowSecurity<'_, DB::Policy>,
) -> Result<bool, LookupError> {
    let Some(gates) = security.gates() else {
        // An exempt role reads every row, and a refused read reads none.
        return Ok(security.infinite_recursion().is_some());
    };
    for gate in gates {
        let mut admitted = false;
        for term in gate.permissive() {
            if is_tautology(database, parent, term.expression().expression())? {
                admitted = true;
                break;
            }
        }
        for term in gate.restrictive() {
            if !is_tautology(database, parent, term.expression().expression())? {
                admitted = false;
            }
        }
        if !admitted {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Decides whether the check on a written row confines the foreign key to
/// rows its writer may point at. A set of key columns is a bit mask over
/// their positions in the key, which PostgreSQL caps at 32.
struct Confinement<'a, DB: DatabaseLike> {
    database: &'a DB,
    deployment: &'a Deployment,
    parent: &'a DB::Table,
    key_columns: Vec<Cow<'a, str>>,
    referenced_columns: Vec<Cow<'a, str>>,
}

impl<'a, DB: DatabaseLike> Confinement<'a, DB> {
    fn new(
        database: &'a DB,
        deployment: &'a Deployment,
        foreign_key: &'a DB::ForeignKey,
        parent: &'a DB::Table,
    ) -> Result<Self, LookupError> {
        let key_columns = foreign_key
            .host_columns(database)?
            .map(ColumnLike::stored_column_name)
            .collect();
        let referenced_columns = foreign_key
            .referenced_columns(database)?
            .map(ColumnLike::stored_column_name)
            .collect();
        Ok(Self {
            database,
            deployment,
            parent,
            key_columns,
            referenced_columns,
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

    /// The key columns the conjunct confines.
    fn columns_confined_by_conjunct(
        &self,
        policy: &DB::Policy,
        conjunct: &Expr,
    ) -> Result<u64, LookupError> {
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

    /// The key columns the clause confines: those one of its conjuncts
    /// confines, or every arm of a disjunction does.
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
    /// the `SELECT` policies `read`, for every row `written` admits.
    fn reads_matched_rows(
        &self,
        written: &RowGate<'_, DB::Policy>,
        read: &RowSecurity<'_, DB::Policy>,
    ) -> Result<bool, LookupError> {
        let Some(gates) = read.gates() else {
            return Ok(false);
        };
        for gate in gates {
            for term in gate.restrictive() {
                let condition = term.expression().expression();
                if !is_tautology(self.database, self.parent, condition)?
                    && !self.gate_implies(written, &self.condition(condition))
                {
                    return Ok(false);
                }
            }
            let mut admitted = false;
            for term in gate.permissive() {
                let condition = term.expression().expression();
                if is_tautology(self.database, self.parent, condition)?
                    || self.gate_implies(written, &self.condition(condition))
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

    /// Whether every row `gate` admits meets `condition`: a restrictive term
    /// or every permissive one implies it, or each of its conjuncts or one of
    /// its arms.
    fn gate_implies(&self, gate: &RowGate<'_, DB::Policy>, condition: &Condition<'_>) -> bool {
        let implied_by = |term: &GateTerm<'_, DB::Policy>| {
            self.clause_implies(term.expression().expression(), condition)
        };
        gate.restrictive().iter().any(implied_by)
            || (!gate.permissive().is_empty() && gate.permissive().iter().all(implied_by))
            || (!condition.parts.is_empty()
                && condition
                    .parts
                    .iter()
                    .all(|part| self.gate_implies(gate, part)))
            || condition
                .arms
                .iter()
                .any(|arm| self.gate_implies(gate, arm))
    }

    /// `condition` on the referenced row as a check on the written row would
    /// state it of the key columns.
    fn condition<'e>(&self, condition: &'e Expr) -> Condition<'e> {
        let condition = without_parentheses(condition);
        let split = |operands: Vec<&'e Expr>| {
            if operands.len() > 1 {
                operands
                    .into_iter()
                    .map(|operand| self.condition(operand))
                    .collect()
            } else {
                Vec::new()
            }
        };
        Condition {
            renamed: renamed(condition, |column| {
                self.referenced_columns
                    .iter()
                    .position(|referenced| *referenced == column)
                    .map(|position| self.key_columns[position].to_string())
            }),
            membership: membership(condition)
                .map(|(column, members)| (positions(&self.referenced_columns, column), members))
                .filter(|(mapped, _)| *mapped != 0),
            parts: split(conjuncts(condition)),
            arms: split(disjuncts(condition)),
        }
    }

    /// Whether every row `clause` admits meets `condition`: the clause states
    /// it, every arm of the clause or one of its conjuncts implies it, or the
    /// clause implies each conjunct or one arm of `condition`.
    fn clause_implies(&self, clause: &Expr, condition: &Condition<'_>) -> bool {
        let clause = without_parentheses(clause);
        if let Some(stated) = &condition.renamed
            && renamed(clause, |column| Some(column.into_owned())).as_ref() == Some(stated)
        {
            return true;
        }
        if let Some((mapped, wider)) = condition.membership
            && let Some((column, members)) = membership(clause)
            && self.key_columns_named(column) & mapped != 0
            && members.within(wider, self.deployment)
        {
            return true;
        }
        let arms = disjuncts(clause);
        if arms.len() > 1 && arms.iter().all(|arm| self.clause_implies(arm, condition)) {
            return true;
        }
        if !condition.parts.is_empty()
            && condition
                .parts
                .iter()
                .all(|part| self.clause_implies(clause, part))
        {
            return true;
        }
        let parts = conjuncts(clause);
        (parts.len() > 1
            && parts
                .iter()
                .any(|part| self.clause_implies(part, condition)))
            || condition
                .arms
                .iter()
                .any(|arm| self.clause_implies(clause, arm))
    }
}

/// Whether `expression` is a column reference, bare or qualified.
fn is_column(expression: &Expr) -> bool {
    matches!(
        unwrapped(expression),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
    )
}

/// Whether `node` mentions a column, which in a policy can be one of the
/// written row's.
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

/// A condition of a `SELECT` policy of the referenced table, as a check on
/// the written row would state it of the key columns.
struct Condition<'e> {
    /// The condition with each column it tests named by the key column the
    /// key maps onto it, when the key maps every one.
    renamed: Option<Expr>,
    /// The key columns mapped onto the column the condition tests against a
    /// set, and the members of the set.
    membership: Option<(u64, Members<'e>)>,
    /// The conjuncts of an `AND`, each implied for the whole.
    parts: Vec<Condition<'e>>,
    /// The arms of an `OR`, one implied for the whole.
    arms: Vec<Condition<'e>>,
}

/// `expression` with every column reference named by `rename` of its stored
/// name, or `None` when `rename` names none for one or a subquery reads a
/// column, which may resolve to another table's.
fn renamed(expression: &Expr, rename: impl Fn(Cow<'_, str>) -> Option<String>) -> Option<Expr> {
    struct Renamer<F> {
        rename: F,
        depth: usize,
    }

    impl<F: Fn(Cow<'_, str>) -> Option<String>> VisitorMut for Renamer<F> {
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
            match stored_name(expression).and_then(&self.rename) {
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

/// The members of a set a policy tests a column against, by the expression
/// yielding them, which reads no column.
#[derive(Clone, Copy)]
enum Members<'e> {
    /// The value of `=`, or the rows of a subquery projecting it alone.
    Rows(&'e Expr),
    /// The elements of an array.
    Elements(&'e Expr),
}

impl<'e> Members<'e> {
    /// The members of `value` as the operand of `=`.
    fn of_value(value: &'e Expr) -> Option<Self> {
        match unwrapped(value) {
            Expr::Subquery(query) => Self::of_query(query),
            value => (!references_column(value)).then_some(Self::Rows(value)),
        }
    }

    /// The members of `query`, when it projects one expression and reads,
    /// filters and limits nothing.
    fn of_query(query: &'e Query) -> Option<Self> {
        let SetExpr::Select(select) = query.body.as_ref() else {
            return None;
        };
        if query.with.is_some()
            || query.limit_clause.is_some()
            || query.fetch.is_some()
            || !query.pipe_operators.is_empty()
            || !select.from.is_empty()
            || select.selection.is_some()
            || select.having.is_some()
        {
            return None;
        }
        match select.projection.as_slice() {
            [SelectItem::UnnamedExpr(value) | SelectItem::ExprWithAlias { expr: value, .. }] => {
                Self::of_value(value)
            }
            _ => None,
        }
    }

    /// The members of `array` as the operand of `= ANY`.
    fn of_array(array: &'e Expr) -> Option<Self> {
        match unwrapped(array) {
            Expr::Function(function) if function.name.to_string().eq_ignore_ascii_case("array") => {
                match &function.args {
                    FunctionArguments::Subquery(query) => Self::of_query(query),
                    _ => None,
                }
            }
            array => (!references_column(array)).then_some(Self::Elements(array)),
        }
    }

    /// Whether every member is one of `wider`, as written or declared.
    fn within(self, wider: Self, deployment: &Deployment) -> bool {
        match (self, wider) {
            (Self::Rows(narrower), Self::Rows(wider))
            | (Self::Elements(narrower), Self::Elements(wider)) => {
                deployment.is_set_within(narrower, wider)
            }
            _ => false,
        }
    }
}

/// The column `condition` tests against a set with `=`, `= ANY` or `IN`,
/// and the members of the set.
fn membership(condition: &Expr) -> Option<(&Expr, Members<'_>)> {
    match unwrapped(condition) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => [(left, right), (right, left)]
            .into_iter()
            .find_map(|(column, value)| {
                if is_column(column) {
                    Some((column.as_ref(), Members::of_value(value)?))
                } else {
                    None
                }
            }),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } if is_column(left) => Some((left, Members::of_array(right)?)),
        Expr::In {
            expr,
            target: InTarget::Subquery(query),
            negated: false,
            ..
        } if is_column(expr) => Some((expr, Members::of_query(query)?)),
        _ => None,
    }
}

/// Whether `role` may write a key of its choosing through `statement` on the
/// referencing table, past its policies and unconfined by them, while `read`
/// holds the `SELECT` policies it meets on the referenced table.
fn writes_free_key<DB: DatabaseLike>(
    confinement: &Confinement<'_, DB>,
    child: &DB::Table,
    statement: RowStatement,
    written: RowVersion,
    role: Option<&DB::Role>,
    read: &RowSecurity<'_, DB::Policy>,
) -> Result<bool, LookupError> {
    let Some(security) = row_security(confinement.database, child, statement, role)? else {
        return Ok(false);
    };
    let Some(gates) = security.gates() else {
        return Ok(security.exemption().is_some());
    };
    if gates.iter().any(|gate| gate.permissive().is_empty()) {
        return Ok(false);
    }
    for gate in gates.iter().filter(|gate| gate.row() == written) {
        if confinement.confining_gate(gate)? || confinement.reads_matched_rows(gate, read)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `privilege` lets its holder write a whole key of `foreign_key`
/// for PostgreSQL to check. An insert must name every key column, since an
/// unnamed one is `NULL` and the check is skipped. An update must set one,
/// and every other column it leaves must be `NOT NULL` when `kept` is set,
/// so that the stored value completes the key.
fn writes_whole_key<DB: DatabaseLike>(
    database: &DB,
    foreign_key: &DB::ForeignKey,
    privilege: &ColumnPrivilege<'_, DB::Column>,
    kept: bool,
) -> Result<bool, LookupError> {
    let mut sets_one = false;
    for column in foreign_key.host_columns(database)? {
        if privilege.on_column(column) {
            sets_one = true;
        } else if !kept || column.is_nullable(database)? {
            return Ok(false);
        }
    }
    Ok(sets_one)
}

impl<DB: DatabaseLike> ForeignKeyRule for ForeignKeyExistenceOracle<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let parent = foreign_key.referenced_table(database)?;
        if !parent.has_row_level_security(database)? {
            return Ok(());
        }
        let child = foreign_key.host_table(database);
        let confinement = Confinement::new(database, reporter.deployment(), foreign_key, parent)?;
        let mut probes = Vec::new();
        for (name, role) in client_roles(database, reporter.deployment()) {
            let Some(read) = row_security(database, parent, RowStatement::Select, role)? else {
                continue;
            };
            if !hides_rows(database, parent, &read)? {
                continue;
            }
            let held = child.privileges(acting(role), database)?;
            let mut commands = Vec::new();
            if writes_whole_key(database, foreign_key, &held.insert, false)?
                && writes_free_key(
                    &confinement,
                    child,
                    RowStatement::Insert { returning: false },
                    RowVersion::Inserted,
                    role,
                    &read,
                )?
            {
                commands.push("INSERT");
            }
            if writes_whole_key(database, foreign_key, &held.update, true)?
                && writes_free_key(
                    &confinement,
                    child,
                    RowStatement::Update { reads: false },
                    RowVersion::Updated,
                    role,
                    &read,
                )?
            {
                commands.push("UPDATE");
            }
            if !commands.is_empty() {
                probes.push(format!("{name} through {}", commands.join(" and ")));
            }
        }
        if probes.is_empty() {
            return Ok(());
        }
        let child_name = child.table_name();
        let parent_name = parent.table_name();
        reporter.foreign_key(
            foreign_key,
            format!(
                "A foreign key of '{child_name}' into '{parent_name}' tells {} whether a row of '{parent_name}' it cannot read exists, since the key is checked past row-level security.",
                probes.join(", ")
            ),
            format!("Keep the key server-written, confine it in the WITH CHECK of '{child_name}' to rows the writer may point at, such as `IN (SELECT ... FROM {parent_name})` or the set the SELECT policies of '{parent_name}' test the column the key maps onto against, or let the writer read every row of '{parent_name}'."),
        )?;
        Ok(())
    }
}
