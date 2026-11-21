//! Submodule providing the `ForeignKeyExistenceOracle` rule.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::{LookupError, RowSecurityError},
    structs::{ColumnPrivilege, RowGate, RowSecurity, RowStatement, RowVersion},
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArguments, InTarget, Query, SelectItem, SetExpr, TableFactor,
    Visit, visit_expressions,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::names_cast_column,
        policy_read_support::sublink_reads,
        policy_support::{acting, client_roles, conjuncts, disjuncts, is_tautology, unwrapped},
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
/// every permissive one, with `=`, `= ANY` or `IN` to a function call that
/// reads no column or to a subquery reading the referenced table, or with an
/// `EXISTS` over the referenced table equating its column with the key column.
/// Such a subquery runs under the role's own policies and fails alike for a
/// hidden and a missing key. The rule does not run on SQLite, which has no
/// row-level security.
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

/// Whether the `SELECT` policies `role` meets on `parent` leave some row out.
fn hides_rows<DB: DatabaseLike>(
    database: &DB,
    parent: &DB::Table,
    role: Option<&DB::Role>,
) -> Result<bool, LookupError> {
    let Some(security) = row_security(database, parent, RowStatement::Select, role)? else {
        return Ok(false);
    };
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

/// Decides whether the check on a written row confines every column of the
/// foreign key to values its writer may point at. A set of key columns is a
/// bit mask over their positions in the key, which PostgreSQL caps at 32.
struct Confinement<'a, DB: DatabaseLike> {
    database: &'a DB,
    parent: &'a DB::Table,
    key_columns: Vec<Cow<'a, str>>,
}

impl<'a, DB: DatabaseLike> Confinement<'a, DB> {
    fn new(
        database: &'a DB,
        foreign_key: &'a DB::ForeignKey,
        parent: &'a DB::Table,
    ) -> Result<Self, LookupError> {
        let key_columns = foreign_key
            .host_columns(database)?
            .map(ColumnLike::stored_column_name)
            .collect();
        Ok(Self {
            database,
            parent,
            key_columns,
        })
    }

    /// Every key column.
    fn whole_key(&self) -> u64 {
        (1 << self.key_columns.len()) - 1
    }

    /// The key columns `expression` names.
    fn key_columns_named(&self, expression: &Expr) -> u64 {
        self.key_columns
            .iter()
            .enumerate()
            .filter(|(_, column)| names_cast_column(expression, column))
            .fold(0, |mask, (position, _)| mask | 1 << position)
    }

    /// Whether `query` yields only keys its writer may point at: rows of the
    /// referenced table read under the writer's policies, or values a
    /// function names without reading the written row.
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
        let mut functions = select.from.iter().flat_map(|from| {
            std::iter::once(&from.relation)
                .chain(from.joins.iter().map(|join| &join.relation))
                .filter(|factor| {
                    matches!(
                        factor,
                        TableFactor::Function { .. } | TableFactor::Table { args: Some(_), .. }
                    )
                })
        });
        if let Some(first) = functions.next() {
            return Ok(std::iter::once(first)
                .chain(functions)
                .all(|factor| !references_column(factor)));
        }
        let (_, reads) = sublink_reads(self.database, policy, Some(query))?;
        Ok(reads.iter().any(|read| read.table == self.parent))
    }

    /// Whether `value` holds only keys its writer may point at.
    fn confining_value(&self, policy: &DB::Policy, value: &Expr) -> Result<bool, LookupError> {
        match unwrapped(value) {
            Expr::Subquery(query) => self.confining_query(policy, query),
            Expr::Function(function) => match &function.args {
                FunctionArguments::Subquery(query)
                    if function.name.to_string().eq_ignore_ascii_case("array") =>
                {
                    self.confining_query(policy, query)
                }
                _ => Ok(!references_column(value)),
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

/// Whether `role` may write a key of its choosing through `statement` on the
/// referencing table, past its policies and unconfined by them.
fn writes_free_key<DB: DatabaseLike>(
    confinement: &Confinement<'_, DB>,
    child: &DB::Table,
    statement: RowStatement,
    written: RowVersion,
    role: Option<&DB::Role>,
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
        if confinement.confining_gate(gate)? {
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
        let confinement = Confinement::new(database, foreign_key, parent)?;
        let mut probes = Vec::new();
        for (name, role) in client_roles(database, reporter.deployment()) {
            if !hides_rows(database, parent, role)? {
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
            format!("Keep the key server-written, confine it in the WITH CHECK of '{child_name}' to rows the writer may point at, such as `IN (SELECT ... FROM {parent_name})`, or let the writer read every row of '{parent_name}'."),
        )?;
        Ok(())
    }
}
