//! Submodule providing the `ForeignKeyBrokenBeforeRepair` rule.

use std::{
    collections::{HashMap, HashSet},
    ops::ControlFlow,
};

use sql_traits::{
    errors::LookupError,
    structs::ConstraintDeferral,
    traits::{
        ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, Relation, TableLike, TriggerLike,
    },
};
use sqlparser::ast::{
    AssignmentTarget, Delete, Expr, FromTable, Ident, Insert, ObjectName, Query, ReferentialAction,
    SetExpr, Statement, TableFactor, TableObject, TableWithJoins, TriggerPeriod, Update, Visitor,
};
use sqlparser_plpgsql::embedded::{Node, NodeKind};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::stored_table,
        key_support::{equality_keys, key_pairs},
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        policy_support::conjuncts,
        trigger_support::{fires_on_insert, last_name, row_trigger, stored},
        walk_support::{canonical, walk},
    },
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports a PL/pgSQL body statement leaving
    /// rows that reference a missing row, when only a later statement of the
    /// same body deletes, repoints or inserts what would repair them.
    ///
    /// PostgreSQL checks a foreign key that is not `INITIALLY DEFERRED` at
    /// the end of each statement a function body runs, not at the end of the
    /// statement that called the function, and a `RESTRICT` action checks
    /// even a deferred key there. The rule reports three orders, each where
    /// the two statements name the rows by the same values:
    ///
    /// - a `DELETE` of referenced rows, or an `UPDATE` of their key, under a
    ///   `NO ACTION` or `RESTRICT` action, before a statement deleting or
    ///   repointing the referencing rows;
    /// - an `INSERT` or an `UPDATE` writing the key of referencing rows
    ///   before an `INSERT` of the row they reference;
    /// - in the function of a row-level `AFTER INSERT` trigger that fires
    ///   before the key's own check of `NEW`, an `UPDATE` of the row the
    ///   trigger fired for, matched on a unique key against `NEW`, before an
    ///   `INSERT` of the row `NEW` references. PostgreSQL checks the
    ///   unchanged key of a row the transaction wrote again. It fires the
    ///   `AFTER` row triggers of one row in the byte order of their names,
    ///   and names the key's check `RI_ConstraintTrigger_c_` and a number.
    ///
    /// Statements inside a block with an `EXCEPTION` clause are left out,
    /// as are writes held in one statement, such as a data-modifying `WITH`,
    /// which PostgreSQL checks at the statement's end.
    ///
    /// The rule does not run on SQLite, which has no stored functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ForeignKeyBrokenBeforeRepair::default().into();
    /// let schema = |body: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE TABLE p (id INT PRIMARY KEY);
    ///          CREATE TABLE t (id INT PRIMARY KEY, parent INT REFERENCES p (id));
    ///          CREATE FUNCTION drop_parent() RETURNS trigger LANGUAGE plpgsql AS $$
    ///          BEGIN {body} RETURN OLD; END $$;"
    ///     ))
    ///     .unwrap()
    /// };
    /// let parent_first = schema(
    ///     "DELETE FROM p WHERE id = OLD.parent; DELETE FROM t WHERE parent = OLD.parent;",
    /// );
    /// assert!(constrainer.validate_schema(&parent_first).is_err());
    /// let children_first = schema(
    ///     "DELETE FROM t WHERE parent = OLD.parent; DELETE FROM p WHERE id = OLD.parent;",
    /// );
    /// assert!(constrainer.validate_schema(&children_first).is_ok());
    /// ```
    ForeignKeyBrokenBeforeRepair,
    register_function_rule,
    LintGroup::Correctness,
    "PostgreSQL checks an immediate foreign key at the end of each statement inside a function body, so a statement that leaves rows referencing a missing row raises even when a later statement of the same body would repair them.",
    Some(
        "https://www.postgresql.org/docs/18/sql-createtable.html#SQL-CREATETABLE-PARMS-REFERENCES"
    ),
    RuleExample {
        bad: "CREATE TABLE parents (id integer PRIMARY KEY);\n\
CREATE TABLE children (id integer PRIMARY KEY, parent_id integer REFERENCES parents (id));\n\
CREATE FUNCTION drop_parent() RETURNS trigger LANGUAGE plpgsql AS $$\n\
BEGIN\n  DELETE FROM parents WHERE id = OLD.parent_id;\n  DELETE FROM children WHERE parent_id = OLD.parent_id;\n  RETURN OLD;\nEND $$;",
        good: "CREATE TABLE parents (id integer PRIMARY KEY);\n\
CREATE TABLE children (id integer PRIMARY KEY, parent_id integer REFERENCES parents (id));\n\
CREATE FUNCTION drop_parent() RETURNS trigger LANGUAGE plpgsql AS $$\n\
BEGIN\n  DELETE FROM children WHERE parent_id = OLD.parent_id;\n  DELETE FROM parents WHERE id = OLD.parent_id;\n  RETURN OLD;\nEND $$;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

/// What a body statement does to the rows of one table.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Insert,
    Update,
    Delete,
}

/// A `DELETE`, `UPDATE` or `INSERT` of one table, with the values it names
/// rows by and the values it writes, each in a canonical spelling.
struct Write<'db, DB: DatabaseLike> {
    kind: Kind,
    table: &'db DB::Table,
    /// The value each column is set equal to by a conjunct of the `WHERE`.
    pinned: Vec<(String, String)>,
    /// The value written to each column, when it reads no column of the
    /// written table.
    written: Vec<(String, String)>,
    /// Every column the statement writes.
    assigned: Vec<String>,
}

impl<DB: DatabaseLike> Write<'_, DB> {
    fn pinned(&self, column: &str) -> Option<&str> {
        value_of(&self.pinned, column)
    }

    fn written(&self, column: &str) -> Option<&str> {
        value_of(&self.written, column)
    }

    fn assigns(&self, column: &str) -> bool {
        self.assigned.iter().any(|assigned| assigned == column)
    }
}

/// The value `pairs` gives `column`.
fn value_of<'p>(pairs: &'p [(String, String)], column: &str) -> Option<&'p str> {
    pairs
        .iter()
        .find_map(|(named, value)| (named == column).then_some(value.as_str()))
}

/// How a statement leaves rows referencing a missing row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cause {
    /// It deleted referenced rows.
    Deleted,
    /// It changed the key of referenced rows.
    Rekeyed,
    /// It wrote the key of referencing rows.
    Referencing,
    /// It updated the row an `AFTER INSERT` trigger fired for.
    OwnRow,
}

/// An enforced foreign key, with its tables and the stored names of its
/// `(host, referenced)` column pairs.
struct Key<'db, DB: DatabaseLike> {
    constraint: &'db DB::ForeignKey,
    host: &'db DB::Table,
    referenced: &'db DB::Table,
    pairs: Vec<(String, String)>,
}

/// A statement that leaves rows referencing a missing row unless they are
/// already repaired, waiting for a later statement that repairs them.
#[derive(Clone)]
struct Broken {
    /// The position of the statement in the body.
    order: usize,
    /// The position of the foreign key among the walked keys.
    key: usize,
    /// The value of each column pair of the key the statement names the
    /// rows by, in the key's order.
    values: Vec<String>,
    cause: Cause,
    /// Whether the key's action is `RESTRICT`.
    restricts: bool,
}

/// The statements a path ran that wait for a repair.
#[derive(Clone)]
struct Pending(Vec<Broken>);

impl FlowState for Pending {
    fn join(&mut self, other: Self) {
        for broken in other.0 {
            if !self.0.iter().any(|known| {
                (known.order, known.key, known.cause) == (broken.order, broken.key, broken.cause)
            }) {
                self.0.push(broken);
            }
        }
    }
}

/// A repair that came too late, as the rule reports it.
struct Finding {
    message: String,
    advice: String,
}

/// Walks a body, pairing each statement that leaves rows referencing a
/// missing row with a later one that repairs them.
struct Repairs<'db, DB: DatabaseLike> {
    database: &'db DB,
    /// Every enforced foreign key of the schema.
    keys: Vec<Key<'db, DB>>,
    /// The tables a row-level `AFTER INSERT` trigger running the function
    /// is on.
    inserted: Vec<&'db DB::Table>,
    /// The position of each statement, in the order the walk first meets
    /// them, which is the order of the body's text.
    orders: HashMap<*const Statement, usize>,
    /// The statements inside a block with an `EXCEPTION` clause.
    handled: HashSet<*const Statement>,
    /// The `(statement, key)` pairs already reported.
    reported: HashSet<(usize, usize)>,
    signature: String,
    findings: Vec<Finding>,
    failure: Option<LookupError>,
}

/// Collects the statements under a block with an `EXCEPTION` clause.
fn handled_statements(nodes: &[Node], handled: bool, found: &mut HashSet<*const Statement>) {
    for node in nodes {
        match &node.kind {
            NodeKind::Statement { statement, .. } if handled => {
                found.insert(&raw const **statement);
            }
            NodeKind::Block(block) => {
                handled_statements(
                    &block.statements,
                    handled || !block.handlers.is_empty(),
                    found,
                );
                for handler in &block.handlers {
                    handled_statements(&handler.statements, handled, found);
                }
            }
            NodeKind::If(conditional) => {
                for branch in &conditional.branches {
                    handled_statements(&branch.statements, handled, found);
                }
                handled_statements(&conditional.otherwise, handled, found);
            }
            NodeKind::Case(case) => {
                for branch in &case.branches {
                    handled_statements(&branch.statements, handled, found);
                }
                if let Some(otherwise) = &case.otherwise {
                    handled_statements(otherwise, handled, found);
                }
            }
            NodeKind::Loop(repeated) => {
                handled_statements(&repeated.statements, handled, found);
            }
            _ => {}
        }
    }
}

/// The columns of a written table and the name its rows go by.
struct Target<'n> {
    exposed: &'n str,
    columns: &'n [String],
}

impl Target<'_> {
    /// The column of the table `expression` names.
    fn column(&self, expression: &Expr) -> Option<String> {
        let (qualifier, ident) = match expression {
            Expr::Nested(inner) => return self.column(inner),
            Expr::Identifier(ident) => (None, ident),
            Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                [qualifier, ident] => (Some(qualifier), ident),
                _ => return None,
            },
            _ => return None,
        };
        let name = stored(ident);
        (qualifier.is_none_or(|qualifier| stored(qualifier) == self.exposed)
            && self.columns.iter().any(|column| *column == name))
        .then(|| name.into_owned())
    }

    /// The canonical spelling of `expression` when it stands for one value
    /// the statement does not read from the table: no column of it, no
    /// query and no call, whose result may change between statements.
    fn outside(&self, expression: &Expr) -> Option<String> {
        struct Reads<'t, 'n>(&'t Target<'n>);
        impl Visitor for Reads<'_, '_> {
            type Break = ();
            fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
                match expression {
                    Expr::Identifier(_) | Expr::CompoundIdentifier(_)
                        if self.0.column(expression).is_some() =>
                    {
                        ControlFlow::Break(())
                    }
                    Expr::Function(_) => ControlFlow::Break(()),
                    _ => ControlFlow::Continue(()),
                }
            }
            fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
                ControlFlow::Break(())
            }
        }
        if walk(expression, &mut Reads(self)).is_break() {
            return None;
        }
        let spelled = canonical(expression);
        (spelled != "NULL").then_some(spelled)
    }

    /// The `column = value` conjuncts of `selection`.
    fn pinned(&self, selection: Option<&Expr>) -> Vec<(String, String)> {
        let mut pinned = Vec::new();
        for conjunct in selection.map_or_default(conjuncts) {
            let Expr::BinaryOp {
                left,
                op: sqlparser::ast::BinaryOperator::Eq,
                right,
            } = conjunct
            else {
                continue;
            };
            for (column, value) in [(left, right), (right, left)] {
                if let Some(column) = self.column(column)
                    && let Some(value) = self.outside(value)
                {
                    pinned.push((column, value));
                }
            }
        }
        pinned
    }
}

/// The stored names of the `AFTER` row triggers PostgreSQL fires before a
/// foreign key's check of an inserted row sort below this prefix of the
/// check's own name.
const KEY_CHECK_TRIGGER: &str = "RI_ConstraintTrigger_c_";

/// The canonical spelling of `NEW.column`.
fn new_column(column: &str) -> String {
    canonical(&Expr::CompoundIdentifier(vec![
        Ident::new("new"),
        Ident::with_quote('"', column),
    ]))
}

/// The single table a `DELETE` or `UPDATE` writes, with the name it goes by.
fn sole_table(relation: &TableWithJoins) -> Option<(&ObjectName, String)> {
    let TableFactor::Table {
        name,
        alias,
        args: None,
        ..
    } = &relation.relation
    else {
        return None;
    };
    if !relation.joins.is_empty() {
        return None;
    }
    let exposed = match alias {
        Some(alias) if alias.columns.is_empty() => stored(&alias.name).into_owned(),
        Some(_) => return None,
        None => last_name(name)?,
    };
    Some((name, exposed))
}

impl<'db, DB: DatabaseLike> Repairs<'db, DB> {
    /// The stored names of the columns of `table`.
    fn columns(&self, table: &DB::Table) -> Result<Vec<String>, LookupError> {
        Ok(table
            .columns(self.database)?
            .map(|column| column.stored_column_name().into_owned())
            .collect())
    }

    /// The write `statement` makes, when it writes one plain table.
    fn write(&self, statement: &Statement) -> Result<Option<Write<'db, DB>>, LookupError> {
        match statement {
            Statement::Delete(Delete {
                from: FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from),
                using: None,
                selection,
                ..
            }) => {
                let [relation] = from.as_slice() else {
                    return Ok(None);
                };
                self.filtered(Kind::Delete, relation, selection.as_ref(), &[])
            }
            Statement::Update(Update {
                table,
                assignments,
                from: None,
                selection,
                ..
            }) => {
                let mut set = Vec::new();
                for assignment in assignments {
                    let AssignmentTarget::ColumnName(column) = &assignment.target else {
                        return Ok(None);
                    };
                    let Some(column) = last_name(column) else {
                        return Ok(None);
                    };
                    set.push((column, &assignment.value));
                }
                self.filtered(Kind::Update, table, selection.as_ref(), &set)
            }
            Statement::Insert(insert) => self.inserted_row(insert),
            _ => Ok(None),
        }
    }

    /// The `DELETE` or `UPDATE` of `relation` filtered by `selection` and
    /// setting `set`.
    fn filtered(
        &self,
        kind: Kind,
        relation: &TableWithJoins,
        selection: Option<&Expr>,
        set: &[(String, &Expr)],
    ) -> Result<Option<Write<'db, DB>>, LookupError> {
        let Some((name, exposed)) = sole_table(relation) else {
            return Ok(None);
        };
        let Some(table) = stored_table(self.database, name, None)? else {
            return Ok(None);
        };
        let columns = self.columns(table)?;
        let target = Target {
            exposed: &exposed,
            columns: &columns,
        };
        Ok(Some(Write {
            kind,
            table,
            pinned: target.pinned(selection),
            written: set
                .iter()
                .filter_map(|(column, value)| Some((column.clone(), target.outside(value)?)))
                .collect(),
            assigned: set.iter().map(|(column, _)| column.clone()).collect(),
        }))
    }

    /// The `INSERT` of one `VALUES` row.
    fn inserted_row(&self, insert: &Insert) -> Result<Option<Write<'db, DB>>, LookupError> {
        let TableObject::TableName(name) = &insert.table else {
            return Ok(None);
        };
        let Some(source) = insert.source.as_deref() else {
            return Ok(None);
        };
        let SetExpr::Values(values) = source.body.as_ref() else {
            return Ok(None);
        };
        let [row] = values.rows.as_slice() else {
            return Ok(None);
        };
        let Some(table) = stored_table(self.database, name, None)? else {
            return Ok(None);
        };
        let columns = self.columns(table)?;
        let named: Vec<String> = if insert.columns.is_empty() {
            columns
        } else {
            let mut named = Vec::new();
            for column in &insert.columns {
                let Some(column) = last_name(column) else {
                    return Ok(None);
                };
                named.push(column);
            }
            named
        };
        let target = Target {
            exposed: "",
            columns: &[],
        };
        Ok(Some(Write {
            kind: Kind::Insert,
            table,
            pinned: Vec::new(),
            written: named
                .iter()
                .zip(&row.content)
                .filter_map(|(column, value)| Some((column.clone(), target.outside(value)?)))
                .collect(),
            assigned: named,
        }))
    }

    /// Whether `write` updates only the row an `AFTER INSERT` trigger fired
    /// for, naming every column of one of its unique keys by `NEW`'s field.
    fn own_row(&self, write: &Write<'db, DB>) -> Result<bool, LookupError> {
        if write.kind != Kind::Update
            || !self
                .inserted
                .iter()
                .any(|table| std::ptr::eq(*table, write.table))
        {
            return Ok(false);
        }
        Ok(equality_keys(self.database, write.table)?
            .iter()
            .any(|key| {
                key.iter().all(|column| {
                    let name = column.stored_column_name();
                    write.pinned(&name) == Some(new_column(&name).as_str())
                })
            }))
    }

    /// The rows `write` leaves referencing a missing row unless they are
    /// already repaired.
    fn breaks(&self, order: usize, write: &Write<'db, DB>) -> Result<Vec<Broken>, LookupError> {
        let mut found = Vec::new();
        for (index, key) in self.keys.iter().enumerate() {
            let foreign_key = key.constraint;
            if std::ptr::eq(key.referenced, write.table) {
                let (cause, action) = match write.kind {
                    Kind::Delete => (Cause::Deleted, foreign_key.on_delete(self.database)),
                    Kind::Update
                        if key
                            .pairs
                            .iter()
                            .any(|(_, referenced)| write.assigns(referenced)) =>
                    {
                        (Cause::Rekeyed, foreign_key.on_update(self.database))
                    }
                    _ => continue,
                };
                let restricts = action == ReferentialAction::Restrict;
                let checked = restricts
                    || (action == ReferentialAction::NoAction
                        && foreign_key.deferral(self.database)
                            != ConstraintDeferral::InitiallyDeferred);
                let values: Option<Vec<String>> = key
                    .pairs
                    .iter()
                    .map(|(_, referenced)| write.pinned(referenced).map(str::to_owned))
                    .collect();
                if checked && let Some(values) = values {
                    found.push(Broken {
                        order,
                        key: index,
                        values,
                        cause,
                        restricts,
                    });
                }
            }
            if !std::ptr::eq(key.host, write.table)
                || write.kind == Kind::Delete
                || foreign_key.deferral(self.database) == ConstraintDeferral::InitiallyDeferred
            {
                continue;
            }
            let written: Option<Vec<String>> = key
                .pairs
                .iter()
                .map(|(host, _)| write.written(host).map(str::to_owned))
                .collect();
            let (cause, values) = if let Some(values) = written {
                (Cause::Referencing, values)
            } else if key.pairs.iter().all(|(host, _)| !write.assigns(host))
                && self.own_row(write)?
            {
                let values = key.pairs.iter().map(|(host, _)| new_column(host)).collect();
                (Cause::OwnRow, values)
            } else {
                continue;
            };
            found.push(Broken {
                order,
                key: index,
                values,
                cause,
                restricts: false,
            });
        }
        Ok(found)
    }

    /// Whether `write` repairs the rows `broken` left.
    fn repairs(&self, broken: &Broken, write: &Write<'db, DB>) -> bool {
        let key = &self.keys[broken.key];
        let mut pairs = key.pairs.iter().zip(&broken.values);
        match broken.cause {
            Cause::Deleted | Cause::Rekeyed => {
                std::ptr::eq(key.host, write.table)
                    && (write.kind == Kind::Delete
                        || (write.kind == Kind::Update
                            && key.pairs.iter().any(|(host, _)| write.assigns(host))))
                    && pairs.all(|((host, _), value)| write.pinned(host) == Some(value.as_str()))
            }
            Cause::Referencing | Cause::OwnRow => {
                write.kind == Kind::Insert
                    && std::ptr::eq(key.referenced, write.table)
                    && pairs.all(|((_, referenced), value)| {
                        write.written(referenced) == Some(value.as_str())
                    })
            }
        }
    }

    /// The finding for `broken`, repaired by `write`.
    fn finding(&self, broken: &Broken, write: &Write<'db, DB>) -> Finding {
        let key = &self.keys[broken.key];
        let host = key.host.table_name();
        let referenced = key.referenced.table_name();
        let columns = key
            .pairs
            .iter()
            .map(|(host, _)| host.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let signature = &self.signature;
        let error = if broken.restricts {
            "23001 (restrict_violation)"
        } else {
            "23503 (foreign_key_violation)"
        };
        let tail = format!(
            "but PostgreSQL checks the foreign key at the end of each statement of a function body and raises {error} first."
        );
        let parent_first = format!(
            "Insert the row of '{referenced}' before the statement writing '{host}', or declare the foreign key DEFERRABLE INITIALLY DEFERRED."
        );
        match broken.cause {
            Cause::Deleted | Cause::Rekeyed => {
                let did = if broken.cause == Cause::Deleted {
                    "deletes rows"
                } else {
                    "changes the key of rows"
                };
                let repair = if write.kind == Kind::Delete {
                    "deletes"
                } else {
                    "repoints"
                };
                let deferred = if broken.restricts {
                    "NO ACTION DEFERRABLE INITIALLY DEFERRED"
                } else {
                    "DEFERRABLE INITIALLY DEFERRED"
                };
                Finding {
                    message: format!(
                        "Function '{signature}' {did} of '{referenced}' that rows of '{host}' may still reference through ({columns}), and only a later statement of the body {repair} those rows, {tail}"
                    ),
                    advice: format!(
                        "Delete or repoint the rows of '{host}' before the statement on '{referenced}', or declare the foreign key {deferred}."
                    ),
                }
            }
            Cause::Referencing => Finding {
                message: format!(
                    "Function '{signature}' writes rows of '{host}' referencing through ({columns}) a row of '{referenced}' that only a later statement of the body inserts, {tail}"
                ),
                advice: parent_first,
            },
            Cause::OwnRow => Finding {
                message: format!(
                    "Function '{signature}' updates the row of '{host}' its AFTER INSERT trigger fired for, whose unchanged key through ({columns}) PostgreSQL checks again since the transaction wrote the row, and only a later statement of the body inserts the row of '{referenced}' it references, {tail}"
                ),
                advice: parent_first,
            },
        }
    }

    /// Pairs `statement` with the earlier statements of the path it
    /// repairs, then records the rows it leaves waiting for a repair.
    fn step(&mut self, statement: &Statement, state: &mut Pending) -> Result<(), LookupError> {
        let next = self.orders.len();
        let order = *self.orders.entry(&raw const *statement).or_insert(next);
        let Some(write) = self.write(statement)? else {
            return Ok(());
        };
        for broken in &state.0 {
            if broken.order < order
                && self.repairs(broken, &write)
                && self.reported.insert((broken.order, broken.key))
            {
                let finding = self.finding(broken, &write);
                self.findings.push(finding);
            }
        }
        if !self.handled.contains(&(&raw const *statement)) {
            let breaks = self.breaks(order, &write)?;
            state.join(Pending(breaks));
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> FlowVisitor for Repairs<'_, DB> {
    type State = Pending;

    fn query(&mut self, _query: &Query, _state: &mut Self::State) {}

    fn statement(&mut self, statement: &Statement, state: &mut Self::State) {
        if self.failure.is_some() {
            return;
        }
        if let Err(error) = self.step(statement, state) {
            self.failure = Some(error);
        }
    }
}

impl<DB: DatabaseLike> FunctionRule for ForeignKeyBrokenBeforeRepair<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let Some(block) = plpgsql_block(function) else {
            return Ok(());
        };
        let mut keys = Vec::new();
        for table in database.tables() {
            for foreign_key in table.foreign_keys(database)? {
                if !foreign_key.is_enforced(database) {
                    continue;
                }
                keys.push(Key {
                    constraint: foreign_key,
                    host: table,
                    referenced: foreign_key.referenced_table(database)?,
                    pairs: key_pairs(database, foreign_key)?
                        .into_iter()
                        .map(|(host, referenced)| {
                            (
                                host.stored_column_name().into_owned(),
                                referenced.stored_column_name().into_owned(),
                            )
                        })
                        .collect(),
                });
            }
        }
        if keys.is_empty() {
            return Ok(());
        }
        let mut inserted = Vec::new();
        for trigger in function.triggers(database) {
            if row_trigger(trigger, TriggerPeriod::After)
                && fires_on_insert(trigger)
                && trigger.stored_name().as_ref() < KEY_CHECK_TRIGGER
                && let Relation::Table(table) = trigger.relation(database)?
            {
                inserted.push(table);
            }
        }
        let mut handled = HashSet::new();
        handled_statements(&block.statements, !block.handlers.is_empty(), &mut handled);
        for handler in &block.handlers {
            handled_statements(&handler.statements, false, &mut handled);
        }
        let mut repairs = Repairs {
            database,
            keys,
            inserted,
            orders: HashMap::new(),
            handled,
            reported: HashSet::new(),
            signature: signature(function, database),
            findings: Vec::new(),
            failure: None,
        };
        walk_block(&mut repairs, &block, Pending(Vec::new()));
        if let Some(failure) = repairs.failure {
            return Err(failure.into());
        }
        for Finding { message, advice } in repairs.findings {
            reporter.function(function, message, advice)?;
        }
        Ok(())
    }
}
