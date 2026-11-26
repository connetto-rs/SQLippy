//! Submodule providing the `TriggerFilterInBody` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::IdentifierCase,
    traits::{ColumnLike, DatabaseLike, FunctionLike, Relation, TableLike, TriggerLike},
};
use sqlparser::ast::{
    BinaryOperator, Delete, Expr, FromTable, Function, FunctionBehavior, GroupByExpr, Ident,
    ObjectName, ObjectNamePart, Query, Select, SetExpr, Statement, TableFactor, TableObject,
    TableWithJoins, TriggerEvent, TriggerPeriod, Update, Value, Visitor,
};
use sqlparser_plpgsql::embedded::{DeclarationKind, Node, NodeKind};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::stored_table,
        not_in_support::projects_aggregate,
        plpgsql_flow_support::plpgsql_block,
        policy_support::conjuncts,
        trigger_support::{evaluated, last_name, row, row_trigger, stored},
        walk_support::{canonical, walk},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports a trigger filtering rows in its
    /// body with a condition its `WHEN` clause could test instead.
    ///
    /// On PostgreSQL it reports a row-level `AFTER` trigger whose function
    /// starts by returning when a condition on `NEW` and `OLD` holds. A
    /// condition reading anything but `NEW` and `OLD` fields, or holding a
    /// subquery, stays in the body, as does one reading `OLD` for an `INSERT`
    /// trigger or `NEW` for a `DELETE` trigger, which `WHEN` cannot read.
    ///
    /// On SQLite it reports a trigger without `WHEN` where every statement of
    /// the body carries the same conjunct in its `WHERE`. SQLite's `WHEN`
    /// may read other tables through subqueries, so such a conjunct moves
    /// too, unless it reads a column of the rows the statement works on,
    /// calls a function that may answer differently at each call, or reads
    /// a table an earlier statement of the body writes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = TriggerFilterInBody::default().into();
    /// let schema = |filter: &str, when: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);
    ///          CREATE TABLE audit (note_id INT);
    ///          CREATE FUNCTION log_note() RETURNS trigger LANGUAGE plpgsql AS $$
    ///          BEGIN {filter} INSERT INTO audit VALUES (NEW.id); RETURN NEW; END $$;
    ///          CREATE TRIGGER log_note AFTER UPDATE ON notes FOR EACH ROW {when} EXECUTE FUNCTION log_note();"
    ///     ))
    ///     .unwrap()
    /// };
    /// let in_body = schema("IF OLD.body IS NOT DISTINCT FROM NEW.body THEN RETURN NULL; END IF;", "");
    /// assert!(constrainer.validate_schema(&in_body).is_err());
    /// let in_when = schema("", "WHEN (OLD.body IS DISTINCT FROM NEW.body)");
    /// assert!(constrainer.validate_schema(&in_when).is_ok());
    ///
    /// let sqlite = |when: &str, guard: &str| {
    ///     ParserDB::parse::<SQLiteDialect>(&format!(
    ///         "CREATE TABLE frames (id INTEGER PRIMARY KEY, owner TEXT);
    ///          CREATE TABLE child (id INTEGER PRIMARY KEY, parent INTEGER);
    ///          CREATE TABLE records (frame INTEGER, key INTEGER);
    ///          CREATE TRIGGER record AFTER INSERT ON child FOR EACH ROW {when} BEGIN
    ///            INSERT INTO records (frame, key) SELECT (SELECT max(id) FROM frames), NEW.parent {guard};
    ///          END;"
    ///     ))
    ///     .unwrap()
    /// };
    /// let exists = "EXISTS (SELECT 1 FROM frames WHERE owner = 'body')";
    /// let guarded_body = sqlite("", &format!("WHERE {exists}"));
    /// assert!(constrainer.validate_schema(&guarded_body).is_err());
    /// let guarded_trigger = sqlite(&format!("WHEN {exists}"), "");
    /// assert!(constrainer.validate_schema(&guarded_trigger).is_ok());
    /// ```
    TriggerFilterInBody,
    register_schema_rule,
    LintGroup::Perf,
    "A trigger whose body skips its work when a condition fails still runs the body for every row, while the same condition in the trigger's WHEN clause skips the body.",
    Some("https://www.postgresql.org/docs/18/sql-createtrigger.html"),
    RuleExample {
        bad: "CREATE TABLE notes (id integer PRIMARY KEY, body text NOT NULL);\n\
CREATE TABLE audit_events (event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, note_id integer NOT NULL);\n\
CREATE FUNCTION record_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.body IS NOT DISTINCT FROM NEW.body THEN RETURN NEW; END IF; INSERT INTO audit_events (note_id) VALUES (NEW.id); RETURN NEW; END $$;\n\
CREATE TRIGGER record_note AFTER UPDATE ON notes FOR EACH ROW EXECUTE FUNCTION record_note();",
        good: "CREATE TABLE notes (id integer PRIMARY KEY, body text NOT NULL);\n\
CREATE TABLE audit_events (event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, note_id integer NOT NULL);\n\
CREATE FUNCTION record_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO audit_events (note_id) VALUES (NEW.id); RETURN NEW; END $$;\n\
CREATE TRIGGER record_note AFTER UPDATE ON notes FOR EACH ROW WHEN (OLD.body IS DISTINCT FROM NEW.body) EXECUTE FUNCTION record_note();",
    },
    Basis::Declared,
    &Engine::ALL
);

/// Which trigger rows a condition reads, stopping at anything a `WHEN`
/// clause cannot hold in its place, and at a call that is not `IMMUTABLE`,
/// which may answer differently when `WHEN` runs it at the row change.
struct RowsRead<'db, DB: DatabaseLike> {
    database: &'db DB,
    new: bool,
    old: bool,
}

impl<DB: DatabaseLike> RowsRead<'_, DB> {
    fn record(&mut self, ident: &Ident) -> ControlFlow<()> {
        match row(ident) {
            Some(true) => self.new = true,
            Some(false) => self.old = true,
            None => return ControlFlow::Break(()),
        }
        ControlFlow::Continue(())
    }

    fn immutable(&self, call: &Function) -> ControlFlow<()> {
        let Ok(reached) = self
            .database
            .functions_reached_by(call, IdentifierCase::Folded)
        else {
            return ControlFlow::Break(());
        };
        let mut immutable = false;
        for function in reached {
            if function.volatility() != FunctionBehavior::Immutable {
                return ControlFlow::Break(());
            }
            immutable = true;
        }
        if immutable {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
    }
}

impl<DB: DatabaseLike> Visitor for RowsRead<'_, DB> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        match expression {
            Expr::Identifier(ident) => self.record(ident),
            Expr::Function(call) => self.immutable(call),
            Expr::CompoundIdentifier(parts) if parts.len() == 2 => self.record(&parts[0]),
            Expr::QualifiedWildcard(name, _) if name.0.len() == 1 => name
                .0
                .first()
                .and_then(ObjectNamePart::as_ident)
                .map_or(ControlFlow::Break(()), |ident| self.record(ident)),
            Expr::CompoundIdentifier(_) | Expr::QualifiedWildcard(..) => ControlFlow::Break(()),
            _ => ControlFlow::Continue(()),
        }
    }

    /// A `WHEN` condition holds no subquery.
    fn pre_visit_query(&mut self, _query: &sqlparser::ast::Query) -> ControlFlow<()> {
        ControlFlow::Break(())
    }
}

/// The `WHEN` condition that fires exactly when the body does not return at
/// once on `skip`.
fn negated(skip: &Expr) -> String {
    match skip {
        Expr::Nested(inner) => negated(inner),
        Expr::IsNotDistinctFrom(left, right) => format!("{left} IS DISTINCT FROM {right}"),
        Expr::IsDistinctFrom(left, right) => format!("{left} IS NOT DISTINCT FROM {right}"),
        Expr::IsNull(inner) => format!("{inner} IS NOT NULL"),
        Expr::IsNotNull(inner) => format!("{inner} IS NULL"),
        _ => format!("({skip}) IS NOT TRUE"),
    }
}

/// The condition a body returns at once on, as its first statement, with
/// the trigger rows it reads.
fn early_return<'b, 'db, DB: DatabaseLike>(
    database: &'db DB,
    nodes: &'b [Node],
) -> Option<(&'b Expr, RowsRead<'db, DB>)> {
    let Some(Node {
        kind: NodeKind::If(conditional),
        ..
    }) = nodes.first()
    else {
        return None;
    };
    let [branch] = conditional.branches.as_slice() else {
        return None;
    };
    if !conditional.otherwise.is_empty()
        || !matches!(
            branch.statements.as_slice(),
            [Node {
                kind: NodeKind::Return { .. },
                ..
            }]
        )
    {
        return None;
    }
    let condition = evaluated(&branch.condition)?;
    let mut read = RowsRead {
        database,
        new: false,
        old: false,
    };
    if walk(condition, &mut read).is_break() || !(read.new || read.old) {
        return None;
    }
    Some((condition, read))
}

impl<DB: DatabaseLike> SchemaRule for TriggerFilterInBody<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        match Engine::of(database) {
            Engine::PostgreSql => function_filters(database, reporter),
            Engine::Sqlite => repeated_guards(database, reporter),
        }
    }
}

/// Reports the PostgreSQL trigger functions that return at once on a
/// condition each of their triggers' `WHEN` could test.
fn function_filters<DB: DatabaseLike>(
    database: &DB,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    for function in database.functions() {
        let Some(block) = plpgsql_block(function) else {
            continue;
        };
        // A default runs before the condition, which WHEN would skip.
        let defaulted = block.declarations.iter().any(|declaration| {
            matches!(&declaration.kind, DeclarationKind::Variable(variable) if variable.default.is_some())
        });
        if defaulted {
            continue;
        }
        let Some((condition, read)) = early_return(database, &block.statements) else {
            continue;
        };
        let triggers: Vec<&DB::Trigger> = function.triggers(database).collect();
        let movable = |trigger: &&DB::Trigger| {
            row_trigger(*trigger, TriggerPeriod::After)
                && trigger.events().iter().all(|event| match event {
                    TriggerEvent::Insert => !read.old,
                    TriggerEvent::Delete => !read.new,
                    // A row trigger never fires on `TRUNCATE`.
                    event => matches!(event, TriggerEvent::Update(_)),
                })
        };
        if triggers.is_empty() || !triggers.iter().all(movable) {
            continue;
        }
        let when = negated(condition);
        let called = signature(function, database);
        for trigger in triggers {
            let (Relation::Table(table) | Relation::ForeignTable(table)) =
                trigger.relation(database)?
            else {
                continue;
            };
            reporter.table(
                table,
                format!(
                    "Trigger '{}' on '{}' calls '{called}' for every row, and the function returns at once when `{condition}`.",
                    trigger.name(),
                    table.table_name()
                ),
                format!(
                    "Remove the early return and add `WHEN ({when})` to trigger '{}', so the function runs only for the rows it acts on.",
                    trigger.name()
                ),
            )?;
        }
    }
    Ok(())
}

const NONDETERMINISTIC_CALLS: [&str; 5] = [
    "random",
    "randomblob",
    "changes",
    "last_insert_rowid",
    "total_changes",
];

/// Stored tables by the name a statement reads their rows under.
type Relations<'db, DB> = Vec<(String, &'db <DB as DatabaseLike>::Table)>;

/// The `WHERE` of a SQLite trigger body statement, the relations its
/// conjuncts may read the rows of, by the name each goes by, and the table
/// it writes.
struct Filtered<'s, 'db, DB: DatabaseLike> {
    selection: &'s Expr,
    relations: Relations<'db, DB>,
    written: Option<&'db DB::Table>,
}

/// The relations `from` names, or `None` when one is not a stored table.
fn relations<'db, DB: DatabaseLike>(
    database: &'db DB,
    from: &[TableWithJoins],
) -> Result<Option<Relations<'db, DB>>, LookupError> {
    let mut found = Vec::new();
    for item in from {
        for factor in
            std::iter::once(&item.relation).chain(item.joins.iter().map(|join| &join.relation))
        {
            let TableFactor::Table {
                name,
                alias,
                args: None,
                ..
            } = factor
            else {
                return Ok(None);
            };
            let Some(table) = stored_table(database, name, None)? else {
                return Ok(None);
            };
            let exposed = match alias {
                Some(alias) => stored(&alias.name).into_owned(),
                None => match last_name(name) {
                    Some(name) => name,
                    None => return Ok(None),
                },
            };
            found.push((exposed, table));
        }
    }
    Ok(Some(found))
}

/// Whether `call` names an aggregate SQLite defines. A `min` or `max` with
/// several arguments, which is scalar, counts too and only keeps a guard.
fn sqlite_aggregate(call: &Function) -> bool {
    last_name(&call.name).is_some_and(|name| {
        [
            "avg",
            "count",
            "group_concat",
            "json_group_array",
            "json_group_object",
            "jsonb_group_array",
            "jsonb_group_object",
            "max",
            "min",
            "string_agg",
            "sum",
            "total",
        ]
        .contains(&name.as_str())
    })
}

/// Whether `select` returns a row even when its `WHERE` rejects every row,
/// as an aggregate or a `HAVING` without `GROUP BY` does.
fn aggregates_ungrouped(select: &Select) -> bool {
    matches!(&select.group_by, GroupByExpr::Expressions(expressions, _) if expressions.is_empty())
        && (select.having.is_some() || projects_aggregate(&select.projection, sqlite_aggregate))
}

/// The filter of a SQLite trigger body statement, `None` for a statement
/// without `WHERE`, one returning a row whatever its `WHERE` admits, or one
/// whose relations are not all stored tables.
fn filtered<'s, 'db, DB: DatabaseLike>(
    database: &'db DB,
    statement: &'s Statement,
) -> Result<Option<Filtered<'s, 'db, DB>>, LookupError> {
    let select_filter = |select: &'s Select, written| -> Result<_, LookupError> {
        let Some(selection) = &select.selection else {
            return Ok(None);
        };
        if aggregates_ungrouped(select) {
            return Ok(None);
        }
        Ok(
            relations(database, &select.from)?.map(|relations| Filtered {
                selection,
                relations,
                written,
            }),
        )
    };
    match statement {
        Statement::Insert(insert) => {
            let TableObject::TableName(name) = &insert.table else {
                return Ok(None);
            };
            let Some(source) = insert.source.as_deref() else {
                return Ok(None);
            };
            let SetExpr::Select(select) = source.body.as_ref() else {
                return Ok(None);
            };
            let written = stored_table(database, name, None)?;
            select_filter(select, written)
        }
        Statement::Query(query) => {
            let SetExpr::Select(select) = query.body.as_ref() else {
                return Ok(None);
            };
            select_filter(select, None)
        }
        Statement::Update(Update {
            table,
            selection: Some(selection),
            from: None,
            ..
        }) => Ok(
            relations(database, std::slice::from_ref(table))?.map(|relations| Filtered {
                selection,
                written: relations.first().map(|(_, table)| *table),
                relations,
            }),
        ),
        Statement::Delete(Delete {
            from: FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from),
            using: None,
            selection: Some(selection),
            ..
        }) => Ok(relations(database, from)?.map(|relations| Filtered {
            selection,
            written: relations.first().map(|(_, table)| *table),
            relations,
        })),
        _ => Ok(None),
    }
}

/// Whether a conjunct of a SQLite trigger body statement reads only `NEW`,
/// `OLD`, literals and subqueries over tables no earlier statement writes,
/// so `WHEN` can test it before the body.
struct Movable<'f, 'db, DB: DatabaseLike> {
    database: &'db DB,
    relations: &'f [(String, &'db DB::Table)],
    written: &'f [&'db DB::Table],
    depth: usize,
    failure: Option<LookupError>,
}

impl<DB: DatabaseLike> Movable<'_, '_, DB> {
    /// Whether a bare `name` inside a subquery may name a column of the
    /// statement's relations.
    fn outer_column(&mut self, name: &str) -> ControlFlow<()> {
        for (_, table) in self.relations {
            match table.columns(self.database) {
                Ok(mut columns) => {
                    if columns.any(|column| column.stored_column_name() == name) {
                        return ControlFlow::Break(());
                    }
                }
                Err(error) => {
                    self.failure.get_or_insert(error);
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }
}

impl<DB: DatabaseLike> Visitor for Movable<'_, '_, DB> {
    type Break = ();

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<()> {
        match stored_table(self.database, relation, None) {
            Ok(Some(table))
                if self
                    .written
                    .iter()
                    .any(|written| std::ptr::eq(*written, table)) =>
            {
                ControlFlow::Break(())
            }
            Ok(_) => ControlFlow::Continue(()),
            Err(error) => {
                self.failure = Some(error);
                ControlFlow::Break(())
            }
        }
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        match expression {
            Expr::Identifier(_) if self.depth == 0 => ControlFlow::Break(()),
            Expr::Identifier(ident) => self.outer_column(&stored(ident)),
            Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                [record, _] if row(record).is_some() => ControlFlow::Continue(()),
                _ if self.depth == 0 => ControlFlow::Break(()),
                [qualifier, ..] => {
                    let qualifier = stored(qualifier);
                    if self.relations.iter().any(|(name, _)| *name == qualifier) {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    }
                }
                [] => ControlFlow::Continue(()),
            },
            Expr::Function(call) if nondeterministic(call) => ControlFlow::Break(()),
            Expr::Value(value) if matches!(&value.value, Value::SingleQuotedString(text) if text.eq_ignore_ascii_case("now")) => {
                ControlFlow::Break(())
            }
            _ => ControlFlow::Continue(()),
        }
    }
}

/// Whether `call` is to a SQLite function that may answer differently at
/// each call.
fn nondeterministic(call: &Function) -> bool {
    call.name
        .0
        .last()
        .and_then(ObjectNamePart::as_ident)
        .is_some_and(|name| {
            NONDETERMINISTIC_CALLS
                .iter()
                .any(|called| name.value.eq_ignore_ascii_case(called))
        })
}

/// The conjuncts every statement of a SQLite trigger body carries in its
/// `WHERE` that `WHEN` can test instead, as the first statement writes
/// them.
fn shared_guard<'s, DB: DatabaseLike>(
    database: &DB,
    statements: &'s [Statement],
) -> Result<Vec<&'s Expr>, LookupError> {
    let mut written = Vec::new();
    let mut shared: Option<Vec<(&'s Expr, String)>> = None;
    for statement in statements {
        let Some(filter) = filtered(database, statement)? else {
            return Ok(Vec::new());
        };
        let mut movable = Vec::new();
        for conjunct in conjuncts(filter.selection) {
            let mut reads = Movable {
                database,
                relations: &filter.relations,
                written: &written,
                depth: 0,
                failure: None,
            };
            let stopped = walk(conjunct, &mut reads).is_break();
            if let Some(failure) = reads.failure {
                return Err(failure);
            }
            if !stopped {
                movable.push((conjunct, canonical(conjunct)));
            }
        }
        let kept = match shared {
            None => movable,
            Some(mut previous) => {
                previous.retain(|(_, spelled)| movable.iter().any(|(_, other)| other == spelled));
                previous
            }
        };
        if kept.is_empty() {
            return Ok(Vec::new());
        }
        shared = Some(kept);
        written.extend(filter.written);
    }
    Ok(shared
        .unwrap_or_default()
        .into_iter()
        .map(|(conjunct, _)| conjunct)
        .collect())
}

/// `guard` as one condition, each conjunct of an `OR` parenthesized.
fn joined(guard: &[&Expr]) -> String {
    guard
        .iter()
        .map(|conjunct| match conjunct {
            Expr::BinaryOp {
                op: BinaryOperator::Or,
                ..
            } if guard.len() > 1 => format!("({conjunct})"),
            _ => conjunct.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// Reports the SQLite triggers without `WHEN` whose every body statement
/// carries a guard `WHEN` could test instead.
fn repeated_guards<DB: DatabaseLike>(
    database: &DB,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    for trigger in database.triggers() {
        if trigger.condition().is_some() || trigger.statements().is_empty() {
            continue;
        }
        let Relation::Table(table) = trigger.relation(database)? else {
            continue;
        };
        let guard = shared_guard(database, trigger.statements())?;
        if guard.is_empty() {
            continue;
        }
        let guard = joined(&guard);
        reporter.table(
            table,
            format!(
                "Trigger '{}' on '{}' runs its body for every row, and every statement of the body tests `{guard}`.",
                trigger.name(),
                table.table_name()
            ),
            format!(
                "Move `{guard}` into a WHEN clause of trigger '{}', so a row that fails it skips the body.",
                trigger.name()
            ),
        )?;
    }
    Ok(())
}
