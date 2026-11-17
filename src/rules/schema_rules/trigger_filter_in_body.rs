//! Submodule providing the `TriggerFilterInBody` rule.

use std::ops::ControlFlow;

use sql_traits::{
    structs::IdentifierCase,
    traits::{DatabaseLike, FunctionLike, TableLike, TriggerLike},
};
use sqlparser::ast::{
    Expr, Function, FunctionBehavior, Ident, ObjectNamePart, TriggerEvent, TriggerPeriod, Visitor,
};
use sqlparser_plpgsql::embedded::{DeclarationKind, Node};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        plpgsql_flow_support::plpgsql_block,
        trigger_support::{evaluated, row, row_trigger},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

schema_rule!(
    /// Struct defining a rule that reports a row-level `AFTER` trigger whose
    /// function starts by returning when a condition on `NEW` and `OLD` holds,
    /// a condition the trigger's `WHEN` clause could test instead.
    ///
    /// A condition reading anything but `NEW` and `OLD` fields, or holding a
    /// subquery, stays in the body, as does one reading `OLD` for an `INSERT`
    /// trigger or `NEW` for a `DELETE` trigger, which `WHEN` cannot read.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
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
    /// ```
    TriggerFilterInBody,
    LintGroup::Perf,
    "A trigger function that returns at once when a condition on NEW and OLD holds is still called for every row, while the same condition in the trigger's WHEN clause skips the call.",
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
    }
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
    let Some(Node::If(conditional)) = nodes.first() else {
        return None;
    };
    let [branch] = conditional.branches.as_slice() else {
        return None;
    };
    if !conditional.otherwise.is_empty()
        || !matches!(branch.statements.as_slice(), [Node::Return { .. }])
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
                let table = trigger.table(database)?;
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
}
