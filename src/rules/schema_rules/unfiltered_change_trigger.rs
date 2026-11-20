//! Submodule providing the `UnfilteredChangeTrigger` rule.

use std::ops::ControlFlow;

use sql_traits::traits::{DatabaseLike, Relation, TableLike, TriggerLike};
use sqlparser::ast::{Expr, Query, Statement, TriggerPeriod, Visitor};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        function_reach_support::Reach,
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        trigger_support::{
            WritesElsewhere, evaluated, fires_on_update, row, row_trigger, triggers_with_functions,
        },
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

schema_rule!(
    /// Struct defining a rule that reports a row-level `AFTER UPDATE`
    /// trigger without a `WHEN` clause whose function writes another table
    /// before any test comparing `OLD` with `NEW`.
    ///
    /// An `UPDATE` that leaves a row unchanged still fires the trigger, so
    /// an audit of state changes records a change that did not happen. A
    /// statement-level trigger, which audits the attempt, is not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnfilteredChangeTrigger::default().into();
    /// let schema = |when: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);
    ///          CREATE TABLE audit (note_id INT);
    ///          CREATE FUNCTION log_note() RETURNS trigger LANGUAGE plpgsql AS $$
    ///          BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NEW; END $$;
    ///          CREATE TRIGGER log_note AFTER UPDATE ON notes FOR EACH ROW {when} EXECUTE FUNCTION log_note();"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("")).is_err());
    /// let filtered = schema("WHEN (OLD.* IS DISTINCT FROM NEW.*)");
    /// assert!(constrainer.validate_schema(&filtered).is_ok());
    /// ```
    UnfilteredChangeTrigger,
    LintGroup::Pedantic,
    "An UPDATE that leaves every value unchanged still fires a row-level AFTER UPDATE trigger, so a trigger auditing state changes writes an audit row for a change that did not happen and adds write load.",
    Some("https://www.postgresql.org/docs/18/sql-createtrigger.html"),
    RuleExample {
        bad: "CREATE TABLE notes (id integer PRIMARY KEY, body text NOT NULL);\n\
CREATE TABLE audit_events (event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, note_id integer NOT NULL);\n\
CREATE FUNCTION record_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO audit_events (note_id) VALUES (NEW.id); RETURN NEW; END $$;\n\
CREATE TRIGGER record_note AFTER UPDATE ON notes FOR EACH ROW EXECUTE FUNCTION record_note();",
        good: "CREATE TABLE notes (id integer PRIMARY KEY, body text NOT NULL);\n\
CREATE TABLE audit_events (event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, note_id integer NOT NULL);\n\
CREATE FUNCTION record_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO audit_events (note_id) VALUES (NEW.id); RETURN NEW; END $$;\n\
CREATE TRIGGER record_note AFTER UPDATE ON notes FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION record_note();",
    }
);

/// Whether a path has passed a test comparing `OLD` with `NEW`.
#[derive(Clone, Copy, Default)]
struct Compared(bool);

impl FlowState for Compared {
    fn join(&mut self, other: Self) {
        self.0 &= other.0;
    }
}

/// Which trigger rows an expression reads.
#[derive(Default)]
struct Rows {
    new: bool,
    old: bool,
}

impl Visitor for Rows {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        let ident = match expression {
            Expr::Identifier(ident) => Some(ident),
            Expr::CompoundIdentifier(parts) => parts.first(),
            Expr::QualifiedWildcard(name, _) => name.0.first().and_then(|part| part.as_ident()),
            _ => None,
        };
        match ident.and_then(row) {
            Some(true) => self.new = true,
            Some(false) => self.old = true,
            None => {}
        }
        ControlFlow::Continue(())
    }
}

/// Whether some path writes another table before comparing `OLD` with
/// `NEW`.
struct Unfiltered<'r, 'db, DB: DatabaseLike> {
    reach: &'r mut Reach<'db, DB, WritesElsewhere<'db, DB>>,
    found: bool,
}

impl<DB: DatabaseLike> Unfiltered<'_, '_, DB> {
    /// Records a write `node` makes to another table on a path that has not
    /// compared `OLD` with `NEW`.
    fn wrote<V: sqlparser::ast::Visit + ?Sized>(&mut self, node: &V, state: Compared) {
        if !state.0 && !self.reach.occurrences(node).is_empty() {
            self.found = true;
        }
    }
}

impl<DB: DatabaseLike> FlowVisitor for Unfiltered<'_, '_, DB> {
    type State = Compared;

    fn query(&mut self, query: &Query, state: &mut Compared) {
        self.wrote(query, *state);
    }

    fn statement(&mut self, statement: &Statement, state: &mut Compared) {
        self.wrote(statement, *state);
    }

    fn assume(&mut self, condition: &Query, _holds: bool, state: &mut Compared) {
        let mut rows = Rows::default();
        if let Some(condition) = evaluated(condition) {
            let _ = walk(condition, &mut rows);
        }
        state.0 |= rows.new && rows.old;
    }
}

impl<DB: DatabaseLike> SchemaRule for UnfilteredChangeTrigger<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for (function, trigger) in triggers_with_functions(database) {
            if !row_trigger(trigger, TriggerPeriod::After)
                || !fires_on_update(trigger)
                || trigger.condition().is_some()
            {
                continue;
            }
            let Some(block) = plpgsql_block(function) else {
                continue;
            };
            let (Relation::Table(table) | Relation::ForeignTable(table)) =
                trigger.relation(database)?
            else {
                continue;
            };
            let mut reach = Reach::new(database, WritesElsewhere::new(database, table));
            let mut unfiltered = Unfiltered {
                reach: &mut reach,
                found: false,
            };
            walk_block(&mut unfiltered, &block, Compared::default());
            if !unfiltered.found {
                continue;
            }
            let (name, relation) = (trigger.name(), table.table_name());
            reporter.table(
                table,
                format!(
                    "Trigger '{name}' on '{relation}' runs '{}' AFTER UPDATE for every updated row, and it writes another table even when the UPDATE changed no value.",
                    signature(function, database)
                ),
                format!(
                    "Add `WHEN (OLD.* IS DISTINCT FROM NEW.*)` to trigger '{name}', or a narrower comparison of the audited columns, unless every UPDATE attempt is meant to be recorded."
                ),
            )?;
        }
        Ok(())
    }
}
