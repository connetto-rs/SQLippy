//! Submodule providing the `BeforeTriggerWritesOtherTable` rule.

use sql_traits::traits::{DatabaseLike, TableLike, TriggerLike};
use sqlparser::ast::{Query, Statement, TriggerPeriod};
use sqlparser_plpgsql::embedded::Node;

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::is_null_literal,
        function_reach_support::Reach,
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        trigger_support::{WritesElsewhere, evaluated, fires_on_insert, row_trigger},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

schema_rule!(
    /// Struct defining a rule that reports a row-level `BEFORE INSERT`
    /// trigger whose function writes another table.
    ///
    /// The write stays when the insert does not happen, as under `ON
    /// CONFLICT DO NOTHING`. A function returning `NULL` after the write
    /// redirects the row instead, and is reported with its own message.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     BeforeTriggerWritesOtherTable::default().into();
    /// let schema = |timing: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE TABLE notes (id INT PRIMARY KEY);
    ///          CREATE TABLE audit (note_id INT);
    ///          CREATE FUNCTION log_note() RETURNS trigger LANGUAGE plpgsql AS $$
    ///          BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NEW; END $$;
    ///          CREATE TRIGGER log_note {timing} INSERT ON notes FOR EACH ROW EXECUTE FUNCTION log_note();"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("BEFORE")).is_err());
    /// assert!(constrainer.validate_schema(&schema("AFTER")).is_ok());
    /// ```
    BeforeTriggerWritesOtherTable,
    LintGroup::Suspicious,
    "A row-level BEFORE INSERT trigger runs for rows that are never inserted, such as those ON CONFLICT DO NOTHING skips, and its write to another table stays. A trigger that writes the row elsewhere and returns NULL makes the INSERT report no row, so RETURNING yields nothing and ON CONFLICT never sees it.",
    Some("https://www.postgresql.org/docs/18/trigger-definition.html"),
    RuleExample {
        bad: "CREATE TABLE notes (id integer PRIMARY KEY, body text NOT NULL);\n\
CREATE TABLE audit_events (event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, note_id integer NOT NULL);\n\
CREATE FUNCTION record_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO audit_events (note_id) VALUES (NEW.id); RETURN NEW; END $$;\n\
CREATE TRIGGER record_note BEFORE INSERT ON notes FOR EACH ROW EXECUTE FUNCTION record_note();",
        good: "CREATE TABLE notes (id integer PRIMARY KEY, body text NOT NULL);\n\
CREATE TABLE audit_events (event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, note_id integer NOT NULL);\n\
CREATE FUNCTION record_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO audit_events (note_id) VALUES (NEW.id); RETURN NEW; END $$;\n\
CREATE TRIGGER record_note AFTER INSERT ON notes FOR EACH ROW EXECUTE FUNCTION record_note();",
    }
);

/// Whether a path has written another table.
#[derive(Clone, Copy, Default)]
struct Wrote(bool);

impl FlowState for Wrote {
    fn join(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// How the paths that wrote another table leave the function.
struct Returns<'r, 'db, DB: DatabaseLike> {
    reach: &'r mut Reach<'db, DB, WritesElsewhere<'db, DB>>,
    /// A path that wrote returns a row, so the insert goes on.
    row: bool,
    /// A path that wrote returns `NULL`, so the insert is skipped.
    null: bool,
}

impl<DB: DatabaseLike> FlowVisitor for Returns<'_, '_, DB> {
    type State = Wrote;

    fn query(&mut self, query: &Query, state: &mut Wrote) {
        state.0 |= !self.reach.occurrences(query).is_empty();
    }

    fn statement(&mut self, statement: &Statement, state: &mut Wrote) {
        state.0 |= !self.reach.occurrences(statement).is_empty();
    }

    fn step(&mut self, node: &Node, state: &mut Wrote) {
        if let Node::Return { value } = node
            && state.0
        {
            if value
                .as_deref()
                .and_then(evaluated)
                .is_some_and(is_null_literal)
            {
                self.null = true;
            } else {
                self.row = true;
            }
        }
    }
}

impl<DB: DatabaseLike> SchemaRule for BeforeTriggerWritesOtherTable<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for trigger in database.triggers() {
            if !row_trigger(trigger, TriggerPeriod::Before) || !fires_on_insert(trigger) {
                continue;
            }
            let Some(function) = trigger.function(database) else {
                continue;
            };
            let Some(block) = plpgsql_block(function) else {
                continue;
            };
            let table = trigger.table(database)?;
            let mut reach = Reach::new(database, WritesElsewhere::new(database, table));
            let mut returns = Returns {
                reach: &mut reach,
                row: false,
                null: false,
            };
            walk_block(&mut returns, &block, Wrote::default());
            let (name, relation) = (trigger.name(), table.table_name());
            let function = signature(function, database);
            if returns.row {
                reporter.table(
                    table,
                    format!(
                        "Trigger '{name}' on '{relation}' runs '{function}' BEFORE INSERT, which writes another table, so the write stays when the insert is skipped, as by ON CONFLICT DO NOTHING."
                    ),
                    "Run the write from an AFTER INSERT trigger, which fires only for inserted rows."
                        .to_owned(),
                )?;
            } else if returns.null {
                reporter.table(
                    table,
                    format!(
                        "Trigger '{name}' on '{relation}' runs '{function}' BEFORE INSERT, which writes the row to another table and returns NULL, so the INSERT reports no row, RETURNING yields nothing and ON CONFLICT never sees the row."
                    ),
                    "Use declarative partitioning, or insert into the target table directly."
                        .to_owned(),
                )?;
            }
        }
        Ok(())
    }
}
