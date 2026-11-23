//! Submodule providing the `BeforeTriggerWritesOtherTable` rule.

use sql_traits::traits::{DatabaseLike, Relation, TableLike, TriggerLike};
use sqlparser::ast::{Query, Statement, TriggerPeriod};
use sqlparser_plpgsql::embedded::{Node, NodeKind};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::is_null_literal,
        function_reach_support::Reach,
        guarded_parent_support::Parent,
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        trigger_support::{
            WritesElsewhere, evaluated, fires_on_insert, row_trigger, triggers_with_functions,
        },
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports a row-level `BEFORE INSERT`
    /// trigger whose function writes another table.
    ///
    /// The write stays when the insert does not happen, as under `ON
    /// CONFLICT DO NOTHING`. A function returning `NULL` after the write
    /// redirects the row instead, and is reported with its own message.
    ///
    /// A write inserting the row a foreign key of the table references, as
    /// one `VALUES` row holding `NEW`'s value of each host column, possibly
    /// `ON CONFLICT DO NOTHING`, is not reported when the referenced table
    /// refuses that row at commit while no row of the table references it.
    /// A subtype table whose key must reach its parent table before a `NOT
    /// DEFERRABLE` foreign key is checked has no other place for that write.
    /// The refusal is an enabled `DEFERRABLE INITIALLY DEFERRED` row-level
    /// constraint trigger on the referenced table, firing on `INSERT`, whose
    /// `WHEN` condition, if any, holds for every row the table can reference,
    /// running a PL/pgSQL function that reaches every `RETURN` only past a
    /// condition showing either of two facts, with neither table written
    /// since.
    ///
    /// - A row of the table references the trigger's row. An `EXISTS` over
    ///   the table alone shows it, equating host columns with `NEW`'s
    ///   referenced columns that cover a unique key of the referenced table,
    ///   while the other host columns are `NOT NULL`.
    /// - The trigger's row is gone. A `NOT EXISTS` over the referenced table
    ///   alone shows it, equating `NOT NULL` columns with `NEW`'s, read by a
    ///   function that sees every row past row-level security.
    ///
    /// A `CASE` over a column of `NEW`, and the `WHEN` condition, are read
    /// through the one value a validated check of the table pins the host
    /// column to. The trigger's own function, and every other enabled
    /// `BEFORE INSERT` row trigger of the table, must return `NEW` with its
    /// host columns unwritten, so the row checked is the row written.
    ///
    /// The rule does not run on SQLite, which has no trigger functions.
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
    register_schema_rule,
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
    },
    Basis::Declared,
    &[Engine::PostgreSql]
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
    /// The referenced rows whose insert a deferred check refuses while
    /// unreferenced at commit.
    guarded: &'r [Parent<'db, DB>],
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
        if self
            .guarded
            .iter()
            .any(|parent| parent.inserts(statement, true))
        {
            return;
        }
        state.0 |= !self.reach.occurrences(statement).is_empty();
    }

    fn step(&mut self, node: &Node, state: &mut Wrote) {
        if let NodeKind::Return { value } = &node.kind
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
        for (function, trigger) in triggers_with_functions(database) {
            if !row_trigger(trigger, TriggerPeriod::Before) || !fires_on_insert(trigger) {
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
            let mut guarded = Vec::new();
            for foreign_key in table.foreign_keys(database)? {
                let parent = Parent::new(database, table, foreign_key)?;
                if parent.guarded(false)? && parent.settled()? {
                    guarded.push(parent);
                }
            }
            let mut reach = Reach::new(database, WritesElsewhere::new(database, table));
            let mut returns = Returns {
                reach: &mut reach,
                guarded: &guarded,
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
