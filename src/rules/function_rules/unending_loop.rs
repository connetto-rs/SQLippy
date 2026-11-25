//! Submodule providing the `UnendingLoop` rule.

use sql_traits::traits::DatabaseLike;
use sqlparser_plpgsql::embedded::{Loop, LoopControl};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        function_rules::readable,
        plpgsql_site_support::{CASE, plpgsql_body, written},
    },
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports a `LOOP` or `WHILE` loop of a
    /// PL/pgSQL body that a path enters and no path leaves.
    ///
    /// Control leaves a loop when its condition is false or `NULL`, an
    /// `EXIT` ends it, an `EXIT` or `CONTINUE` inside it reaches a block or
    /// loop around it, a `RETURN` inside it runs, or a step inside it surely
    /// raises an error no handler inside it catches, under what each
    /// variable may hold where the body runs it. A loop control never
    /// leaves runs until the statement is cancelled. A loop written
    /// `WHILE true` with an `EXIT` it may take is not reported, and neither
    /// is a `FOR` loop, which ends when its range, rows or elements run out.
    ///
    /// The rule does not run on SQLite, which has no stored functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnendingLoop::default().into();
    /// let schema = |step: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE FUNCTION drain() RETURNS INT LANGUAGE plpgsql AS $$
    ///          DECLARE remaining INT := 10;
    ///          BEGIN
    ///              WHILE remaining > 0 LOOP
    ///                  {step}
    ///              END LOOP;
    ///              RETURN remaining;
    ///          END $$;"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("PERFORM pg_sleep(1);")).is_err());
    /// assert!(constrainer.validate_schema(&schema("remaining := remaining - 1;")).is_ok());
    /// ```
    UnendingLoop,
    register_function_rule,
    LintGroup::Suspicious,
    "A PL/pgSQL loop no condition, EXIT, RETURN or error leaves runs until the statement is cancelled, which usually means it updates the wrong variable or lacks its EXIT.",
    Some(
        "https://www.postgresql.org/docs/18/plpgsql-control-structures.html#PLPGSQL-CONTROL-STRUCTURES-LOOPS"
    ),
    RuleExample {
        bad: "CREATE FUNCTION drain() RETURNS integer LANGUAGE plpgsql AS $$ DECLARE remaining integer := 10; BEGIN WHILE remaining > 0 LOOP PERFORM pg_sleep(1); END LOOP; RETURN remaining; END $$;",
        good: "CREATE FUNCTION drain() RETURNS integer LANGUAGE plpgsql AS $$ DECLARE remaining integer := 10; BEGIN WHILE remaining > 0 LOOP remaining := remaining - 1; END LOOP; RETURN remaining; END $$;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

/// Describes `repeated` as a finding names it, `None` for a `FOR` loop.
fn described(repeated: &Loop) -> Option<String> {
    let labelled = repeated
        .label
        .as_ref()
        .map_or_else(String::new, |label| format!(" labelled `{label}`"));
    match &repeated.control {
        LoopControl::Unconditional => Some(format!("the LOOP{labelled}")),
        LoopControl::While(condition) => Some(format!(
            "the WHILE loop{labelled} on `{}`",
            written(condition)
        )),
        LoopControl::Range { .. }
        | LoopControl::Query { .. }
        | LoopControl::Cursor { .. }
        | LoopControl::Dynamic { .. }
        | LoopControl::Array { .. } => None,
    }
}

impl<DB: DatabaseLike> FunctionRule for UnendingLoop<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let Some(body) = plpgsql_body(database, function)? else {
            return Ok(());
        };
        for found in readable(body.loops(CASE))? {
            if found.ends() != Some(false) {
                continue;
            }
            let Some(described) = described(found.repeated()) else {
                continue;
            };
            reporter.function(
                function,
                format!(
                    "In function '{}', {described} never ends once the body enters it.",
                    signature(function, database)
                ),
                "Add the EXIT or RETURN that should end the loop, or correct the condition or the variable it reads.".to_owned(),
            )?;
        }
        Ok(())
    }
}
