//! Submodule providing the `ReplacementWithoutTrustedCreation` rule.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::Statement;

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::script_support::{Guard, Object, ScriptState, creation},
    traits::{Constrainer, GenericConstrainer, Reporter, ScriptRule},
};

rule_definition!(
    /// Struct defining a rule that reports `CREATE OR REPLACE` of a function,
    /// aggregate, view or trigger that no earlier statement of the script
    /// established.
    ///
    /// A replacement is established when the script earlier created, without
    /// `OR REPLACE` or `IF NOT EXISTS`, the schema it lands in, the same
    /// object with the same signature, or for a trigger its table. Otherwise
    /// the statement can take over an object someone else created first,
    /// keeping that owner, who can then rewrite it, and the grants on it.
    /// The order is read from the script, since the built schema keeps only
    /// the last definition.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     ReplacementWithoutTrustedCreation::default().into();
    /// let view = "CREATE OR REPLACE VIEW app.answers AS SELECT 42 AS answer;";
    /// for (sql, findings) in [
    ///     (format!("CREATE SCHEMA IF NOT EXISTS app; {view}"), 1),
    ///     (format!("CREATE SCHEMA app; {view}"), 0),
    /// ] {
    ///     let database = ParserDB::parse::<PostgreSqlDialect>(&sql).unwrap();
    ///     let statements = Parser::parse_sql(&PostgreSqlDialect {}, &sql).unwrap();
    ///     assert_eq!(constrainer.script_diagnostics(&database, &statements).len(), findings);
    /// }
    /// ```
    ReplacementWithoutTrustedCreation,
    register_script_rule,
    LintGroup::Restriction,
    "`CREATE OR REPLACE` takes over an object that already exists, so an installer replacing one an attacker created first leaves it owned by the attacker, with every grant the attacker gave.",
    Some("https://github.com/timescale/pgspot/blob/main/src/pgspot/visitors.py"),
    RuleExample {
        bad: "CREATE OR REPLACE FUNCTION public.answer() RETURNS INT\n\
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$ SELECT 42 $$;\n\
CREATE OR REPLACE VIEW public.answers AS SELECT 42 AS answer;",
        good: "CREATE SCHEMA application;\n\
CREATE OR REPLACE FUNCTION application.answer() RETURNS INT\n\
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$ SELECT 42 $$;\n\
CREATE OR REPLACE VIEW application.answers AS SELECT 42 AS answer;",
    }
);

impl<DB: DatabaseLike> ScriptRule for ReplacementWithoutTrustedCreation<DB> {
    type Database = DB;

    fn check_script(
        &self,
        _database: &Self::Database,
        statements: &[Statement],
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut state = ScriptState::default();
        for statement in statements {
            if let Some(creation) = creation(statement)
                && creation.guard == Guard::OrReplace
                && matches!(
                    creation.object,
                    Object::Function(_)
                        | Object::Aggregate(_)
                        | Object::View(_)
                        | Object::Trigger { .. }
                )
                && !state.establishes(&creation)
            {
                let described = creation.object.to_string();
                let place = creation.schema.as_deref().map_or_else(
                    || "wherever the search_path puts it".to_owned(),
                    |schema| format!("in schema {schema}"),
                );
                reporter.statement(
                    statement,
                    described.clone(),
                    format!(
                        "CREATE OR REPLACE of {described} takes over one someone else may have created first {place}, keeping that owner and its grants, since this script created neither the object nor its schema earlier."
                    ),
                    format!(
                        "Create the schema earlier in this script with CREATE SCHEMA and no IF NOT EXISTS, or create {described} without OR REPLACE."
                    ),
                )?;
            }
            state.advance(statement);
        }
        Ok(())
    }
}
