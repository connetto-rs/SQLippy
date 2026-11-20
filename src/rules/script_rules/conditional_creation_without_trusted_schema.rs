//! Submodule providing the `ConditionalCreationWithoutTrustedSchema` rule.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::Statement;

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::script_support::{Guard, Object, ScriptState, creation},
    traits::{Constrainer, GenericConstrainer, Reporter, ScriptRule},
};

rule_definition!(
    /// Struct defining a rule that reports `IF NOT EXISTS` on a schema,
    /// table, materialized view, sequence, index or foreign server that no
    /// earlier statement of the script established.
    ///
    /// A guarded creation is established when the script earlier created,
    /// without `OR REPLACE` or `IF NOT EXISTS`, the schema the object lands
    /// in or the object itself. A foreign server lands in no schema, so only
    /// an earlier unconditional `CREATE SERVER` establishes it. `CREATE
    /// SCHEMA IF NOT EXISTS` establishes nothing, since it too accepts a
    /// schema someone else created. The rule does not run on SQLite, whose
    /// objects have no owner or grants to adopt.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     ConditionalCreationWithoutTrustedSchema::default().into();
    /// let table = "CREATE TABLE IF NOT EXISTS app.docs (id INT);";
    /// for (sql, findings) in [
    ///     (format!("CREATE SCHEMA IF NOT EXISTS app; {table}"), 2),
    ///     (format!("CREATE SCHEMA app; {table}"), 0),
    /// ] {
    ///     let database = ParserDB::parse::<PostgreSqlDialect>(&sql).unwrap();
    ///     let statements = Parser::parse_sql(&PostgreSqlDialect {}, &sql).unwrap();
    ///     assert_eq!(constrainer.script_diagnostics(&database, &statements).len(), findings);
    /// }
    /// ```
    ConditionalCreationWithoutTrustedSchema,
    register_script_rule,
    LintGroup::Restriction,
    "`IF NOT EXISTS` accepts an object someone else created first, so its owner, definition and grants survive the installation unchanged.",
    Some("https://github.com/timescale/pgspot/blob/main/src/pgspot/visitors.py"),
    RuleExample {
        bad: "CREATE SCHEMA IF NOT EXISTS application;\n\
CREATE SEQUENCE IF NOT EXISTS public.ticket_numbers;\n\
CREATE TABLE IF NOT EXISTS public.documents (identifier INT PRIMARY KEY);\n\
CREATE INDEX IF NOT EXISTS document_identifiers ON public.documents (identifier);",
        good: "CREATE SCHEMA application;\n\
CREATE SEQUENCE IF NOT EXISTS application.ticket_numbers;\n\
CREATE TABLE IF NOT EXISTS application.documents (identifier INT PRIMARY KEY);\n\
CREATE INDEX IF NOT EXISTS document_identifiers ON application.documents (identifier);",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> ScriptRule for ConditionalCreationWithoutTrustedSchema<DB> {
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
                && creation.guard == Guard::IfNotExists
                && !state.establishes(&creation)
            {
                let described = creation.object.to_string();
                let resolution = match (&creation.object, creation.schema.as_deref()) {
                    (Object::Schema(name), _) => format!(
                        "Write CREATE SCHEMA {name} without IF NOT EXISTS, so the installation fails rather than adopt a schema someone else owns."
                    ),
                    (Object::Server(name), _) => format!(
                        "Write CREATE SERVER {name} without IF NOT EXISTS, since no schema protects a server."
                    ),
                    (_, Some(schema)) => format!(
                        "Create schema {schema} earlier in this script without IF NOT EXISTS, or drop IF NOT EXISTS from this statement."
                    ),
                    (_, None) => format!(
                        "Qualify {described} with a schema this script creates earlier without IF NOT EXISTS, or drop IF NOT EXISTS from this statement."
                    ),
                };
                reporter.statement(
                    statement,
                    described.clone(),
                    format!(
                        "IF NOT EXISTS keeps any {described} someone else created first, with its owner, definition and grants, since this script established neither it nor its schema earlier."
                    ),
                    resolution,
                )?;
            }
            state.advance(statement);
        }
        Ok(())
    }
}
