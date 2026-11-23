//! Submodule providing the `RepeatedFunctionSearchPath` rule.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::Statement;

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::script_support::is_search_path,
    traits::{Constrainer, GenericConstrainer, Reporter, ScriptRule},
};

rule_definition!(
    /// Struct defining a rule that reports a `CREATE FUNCTION` writing more
    /// than one `SET search_path` clause.
    ///
    /// The function runs with the last clause, which the built schema keeps
    /// alone, so only the statement as written shows the earlier ones.
    ///
    /// The rule does not run on SQLite, which has no stored functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     RepeatedFunctionSearchPath::default().into();
    /// for (sql, findings) in [
    ///     ("CREATE FUNCTION f() RETURNS INT LANGUAGE sql SET search_path = pg_catalog, pg_temp
    ///       SET search_path = public AS 'SELECT 1';", 1),
    ///     ("CREATE FUNCTION f() RETURNS INT LANGUAGE sql SET search_path = pg_catalog, pg_temp
    ///       AS 'SELECT 1';", 0),
    /// ] {
    ///     let database = ParserDB::parse::<PostgreSqlDialect>(sql).unwrap();
    ///     let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap();
    ///     assert_eq!(constrainer.script_diagnostics(&database, &statements).len(), findings);
    /// }
    /// ```
    RepeatedFunctionSearchPath,
    register_script_rule,
    LintGroup::Suspicious,
    "A function runs with its last `SET search_path` clause, so a reviewer reading the first, safe-looking clause misses the path the function resolves names with.",
    Some("https://github.com/timescale/pgspot/blob/main/src/pgspot/visitors.py"),
    RuleExample {
        bad: "CREATE FUNCTION public.answer() RETURNS INT LANGUAGE sql\n\
SET search_path = pg_catalog, pg_temp\n\
SET search_path = public\n\
AS $$ SELECT 42 $$;",
        good: "CREATE FUNCTION public.answer() RETURNS INT LANGUAGE sql\n\
SET search_path = pg_catalog, pg_temp\n\
AS $$ SELECT 42 $$;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> ScriptRule for RepeatedFunctionSearchPath<DB> {
    type Database = DB;

    fn check_script(
        &self,
        _database: &Self::Database,
        statements: &[Statement],
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for statement in statements {
            let Statement::CreateFunction(function) = statement else {
                continue;
            };
            let clauses: Vec<String> = function
                .set_params
                .iter()
                .filter(|param| is_search_path(&param.name))
                .map(ToString::to_string)
                .collect();
            let [.., last] = clauses.as_slice() else {
                continue;
            };
            if clauses.len() < 2 {
                continue;
            }
            let name = &function.name;
            reporter.statement(
                statement,
                clauses.join(" "),
                format!(
                    "Function '{name}' writes {} search_path clauses and runs with the last, {last}.",
                    clauses.len()
                ),
                format!("Keep only the search_path clause '{name}' should run with."),
            )?;
        }
        Ok(())
    }
}
