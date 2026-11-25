//! Submodule providing the `CaseWithoutMatch` rule.

use sql_traits::{
    structs::{EmbeddedSql, PlPgSqlSiteRole},
    traits::DatabaseLike,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        function_rules::readable,
        plpgsql_site_support::{CASE, plpgsql_sites, written},
    },
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports a PL/pgSQL `CASE` statement
    /// without `ELSE` that some path reaches the end of with no `WHEN`
    /// matched.
    ///
    /// PostgreSQL raises `case_not_found` there. The `WHEN` clauses are read
    /// under what each variable may hold where the body reaches the `CASE`,
    /// so a `CASE` whose clauses cover every value the subject may hold
    /// there, `NULL` included, is not reported.
    ///
    /// The rule does not run on SQLite, which has no stored functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = CaseWithoutMatch::default().into();
    /// let schema = |last: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE FUNCTION sign_of(n INT) RETURNS TEXT LANGUAGE plpgsql AS $$
    ///          BEGIN
    ///              CASE WHEN n > 0 THEN RETURN 'positive';
    ///                   WHEN n < 0 THEN RETURN 'negative';
    ///                   {last}
    ///              END CASE;
    ///          END $$;"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("WHEN n = 0 THEN RETURN 'zero';")).is_err());
    /// assert!(constrainer.validate_schema(&schema("ELSE RETURN 'zero or null';")).is_ok());
    /// ```
    CaseWithoutMatch,
    register_function_rule,
    LintGroup::Suspicious,
    "A PL/pgSQL CASE statement without ELSE raises case_not_found when no WHEN matches, which a value the WHEN clauses leave out, NULL among them, makes happen at run time.",
    Some(
        "https://www.postgresql.org/docs/18/plpgsql-control-structures.html#PLPGSQL-CONDITIONALS-SIMPLE-CASE"
    ),
    RuleExample {
        bad: "CREATE FUNCTION sign_of(n integer) RETURNS text LANGUAGE plpgsql AS $$ BEGIN CASE WHEN n > 0 THEN RETURN 'positive'; WHEN n < 0 THEN RETURN 'negative'; WHEN n = 0 THEN RETURN 'zero'; END CASE; END $$;",
        good: "CREATE FUNCTION sign_of(n integer) RETURNS text LANGUAGE plpgsql AS $$ BEGIN CASE WHEN n > 0 THEN RETURN 'positive'; WHEN n < 0 THEN RETURN 'negative'; ELSE RETURN 'zero or null'; END CASE; END $$;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> FunctionRule for CaseWithoutMatch<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        plpgsql_sites(database, function, |site| {
            let EmbeddedSql::Expression(query) = site.sql() else {
                return Ok(());
            };
            let opening = match site.role() {
                PlPgSqlSiteRole::CaseSubject => format!("CASE {}", written(query)),
                PlPgSqlSiteRole::CaseWhen { .. } => format!("CASE WHEN {}", written(query)),
                _ => return Ok(()),
            };
            if readable(site.unmatched(CASE))? != Some(true) {
                return Ok(());
            }
            reporter.function(
                function,
                format!(
                    "In function '{}', a path reaches the end of the CASE statement `{opening}` with no WHEN matched, where PostgreSQL raises case_not_found.",
                    signature(function, database)
                ),
                "Add an ELSE for the values no WHEN matches, NULL among them, or a WHEN for each.".to_owned(),
            )
        })
    }
}
