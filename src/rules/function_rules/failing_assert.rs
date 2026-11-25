//! Submodule providing the `FailingAssert` rule.

use sql_traits::{
    structs::{PlPgSqlSiteRole, Raising},
    traits::DatabaseLike,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::plpgsql_site_support::{EvaluatedSite, evaluated_sites},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports an `ASSERT` of a PL/pgSQL body
    /// whose condition is never true on any path reaching it.
    ///
    /// PostgreSQL raises `assert_failure` when the condition is false or
    /// `NULL`, so such an `ASSERT` fails every time the body reaches it
    /// while `plpgsql.check_asserts` is on, the default. The condition is
    /// read under what each variable may hold where the body tests it, and a
    /// condition that raises on every path is left to
    /// `always_raising_expression`.
    ///
    /// The rule does not run on SQLite, which has no stored functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = FailingAssert::default().into();
    /// let schema = |declared: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE FUNCTION scaled(amount INT) RETURNS INT LANGUAGE plpgsql AS $$
    ///          DECLARE factor INT{declared};
    ///          BEGIN
    ///              ASSERT factor IS NOT NULL, 'factor unset';
    ///              RETURN amount * factor;
    ///          END $$;"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("")).is_err());
    /// assert!(constrainer.validate_schema(&schema(" := 100")).is_ok());
    /// ```
    FailingAssert,
    register_function_rule,
    LintGroup::Correctness,
    "A PL/pgSQL ASSERT whose condition is never true where the body tests it raises assert_failure every time the body reaches it.",
    Some(
        "https://www.postgresql.org/docs/18/plpgsql-errors-and-messages.html#PLPGSQL-STATEMENTS-ASSERT"
    ),
    RuleExample {
        bad: "CREATE FUNCTION scaled(amount integer) RETURNS integer LANGUAGE plpgsql AS $$ DECLARE factor integer; BEGIN ASSERT factor IS NOT NULL, 'factor unset'; RETURN amount * factor; END $$;",
        good: "CREATE FUNCTION scaled(amount integer) RETURNS integer LANGUAGE plpgsql AS $$ DECLARE factor integer := 100; BEGIN ASSERT factor IS NOT NULL, 'factor unset'; RETURN amount * factor; END $$;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> FunctionRule for FailingAssert<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        evaluated_sites(database, function, |site| {
            let EvaluatedSite {
                role: PlPgSqlSiteRole::AssertCondition,
                described,
                truth,
            } = site
            else {
                return Ok(());
            };
            if truth.outcomes.truth || truth.raising == Raising::Always {
                return Ok(());
            }
            reporter.function(
                function,
                format!(
                    "In function '{}', {described} is never true where the body tests it, so the ASSERT fails every time the body reaches it.",
                    signature(function, database)
                ),
                "Correct the condition, or the values the body gives it before the ASSERT.".to_owned(),
            )
        })
    }
}
