//! Submodule providing the `DeadBranch` rule.

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
    /// Struct defining a rule that reports an `IF`, `ELSIF` or searched
    /// `CASE` branch of a PL/pgSQL body whose condition is never true on any
    /// path reaching it.
    ///
    /// The condition is read under what each variable may hold where the
    /// body tests it, from the values assigned on the way, the conditions
    /// taken to get there and the declared type of each parameter. A branch
    /// inside one already never taken is not reported again, and a condition
    /// that raises on every path is left to `always_raising_expression`.
    ///
    /// The rule does not run on SQLite, which has no stored functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = DeadBranch::default().into();
    /// let schema = |second: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE FUNCTION grade(score INT) RETURNS TEXT LANGUAGE plpgsql AS $$
    ///          BEGIN
    ///              IF score >= 50 THEN RETURN 'pass';
    ///              ELSIF {second} THEN RETURN 'distinction';
    ///              END IF;
    ///              RETURN 'fail';
    ///          END $$;"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("score >= 90")).is_err());
    /// assert!(constrainer.validate_schema(&schema("score >= 30")).is_ok());
    /// ```
    DeadBranch,
    register_function_rule,
    LintGroup::Suspicious,
    "A PL/pgSQL branch whose condition is never true where the body tests it never runs, which usually means the conditions are written in the wrong order or test the wrong variable.",
    Some("https://www.postgresql.org/docs/18/plpgsql-control-structures.html#PLPGSQL-CONDITIONALS"),
    RuleExample {
        bad: "CREATE FUNCTION grade(score integer) RETURNS text LANGUAGE plpgsql AS $$ BEGIN IF score >= 50 THEN RETURN 'pass'; ELSIF score >= 90 THEN RETURN 'distinction'; END IF; RETURN 'fail'; END $$;",
        good: "CREATE FUNCTION grade(score integer) RETURNS text LANGUAGE plpgsql AS $$ BEGIN IF score >= 90 THEN RETURN 'distinction'; ELSIF score >= 50 THEN RETURN 'pass'; END IF; RETURN 'fail'; END $$;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> FunctionRule for DeadBranch<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        evaluated_sites(database, function, |site| {
            let EvaluatedSite {
                role:
                    PlPgSqlSiteRole::IfCondition { .. }
                    | PlPgSqlSiteRole::ElsifCondition { .. }
                    | PlPgSqlSiteRole::CaseWhen { .. },
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
                    "In function '{}', {described} is never true where the body tests it, so the branch it guards never runs.",
                    signature(function, database)
                ),
                "Remove the branch, or correct its condition or the ones tested before it.".to_owned(),
            )
        })
    }
}
