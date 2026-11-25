//! Submodule providing the `DecidedBranch` rule.

use sql_traits::{
    structs::{Outcomes, PlPgSqlSiteRole},
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
    /// `CASE` condition of a PL/pgSQL body that is always true on every path
    /// reaching it, while an `ELSIF`, a `WHEN` or an `ELSE` follows it.
    ///
    /// The branches after such a condition never run. The condition is read
    /// under what each variable may hold where the body tests it, from the
    /// values assigned on the way, the conditions taken to get there and the
    /// declared type of each parameter. A condition with nothing after it is
    /// not reported, since no branch depends on it being false.
    ///
    /// The rule does not run on SQLite, which has no stored functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = DecidedBranch::default().into();
    /// let schema = |second: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE FUNCTION label(quantity INT) RETURNS TEXT LANGUAGE plpgsql AS $$
    ///          BEGIN
    ///              IF quantity IS NULL THEN RETURN 'unknown';
    ///              ELSIF {second} THEN RETURN 'stock';
    ///              ELSE RETURN 'backorder';
    ///              END IF;
    ///          END $$;"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("quantity IS NOT NULL")).is_err());
    /// assert!(constrainer.validate_schema(&schema("quantity > 0")).is_ok());
    /// ```
    DecidedBranch,
    register_function_rule,
    LintGroup::Suspicious,
    "A PL/pgSQL condition that is always true where the body tests it leaves every branch after it dead, which usually means it tests the wrong variable or a value already settled.",
    Some("https://www.postgresql.org/docs/18/plpgsql-control-structures.html#PLPGSQL-CONDITIONALS"),
    RuleExample {
        bad: "CREATE FUNCTION label(quantity integer) RETURNS text LANGUAGE plpgsql AS $$ BEGIN IF quantity IS NULL THEN RETURN 'unknown'; ELSIF quantity IS NOT NULL THEN RETURN 'stock'; ELSE RETURN 'backorder'; END IF; END $$;",
        good: "CREATE FUNCTION label(quantity integer) RETURNS text LANGUAGE plpgsql AS $$ BEGIN IF quantity IS NULL THEN RETURN 'unknown'; ELSIF quantity > 0 THEN RETURN 'stock'; ELSE RETURN 'backorder'; END IF; END $$;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> FunctionRule for DecidedBranch<DB> {
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
                    PlPgSqlSiteRole::IfCondition { followed: true }
                    | PlPgSqlSiteRole::ElsifCondition { followed: true }
                    | PlPgSqlSiteRole::CaseWhen { followed: true },
                described,
                truth,
            } = site
            else {
                return Ok(());
            };
            if truth.outcomes != Outcomes::TRUE {
                return Ok(());
            }
            reporter.function(
                function,
                format!(
                    "In function '{}', {described} is always true where the body tests it, so the branches after it never run.",
                    signature(function, database)
                ),
                "Remove the condition and the branches after it, or correct the condition.".to_owned(),
            )
        })
    }
}
