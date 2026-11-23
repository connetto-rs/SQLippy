//! Submodule providing the `LeakproofUserFunction` rule.

use sql_traits::traits::{DatabaseLike, FunctionLike};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Struct defining a rule that reports a user-defined function marked
/// `LEAKPROOF`.
///
/// The planner may evaluate a `LEAKPROOF` function before a row-level security
/// policy or a `security_barrier` view filters rows, so the function sees rows
/// the caller cannot read. A body that raises an error or a notice naming an
/// argument, or whose running time depends on one, discloses those rows.
/// Whether a body is free of such channels cannot be read from its text, so
/// every marking is reported for audit. PostgreSQL's own functions in
/// `pg_catalog` are not reported.
///
/// The rule does not run on SQLite, which has no stored functions.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = LeakproofUserFunction::default().into();
/// let marked = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE FUNCTION same(a TEXT, b TEXT) RETURNS BOOLEAN LANGUAGE sql LEAKPROOF
///        AS 'SELECT a = b';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&marked).is_err());
/// let unmarked = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE FUNCTION same(a TEXT, b TEXT) RETURNS BOOLEAN LANGUAGE sql
///        AS 'SELECT a = b';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&unmarked).is_ok());
/// ```
pub struct LeakproofUserFunction<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for LeakproofUserFunction<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<LeakproofUserFunction<DB>> for GenericConstrainer<DB> {
    fn from(rule: LeakproofUserFunction<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for LeakproofUserFunction<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(LeakproofUserFunction),
            group: LintGroup::Suspicious,
            rationale: "PostgreSQL may run a LEAKPROOF function on rows before row-level security or a security_barrier view filters them, so an error, notice or timing that depends on an argument discloses rows the caller cannot read.",
            source: Some("https://www.postgresql.org/docs/current/sql-createfunction.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE FUNCTION same(a TEXT, b TEXT) RETURNS BOOLEAN LANGUAGE sql LEAKPROOF AS 'SELECT a = b';",
                good: "CREATE FUNCTION same(a TEXT, b TEXT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT a = b';",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

impl<DB: DatabaseLike> FunctionRule for LeakproofUserFunction<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !function.is_leakproof() || function.target_name().schema() == Some("pg_catalog") {
            return Ok(());
        }
        let signature = signature(function, database);
        reporter.function(
            function,
            format!(
                "Function '{signature}' is marked LEAKPROOF, so PostgreSQL may run it on rows that row-level security hides, and any error, notice or timing that depends on an argument discloses them."
            ),
            format!(
                "Run ALTER FUNCTION {signature} NOT LEAKPROOF, or confirm that no error, notice or timing in its body depends on an argument."
            ),
        )?;
        Ok(())
    }
}
