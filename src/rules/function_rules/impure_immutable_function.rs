//! Submodule providing the `ImpureImmutableFunction` rule.

use sql_traits::traits::{DatabaseLike, FunctionLike, TableLike};
use sqlparser::ast::FunctionBehavior;

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::function_rules::unreadable_body,
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Struct defining a rule that reports a function declared `IMMUTABLE`
/// whose body reads a table or calls a function that is not `IMMUTABLE`.
///
/// The planner evaluates an immutable call ahead of time, and an index or
/// generated column built on it keeps the value it computed, so a function
/// whose result can change goes stale there. Bodies whose reads cannot be
/// known are skipped.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ImpureImmutableFunction::default().into();
/// let schema = "CREATE TABLE rates (rate NUMERIC);";
/// let reading = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE FUNCTION rate() RETURNS NUMERIC LANGUAGE sql IMMUTABLE
///        SET search_path = '' AS $$ SELECT max(rate) FROM public.rates $$;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&reading).is_err());
/// let pure = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE FUNCTION twice(x NUMERIC) RETURNS NUMERIC LANGUAGE sql IMMUTABLE
///        AS $$ SELECT x * 2 $$;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&pure).is_ok());
/// ```
pub struct ImpureImmutableFunction<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ImpureImmutableFunction<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ImpureImmutableFunction<DB>> for GenericConstrainer<DB> {
    fn from(rule: ImpureImmutableFunction<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ImpureImmutableFunction<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "ImpureImmutableFunction",
            group: LintGroup::Suspicious,
            rationale: "PostgreSQL assumes an IMMUTABLE function returns the same result for the same arguments forever, so it pre-evaluates calls and indexes and generated columns keep their results, which go stale when the function reads a table or a function that can change.",
            source: Some("https://www.postgresql.org/docs/current/xfunc-volatility.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE rates (rate NUMERIC);\n\
CREATE FUNCTION rate() RETURNS NUMERIC LANGUAGE sql IMMUTABLE SET search_path = '' AS 'SELECT max(rate) FROM public.rates';",
                good: "CREATE TABLE rates (rate NUMERIC);\n\
CREATE FUNCTION rate() RETURNS NUMERIC LANGUAGE sql STABLE SET search_path = '' AS 'SELECT max(rate) FROM public.rates';",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> FunctionRule for ImpureImmutableFunction<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if function.volatility() != FunctionBehavior::Immutable
            || function.target_name().schema() == Some("pg_catalog")
        {
            return Ok(());
        }
        let read = function
            .referenced_tables(database)
            .and_then(|tables| Ok((tables, function.referenced_functions(database)?)))
            .map(Some)
            .or_else(|error| unreadable_body(&error).then_some(None).ok_or(error))?;
        let Some((tables, calls)) = read else {
            return Ok(());
        };
        let mut changing: Vec<String> = tables
            .iter()
            .map(|table| format!("reads '{}'", table.table_name()))
            .collect();
        changing.extend(
            calls
                .iter()
                .filter(|called| called.volatility() != FunctionBehavior::Immutable)
                .map(|called| {
                    format!(
                        "calls {} '{}'",
                        called.volatility().to_string().to_ascii_lowercase(),
                        signature(*called, database)
                    )
                }),
        );
        if changing.is_empty() {
            return Ok(());
        }
        let signature = signature(function, database);
        reporter.function(
            function,
            format!(
                "IMMUTABLE function '{signature}' {}, so its result can change while PostgreSQL treats it as fixed.",
                changing.join(" and ")
            ),
            format!("Declare '{signature}' STABLE, or pass what it reads as arguments."),
        )?;
        Ok(())
    }
}
