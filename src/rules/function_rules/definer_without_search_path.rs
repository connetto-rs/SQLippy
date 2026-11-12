//! Submodule providing the `DefinerWithoutSearchPath` rule.

use sql_traits::traits::{DatabaseLike, FunctionLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Struct defining a rule that reports a `SECURITY DEFINER` function that sets
/// no `search_path` and resolves its body when it is called.
///
/// The body then resolves unqualified names under the caller's `search_path`,
/// so a caller's temporary table, or a schema the caller can write and puts
/// first, replaces the relations it names while it runs with its owner's
/// rights. A body written `RETURN <expression>` or as a `BEGIN ATOMIC` block is
/// bound when the function is created and is not reported.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DefinerWithoutSearchPath::default().into();
///
/// let unpinned = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT);
///      CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
///        AS 'SELECT count(*) FROM docs';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&unpinned).is_err());
///
/// let pinned = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT);
///      CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
///        SET search_path = '' AS 'SELECT count(*) FROM public.docs';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&pinned).is_ok());
/// ```
pub struct DefinerWithoutSearchPath<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DefinerWithoutSearchPath<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DefinerWithoutSearchPath<DB>> for GenericConstrainer<DB> {
    fn from(rule: DefinerWithoutSearchPath<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DefinerWithoutSearchPath<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DefinerWithoutSearchPath),
            group: LintGroup::Correctness,
            rationale: "A `SECURITY DEFINER` function without its own `search_path` resolves the names in its body under the caller's path, so a caller's temporary table or schema runs in their place with the owner's rights.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (id INT);\n\
CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER AS 'SELECT count(*) FROM public.docs';",
                good: "CREATE TABLE docs (id INT);\n\
CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER SET search_path = '' AS 'SELECT count(*) FROM public.docs';",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> FunctionRule for DefinerWithoutSearchPath<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !super::resolves_as_definer::<DB>(function) || function.search_path(database)?.is_some()
        {
            return Ok(());
        }
        let signature = signature(function, database);
        reporter.function(
            function,
            format!(
                "`SECURITY DEFINER` function '{signature}' sets no `search_path`, so the names in its body resolve under the caller's path, temporary tables first."
            ),
            format!(
                "ALTER FUNCTION {signature} SET search_path = ''; and qualify every name its body uses."
            ),
        )
    }
}
