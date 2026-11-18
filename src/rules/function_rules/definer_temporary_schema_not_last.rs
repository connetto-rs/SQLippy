//! Submodule providing the `DefinerTemporarySchemaNotLast` rule.

use sql_traits::traits::{DatabaseLike, FunctionLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Struct defining a rule that reports a `SECURITY DEFINER` function whose own
/// `search_path` names a schema but leaves `pg_temp` out or before the end.
///
/// PostgreSQL searches the temporary schema first for relations unless the
/// path places it, so a caller's temporary table shadows a table the body
/// names without a schema. A path that names no schema, as `SET search_path =
/// ''` writes it, is left to the body's qualified names and is not reported.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DefinerTemporarySchemaNotLast::default().into();
///
/// let implicit = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT);
///      CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
///        SET search_path = public AS 'SELECT count(*) FROM docs';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&implicit).is_err());
///
/// let last = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT);
///      CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
///        SET search_path = public, pg_temp AS 'SELECT count(*) FROM docs';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&last).is_ok());
/// ```
pub struct DefinerTemporarySchemaNotLast<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DefinerTemporarySchemaNotLast<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DefinerTemporarySchemaNotLast<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: DefinerTemporarySchemaNotLast<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DefinerTemporarySchemaNotLast<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DefinerTemporarySchemaNotLast),
            group: LintGroup::Correctness,
            rationale: "PostgreSQL searches `pg_temp` first for relations unless the path places it, so a `SECURITY DEFINER` function whose path leaves it implicit or before the end reads a caller's temporary table in place of its own.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (id INT);\n\
CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER SET search_path = public AS 'SELECT count(*) FROM docs';",
                good: "CREATE TABLE docs (id INT);\n\
CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS 'SELECT count(*) FROM docs';",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> FunctionRule for DefinerTemporarySchemaNotLast<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !super::resolves_as_definer::<DB>(function) {
            return Ok(());
        }
        let Some(path) = function.search_path(database)? else {
            return Ok(());
        };
        let Some(place) = super::misplaced_temporary_schema(&path) else {
            return Ok(());
        };
        let signature = signature(function, database);
        reporter.function(
            function,
            format!(
                "`SECURITY DEFINER` function '{signature}' sets `search_path = {}` and leaves `pg_temp` {place}.",
                super::written_path(&path)
            ),
            format!(
                "ALTER FUNCTION {signature} SET search_path = {};",
                super::temporary_schema_last(&path)
            ),
        )
    }
}
