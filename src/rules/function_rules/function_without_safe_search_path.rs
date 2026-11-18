//! Submodule providing the `FunctionWithoutSafeSearchPath` rule.

use sql_traits::{
    structs::FunctionKind,
    traits::{DatabaseLike, FunctionLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports a function without a
    /// fixed `search_path` of its own, and a `sql` or `plpgsql` one whose
    /// fixed path searches `pg_temp` before its end or a schema another role
    /// may create objects in.
    ///
    /// The convention is strict. It also reports bodies that name every
    /// relation and function with its schema and bodies PostgreSQL binds at
    /// creation, whose exposure to the caller's path is smaller today but
    /// returns with the first unqualified name a later revision adds.
    /// Aggregates, which take no configuration, are skipped. So are the
    /// findings `definer_without_search_path`,
    /// `definer_temporary_schema_not_last`, `definer_path_creatable_schema` and
    /// `invoker_without_search_path` already raise on the same function.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     FunctionWithoutSafeSearchPath::default().into();
    /// let unpinned = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE FUNCTION norm(x TEXT) RETURNS TEXT LANGUAGE sql AS 'SELECT lower(x)';",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&unpinned).is_err());
    /// let pinned = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE FUNCTION norm(x TEXT) RETURNS TEXT LANGUAGE sql
    ///        SET search_path = pg_catalog, pg_temp AS 'SELECT pg_catalog.lower(x)';",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&pinned).is_ok());
    /// ```
    FunctionWithoutSafeSearchPath,
    register_function_rule,
    LintGroup::Restriction,
    "A function without a fixed `search_path` resolves names under whatever path its caller set, and a fixed path searching `pg_temp` early or a schema another role can create in lets that role supply the relation, function or operator the body calls.",
    Some(
        "https://github.com/supabase/splinter/blob/main/lints/0011_function_search_path_mutable.sql"
    ),
    RuleExample {
        bad: "CREATE FUNCTION public.normalize(value TEXT) RETURNS TEXT\n\
LANGUAGE sql AS $$ SELECT lower(value) $$;",
        good: "CREATE FUNCTION public.normalize(value TEXT) RETURNS TEXT\n\
LANGUAGE sql SET search_path = pg_catalog, pg_temp\n\
AS $$ SELECT pg_catalog.lower(value) $$;",
    },
    Basis::Declared
);

/// Whether PostgreSQL resolves the names of the function's body with the
/// parser of `sql` or `plpgsql`, the languages whose path this rule judges.
fn resolves_sql<DB: DatabaseLike>(function: &DB::Function) -> bool {
    function
        .stored_language()
        .is_none_or(|language| matches!(language.as_ref(), "sql" | "plpgsql"))
}

impl<DB: DatabaseLike> FunctionRule for FunctionWithoutSafeSearchPath<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if function.target_name().schema() == Some("pg_catalog")
            || super::resolves_as_definer::<DB>(function)
            || function.kind(database)? == FunctionKind::Aggregate
        {
            return Ok(());
        }
        let signature = signature(function, database);
        let Some(path) = function.search_path(database)? else {
            if super::invoker_without_search_path::unpinned_reaching_site(database, function)?
                .is_some()
            {
                return Ok(());
            }
            let exposure = if function.body_is_bound() {
                " PostgreSQL bound its body at creation, so today only names it resolves when it runs, such as those of dynamic SQL, follow the caller's path."
            } else {
                ""
            };
            return reporter.function(
                function,
                format!(
                    "Function '{signature}' sets no `search_path`, so the names its body resolves when it runs follow the caller's path.{exposure}"
                ),
                format!(
                    "ALTER FUNCTION {signature} SET search_path = pg_catalog, pg_temp; and qualify every other name its body uses."
                ),
            );
        };
        if !resolves_sql::<DB>(function) {
            return Ok(());
        }
        if let Some(place) = super::misplaced_temporary_schema(&path) {
            reporter.function(
                function,
                format!(
                    "Function '{signature}' sets `search_path = {}` and leaves `pg_temp` {place}, so a caller's temporary relation shadows the ones its body names.",
                    super::written_path(&path)
                ),
                format!(
                    "ALTER FUNCTION {signature} SET search_path = {};",
                    super::temporary_schema_last(&path)
                ),
            )?;
        }
        let owner = function.owner(database)?;
        for (schema, creators) in super::creatable_path_schemas(database, &path, owner) {
            reporter.function(
                function,
                format!(
                    "Function '{signature}' searches schema '{schema}', where {} can create objects, so a function or operator created there replaces the one its body calls.",
                    creators.join(", ")
                ),
                format!(
                    "Drop '{schema}' from the function's search_path and qualify the names its body uses, or keep CREATE on '{schema}' to the function's owner."
                ),
            )?;
        }
        Ok(())
    }
}
