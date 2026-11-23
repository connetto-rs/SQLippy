//! Submodule providing the `DefinerPathCreatableSchema` rule.

use sql_traits::traits::{DatabaseLike, FunctionLike};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Struct defining a rule that reports a `SECURITY DEFINER` function whose
/// own `search_path` names a schema another role may create objects in.
///
/// A body resolved when the function runs picks, among the functions and
/// operators of every schema on the path, the best match for each call, so a
/// role creating a better-matching overload in any of those schemas, before or
/// after `pg_catalog`, has its code run with the owner's rights. A schema
/// counts when `CREATE` on it is granted to `PUBLIC` or to a role other than
/// the function's owner, or when its owner is another role, `pg_database_owner`
/// aside. A function created before any role was set has no known owner, so
/// every named owner differs from it. `pg_catalog`, `pg_temp` and `$user`,
/// which inside the function names the owner's schema, are not judged, nor are
/// bodies PostgreSQL binds at creation.
///
/// The rule does not run on SQLite, which has no stored functions.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DefinerPathCreatableSchema::default().into();
/// let function = "CREATE FUNCTION app.norm(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER
///                   SET search_path = app, pg_catalog AS 'SELECT lower(x)';";
///
/// let granted = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "CREATE ROLE mallory; CREATE SCHEMA app; GRANT CREATE ON SCHEMA app TO mallory; {function}"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&granted).is_err());
///
/// let used = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "CREATE ROLE mallory; CREATE SCHEMA app; GRANT USAGE ON SCHEMA app TO mallory; {function}"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&used).is_ok());
/// ```
pub struct DefinerPathCreatableSchema<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DefinerPathCreatableSchema<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DefinerPathCreatableSchema<DB>> for GenericConstrainer<DB> {
    fn from(rule: DefinerPathCreatableSchema<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DefinerPathCreatableSchema<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DefinerPathCreatableSchema),
            group: LintGroup::Correctness,
            rationale: "A role that may create objects in a schema on a `SECURITY DEFINER` function's `search_path` can add a better-matching function or operator there, which the body then calls with the owner's rights.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE mallory;\n\
CREATE SCHEMA app;\n\
GRANT CREATE ON SCHEMA app TO mallory;\n\
CREATE FUNCTION app.norm(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER SET search_path = app, pg_catalog AS 'SELECT lower(x)';",
                good: "CREATE ROLE mallory;\n\
CREATE SCHEMA app;\n\
GRANT USAGE ON SCHEMA app TO mallory;\n\
CREATE FUNCTION app.norm(x TEXT) RETURNS TEXT LANGUAGE sql SECURITY DEFINER SET search_path = app, pg_catalog AS 'SELECT lower(x)';",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

impl<DB: DatabaseLike> FunctionRule for DefinerPathCreatableSchema<DB> {
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
        let owner = function.owner(database)?;
        for (schema, creators) in super::creatable_path_schemas(database, &path, owner) {
            let signature = signature(function, database);
            reporter.function(
                function,
                format!(
                    "`SECURITY DEFINER` function '{signature}' searches schema '{schema}', where {} can create objects, so a function or operator created there runs with the owner's rights.",
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
