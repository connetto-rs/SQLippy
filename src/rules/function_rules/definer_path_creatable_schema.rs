//! Submodule providing the `DefinerPathCreatableSchema` rule.

use sql_traits::{
    traits::{DatabaseLike, FunctionLike, GrantLike, SchemaLike, grant::GrantTarget},
    utils::identifier_resolution::{is_temporary_schema, normalize_identifier},
};
use sqlparser::ast::{Action, GranteeName};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::grant_support::grants_privilege,
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// The predefined role owning the `public` schema, standing for whoever owns
/// the database.
const DATABASE_OWNER: &str = "pg_database_owner";

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
}

/// The roles other than `owner` that may create objects in `schema`, as they
/// read in a message.
fn creators<DB: DatabaseLike>(database: &DB, schema: &str, owner: Option<&str>) -> Vec<String> {
    let mut creators = Vec::new();
    let is_owner = |role: &str| owner == Some(role);
    if let Some(schema_owner) = database
        .schema(schema)
        .and_then(SchemaLike::authorization)
        .filter(|schema_owner| *schema_owner != DATABASE_OWNER && !is_owner(schema_owner))
    {
        creators.push(format!("its owner '{schema_owner}'"));
    }
    for grant in database.table_grants() {
        let GrantTarget::Schemas(mut targets) = grant.target() else {
            continue;
        };
        if !targets
            .any(|target| normalize_identifier(target.name(), target.name_is_quoted()) == schema)
            || !grants_privilege(database, grant, |action| {
                matches!(action, Action::Create { .. })
            })
        {
            continue;
        }
        if grant.applies_to_public() {
            creators.push("PUBLIC".to_owned());
            continue;
        }
        for grantee in grant.grantees(database) {
            let Some(GranteeName::ObjectName(name)) = &grantee.name else {
                continue;
            };
            let Some(ident) = name.0.last().and_then(|part| part.as_ident()) else {
                continue;
            };
            let role = normalize_identifier(&ident.value, ident.quote_style.is_some());
            let creator = format!("role '{role}'");
            if !is_owner(&role) && !creators.contains(&creator) {
                creators.push(creator);
            }
        }
    }
    creators
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
        for (schema, quoted) in &path {
            let schema = normalize_identifier(schema, *quoted);
            if schema.is_empty()
                || schema == "pg_catalog"
                || schema == "$user"
                || is_temporary_schema(&schema, true)
            {
                continue;
            }
            let creators = creators(database, &schema, owner);
            if creators.is_empty() {
                continue;
            }
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
