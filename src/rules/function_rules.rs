//! Submodule providing constraint structs that can be applied to functions.

mod dynamic_sql_injection;
pub use dynamic_sql_injection::DynamicSqlInjection;
mod definer_without_search_path;
pub use definer_without_search_path::DefinerWithoutSearchPath;
mod definer_temporary_schema_not_last;
pub use definer_temporary_schema_not_last::DefinerTemporarySchemaNotLast;
mod definer_path_creatable_schema;
pub use definer_path_creatable_schema::DefinerPathCreatableSchema;
mod exposed_definer_over_protected_table;
pub use exposed_definer_over_protected_table::ExposedDefinerOverProtectedTable;
mod impure_immutable_function;
pub use impure_immutable_function::ImpureImmutableFunction;
mod invoker_without_search_path;
pub use invoker_without_search_path::InvokerWithoutSearchPath;
mod leakproof_user_function;
pub use leakproof_user_function::LeakproofUserFunction;
mod writing_non_volatile_function;
pub use writing_non_volatile_function::WritingNonVolatileFunction;
mod table_name_dispatch;
pub use table_name_dispatch::TableNameDispatch;
mod snapshot_before_lock;
pub use snapshot_before_lock::SnapshotBeforeLock;
mod plpgsql_ambiguous_name;
pub use plpgsql_ambiguous_name::PlpgsqlAmbiguousName;
mod function_without_safe_search_path;
pub use function_without_safe_search_path::FunctionWithoutSafeSearchPath;

use std::borrow::Cow;

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, FunctionLike, GrantLike, SchemaLike, grant::GrantTarget},
    utils::identifier_resolution::{SearchPath, is_temporary_schema, normalize_identifier},
};
use sqlparser::ast::{Action, FunctionSecurity};

use crate::rules::grant_support::{grantee_role, grants_privilege};

/// The predefined role owning the `public` schema, standing for whoever owns
/// the database.
const DATABASE_OWNER: &str = "pg_database_owner";

/// Whether the function runs with its owner's rights and resolves the names in
/// its body when it is called.
fn resolves_as_definer<DB: DatabaseLike>(function: &DB::Function) -> bool {
    function.security_mode() == FunctionSecurity::Definer && !function.body_is_bound()
}

/// Where `path` leaves `pg_temp` when it does not search `pg_temp` last, as it
/// reads in a message.
///
/// PostgreSQL searches the temporary schema first for relations and types
/// unless the path places it, so a path naming no schema searches it before
/// `pg_catalog`.
fn misplaced_temporary_schema(path: &SearchPath<'_>) -> Option<&'static str> {
    let mut schemas = path.iter().filter(|(schema, _)| !schema.is_empty());
    match schemas.next_back() {
        Some((last, last_quoted)) if is_temporary_schema(last, *last_quoted) => None,
        Some(_) if schemas.any(|(schema, quoted)| is_temporary_schema(schema, *quoted)) => {
            Some("before the end")
        }
        _ => Some("out, so it is searched first"),
    }
}

/// The schemas of `path`, as `SET search_path` lists them.
fn written_path(path: &SearchPath<'_>) -> String {
    if path.iter().all(|(schema, _)| schema.is_empty()) {
        return "''".to_owned();
    }
    path.iter()
        .map(|(schema, _)| schema.as_ref())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The schemas of `path` with `pg_temp` moved last, as `SET search_path`
/// lists them, behind `pg_catalog` when `path` names no other schema.
fn temporary_schema_last(path: &SearchPath<'_>) -> String {
    let mut schemas: Vec<&str> = path
        .iter()
        .map(|(schema, _)| schema.as_ref())
        .filter(|schema| !schema.is_empty() && !is_temporary_schema(schema, false))
        .collect();
    if schemas.is_empty() {
        schemas.push("pg_catalog");
    }
    schemas.push("pg_temp");
    schemas.join(", ")
}

/// Each schema on `path` that a role other than `owner` may create objects
/// in, with those roles as they read in a message.
///
/// `pg_catalog`, `pg_temp` and `$user` are not judged.
fn creatable_path_schemas<'path, DB: DatabaseLike>(
    database: &DB,
    path: &'path SearchPath<'_>,
    owner: Option<&str>,
) -> Vec<(Cow<'path, str>, Vec<String>)> {
    path.iter()
        .map(|(schema, quoted)| normalize_identifier(schema, *quoted))
        .filter(|schema| {
            !schema.is_empty()
                && schema != "pg_catalog"
                && schema != "$user"
                && !is_temporary_schema(schema, true)
        })
        .filter_map(|schema| {
            let creators = creators(database, &schema, owner);
            (!creators.is_empty()).then_some((schema, creators))
        })
        .collect()
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
        for role in grant.grantees(database).filter_map(grantee_role) {
            let creator = format!("role '{role}'");
            if !is_owner(&role) && !creators.contains(&creator) {
                creators.push(creator);
            }
        }
    }
    creators
}

/// Whether the error says a function body's reads cannot be known, as opposed
/// to a schema object failing to resolve.
pub(crate) fn unreadable_body(error: &LookupError) -> bool {
    matches!(
        error,
        LookupError::FunctionBodyNotSql { .. }
            | LookupError::FunctionBodyUnavailable { .. }
            | LookupError::FunctionBodyUnresolvable { .. }
            | LookupError::FunctionBodyUnparsable { .. }
    )
}

/// `result`, or the default value for a body that is not SQL, is missing or
/// does not parse.
pub(crate) fn readable<T: Default>(result: Result<T, LookupError>) -> Result<T, LookupError> {
    result.or_else(|error| unreadable_body(&error).then(T::default).ok_or(error))
}
