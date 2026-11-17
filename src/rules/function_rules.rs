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

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, FunctionLike},
};
use sqlparser::ast::FunctionSecurity;

/// Whether the function runs with its owner's rights and resolves the names in
/// its body when it is called.
fn resolves_as_definer<DB: DatabaseLike>(function: &DB::Function) -> bool {
    function.security_mode() == FunctionSecurity::Definer && !function.body_is_bound()
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
