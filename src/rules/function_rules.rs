//! Submodule providing constraint structs that can be applied to functions.

mod definer_without_search_path;
pub use definer_without_search_path::DefinerWithoutSearchPath;
mod definer_temporary_schema_not_last;
pub use definer_temporary_schema_not_last::DefinerTemporarySchemaNotLast;
mod exposed_definer_over_protected_table;
pub use exposed_definer_over_protected_table::ExposedDefinerOverProtectedTable;

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
