//! Submodule providing constraint structs that can be applied to tables.

mod lowercase_table_name;
pub use lowercase_table_name::LowercaseTableName;
mod snake_case_table_name;
pub use snake_case_table_name::SnakeCaseTableName;
mod plural_table_name;
pub use plural_table_name::PluralTableName;
mod unique_check_rule;
pub use unique_check_rule::UniqueCheckRule;
mod unique_unique_index;
pub use unique_unique_index::UniqueUniqueIndex;
mod unique_foreign_key;
pub use unique_foreign_key::UniqueForeignKey;
mod has_primary_key;
pub use has_primary_key::HasPrimaryKey;
mod no_forbidden_column_in_extension;
pub use no_forbidden_column_in_extension::NoForbiddenColumnInExtension;
mod no_rust_keyword_table_name;
pub use no_rust_keyword_table_name::NoRustKeywordTableName;
mod no_negation_check_rule;
pub use no_negation_check_rule::NoNegationCheckRule;
mod non_redundant_extension_dag;
pub use non_redundant_extension_dag::NonRedundantExtensionDag;
mod unique_column_names_in_extension_graph;
pub use unique_column_names_in_extension_graph::UniqueColumnNamesInExtensionGraph;
mod no_tautological_check_rule;
pub use no_tautological_check_rule::NoTautologicalCheckRule;
mod policies_require_row_level_security;
pub use policies_require_row_level_security::PoliciesRequireRowLevelSecurity;
mod dead_permissive_policy;
pub use dead_permissive_policy::DeadPermissivePolicy;
mod tautological_with_check;
pub use tautological_with_check::TautologicalWithCheck;
mod unforced_row_level_security;
pub use unforced_row_level_security::UnforcedRowLevelSecurity;
mod reachable_table_without_row_level_security;
pub use reachable_table_without_row_level_security::ReachableTableWithoutRowLevelSecurity;
mod truncate_granted_to_client_role;
pub use truncate_granted_to_client_role::{
    TruncateGrantedToAnonymousRole, TruncateGrantedToAppRole,
};
mod references_granted_to_client_role;
pub use references_granted_to_client_role::ReferencesGrantedToClientRole;
mod grant_option_to_client_role;
pub use grant_option_to_client_role::GrantOptionToClientRole;
