//! Submodule providing constraint structs that can be applied to foreign keys.

mod incompatible_foreign_key;
pub use incompatible_foreign_key::IncompatibleForeignKey;
mod mixed_case_foreign_key_name;
pub use mixed_case_foreign_key_name::MixedCaseForeignKeyName;
mod rust_keyword_foreign_key_name;
pub use rust_keyword_foreign_key_name::RustKeywordForeignKeyName;
mod reference_without_id_suffix;
pub use reference_without_id_suffix::ReferenceWithoutIdSuffix;
mod extension_foreign_key_on_delete_cascade;
pub use extension_foreign_key_on_delete_cascade::ExtensionForeignKeyOnDeleteCascade;
mod key_coverage;
pub use key_coverage::{NullableCompositeForeignKey, UnindexedForeignKey};
mod cascade_into_row_level_security_table;
pub use cascade_into_row_level_security_table::CascadeIntoRowLevelSecurityTable;
