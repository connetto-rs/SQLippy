//! Submodule providing constraint structs that can be applied to columns.

mod lowercase_column_name;
pub use lowercase_column_name::LowercaseColumnName;
mod no_rust_keyword_column_name;
pub use no_rust_keyword_column_name::NoRustKeywordColumnName;
mod non_composite_primary_key_named_id;
pub use non_composite_primary_key_named_id::NonCompositePrimaryKeyNamedId;
mod no_surrogate_primary_key_in_extension;
pub use no_surrogate_primary_key_in_extension::NoSurrogatePrimaryKeyInExtension;
mod snake_case_column_name;
pub use snake_case_column_name::SnakeCaseColumnName;
mod singular_column_name;
pub use singular_column_name::SingularColumnName;
mod textual_column_rule;
pub use textual_column_rule::TextualColumnRule;
mod non_empty_textual_column_rule;
pub use non_empty_textual_column_rule::NonEmptyTextualColumnRule;
mod counter_keys;
pub use counter_keys::{ClientWrittenCounterKey, NarrowIntegerKey, SerialColumn};
mod past_time_column_rule;
pub use past_time_column_rule::PastTimeColumnRule;
