//! Submodule providing rules that check a statement an application sends.

/// Defines a query rule's struct, constructor, registration and metadata.
macro_rules! query_rule {
    (
        $(#[$doc:meta])*
        $name:ident, $group:expr, $rationale:literal, $source:expr
    ) => {
        rule_definition!($(#[$doc])* $name, register_query_rule, $group, $rationale, $source);
    };
}

mod credential_setting_write;
pub use credential_setting_write::CredentialSettingWrite;
mod outer_column_capture;
pub use outer_column_capture::OuterColumnCapture;
mod paging_rules;
pub use paging_rules::{OffsetPaging, RandomOrderLimit};
mod unfiltered_write;
pub use unfiltered_write::UnfilteredWrite;
