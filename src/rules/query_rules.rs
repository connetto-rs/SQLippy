//! Submodule providing rules that check a statement an application sends.

/// Defines a query rule's struct, constructor, registration and metadata.
macro_rules! query_rule {
    (
        $(#[$doc:meta])*
        $name:ident, $group:expr, $rationale:literal, $source:expr
    ) => {
        $(#[$doc])*
        pub struct $name<DB>(std::marker::PhantomData<DB>);

        impl<DB> Default for $name<DB> {
            fn default() -> Self {
                Self(std::marker::PhantomData)
            }
        }

        impl<DB: DatabaseLike + 'static> From<$name<DB>> for GenericConstrainer<DB> {
            fn from(rule: $name<DB>) -> Self {
                let mut constrainer = GenericConstrainer::default();
                constrainer.register_query_rule(Box::new(rule));
                constrainer
            }
        }

        impl<DB> Rule for $name<DB> {
            fn metadata(&self) -> &'static RuleMetadata {
                static METADATA: RuleMetadata = RuleMetadata {
                    name: stringify!($name),
                    group: $group,
                    rationale: $rationale,
                    source: $source,
                };
                &METADATA
            }
        }
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
