//! Submodule providing structs to add custom rules on SQL schemas.

/// Defines a rule's struct, its `Default`, the constrainer that runs it alone
/// through `$register`, and its metadata.
macro_rules! rule_definition {
    (
        $(#[$doc:meta])*
        $name:ident, $register:ident, $group:expr, $rationale:literal, $source:expr
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
                constrainer.$register(Box::new(rule));
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

mod table_rules;
pub use table_rules::*;
mod column_rules;
pub use column_rules::*;
mod foreign_key_rules;
pub use foreign_key_rules::*;
mod schema_rules;
pub use schema_rules::*;
mod function_rules;
pub use function_rules::*;
mod query_rules;
pub use query_rules::*;
mod authority_support;
mod credential_support;
mod grant_support;
mod key_support;
mod not_in_support;
mod policy_support;
pub mod rust_keywords;
mod statement_support;
mod type_support;
