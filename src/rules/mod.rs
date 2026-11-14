//! Submodule providing structs to add custom rules on SQL schemas.

/// Derives a rule's configuration key from its type identifier.
macro_rules! rule_name {
    ($name:ident) => {{
        const LEN: usize = $crate::lint::snake_len(stringify!($name));
        const BYTES: [u8; LEN] = $crate::lint::to_snake::<LEN>(stringify!($name));
        const NAME: &str = match core::str::from_utf8(&BYTES) {
            Ok(name) => name,
            Err(_) => panic!("rule names must be UTF-8"),
        };
        NAME
    }};
}

/// Defines a rule's struct, its `Default`, the constrainer that runs it alone
/// through `$register`, and its metadata with its `$example`, deciding from
/// declared structure unless a `$basis` follows.
macro_rules! rule_definition {
    (
        $(#[$doc:meta])*
        $name:ident, $register:ident, $group:expr, $rationale:literal, $source:expr,
        $example:expr
    ) => {
        rule_definition!(
            $(#[$doc])* $name, $register, $group, $rationale, $source, $example,
            $crate::lint::Basis::Declared
        );
    };
    (
        $(#[$doc:meta])*
        $name:ident, $register:ident, $group:expr, $rationale:literal, $source:expr,
        $example:expr, $basis:expr
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
                    name: rule_name!($name),
                    group: $group,
                    rationale: $rationale,
                    source: $source,
                    basis: $basis,
                    example: $example,
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
mod clock_support;
mod credential_support;
mod grant_support;
mod index_support;
mod key_support;
mod name_support;
mod not_in_support;
mod policy_support;
pub mod rust_keywords;
mod statement_support;
mod type_support;
mod volatility_support;
mod walk_support;

#[cfg(test)]
mod tests {
    #[test]
    fn rule_names_split_acronyms_and_digit_boundaries() {
        for (actual, expected) in [
            (rule_name!(A), "a"),
            (rule_name!(Rule), "rule"),
            (rule_name!(MissingPrimaryKey), "missing_primary_key"),
            (rule_name!(XMLHttpRequest), "xml_http_request"),
            (rule_name!(UUID), "uuid"),
            (rule_name!(Rule2Name), "rule2_name"),
            (rule_name!(HTTP2Parser), "http2_parser"),
            (rule_name!(RuleXML), "rule_xml"),
        ] {
            assert_eq!(actual, expected);
        }
    }
}
