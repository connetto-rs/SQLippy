#![doc = include_str!("../README.md")]

pub mod deployment;
pub mod error;
pub mod lint;
pub mod rules;
pub mod traits;

/// Prelude module re-exporting commonly used items from the crate.
pub mod prelude {
    pub use sql_traits::prelude::*;

    pub use crate::{
        deployment::{Declaration, Deployment},
        error::{
            Error, InactiveRule, Interruption, Location, PolicyAllowance, PolicyClause, PolicySite,
            Violation,
        },
        lint::{Level, LintGroup, Rule, RuleMetadata},
        rules::*,
        traits::*,
    };
}
