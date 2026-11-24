#![doc = include_str!("../README.md")]

pub mod deployment;
pub mod engine;
pub mod error;
pub mod lint;
pub mod rules;
pub mod traits;
pub mod vocabulary;

/// Prelude module re-exporting commonly used items from the crate.
pub mod prelude {
    pub use sql_traits::prelude::*;

    pub use crate::{
        deployment::{Declaration, Deployment, ExternalForeignKey, WriteEvent},
        engine::Engine,
        error::{
            Allowance, AllowedObject, Error, FunctionAllowance, InactiveRule, Interruption,
            Location, PolicyClause, PolicySite, SchemaAllowance, StatementAllowance, StatementSite,
            UnresolvedForeignKey, Violation,
        },
        lint::{
            Basis, Level, LintGroup, RegisteredRule, Rule, RuleExample, RuleKind, RuleMetadata,
        },
        rules::*,
        traits::*,
        vocabulary::Vocabulary,
    };
}
