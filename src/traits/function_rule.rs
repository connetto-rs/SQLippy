//! Submodule defining the `FunctionRule` trait, which defines a rule applied
//! to each function of a schema.

use sql_traits::traits::DatabaseLike;

use crate::{error::Interruption, lint::Rule, traits::Reporter};

/// Trait for types that define a function rule object.
pub trait FunctionRule: Rule {
    /// The database type that this rule applies to.
    type Database: DatabaseLike;

    /// Reports every violation of this rule on the given function.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Lookup`] when a schema object the rule reads
    /// cannot be resolved, and [`Interruption::Halted`] when the reporter
    /// needs no further violations.
    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption>;
}
