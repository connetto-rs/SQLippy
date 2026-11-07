//! Submodule defining the `QueryRule` trait, which defines a rule applied to
//! a statement an application sends.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::Statement;

use crate::{error::Interruption, lint::Rule, traits::Reporter};

/// Trait for types that define a rule checking one statement against the
/// schema it runs on.
pub trait QueryRule: Rule {
    /// The database type that this rule applies to.
    type Database: DatabaseLike;

    /// Reports every violation of this rule in the given statement.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Lookup`] when a schema object the statement
    /// names cannot be resolved, and [`Interruption::Halted`] when the
    /// reporter needs no further violations.
    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption>;
}
