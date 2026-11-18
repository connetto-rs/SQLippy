//! Submodule defining the `ScriptRule` trait, which defines a rule applied to
//! the statements of a script in the order they run.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::Statement;

use crate::{error::Interruption, lint::Rule, traits::Reporter};

/// Trait for types that define a rule checking a script's statements in the
/// order they run, reading what each earlier statement established.
///
/// The database is the schema the whole script builds. A script rule reads
/// it for facts the order cannot change, and reads `statements` for what the
/// built schema no longer holds: `OR REPLACE` and `IF NOT EXISTS` guards,
/// repeated settings, original quotation and the session's `search_path`
/// at each statement.
pub trait ScriptRule: Rule {
    /// The database type that this rule applies to.
    type Database: DatabaseLike;

    /// Reports every violation of this rule in the given statements.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Lookup`] when a schema object a statement
    /// names cannot be resolved, and [`Interruption::Halted`] when the
    /// reporter needs no further violations.
    fn check_script(
        &self,
        database: &Self::Database,
        statements: &[Statement],
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption>;
}
