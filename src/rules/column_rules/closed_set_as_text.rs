//! Submodule providing the `ClosedSetAsText` rule.

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::closed_set_support::closed_set,
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

rule_definition!(
    /// Struct defining a rule that reports a text column a check restricts
    /// to a fixed list of string literals.
    ///
    /// A top-level conjunct of a check of the column listing at least two
    /// distinct literals is reported, written `column IN ('a', 'b')`,
    /// `column = ANY (ARRAY['a', 'b'])` or `column = 'a' OR column = 'b'`.
    /// The column's type is read through arrays and domains. Changing an enum
    /// type later needs a migration, which is why the rule is pedantic.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ClosedSetAsText::default().into();
    /// let text = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE jobs (id INT PRIMARY KEY, state TEXT NOT NULL CHECK (state IN ('queued', 'ready')));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&text).is_err());
    /// let enumeration = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TYPE job_state AS ENUM ('queued', 'ready');
    ///      CREATE TABLE jobs (id INT PRIMARY KEY, state job_state NOT NULL);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&enumeration).is_ok());
    /// ```
    ClosedSetAsText,
    register_column_rule,
    LintGroup::Pedantic,
    "A check listing the values of a text column restates the domain at every column holding it, while an enum type declares it once and gives arguments and results the same type.",
    Some("https://www.postgresql.org/docs/current/datatype-enum.html"),
    RuleExample {
        bad: "CREATE TABLE jobs (id INT PRIMARY KEY, state TEXT NOT NULL CHECK (state IN ('queued', 'ready')));",
        good: "CREATE TYPE job_state AS ENUM ('queued', 'ready');\n\
CREATE TABLE jobs (id INT PRIMARY KEY, state job_state NOT NULL);",
    },
    Basis::Declared
);

impl<DB: DatabaseLike> ColumnRule for ClosedSetAsText<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let Some(labels) = closed_set(database, column)? else {
            return Ok(());
        };
        let listed = labels
            .iter()
            .map(|label| format!("'{}'", label.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(", ");
        reporter.column(
            column,
            format!(
                "Column '{}.{}' is text that a check restricts to {listed}.",
                column.table(database).table_name(),
                column.column_name()
            ),
            format!(
                "Declare the set once as `CREATE TYPE ... AS ENUM ({listed})`, type the column with it and drop the check."
            ),
        )?;
        Ok(())
    }
}
