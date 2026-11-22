//! Submodule providing the `ConstantColumnNotGenerated` rule.

use sql_traits::traits::{
    CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, TableLike,
};
use sqlparser::ast::{BinaryOperator, Expr, ReferentialAction, Value};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::names_cast_column, literal_support::literal, policy_support::conjuncts,
    },
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

rule_definition!(
    /// Struct defining a rule that reports a `NOT NULL` column whose default
    /// is a literal and whose check fixes it to that same literal.
    ///
    /// The check is a top-level conjunct `column = literal`, in either
    /// operand order, of a check of the column's table, compared with the
    /// default through parentheses and casts. A nullable column is not
    /// reported, since a generated column computing the literal would refuse
    /// the `NULL` it admits. Nor is a column among the referencing columns of
    /// a foreign key whose `ON UPDATE` action is `CASCADE`, `SET NULL` or
    /// `SET DEFAULT`, or whose `ON DELETE` action is `SET NULL` or
    /// `SET DEFAULT`, since PostgreSQL refuses such a key over a generated
    /// column.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ConstantColumnNotGenerated::default().into();
    /// let fixed = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE entries (id INT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'entry' CHECK (kind = 'entry'));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&fixed).is_err());
    /// let generated = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE entries (id INT PRIMARY KEY, kind TEXT GENERATED ALWAYS AS ('entry'::text) STORED NOT NULL);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&generated).is_ok());
    /// ```
    ConstantColumnNotGenerated,
    register_column_rule,
    LintGroup::Pedantic,
    "A column a default and a check fix to one literal makes every writer supply or default a value the database can derive, where a generated column computes it and refuses a written one.",
    Some("https://www.postgresql.org/docs/current/ddl-generated-columns.html"),
    RuleExample {
        bad: "CREATE TABLE entries (id INT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'entry' CHECK (kind = 'entry'));",
        good: "CREATE TABLE entries (id INT PRIMARY KEY, kind TEXT GENERATED ALWAYS AS ('entry'::text) STORED NOT NULL);",
    },
    Basis::Declared
);

/// Whether `conjunct` is `column = fixed` in either operand order, the
/// literal compared through parentheses and casts.
fn fixes(conjunct: &Expr, column: &str, fixed: &Value) -> bool {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = conjunct
    else {
        return false;
    };
    (names_cast_column(left, column) && literal(right) == Some(fixed))
        || (names_cast_column(right, column) && literal(left) == Some(fixed))
}

impl<DB: DatabaseLike> ColumnRule for ConstantColumnNotGenerated<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let Some(default) = column.default_expression() else {
            return Ok(());
        };
        let Some(fixed) = literal(default).filter(|value| !matches!(value, Value::Null)) else {
            return Ok(());
        };
        if column.is_generated(database) || column.is_nullable(database)? {
            return Ok(());
        }
        for foreign_key in column.foreign_keys(database)? {
            let writes_referencing = matches!(
                foreign_key.on_update(database),
                ReferentialAction::Cascade
                    | ReferentialAction::SetNull
                    | ReferentialAction::SetDefault
            ) || matches!(
                foreign_key.on_delete(database),
                ReferentialAction::SetNull | ReferentialAction::SetDefault
            );
            if writes_referencing {
                return Ok(());
            }
        }
        let stored = column.stored_column_name();
        let mut held = false;
        for check in column.check_constraints(database)? {
            held |= conjuncts(check.expression(database))
                .into_iter()
                .any(|conjunct| fixes(conjunct, &stored, fixed));
        }
        if !held {
            return Ok(());
        }
        reporter.column(
            column,
            format!(
                "Column '{}.{}' defaults to {default} and a check holds it there, so every row stores the same value.",
                column.table(database).table_name(),
                column.column_name()
            ),
            format!(
                "Declare the column `GENERATED ALWAYS AS ({default}) STORED NOT NULL`, which derives the value and refuses a written one, and drop the default and the check."
            ),
        )?;
        Ok(())
    }
}
