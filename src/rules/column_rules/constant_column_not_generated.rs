//! Submodule providing the `ConstantColumnNotGenerated` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::VariableKind,
    traits::{
        CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, TableLike,
        TriggerLike,
    },
};
use sqlparser::ast::{
    BinaryOperator, Expr, Ident, ReferentialAction, TriggerPeriod, Value, Visitor,
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::{CheckedRows, names_cast_column},
        function_rules::readable,
        literal_support::literal,
        policy_support::conjuncts,
        trigger_support::{fires_on_insert, fires_on_update, row, row_trigger, stored},
        walk_support::walk,
    },
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

rule_definition!(
    /// Struct defining a rule that reports a `NOT NULL` column whose default
    /// is a literal and whose check fixes it to that same literal.
    ///
    /// The check is a top-level conjunct `column = literal`, in either
    /// operand order, of a validated check of the column's table, compared
    /// with the default through parentheses and casts. A check added
    /// `NOT VALID` fixes nothing, since rows stored before it may hold any
    /// value. A nullable column is not reported, since a generated column
    /// computing the literal would refuse the `NULL` it admits. Nor is a
    /// column among the referencing columns of
    /// a foreign key whose `ON UPDATE` action is `CASCADE`, `SET NULL` or
    /// `SET DEFAULT`, or whose `ON DELETE` action is `SET NULL` or
    /// `SET DEFAULT`, since PostgreSQL refuses such a key over a generated
    /// column. Nor is a column that a row-level `BEFORE INSERT` or `BEFORE
    /// UPDATE` trigger of its table reads as `NEW.column`, in its `WHEN`
    /// condition or its PL/pgSQL function, since a stored generated column
    /// holds no value there until those triggers have run.
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

/// Finds `NEW.column` in an expression, where `reaches_new` tells whether the
/// parts before the field name the trigger's `NEW` row.
struct NewField<'c, F> {
    column: &'c str,
    reaches_new: F,
}

impl<F: Fn(&[Ident]) -> bool> Visitor for NewField<'_, F> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if let Expr::CompoundIdentifier(parts) = expression
            && let [record @ .., field] = parts.as_slice()
            && !record.is_empty()
            && stored(field) == self.column
            && (self.reaches_new)(record)
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Whether a row-level `BEFORE INSERT` or `BEFORE UPDATE` trigger of `table`
/// reads `NEW.column` in its `WHEN` condition or its PL/pgSQL function.
fn before_trigger_reads<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    column: &str,
) -> Result<bool, LookupError> {
    let mut in_condition = NewField {
        column,
        reaches_new: |record: &[Ident]| matches!(record, [new] if row(new) == Some(true)),
    };
    for trigger in table.triggers(database)? {
        if !row_trigger(trigger, TriggerPeriod::Before)
            || !(fires_on_insert(trigger) || fires_on_update(trigger))
        {
            continue;
        }
        if trigger
            .condition()
            .is_some_and(|condition| walk(condition, &mut in_condition).is_break())
        {
            return Ok(true);
        }
        let Some(function) = trigger.function(database) else {
            continue;
        };
        let Some(body) = readable(function.plpgsql_sites(database).map(Some))? else {
            continue;
        };
        for site in &readable(body.sites())? {
            let scope = site.plpgsql_scope();
            let mut in_body = NewField {
                column,
                reaches_new: |record: &[Ident]| {
                    scope.variable(record).is_some_and(|variable| {
                        *variable.kind() == VariableKind::Trigger && variable.name() == "new"
                    })
                },
            };
            if walk(&site.sql(), &mut in_body).is_break() {
                return Ok(true);
            }
        }
    }
    Ok(false)
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
        for foreign_key in column
            .foreign_keys(database)?
            .filter(|foreign_key| foreign_key.is_enforced(database))
        {
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
            if !CheckedRows::Stored.checked_by(database, check)? {
                continue;
            }
            held |= conjuncts(check.expression(database))
                .into_iter()
                .any(|conjunct| fixes(conjunct, &stored, fixed));
        }
        if !held || before_trigger_reads(database, column.table(database), &stored)? {
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
