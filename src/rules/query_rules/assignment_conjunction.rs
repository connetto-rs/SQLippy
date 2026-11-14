//! Submodule providing the `AssignmentConjunction` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{IdentifierCase, TargetName},
    traits::{DatabaseLike, TableLike},
    utils::identifier_resolution::stored_ident_name,
};
use sqlparser::ast::{
    AssignmentTarget, BinaryOperator, Expr, Ident, ObjectName, Statement, TableFactor, TableObject,
    UnaryOperator, Value, Visitor,
};

use super::duplicate_column_assignment::{Clause, visit_clauses};
use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{policy_support::unnested, walk_support::walk},
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// Returns the written relation and its alias.
fn written_table(statement: &Statement) -> Option<(&ObjectName, Option<&Ident>)> {
    let factor = match statement {
        Statement::Update(update) => &update.table.relation,
        Statement::Merge(merge) => &merge.table,
        Statement::Insert(insert) => {
            return match &insert.table {
                TableObject::TableName(name) => {
                    Some((name, insert.table_alias.as_ref().map(|alias| &alias.alias)))
                }
                _ => None,
            };
        }
        _ => return None,
    };
    match factor {
        TableFactor::Table {
            name,
            alias,
            args: None,
            ..
        } => Some((name, alias.as_ref().map(|alias| &alias.name))),
        _ => None,
    }
}

/// Whether an expression is a literal with optional parentheses or sign.
fn constant(expression: &Expr) -> bool {
    match unnested(expression) {
        Expr::Value(value) => !matches!(value.value, Value::Placeholder(_)),
        Expr::TypedString(_) => true,
        Expr::Interval(interval) => constant(&interval.value),
        Expr::UnaryOp {
            op: UnaryOperator::Plus | UnaryOperator::Minus,
            expr,
        } => constant(expr),
        _ => false,
    }
}

/// Returns the operands of a comparison following a constant conjunction.
fn compared(value: &Expr) -> Option<(&Expr, &Expr)> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::And | BinaryOperator::Or,
        right,
    } = unnested(value)
    else {
        return None;
    };
    if !constant(left) {
        return None;
    }
    match unnested(right) {
        Expr::BinaryOp {
            left,
            op:
                BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::Lt
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::GtEq,
            right,
        }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => Some((left, right)),
        _ => None,
    }
}

/// Resolves a plain column reference against the written relation.
fn column<'e, DB: DatabaseLike>(
    expression: &'e Expr,
    name: &ObjectName,
    alias: Option<&Ident>,
    table: &DB::Table,
    database: &DB,
) -> Result<Option<&'e Ident>, LookupError> {
    let ident = match unnested(expression) {
        Expr::Identifier(ident) => ident,
        Expr::CompoundIdentifier(parts) => {
            let Some((ident, qualifier)) = parts.split_last() else {
                return Ok(None);
            };
            let matches = if let Some(alias) = alias {
                matches!(qualifier, [part] if stored_ident_name(part) == stored_ident_name(alias))
            } else {
                qualifier.len() <= name.0.len()
                    && qualifier
                        .iter()
                        .rev()
                        .zip(name.0.iter().rev())
                        .all(|(part, target)| {
                            target.as_ident().is_some_and(|target| {
                                stored_ident_name(part) == stored_ident_name(target)
                            })
                        })
            };
            if !matches {
                return Ok(None);
            }
            ident
        }
        _ => return Ok(None),
    };
    Ok(table
        .column(&ident.to_string(), database, IdentifierCase::Folded)?
        .map(|_| ident))
}

/// Collects suspicious assignments in each nested statement.
struct Conjunctions<'db, DB: DatabaseLike> {
    database: &'db DB,
    found: Vec<(String, String)>,
}

impl<DB: DatabaseLike> Conjunctions<'_, DB> {
    /// Checks each assignment to the written table.
    fn check(&mut self, statement: &Statement) -> Result<(), LookupError> {
        let Some((name, alias)) = written_table(statement) else {
            return Ok(());
        };
        let rendered = name.to_string();
        let Ok(target) = TargetName::parse(&rendered) else {
            return Ok(());
        };
        let Some(table) = self
            .database
            .resolve_target_table(target, IdentifierCase::Folded)?
        else {
            return Ok(());
        };
        let mut result = Ok(());
        visit_clauses(statement, |clause| {
            if let Clause::Assignments(_, assignments) = clause
                && result.is_ok()
            {
                result = (|| {
                    for assignment in assignments {
                        let Some((left, right)) = compared(&assignment.value) else {
                            continue;
                        };
                        let intended = match column(left, name, alias, table, self.database)? {
                            Some(column) => Some(column),
                            None => column(right, name, alias, table, self.database)?,
                        };
                        if let Some(intended) = intended {
                            let assigned = match &assignment.target {
                                AssignmentTarget::ColumnName(name) => name.to_string(),
                                AssignmentTarget::Tuple(_) => assignment.target.to_string(),
                            };
                            self.found.push((assigned, intended.to_string()));
                        }
                    }
                    Ok(())
                })();
            }
        });
        result
    }
}

impl<DB: DatabaseLike> Visitor for Conjunctions<'_, DB> {
    type Break = LookupError;

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        self.check(statement)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

query_rule!(
    /// Struct defining a rule that reports an assignment whose value joins a
    /// constant with `AND` or `OR` to a comparison of the written table's
    /// column.
    ///
    /// `UPDATE t SET flag = true AND b = 2` parses as one assignment of
    /// `true AND (b = 2)` to `flag` and leaves `b` unchanged. Since
    /// `true AND x` is `x` and `false AND x` is `false`, nobody writes a
    /// constant there on purpose, and the writer meant a comma. A deliberate
    /// boolean such as `SET is_admin = verified AND role = 'admin'` starts with
    /// a column and is not reported. Assignments in `UPDATE ... SET`,
    /// `ON CONFLICT DO UPDATE SET` and `MERGE ... UPDATE SET` are judged.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = AssignmentConjunction::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE t (flag BOOLEAN, b INT);",
    /// ).unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("UPDATE t SET flag = true AND b = 2").is_err());
    /// assert!(check("UPDATE t SET flag = true, b = 2").is_ok());
    /// ```
    AssignmentConjunction,
    LintGroup::Suspicious,
    "A conjunction after a constant assigns one boolean expression instead of assigning the compared column.",
    Some("https://www.postgresql.org/docs/current/sql-update.html"),
    RuleExample {
        bad: "CREATE TABLE t (flag BOOLEAN, b INT);\nUPDATE t SET flag = true AND b = 2;",
        good: "CREATE TABLE t (flag BOOLEAN, b INT);\nUPDATE t SET flag = true, b = 2;",
    }
);

impl<DB: DatabaseLike> QueryRule for AssignmentConjunction<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut conjunctions = Conjunctions {
            database,
            found: Vec::new(),
        };
        walk(statement, &mut conjunctions)
            .break_value()
            .map_or(Ok(()), Err)?;
        for (assigned, intended) in conjunctions.found {
            let message = format!(
                "Assignment to '{assigned}' combines a constant with a comparison of '{intended}'."
            );
            let resolution =
                format!("Use a comma to assign '{assigned}' and '{intended}' separately.");
            reporter.statement(statement, assigned, message, resolution)?;
        }
        Ok(())
    }
}
