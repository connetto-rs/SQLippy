//! Submodule providing the `DuplicateColumnAssignment` rule.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{traits::DatabaseLike, utils::identifier_resolution::stored_ident_name};
use sqlparser::ast::{
    Assignment, AssignmentTarget, DoUpdate, Insert, Merge, MergeAction, MergeInsertExpr,
    MergeUpdateExpr, MergeUpdateKind, ObjectName, OnConflict, OnConflictAction, OnInsert,
    Statement, Update, Visitor,
};

use crate::rules::walk_support::walk;
use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// The targets of one clause that assigns or lists columns, with the clause
/// as a finding names it.
struct Targets<'s> {
    clause: &'static str,
    targets: Vec<&'s ObjectName>,
}

impl<'s> Targets<'s> {
    fn assignments(clause: &'static str, assignments: &'s [Assignment]) -> Self {
        let targets = assignments
            .iter()
            .flat_map(|assignment| match &assignment.target {
                AssignmentTarget::ColumnName(column) => std::slice::from_ref(column),
                AssignmentTarget::Tuple(columns) => columns.as_slice(),
            })
            .collect();
        Self { clause, targets }
    }

    fn columns(clause: &'static str, columns: &'s [ObjectName]) -> Self {
        Self {
            clause,
            targets: columns.iter().collect(),
        }
    }

    /// The columns assigned more than once where at least one assignment is
    /// to the whole column, each as first written, in order.
    fn duplicated(&self) -> Vec<String> {
        // Column, as first written and as PostgreSQL stores it, the number of
        // targets naming it, and whether every one names a subfield of it.
        let mut columns: Vec<(String, Cow<'s, str>, usize, bool)> = Vec::new();
        for &target in &self.targets {
            let Some(column) = target.0.first().and_then(|part| part.as_ident()) else {
                continue;
            };
            let key = stored_ident_name(column);
            let partial = target.0.len() > 1;
            match columns.iter_mut().find(|(_, seen, ..)| *seen == key) {
                Some((_, _, count, all_partial)) => {
                    *count += 1;
                    *all_partial &= partial;
                }
                None => columns.push((column.to_string(), key, 1, partial)),
            }
        }
        columns
            .into_iter()
            .filter(|(_, _, count, all_partial)| *count > 1 && !all_partial)
            .map(|(written, ..)| written)
            .collect()
    }
}

/// Collects the clauses of each statement that assign or list columns.
#[derive(Default)]
struct Clauses<'s>(Vec<Targets<'s>>);

impl<'s> Clauses<'s> {
    fn statement(&mut self, statement: &'s Statement) {
        match statement {
            Statement::Update(Update { assignments, .. }) => {
                self.0.push(Targets::assignments("SET", assignments));
            }
            Statement::Insert(Insert { columns, on, .. }) => {
                self.0.push(Targets::columns("INSERT column list", columns));
                if let Some(OnInsert::OnConflict(OnConflict {
                    action: OnConflictAction::DoUpdate(DoUpdate { assignments, .. }),
                    ..
                })) = on
                {
                    self.0.push(Targets::assignments(
                        "ON CONFLICT DO UPDATE SET",
                        assignments,
                    ));
                }
            }
            Statement::Merge(Merge { clauses, .. }) => {
                for clause in clauses {
                    match &clause.action {
                        MergeAction::Update(MergeUpdateExpr {
                            kind: MergeUpdateKind::Set(assignments),
                            ..
                        }) => self
                            .0
                            .push(Targets::assignments("MERGE UPDATE SET", assignments)),
                        MergeAction::Insert(MergeInsertExpr { columns, .. }) => self
                            .0
                            .push(Targets::columns("MERGE INSERT column list", columns)),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// Finds the statements a statement holds, itself and those its `WITH`
/// clauses run, with the duplicated columns of each clause.
#[derive(Default)]
struct Duplicates(Vec<(&'static str, String)>);

impl Visitor for Duplicates {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        let mut clauses = Clauses::default();
        clauses.statement(statement);
        for targets in clauses.0 {
            for column in targets.duplicated() {
                self.0.push((targets.clause, column));
            }
        }
        ControlFlow::Continue(())
    }
}

query_rule!(
    /// Struct defining a rule that reports a statement assigning or listing
    /// one column more than once, unless every assignment names a field of it.
    ///
    /// Subscripted targets such as `arr[1]` do not parse, so it never sees them.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     DuplicateColumnAssignment::default().into();
    /// let database =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (a INT, b INT);").unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("UPDATE t SET a = 1, a = 2").is_err());
    /// assert!(check("UPDATE t SET a = 1, b = 2").is_ok());
    /// ```
    DuplicateColumnAssignment,
    LintGroup::Correctness,
    "PostgreSQL rejects a statement that assigns or lists the same column twice, unless every assignment names a field of it.",
    Some("https://www.postgresql.org/docs/current/sql-update.html"),
    RuleExample {
        bad: "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);\n\
UPDATE notes SET body = 'draft', body = 'final' WHERE id = 1;",
        good: "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);\n\
UPDATE notes SET body = 'final' WHERE id = 1;",
    }
);

impl<DB: DatabaseLike> QueryRule for DuplicateColumnAssignment<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        _database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut duplicates = Duplicates::default();
        let _ = walk(statement, &mut duplicates);
        for (clause, column) in duplicates.0 {
            let message = format!(
                "The {clause} assigns column '{column}' more than once, so PostgreSQL rejects the statement."
            );
            let resolution = format!("Assign '{column}' once, or assign only its fields.");
            reporter.statement(statement, column, message, resolution)?;
        }
        Ok(())
    }
}
