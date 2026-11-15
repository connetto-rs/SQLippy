//! Nullable column operands of scalar concatenation.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ExpressionContext, ExpressionScope, IdentifierCase, OperandType},
    traits::{ColumnLike, DataTypeLike, DatabaseLike, FunctionLike, TableLike, ViewLike},
};
use sqlparser::ast::{BinaryOperator, Expr, Query, Statement, Visit, Visitor};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::body_statements, policy_support::unnested,
        statement_support::selects, walk_support::walk,
    },
    traits::{
        Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule, reporter::signature,
    },
};

const RESOLUTION: &str = "Use concat or concat_ws to skip NULL, or COALESCE the nullable operand.";

/// Reports scalar `||` chains with a declared nullable column operand.
///
/// Views are checked in their projections, and statements, generated columns
/// and SQL and PL/pgSQL function bodies are checked throughout.
/// Domain columns and chains with unknown operand types are not judged.
/// Outer-join null extension, policies and check constraints are excluded.
pub struct NullableConcatenation<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NullableConcatenation<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NullableConcatenation<DB>> for GenericConstrainer<DB> {
    fn from(rule: NullableConcatenation<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(NullableConcatenation::default()));
        constrainer
    }
}

impl<DB> Rule for NullableConcatenation<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NullableConcatenation),
            group: LintGroup::Suspicious,
            rationale: "A NULL column operand makes scalar concatenation return NULL for the whole value.",
            source: Some("https://www.postgresql.org/docs/current/functions-string.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE people (first TEXT NOT NULL, middle TEXT); SELECT first || ' ' || middle FROM people;",
                good: "CREATE TABLE people (first TEXT NOT NULL, middle TEXT); SELECT concat_ws(' ', first, middle) FROM people;",
            },
        };
        &METADATA
    }
}

/// Whether `expression` joins two values with `||`.
fn concatenation(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::BinaryOp {
            op: BinaryOperator::StringConcat,
            ..
        }
    )
}

/// Visits the leaves of one parenthesized concatenation chain.
fn operands<'a>(
    expression: &'a Expr,
    visit: &mut impl FnMut(&'a Expr) -> Result<(), LookupError>,
) -> Result<(), LookupError> {
    match unnested(expression) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::StringConcat,
            right,
        } => {
            operands(left, visit)?;
            operands(right, visit)
        }
        operand => visit(operand),
    }
}

/// Whether an operand is known to be scalar or is an untyped literal.
fn scalar<DB: DatabaseLike>(
    database: &DB,
    context: &ExpressionContext<'_, '_, DB>,
    operand: &Expr,
) -> Result<bool, LookupError> {
    let type_name = match context.type_of(operand)? {
        OperandType::UntypedLiteral => return Ok(true),
        OperandType::Unknown => return Ok(false),
        OperandType::Known { type_name, .. } => type_name,
    };
    let Some(facts) = database.type_facts(type_name) else {
        return Ok(false);
    };
    if facts.array_element().is_some() {
        return Ok(false);
    }
    Ok(facts.into_domain().is_none_or(|domain| {
        database
            .type_facts(domain.into_base())
            .is_some_and(|base| base.array_element().is_none())
    }))
}

/// The expression and its first nullable column operand.
struct Finding {
    expression: String,
    column: String,
}

impl Finding {
    /// The diagnostic naming the expression and its nullable operand.
    fn message(&self) -> String {
        format!(
            "Concatenation `{}` uses nullable '{}', so a NULL there makes the whole value NULL.",
            self.expression, self.column
        )
    }
}

/// Collects one finding per scalar concatenation chain.
struct Concatenations<'c, 'query, 'db, DB: DatabaseLike> {
    database: &'db DB,
    context: &'c ExpressionContext<'query, 'db, DB>,
    parents: Vec<bool>,
    query_depth: usize,
    projections: bool,
    found: Vec<Finding>,
}

impl<DB: DatabaseLike> Visitor for Concatenations<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, _: &Query) -> ControlFlow<Self::Break> {
        self.query_depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _: &Query) -> ControlFlow<Self::Break> {
        self.query_depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        let parent_chain = self.parents.last().copied().unwrap_or(false);
        self.parents.push(
            concatenation(expression) || (parent_chain && matches!(expression, Expr::Nested(_))),
        );
        if (self.projections && self.query_depth > 0) || parent_chain || !concatenation(expression)
        {
            return ControlFlow::Continue(());
        }
        let mut all_scalar = true;
        let mut nullable = None;
        let result = operands(expression, &mut |operand| {
            all_scalar &= scalar(self.database, self.context, operand)?;
            if nullable.is_none()
                && let Some((
                    ColumnDefinition::Base {
                        table,
                        column,
                        database,
                    },
                    _,
                )) = self.context.reference(operand)?
                && column.data_type(database).base_type(database).is_none()
                && column.is_nullable(database)?
                && !column.is_primary_key(database)?
            {
                nullable = Some(format!("{}.{}", table.table_name(), column.column_name()));
            }
            Ok(())
        });
        if let Err(error) = result {
            return ControlFlow::Break(error);
        }
        if all_scalar && let Some(column) = nullable {
            self.found.push(Finding {
                expression: expression.to_string(),
                column,
            });
        }
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        self.parents.pop();
        ControlFlow::Continue(())
    }
}

/// Finds chains in a node whose names and types `context` resolves.
fn found<DB: DatabaseLike, V: Visit + ?Sized>(
    database: &DB,
    context: &ExpressionContext<'_, '_, DB>,
    node: &V,
    projections: bool,
) -> Result<Vec<Finding>, LookupError> {
    let mut visitor = Concatenations {
        database,
        context,
        parents: Vec::new(),
        query_depth: 0,
        projections,
        found: Vec::new(),
    };
    walk(node, &mut visitor).break_value().map_or(Ok(()), Err)?;
    Ok(visitor.found)
}

/// Finds chains in the projections of every query in a view.
struct Projections<'c, 'query, 'db, DB: DatabaseLike> {
    database: &'db DB,
    context: &'c ExpressionContext<'query, 'db, DB>,
    found: Vec<Finding>,
}

impl<DB: DatabaseLike> Visitor for Projections<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        for select in selects(&query.body) {
            match found(self.database, self.context, &select.projection, true) {
                Ok(findings) => self.found.extend(findings),
                Err(error) => return ControlFlow::Break(error),
            }
        }
        ControlFlow::Continue(())
    }
}

/// Finds the concatenations of a view's projections.
fn view_findings<DB: DatabaseLike>(
    database: &DB,
    query: &Query,
) -> Result<Vec<Finding>, LookupError> {
    let context = ExpressionContext::new(query, database, IdentifierCase::Folded)?;
    let mut visitor = Projections {
        database,
        context: &context,
        found: Vec::new(),
    };
    walk(query, &mut visitor)
        .break_value()
        .map_or(Ok(()), Err)?;
    Ok(visitor.found)
}

/// Finds concatenations in a statement under its enclosing expression scope.
fn statement_findings<DB: DatabaseLike>(
    database: &DB,
    statement: &Statement,
    scope: &ExpressionScope<'_, '_, DB>,
) -> Result<Vec<Finding>, LookupError> {
    let context =
        ExpressionContext::for_statement(statement, scope, database, IdentifierCase::Folded)?;
    found(database, &context, statement, false)
}

impl<DB: DatabaseLike> SchemaRule for NullableConcatenation<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        for view in database.views() {
            for finding in view_findings(database, view.definition())? {
                reporter.view(view, finding.message(), RESOLUTION.to_owned())?;
            }
        }
        for view in database.materialized_views() {
            for finding in view_findings(database, view.definition())? {
                reporter.materialized_view(view, finding.message(), RESOLUTION.to_owned())?;
            }
        }
        for table in database.tables() {
            for column in table.columns(database)? {
                if let Some(expression) = column.generation_expression() {
                    let context = ExpressionContext::for_expression(
                        expression,
                        &ExpressionScope::Table(table),
                        database,
                        IdentifierCase::Folded,
                    )?;
                    for finding in found(database, &context, expression, false)? {
                        reporter.column(column, finding.message(), RESOLUTION.to_owned())?;
                    }
                }
            }
        }
        for function in database.functions().filter(|function| {
            !matches!(
                function.target_name().schema(),
                Some("pg_catalog" | "information_schema")
            )
        }) {
            let scope = ExpressionScope::FunctionBody(function);
            let mut findings = Vec::new();
            for statement in &body_statements(function) {
                findings.extend(statement_findings(database, statement, &scope)?);
            }
            if let Some(statements) = function.atomic_statements(database)? {
                for statement in statements.iter() {
                    findings.extend(statement_findings(database, statement, &scope)?);
                }
            }
            if let Some(body) = function.body_expression(database)? {
                let context = ExpressionContext::for_expression(
                    &body,
                    &scope,
                    database,
                    IdentifierCase::Folded,
                )?;
                findings.extend(found(database, &context, body.as_ref(), false)?);
            }
            for finding in findings {
                reporter.function(
                    function,
                    format!(
                        "Function '{}'. {}",
                        signature(function, database),
                        finding.message()
                    ),
                    RESOLUTION.to_owned(),
                )?;
            }
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> QueryRule for NullableConcatenation<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &DB,
        statement: &Statement,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        for finding in statement_findings(database, statement, &ExpressionScope::Empty)? {
            let message = finding.message();
            reporter.statement(
                statement,
                finding.expression,
                message,
                RESOLUTION.to_owned(),
            )?;
        }
        Ok(())
    }
}
