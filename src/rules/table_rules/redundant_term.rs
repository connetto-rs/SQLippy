//! Submodule providing the `RedundantTerm` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{
        Assumption, ExpressionContext, ExpressionScope, ExpressionTruth, IdentifierCase, Outcomes,
        Raising,
    },
    traits::{
        CheckConstraintLike, DatabaseLike, DomainLike, FunctionLike, IndexLike, PolicyLike,
        TableLike, ViewLike,
    },
};
use sqlparser::ast::{
    Expr, FromTable, JoinConstraint, Select, Statement, TableFactor, TableWithJoins,
    UpdateTableFromKind, Visitor,
};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::join_constraint,
        function_body_support::{BodyNode, function_body},
        policy_support::{conjuncts, disjuncts, unnested},
        walk_support::walk,
    },
    traits::{
        Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule, TableRule,
        reporter::signature,
    },
};

/// Struct defining a rule that reports a term of an `AND` or `OR` that
/// deleting would not change what the expression admits.
///
/// The terms of the outermost chain are judged by what the site admits. A
/// `CHECK` or a domain check admits a row when its expression is true or
/// `NULL`, and a policy clause, a partial index predicate, a `WHERE` or a
/// `JOIN ... ON` only when it is true. A term of a conjunction is redundant
/// when, on every row the other terms admit, it is admitted and never raises,
/// and a term of a disjunction when, on every row the other terms reject, it
/// is rejected and never raises.
///
/// A term of a nested chain, or of one under `NOT`, is redundant when
/// deleting it leaves the chain's value unchanged on every row, true where
/// it was true, false where it was false and `NULL` where it was `NULL`, and
/// it never raises.
///
/// A `CHECK`, a policy clause and a partial index predicate read under the
/// column types, `NOT NULL`, domain checks, generated columns and validated
/// checks of their table, a `CHECK` under the others only, and their
/// subqueries are not read. A domain check reads over `VALUE` under the
/// domain's other checks and those of the domains it is defined over. The
/// `WHERE` and `ON` clauses of views, materialized views, SQL and PL/pgSQL
/// function bodies and script statements, subqueries included, read each
/// name as its query binds it, a column of a table read from its stored rows
/// under that table's guarantees, a column of a null-extended side under its
/// type alone, and a parameter or variable under its declared type.
///
/// The terms of a chain are walked from the last, each judged under the
/// terms still kept, so deleting every reported term keeps the expression.
/// Expressions admitting every row or no row are left to the tautology and
/// contradiction rules.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = RedundantTerm::default().into();
/// let invalid = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (amount INT, CHECK (amount > 5 AND amount > 3));"
/// ).unwrap();
/// assert!(constrainer.validate_schema(&invalid).is_err());
/// let valid = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE payments (amount INT, CHECK (amount > 5));"
/// ).unwrap();
/// assert!(constrainer.validate_schema(&valid).is_ok());
/// ```
pub struct RedundantTerm<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RedundantTerm<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RedundantTerm<DB>> for GenericConstrainer<DB> {
    fn from(rule: RedundantTerm<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer.register_schema_rule(Box::new(RedundantTerm::default()));
        constrainer.register_query_rule(Box::new(RedundantTerm::default()));
        constrainer
    }
}

impl<DB> Rule for RedundantTerm<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RedundantTerm),
            group: LintGroup::Complexity,
            rationale: "A term the rest of its expression and the constraints of what it reads already decide filters nothing, yet is read and evaluated as if it did.",
            source: Some("https://www.postgresql.org/docs/current/functions-logical.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE payments (amount INT, CHECK (amount > 5 AND amount > 3));",
                good: "CREATE TABLE payments (amount INT, CHECK (amount > 5));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for RedundantTerm<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let checks = table.check_constraints(database)?.collect::<Vec<_>>();
        let mut guaranteed = Vec::with_capacity(checks.len());
        for check in &checks {
            guaranteed
                .push(check.is_enforced() && !check.no_inherit() && check.is_validated(database)?);
        }
        let assumed = |own: Option<usize>| {
            checks
                .iter()
                .zip(&guaranteed)
                .enumerate()
                .filter(|&(position, (_, &guaranteed))| guaranteed && Some(position) != own)
                .map(|(_, (&check, _))| Assumption::Check(check))
                .collect::<Vec<_>>()
        };
        let table_name = table.table_name();
        for (position, check) in checks.iter().enumerate() {
            let case = database.identifier_case();
            let site = Site::new(
                |expression, assumptions| {
                    table.truth_under(database, expression, case, assumptions)
                },
                assumed(Some(position)),
            );
            let expression = check.expression(database);
            for term in site.redundant_terms(expression, Outcomes::NOT_FALSE)? {
                let term = unnested(term);
                reporter.table(
                    table,
                    format!(
                        "Table '{table_name}' has the term `{term}` in CHECK ({expression}), which the rest of the check and the table's other constraints already decide, so deleting it changes nothing."
                    ),
                    format!("Delete `{term}` from CHECK ({expression}) on table '{table_name}'."),
                )?;
            }
        }
        let site = Site::new(
            |expression, assumptions| {
                table.truth_under(database, expression, IdentifierCase::AsWritten, assumptions)
            },
            assumed(None),
        );
        for policy in table.policies(database)? {
            let name = policy.name();
            for (clause, expression) in [
                (PolicyClause::Using, policy.using_expression(database)?),
                (PolicyClause::WithCheck, policy.check_expression(database)?),
            ] {
                let Some(expression) = expression else {
                    continue;
                };
                for term in site.redundant_terms(expression, Outcomes::TRUE)? {
                    let term = unnested(term);
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: expression.to_string(),
                        }],
                        format!(
                            "Policy '{name}' on '{table_name}' has the term `{term}` in its {clause} clause ({expression}), which the rest of the clause and the table's constraints already decide, so deleting it changes nothing."
                        ),
                        format!("Delete `{term}` from the {clause} clause of policy '{name}'."),
                    )?;
                }
            }
        }
        for index in table.indices(database)? {
            let Some(predicate) = index.predicate() else {
                continue;
            };
            let index_name = index.name().unwrap_or("the partial index");
            for term in site.redundant_terms(predicate, Outcomes::TRUE)? {
                let term = unnested(term);
                reporter.index(
                    index,
                    format!(
                        "Index '{index_name}' on '{table_name}' has the term `{term}` in its predicate ({predicate}), which the rest of the predicate and the table's constraints already decide, so deleting it changes nothing."
                    ),
                    format!("Recreate index '{index_name}' without `{term}` in its WHERE clause."),
                )?;
            }
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> SchemaRule for RedundantTerm<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let case = database.identifier_case();
        for domain in database.domains() {
            let checks = domain.check_expressions().collect::<Vec<_>>();
            for (position, &expression) in checks.iter().enumerate() {
                let others = checks
                    .iter()
                    .enumerate()
                    .filter(|&(other, _)| other != position)
                    .map(|(_, &other)| Assumption::Expression {
                        expression: other,
                        outcomes: Outcomes::NOT_FALSE,
                    })
                    .collect();
                let site = Site::new(
                    |expression, assumptions| {
                        domain.truth_under(database, expression, case, assumptions)
                    },
                    others,
                );
                for term in site.redundant_terms(expression, Outcomes::NOT_FALSE)? {
                    let term = unnested(term);
                    let name = domain.name();
                    reporter.domain(
                        domain,
                        format!(
                            "Domain '{name}' has the term `{term}` in CHECK ({expression}), which the rest of the check and the domain's other constraints already decide, so deleting it changes nothing."
                        ),
                        format!("Delete `{term}` from CHECK ({expression}) on domain '{name}'."),
                    )?;
                }
            }
        }
        for view in database.views() {
            let context =
                ExpressionContext::new(view.definition(), database, IdentifierCase::Folded)?;
            let owner = format!("View '{}'", view.view_name());
            for finding in clause_findings(&context, view.definition())? {
                reporter.view(view, finding.message(&owner), finding.resolution())?;
            }
        }
        for view in database.materialized_views() {
            let context =
                ExpressionContext::new(view.definition(), database, IdentifierCase::Folded)?;
            let owner = format!("Materialized view '{}'", view.view_name());
            for finding in clause_findings(&context, view.definition())? {
                reporter.materialized_view(view, finding.message(&owner), finding.resolution())?;
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
            function_body(database, function, |node| -> Result<(), LookupError> {
                match node {
                    BodyNode::Statement(statement) => {
                        let context = ExpressionContext::for_statement(
                            statement,
                            &scope,
                            database,
                            IdentifierCase::Folded,
                        )?;
                        findings.extend(clause_findings(&context, statement)?);
                    }
                    BodyNode::Expression(expression) => {
                        let context = ExpressionContext::for_expression(
                            expression,
                            &scope,
                            database,
                            IdentifierCase::Folded,
                        )?;
                        findings.extend(clause_findings(&context, expression)?);
                    }
                }
                Ok(())
            })?;
            let owner = format!("Function '{}'", signature(function, database));
            for finding in findings {
                reporter.function(function, finding.message(&owner), finding.resolution())?;
            }
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> QueryRule for RedundantTerm<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let context = ExpressionContext::for_statement(
            statement,
            &ExpressionScope::Empty,
            database,
            IdentifierCase::Folded,
        )?;
        for finding in clause_findings(&context, statement)? {
            let message = finding.message("The statement");
            let resolution = finding.resolution();
            reporter.statement(statement, finding.term, message, resolution)?;
        }
        Ok(())
    }
}

/// A redundant term of a `WHERE` or `ON` clause.
struct ClauseFinding {
    /// `WHERE` or `ON`.
    clause: &'static str,
    /// The clause's expression.
    expression: String,
    /// The redundant term.
    term: String,
}

impl ClauseFinding {
    /// The message of the finding in a clause of `owner`.
    fn message(&self, owner: &str) -> String {
        let Self {
            clause,
            expression,
            term,
        } = self;
        format!(
            "{owner} has the term `{term}` in a {clause} clause ({expression}), which the rest of the clause and the constraints of what it reads already decide, so deleting it changes nothing."
        )
    }

    /// The resolution of the finding.
    fn resolution(&self) -> String {
        format!(
            "Delete `{}` from the {} clause ({}).",
            self.term, self.clause, self.expression
        )
    }
}

/// The redundant terms of every `WHERE` and `ON` clause of `node`, a node of
/// the root `context` reads.
///
/// # Errors
///
/// Returns the lookup errors reading a clause.
fn clause_findings<DB: DatabaseLike, N: sqlparser::ast::Visit + ?Sized>(
    context: &ExpressionContext<'_, '_, DB>,
    node: &N,
) -> Result<Vec<ClauseFinding>, LookupError> {
    let mut clauses = Clauses {
        context,
        found: Vec::new(),
    };
    match walk(node, &mut clauses) {
        ControlFlow::Continue(()) => Ok(clauses.found),
        ControlFlow::Break(error) => Err(error),
    }
}

/// Collects the redundant terms of the `WHERE` and `ON` clauses it visits.
struct Clauses<'c, 'query, 'db, DB: DatabaseLike> {
    context: &'c ExpressionContext<'query, 'db, DB>,
    found: Vec<ClauseFinding>,
}

impl<DB: DatabaseLike> Clauses<'_, '_, '_, DB> {
    /// Records the redundant terms of `expression`, a `clause` admitting a
    /// row only when it is true.
    fn clause(&mut self, clause: &'static str, expression: &Expr) -> Result<(), LookupError> {
        let context = self.context;
        let site = Site::new(
            |expression, assumptions| context.truth_under(expression, assumptions),
            Vec::new(),
        );
        for term in site.redundant_terms(expression, Outcomes::TRUE)? {
            self.found.push(ClauseFinding {
                clause,
                expression: expression.to_string(),
                term: unnested(term).to_string(),
            });
        }
        Ok(())
    }

    /// Records the redundant terms of the `ON` clauses of `from`.
    fn joins<'f>(
        &mut self,
        from: impl IntoIterator<Item = &'f TableWithJoins>,
    ) -> Result<(), LookupError> {
        for join in from.into_iter().flat_map(|item| &item.joins) {
            if let Some(JoinConstraint::On(condition)) = join_constraint(&join.join_operator) {
                self.clause("ON", condition)?;
            }
        }
        Ok(())
    }

    /// Records the redundant terms of `selection` and of the `ON` clauses of
    /// `from`.
    fn filtered<'f>(
        &mut self,
        selection: Option<&Expr>,
        from: impl IntoIterator<Item = &'f TableWithJoins>,
    ) -> ControlFlow<LookupError> {
        let result = selection
            .map_or(Ok(()), |selection| self.clause("WHERE", selection))
            .and_then(|()| self.joins(from));
        match result {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => ControlFlow::Break(error),
        }
    }
}

impl<DB: DatabaseLike> Visitor for Clauses<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        self.filtered(select.selection.as_ref(), &select.from)
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        match factor {
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => self.filtered(None, [table_with_joins.as_ref()]),
            _ => ControlFlow::Continue(()),
        }
    }

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        match statement {
            Statement::Update(update) => {
                let from = match &update.from {
                    Some(
                        UpdateTableFromKind::BeforeSet(from) | UpdateTableFromKind::AfterSet(from),
                    ) => from.as_slice(),
                    None => &[],
                };
                self.filtered(
                    update.selection.as_ref(),
                    std::iter::once(&update.table).chain(from),
                )
            }
            Statement::Delete(delete) => {
                let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) =
                    &delete.from;
                self.filtered(
                    delete.selection.as_ref(),
                    from.iter().chain(delete.using.iter().flatten()),
                )
            }
            _ => ControlFlow::Continue(()),
        }
    }
}

/// An expression site, which reads terms through `read` under `base` beside
/// whatever `read` itself assumes.
struct Site<'a, DB: DatabaseLike, R> {
    read: R,
    base: Vec<Assumption<'a, DB>>,
}

impl<'a, DB, R> Site<'a, DB, R>
where
    DB: DatabaseLike,
    R: Fn(&'a Expr, &[Assumption<'a, DB>]) -> Result<ExpressionTruth, LookupError>,
{
    /// A site reading through `read` under `base`.
    fn new(read: R, base: Vec<Assumption<'a, DB>>) -> Self {
        Self { read, base }
    }

    /// The redundant terms of `expression`, at a site admitting a row when
    /// the expression takes one of `admitted`.
    ///
    /// # Errors
    ///
    /// Returns the lookup errors reading the expression.
    fn redundant_terms(
        &self,
        expression: &'a Expr,
        admitted: Outcomes,
    ) -> Result<Vec<&'a Expr>, LookupError> {
        let whole = (self.read)(expression, &self.base)?;
        if whole.outcomes.intersection(admitted).is_empty()
            || (within(whole.outcomes, admitted) && whole.raising == Raising::Never)
        {
            return Ok(Vec::new());
        }
        let mut found = Vec::new();
        let conjunction = conjuncts(expression);
        let disjunction = disjuncts(expression);
        let kept = if conjunction.len() > 1 {
            self.judge(conjunction, &[admitted], &mut found)?
        } else if disjunction.len() > 1 {
            let rejected = Outcomes {
                truth: !admitted.truth,
                falsity: !admitted.falsity,
                null: !admitted.null,
            };
            self.judge(disjunction, &[rejected], &mut found)?
        } else {
            vec![expression]
        };
        for term in kept {
            self.nested(term, &mut found)?;
        }
        Ok(found)
    }

    /// Pushes onto `found` the terms of the chains within `expression` whose
    /// deletion keeps their chain's value, outside subqueries.
    ///
    /// # Errors
    ///
    /// Returns the lookup errors reading the terms.
    fn nested(&self, expression: &'a Expr, found: &mut Vec<&'a Expr>) -> Result<(), LookupError> {
        let expression = unnested(expression);
        let conjunction = conjuncts(expression);
        let disjunction = disjuncts(expression);
        let kept = if conjunction.len() > 1 {
            self.judge(conjunction, &[Outcomes::TRUE, Outcomes::NOT_FALSE], found)?
        } else if disjunction.len() > 1 {
            self.judge(disjunction, &[Outcomes::FALSE, Outcomes::NOT_TRUE], found)?
        } else {
            match expression {
                Expr::UnaryOp { expr, .. }
                | Expr::IsTrue(expr)
                | Expr::IsNotTrue(expr)
                | Expr::IsFalse(expr)
                | Expr::IsNotFalse(expr)
                | Expr::IsNull(expr)
                | Expr::IsNotNull(expr)
                | Expr::IsUnknown(expr)
                | Expr::IsNotUnknown(expr) => vec![expr.as_ref()],
                Expr::BinaryOp { left, right, .. } => vec![left.as_ref(), right.as_ref()],
                Expr::Case {
                    operand,
                    conditions,
                    else_result,
                    ..
                } => operand
                    .iter()
                    .map(AsRef::as_ref)
                    .chain(
                        conditions
                            .iter()
                            .flat_map(|arm| [&arm.condition, &arm.result]),
                    )
                    .chain(else_result.iter().map(AsRef::as_ref))
                    .collect(),
                _ => Vec::new(),
            }
        };
        for term in kept {
            self.nested(term, found)?;
        }
        Ok(())
    }

    /// The terms of a chain kept after pushing its redundant ones onto
    /// `found`, in the chain's order.
    ///
    /// Each read assumes the other kept terms take its outcomes, and a term
    /// is redundant when every read leaves it within them without raising.
    /// The last kept term is never redundant, as deleting it would leave an
    /// empty chain.
    ///
    /// # Errors
    ///
    /// Returns the lookup errors reading the terms.
    fn judge(
        &self,
        mut kept: Vec<&'a Expr>,
        reads: &[Outcomes],
        found: &mut Vec<&'a Expr>,
    ) -> Result<Vec<&'a Expr>, LookupError> {
        let mut assumptions = Vec::with_capacity(self.base.len() + kept.len());
        let mut redundant = Vec::new();
        for position in (0..kept.len()).rev() {
            if kept.len() == 1 {
                break;
            }
            let term = kept[position];
            let mut holds = true;
            for &read in reads {
                assumptions.clear();
                assumptions.extend_from_slice(&self.base);
                assumptions.extend(
                    kept.iter()
                        .enumerate()
                        .filter(|&(other, _)| other != position)
                        .map(|(_, &expression)| Assumption::Expression {
                            expression,
                            outcomes: read,
                        }),
                );
                let truth = (self.read)(term, &assumptions)?;
                if !within(truth.outcomes, read) || truth.raising != Raising::Never {
                    holds = false;
                    break;
                }
            }
            if holds {
                kept.remove(position);
                redundant.push(term);
            }
        }
        found.extend(redundant.into_iter().rev());
        Ok(kept)
    }
}

/// Whether every outcome of `outcomes` is one of `allowed`.
fn within(outcomes: Outcomes, allowed: Outcomes) -> bool {
    outcomes.union(allowed) == allowed
}
