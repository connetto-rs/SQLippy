//! Submodule providing the `UnseededPolicySet` rule.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, FunctionLike},
};
use sqlparser::ast::{Expr, JoinConstraint, JoinOperator, Select, TableFactor, Visit, Visitor};

use crate::{
    deployment::{Declaration, Deployment},
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        authority_support::is_credential_value,
        cte_support::{recursive_items, stored_table},
        function_body_support::{BodyNode, function_body, parameter},
        function_reach_support::policy_functions,
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

/// Finds a credential or input parameter in a seed predicate.
struct SeedInput<'input, 'database, DB: DatabaseLike> {
    deployment: &'input Deployment,
    database: &'database DB,
    function: &'database DB::Function,
}

impl<DB: DatabaseLike> SeedInput<'_, '_, DB> {
    /// Whether a predicate refers to an input parameter or credential.
    fn present(&mut self, expression: &Expr) -> bool {
        walk(expression, self).is_break()
    }
}

impl<DB: DatabaseLike> Visitor for SeedInput<'_, '_, DB> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if parameter(self.database, self.function, expression).is_some()
            || is_credential_value(self.deployment, expression)
        {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// Records table reads and caller constraints of a recursive seed.
struct Seed<'input, 'db, DB: DatabaseLike> {
    database: &'db DB,
    constrained: bool,
    input: SeedInput<'input, 'db, DB>,
    reads_table: bool,
    path: Option<&'input [(Cow<'input, str>, bool)]>,
}

impl<DB: DatabaseLike> Visitor for Seed<'_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        self.constrained |= select
            .selection
            .as_ref()
            .is_some_and(|predicate| self.input.present(predicate));
        for join in select.from.iter().flat_map(|from| &from.joins) {
            let constraint = match &join.join_operator {
                JoinOperator::Join(constraint)
                | JoinOperator::Inner(constraint)
                | JoinOperator::Left(constraint)
                | JoinOperator::LeftOuter(constraint)
                | JoinOperator::Right(constraint)
                | JoinOperator::RightOuter(constraint)
                | JoinOperator::FullOuter(constraint)
                | JoinOperator::Semi(constraint)
                | JoinOperator::LeftSemi(constraint)
                | JoinOperator::RightSemi(constraint)
                | JoinOperator::Anti(constraint)
                | JoinOperator::LeftAnti(constraint)
                | JoinOperator::RightAnti(constraint) => Some(constraint),
                _ => None,
            };
            if let Some(JoinConstraint::On(predicate)) = constraint {
                self.constrained |= self.input.present(predicate);
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table {
            name, args: None, ..
        } = factor
        {
            let table = stored_table(self.database, name, self.path);
            match table {
                Ok(table) => self.reads_table |= table.is_some(),
                Err(error) => return ControlFlow::Break(error),
            }
        }
        ControlFlow::Continue(())
    }
}

/// Reports unconstrained seeds in a reachable function body.
fn check_body<DB: DatabaseLike, V: Visit + ?Sized>(
    database: &DB,
    function: &DB::Function,
    body: &V,
    reporter: &mut Reporter<'_, DB>,
) -> Result<(), Interruption> {
    let path = function.search_path(database)?;
    recursive_items(body, |item, recursive| {
        let mut seed = Seed {
            database,
            path: path.as_deref(),
            input: SeedInput {
                deployment: reporter.deployment(),
                database,
                function,
            },
            reads_table: false,
            constrained: false,
        };
        if let ControlFlow::Break(error) = walk(recursive.seed, &mut seed) {
            return Err(Interruption::from(error));
        }
        if seed.reads_table && !seed.constrained {
            reporter.function(function, format!("Function '{}' has recursive `WITH` item '{}' starting from a table without a parameter or credential predicate.", signature(function, database), item.alias.name), "Constrain the seed with a parameter or declared credential, or use a function allowance for a reviewed global reference-data set.".to_owned())?;
        }
        Ok(())
    })
}

/// Reports policy-reachable recursive sets whose table-reading seeds lack a parameter or credential predicate.
///
/// A global seed can return other subjects' authority rows. Reviewed global reference-data sets can use [`Constrainer::allow_function`].
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
/// let mut constrainer: GenericConstrainer<ParserDB> = UnseededPolicySet::default().into();
/// constrainer.set_deployment(Deployment::example());
/// let schema = "CREATE ROLE authenticated; CREATE TABLE memberships (id INT, parent_id INT, actor_id TEXT);
/// CREATE TABLE resources (id INT); ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
/// CREATE FUNCTION visible_ids() RETURNS SETOF INT LANGUAGE sql AS $$ WITH RECURSIVE reachable(id) AS
/// (SELECT id FROM memberships UNION SELECT memberships.id FROM memberships JOIN reachable ON memberships.parent_id = reachable.id)
/// SELECT id FROM reachable $$;
/// CREATE POLICY resources_read ON resources TO authenticated USING (id IN (SELECT visible_ids()));";
/// let bad = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&bad).is_err());
/// let good = ParserDB::parse::<PostgreSqlDialect>(&schema.replace("SELECT id FROM memberships UNION", "SELECT id FROM memberships WHERE actor_id = current_setting('app.user_id', true) UNION")).unwrap();
/// assert!(constrainer.validate_schema(&good).is_ok());
/// ```
pub struct UnseededPolicySet<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnseededPolicySet<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnseededPolicySet<DB>> for GenericConstrainer<DB> {
    fn from(rule: UnseededPolicySet<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UnseededPolicySet<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UnseededPolicySet),
            group: LintGroup::Pedantic,
            rationale: "A recursive authority set seeded from an entire table can return other subjects' rows. Constrain its seed by a parameter or declared credential, or allow the function when its global reference-data set is intentional.",
            source: Some(
                "https://www.postgresql.org/docs/17/queries-with.html#QUERIES-WITH-RECURSIVE",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE authenticated; CREATE TABLE memberships (id INT, parent_id INT, actor_id TEXT); CREATE TABLE resources (id INT); ALTER TABLE resources ENABLE ROW LEVEL SECURITY; CREATE FUNCTION visible_ids() RETURNS SETOF INT LANGUAGE sql AS $$ WITH RECURSIVE reachable(id) AS (SELECT id FROM memberships UNION SELECT memberships.id FROM memberships JOIN reachable ON memberships.parent_id = reachable.id) SELECT id FROM reachable $$; CREATE POLICY resources_read ON resources TO authenticated USING (id IN (SELECT visible_ids()));",
                good: "CREATE ROLE authenticated; CREATE TABLE memberships (id INT, parent_id INT, actor_id TEXT); CREATE TABLE resources (id INT); ALTER TABLE resources ENABLE ROW LEVEL SECURITY; CREATE FUNCTION visible_ids() RETURNS SETOF INT LANGUAGE sql AS $$ WITH RECURSIVE reachable(id) AS (SELECT id FROM memberships WHERE actor_id = current_setting('app.user_id', true) UNION SELECT memberships.id FROM memberships JOIN reachable ON memberships.parent_id = reachable.id) SELECT id FROM reachable $$; CREATE POLICY resources_read ON resources TO authenticated USING (id IN (SELECT visible_ids()));",
            },
        };
        &METADATA
    }
    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Credentials]
    }
}

impl<DB: DatabaseLike> SchemaRule for UnseededPolicySet<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        for function in policy_functions(database)? {
            function_body(database, function, |node| match node {
                BodyNode::Statement(statement) => {
                    check_body(database, function, statement, reporter)
                }
                BodyNode::Expression(expression) => {
                    check_body(database, function, expression, reporter)
                }
            })?;
        }
        Ok(())
    }
}
