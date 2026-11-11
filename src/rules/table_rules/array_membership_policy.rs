//! Submodule providing the `ArrayMembershipPolicy` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DataTypeLike, DatabaseLike, PolicyLike, TableLike},
};
use sqlparser::ast::{BinaryOperator, Expr, Query, Visit, Visitor};

use crate::{
    deployment::Deployment,
    error::{Interruption, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    rules::policy_support::{derives_from_caller, walked_clauses},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Finds tests of the caller's membership in an array column of the policy's
/// table, outside sublinks.
struct Memberships<'a, 'db, DB: DatabaseLike> {
    database: &'db DB,
    table: &'db DB::Table,
    scope: ColumnScope<'db, 'db, DB>,
    deployment: &'a Deployment,
    depth: usize,
    found: Vec<(String, String)>,
}

impl<DB: DatabaseLike> Memberships<'_, '_, DB> {
    /// The array column of the table `array` names, when `member` derives
    /// from the caller.
    fn membership(&self, array: &Expr, member: &Expr) -> Result<Option<String>, LookupError> {
        let Some(ColumnDefinition::Base { column, .. }) =
            self.scope.resolve_column_definition(array)?
        else {
            return Ok(None);
        };
        Ok((column
            .data_type(self.database)
            .array_element(self.database)
            .is_some()
            && derives_from_caller(self.database, self.table, self.deployment, member)?)
        .then(|| column.column_name().to_owned()))
    }
}

impl<DB: DatabaseLike> Visitor for Memberships<'_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        let (array, member) = match expression {
            _ if self.depth > 0 => return ControlFlow::Continue(()),
            Expr::AnyOp {
                left,
                compare_op: BinaryOperator::Eq,
                right,
                ..
            }
            | Expr::BinaryOp {
                left,
                op: BinaryOperator::ArrowAt,
                right,
            } => (right, left),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::AtArrow,
                right,
            } => (left, right),
            _ => return ControlFlow::Continue(()),
        };
        self.membership(array, member)
            .map_or_else(ControlFlow::Break, |column| {
                self.found
                    .extend(column.map(|column| (column, expression.to_string())));
                ControlFlow::Continue(())
            })
    }
}

/// Struct defining a rule that reports a policy granting access through the
/// caller's membership in an array column of the row.
///
/// The rule reports `caller = ANY (column)`, `column @> caller` and
/// `caller <@ column`, where the column is an array of the policy's table and
/// the other side derives from the caller alone: a declared credential, a
/// `current_setting` call or a read of the current role. An array element
/// carries no foreign key, and every grant or revocation rewrites the row. A
/// small set updated with its row is a legitimate use, so the rule is
/// `pedantic`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ArrayMembershipPolicy::default().into();
/// let schema = "CREATE TABLE docs (owner TEXT, editors TEXT[]);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";
///
/// let array = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY edit ON docs USING (current_setting('app.user_id', true) = ANY (editors));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&array).is_err());
///
/// let owner = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY edit ON docs USING (owner = current_setting('app.user_id', true));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&owner).is_ok());
/// ```
pub struct ArrayMembershipPolicy<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ArrayMembershipPolicy<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ArrayMembershipPolicy<DB>> for GenericConstrainer<DB> {
    fn from(rule: ArrayMembershipPolicy<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ArrayMembershipPolicy<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "ArrayMembershipPolicy",
            group: LintGroup::Pedantic,
            rationale: "An array element carries no foreign key and every grant or revocation rewrites the row, while a membership table with a row per grant is easier to search and scales better.",
            source: Some("https://www.postgresql.org/docs/current/arrays.html"),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for ArrayMembershipPolicy<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            let clauses = walked_clauses(database, policy)?;
            for (clause, expression) in clauses {
                let Some(expression) = expression else {
                    continue;
                };
                let mut memberships = Memberships {
                    database,
                    table,
                    scope: ColumnScope::for_table(table, database, IdentifierCase::Folded),
                    deployment: reporter.deployment(),
                    depth: 0,
                    found: Vec::new(),
                };
                expression
                    .visit(&mut memberships)
                    .break_value()
                    .map_or(Ok(()), Err)?;
                for (column, test) in memberships.found {
                    let (name, table_name) = (policy.name(), table.table_name());
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: test,
                        }],
                        format!(
                            "Policy '{name}' on '{table_name}' grants through the caller's membership in array column '{column}' in its {clause} clause."
                        ),
                        format!(
                            "Move '{column}' into a table with a row per grant and a foreign key to '{table_name}', and test membership with a subquery on it."
                        ),
                    )?;
                }
            }
        }
        Ok(())
    }
}
