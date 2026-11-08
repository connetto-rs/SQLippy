//! Submodule providing the `SelfAssertedClaimPolicy` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnDefinitionScope, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, PolicyLike, TableLike},
};
use sqlparser::ast::{Expr, Query, SetExpr, Visit, Visitor};

use crate::{
    deployment::{Declaration, Deployment},
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::{grant_support::schema_of, policy_support::is_column_reference},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Whether a resolved column is a declared self-asserted column.
fn is_self_asserted<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    definition: Option<&ColumnDefinition<'_, '_, '_, DB>>,
) -> bool {
    let Some(ColumnDefinition::Base { table, column, .. }) = definition else {
        return false;
    };
    let schema = schema_of(database, table.stored_table_schema());
    deployment
        .self_asserted_columns()
        .any(|(declared_schema, declared_table, declared_column)| {
            schema == declared_schema
                && table.stored_table_name() == declared_table
                && column.stored_column_name() == declared_column
        })
}

/// Finds the first read of a self-asserted claim or column in a policy
/// expression on `table`.
struct SelfAssertedRead<'a, 'db, DB: DatabaseLike> {
    database: &'db DB,
    deployment: &'a Deployment,
    table: ColumnScope<'db, 'db, DB>,
    depth: usize,
}

impl<DB: DatabaseLike> SelfAssertedRead<'_, '_, DB> {
    /// Stops on a declared claim, or on a column reference `declared` finds
    /// bound to a declared column.
    fn read(
        &self,
        expression: &Expr,
        declared: impl FnOnce(&Expr) -> Result<bool, LookupError>,
    ) -> ControlFlow<Result<String, LookupError>> {
        let read = self.deployment.is_self_asserted_claim(expression)
            || (is_column_reference(expression)
                && match declared(expression) {
                    Ok(declared) => declared,
                    Err(error) => return ControlFlow::Break(Err(error)),
                });
        if read {
            return ControlFlow::Break(Ok(expression.to_string()));
        }
        ControlFlow::Continue(())
    }
}

/// Reads in one top-level sublink, resolved through the scope of the
/// innermost `SELECT` holding them.
struct SublinkReads<'r, 'a, 'db, 'g, 'q, DB: DatabaseLike> {
    outer: &'r SelfAssertedRead<'a, 'db, DB>,
    root: &'g ColumnScope<'q, 'db, DB>,
    selects: Vec<Option<ColumnDefinitionScope<'g, 'q, 'db, DB>>>,
}

impl<DB: DatabaseLike> Visitor for SublinkReads<'_, '_, '_, '_, '_, DB> {
    type Break = Result<String, LookupError>;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        let scope = match query.body.as_ref() {
            SetExpr::Select(select) => self.root.scope_for_select(select),
            _ => None,
        };
        self.selects.push(scope);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.selects.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        let (outer, root) = (self.outer, self.root);
        let innermost = self.selects.iter().rev().find_map(Option::as_ref);
        outer.read(expression, |reference| {
            let definition = match innermost {
                Some(scope) => scope.resolve_column_definition(reference)?,
                None => root.resolve_column_definition(reference)?,
            };
            Ok(is_self_asserted(
                outer.database,
                outer.deployment,
                definition.as_ref(),
            ))
        })
    }
}

impl<DB: DatabaseLike> Visitor for SelfAssertedRead<'_, '_, DB> {
    type Break = Result<String, LookupError>;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        ColumnScope::from_query(query, self.database, IdentifierCase::Folded)
            .map_err(Err)
            .map_or_else(ControlFlow::Break, |root| {
                query.visit(&mut SublinkReads {
                    outer: self,
                    root: &root,
                    selects: Vec::new(),
                })
            })
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if self.depth > 0 {
            return ControlFlow::Continue(());
        }
        self.read(expression, |reference| {
            let definition = self.table.resolve_column_definition(reference)?;
            Ok(is_self_asserted(
                self.database,
                self.deployment,
                definition.as_ref(),
            ))
        })
    }
}

/// Struct defining a rule that reports a policy reading a claim or column the
/// caller can set.
///
/// The [`Deployment`] declares the self-asserted sources: claim expressions,
/// matched as written, also inside a longer path, and columns of tables in
/// the schema, resolved through aliases and sublinks. The rule is inactive
/// until one is declared, and a declared column whose table the schema does
/// not hold fails the lookup.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = SelfAssertedClaimPolicy::default().into();
/// constrainer.set_deployment(
///     Deployment::default().with_self_asserted_claim("auth.jwt() -> 'user_metadata'").unwrap(),
/// );
/// let schema = "CREATE TABLE docs (team TEXT); ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";
///
/// let trusting = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY p ON docs USING (team = auth.jwt() -> 'user_metadata' ->> 'team');"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&trusting).is_err());
///
/// let issued = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY p ON docs USING (team = auth.jwt() -> 'app_metadata' ->> 'team');"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&issued).is_ok());
/// ```
pub struct SelfAssertedClaimPolicy<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for SelfAssertedClaimPolicy<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<SelfAssertedClaimPolicy<DB>> for GenericConstrainer<DB> {
    fn from(rule: SelfAssertedClaimPolicy<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for SelfAssertedClaimPolicy<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "SelfAssertedClaimPolicy",
            group: LintGroup::Correctness,
            rationale: "A claim or column the caller sets says whatever the caller wants, so a policy granting access on it admits every caller who sets it.",
            source: Some("https://supabase.com/docs/guides/database/postgres/row-level-security"),
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::SelfAssertedSources]
    }
}

impl<DB: DatabaseLike> SchemaRule for SelfAssertedClaimPolicy<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        for (schema, table, _) in deployment.self_asserted_columns() {
            if !database.tables().any(|candidate| {
                schema_of(database, candidate.stored_table_schema()) == schema
                    && candidate.stored_table_name() == table
            }) {
                return Err(LookupError::TableNotFound {
                    object_name: format!("{schema}.{table}"),
                }
                .into());
            }
        }
        for table in database.tables() {
            for policy in table.policies(database)? {
                let clauses = [
                    (PolicyClause::Using, policy.using_expression(database)),
                    (PolicyClause::WithCheck, policy.check_expression(database)),
                ];
                let mut sites = Vec::new();
                for (clause, expression) in clauses {
                    let Some(expression) = expression else {
                        continue;
                    };
                    let mut reads = SelfAssertedRead {
                        database,
                        deployment,
                        table: ColumnScope::for_table(table, database, IdentifierCase::Folded),
                        depth: 0,
                    };
                    if let ControlFlow::Break(read) = expression.visit(&mut reads) {
                        sites.push(PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: read?,
                        });
                    }
                }
                let Some(first) = sites.first() else {
                    continue;
                };
                let (name, table_name, read) =
                    (policy.name(), table.table_name(), first.expression.clone());
                reporter.policies(
                    sites,
                    format!(
                        "Policy '{name}' on '{table_name}' reads `{read}`, which the caller sets, so a caller grants itself whatever the policy grants on it."
                    ),
                    format!(
                        "Base policy '{name}' on a value the caller cannot set, such as a claim only the server issues or a column clients cannot write."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
