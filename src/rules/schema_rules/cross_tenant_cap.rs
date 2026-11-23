//! Submodule providing the `CrossTenantCap` rule.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, FunctionLike, TableLike},
};
use sqlparser::ast::{
    BinaryOperator, Expr, Ident, JoinConstraint, Query, Select, TableAlias, TableFactor,
    TableWithJoins, Visitor,
};

use crate::{
    deployment::{Declaration, Deployment},
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        authority_support::is_credential_value,
        cte_support::{WithScopes, join_constraint, same_name, stored_column, stored_table},
        function_body_support::{function_body, parameter},
        grant_support::schema_of,
        policy_support::{conjuncts, unwrapped},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

/// A tenant-keyed relation instance in one select.
struct TenantRelation<'query, 'database, DB: DatabaseLike> {
    table: &'database DB::Table,
    alias: Option<&'query TableAlias>,
    name: &'query sqlparser::ast::ObjectName,
    tenant: &'database str,
    from: &'query TableWithJoins,
    position: usize,
}

/// Resolves a column against one relation instance.
fn column<'database, DB: DatabaseLike>(
    database: &'database DB,
    relation: &TenantRelation<'_, 'database, DB>,
    expression: &Expr,
) -> Result<Option<&'database DB::Column>, LookupError> {
    let name = match unwrapped(expression) {
        Expr::Identifier(name) => name,
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
            let exposed = relation
                .alias
                .map(|alias| &alias.name)
                .or_else(|| relation.name.0.last().and_then(|part| part.as_ident()));
            if exposed.is_none_or(|name| !same_name(&parts[parts.len() - 2], name)) {
                return Ok(None);
            }
            &parts[parts.len() - 1]
        }
        _ => return Ok(None),
    };
    stored_column(database, relation.table, relation.alias, name)
}

/// Searches function selects for missing tenant-key equality.
struct TenantJoins<'database, 'parameter, DB: DatabaseLike> {
    database: &'database DB,
    deployment: &'database Deployment,
    function: &'database DB::Function,
    path: Option<&'parameter [(Cow<'database, str>, bool)]>,
    scopes: WithScopes,
    found: Option<[&'database DB::Table; 2]>,
}

impl<'database, DB: DatabaseLike> TenantJoins<'database, '_, DB> {
    /// Whether a value is selected by the request or function caller.
    fn request_value(&self, expression: &Expr) -> bool {
        let expression = unwrapped(expression);
        is_credential_value(self.deployment, expression)
            || self.deployment.is_request_setting(expression)
            || parameter(self.database, self.function, expression).is_some()
    }

    /// Checks pairs of tenant-keyed relations in one select.
    fn select(&self, select: &Select) -> Result<Option<[&'database DB::Table; 2]>, LookupError> {
        let mut relations = Vec::new();
        let mut filters: Vec<&Expr> = select.selection.iter().flat_map(conjuncts).collect();
        for from in &select.from {
            for (position, factor) in std::iter::once(&from.relation)
                .chain(from.joins.iter().map(|join| &join.relation))
                .enumerate()
            {
                let TableFactor::Table {
                    name,
                    alias,
                    args: None,
                    ..
                } = factor
                else {
                    continue;
                };
                if self.scopes.binding(name).is_some() {
                    continue;
                }
                let Some(table) = stored_table(self.database, name, self.path)? else {
                    continue;
                };
                let schema = schema_of(self.database, table.stored_table_schema());
                let Some(tenant) = self
                    .deployment
                    .tenant_key(&schema, &table.stored_table_name())
                else {
                    continue;
                };
                relations.push(TenantRelation {
                    table,
                    alias: alias.as_ref(),
                    name,
                    tenant,
                    from,
                    position,
                });
            }
            for join in &from.joins {
                if let Some(JoinConstraint::On(condition)) = join_constraint(&join.join_operator) {
                    filters.extend(conjuncts(condition));
                }
            }
        }
        let pairs: Vec<_> = filters
            .iter()
            .filter_map(|filter| match unwrapped(filter) {
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Eq,
                    right,
                } => Some((left.as_ref(), right.as_ref())),
                _ => None,
            })
            .collect();
        for (position, relation) in relations.iter().enumerate() {
            let mut pinned = false;
            for &(left, right) in &pairs {
                for (reference, value) in [(left, right), (right, left)] {
                    if self.request_value(value)
                        && let Some(column) = column(self.database, relation, reference)?
                        && column.is_primary_key(self.database)?
                    {
                        pinned = true;
                    }
                }
            }
            if !pinned {
                continue;
            }
            for (other_position, other) in relations.iter().enumerate() {
                if position == other_position {
                    continue;
                }
                let mut equal = self.implicit_equality(relation, other)?;
                for &(left, right) in &pairs {
                    for (first, second) in [(left, right), (right, left)] {
                        if column(self.database, relation, first)?
                            .is_some_and(|column| column.stored_column_name() == relation.tenant)
                            && column(self.database, other, second)?
                                .is_some_and(|column| column.stored_column_name() == other.tenant)
                        {
                            equal = true;
                        }
                    }
                }
                if !equal {
                    return Ok(Some([relation.table, other.table]));
                }
            }
        }
        Ok(None)
    }

    /// Whether a `USING` or `NATURAL` join equates the declared tenant columns.
    fn implicit_equality(
        &self,
        first: &TenantRelation<'_, '_, DB>,
        second: &TenantRelation<'_, '_, DB>,
    ) -> Result<bool, LookupError> {
        if !std::ptr::eq(first.from, second.from) {
            return Ok(false);
        }
        let (left, right) = if first.position < second.position {
            (first, second)
        } else {
            (second, first)
        };
        let join = &right.from.joins[right.position - 1];
        let tenant_matches = |name: &Ident| -> Result<bool, LookupError> {
            Ok(stored_column(self.database, left.table, left.alias, name)?
                .is_some_and(|column| column.stored_column_name() == left.tenant)
                && stored_column(self.database, right.table, right.alias, name)?
                    .is_some_and(|column| column.stored_column_name() == right.tenant))
        };
        match join_constraint(&join.join_operator) {
            Some(JoinConstraint::Using(names)) => {
                for name in names {
                    if let Some(name) = name.0.last().and_then(|part| part.as_ident())
                        && tenant_matches(name)?
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Some(JoinConstraint::Natural) => {
                for (position, column) in left.table.columns(self.database)?.enumerate() {
                    if column.stored_column_name() == left.tenant {
                        let stored = Ident::with_quote('"', left.tenant);
                        let name = left
                            .alias
                            .and_then(|alias| alias.columns.get(position))
                            .map_or(&stored, |alias| &alias.name);
                        return tenant_matches(name);
                    }
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }
}

impl<DB: DatabaseLike> Visitor for TenantJoins<'_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.scopes.enter(query);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.scopes.leave(query);
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        match self.select(select) {
            Ok(found) => {
                self.found = self.found.or(found);
                ControlFlow::Continue(())
            }
            Err(error) => ControlFlow::Break(error),
        }
    }
}

/// Reports request-selected tenant rows joined without matching tenant keys, allowing another tenant's cap to change authorization.
///
/// The rule does not run on SQLite, which has no stored functions.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
/// let mut constrainer: GenericConstrainer<ParserDB> = CrossTenantCap::default().into();
/// constrainer.set_deployment(Deployment::example());
/// let schema = "CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT, rank INT);
/// CREATE TABLE caps (id INT PRIMARY KEY, organization_id INT, rank INT);
/// CREATE FUNCTION capped_rank(cap_id INT) RETURNS INT LANGUAGE sql AS $$
/// SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.id = cap_id $$;";
/// let bad = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// let good = ParserDB::parse::<PostgreSqlDialect>(&schema.replace("caps.id = cap_id", "caps.id = cap_id AND caps.organization_id = resources.organization_id")).unwrap();
/// assert!(constrainer.validate_schema(&bad).is_err());
/// assert!(constrainer.validate_schema(&good).is_ok());
/// ```
pub struct CrossTenantCap<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for CrossTenantCap<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<CrossTenantCap<DB>> for GenericConstrainer<DB> {
    fn from(rule: CrossTenantCap<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for CrossTenantCap<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(CrossTenantCap),
            group: LintGroup::Suspicious,
            rationale: "A caller-selected cap from another tenant can change the authorization result when tenant keys are not compared. Missing caps must fail closed.",
            source: Some("https://www.postgresql.org/docs/17/ddl-rowsecurity.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE resources (id TEXT PRIMARY KEY, organization_id TEXT, rank INT); CREATE TABLE caps (id TEXT PRIMARY KEY, organization_id TEXT, rank INT); CREATE FUNCTION capped_rank(resource_id TEXT, cap_id TEXT) RETURNS INT LANGUAGE sql AS $$ SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.id = cap_id WHERE resources.id = resource_id $$;",
                good: "CREATE TABLE resources (id TEXT PRIMARY KEY, organization_id TEXT, rank INT); CREATE TABLE caps (id TEXT PRIMARY KEY, organization_id TEXT, rank INT); CREATE FUNCTION capped_rank(resource_id TEXT, cap_id TEXT) RETURNS INT LANGUAGE sql AS $$ SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.id = cap_id AND caps.organization_id = resources.organization_id WHERE resources.id = resource_id $$;",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::TenantKeys]
    }
}

impl<DB: DatabaseLike> SchemaRule for CrossTenantCap<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        for function in database.functions() {
            let path = function.search_path(database)?;
            let mut visitor = TenantJoins {
                database,
                deployment: reporter.deployment(),
                function,
                path: path.as_deref(),
                scopes: WithScopes::default(),
                found: None,
            };
            function_body(database, function, |node| {
                node.walk(&mut visitor).break_value().map_or(Ok(()), Err)
            })?;
            if let Some([first, second]) = visitor.found {
                reporter.function(function, format!("Function '{}' joins request-selected table '{}' with table '{}' without matching their declared tenant keys.", signature(function, database), first.table_name(), second.table_name()), "Equate both declared tenant keys in a conjunct of the join or filter.".to_owned())?;
            }
        }
        Ok(())
    }
}
