//! Submodule providing the `AuthorityAttributeWritableBelowThreshold` rule.

use std::{borrow::Cow, marker::PhantomData, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnDefinitionScope, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DataTypeLike, DatabaseLike, FunctionLike, PolicyLike, TableLike},
};
use sqlparser::ast::{
    BinaryOperator, CreatePolicyType, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Query,
    Select, SelectItem, SetExpr, Value, Visitor,
};

use crate::{
    deployment::{Declaration, Deployment},
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        authority_support::{compared_set, filters, is_credential_value, selects, tested_columns},
        function_body_support::{function_body, parameter},
        function_reach_support::policy_functions,
        grant_support::withheld,
        policy_support::{Command, Stage, applied, conjuncts, sql_query_body, walked_clauses},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// A helper's enum comparison and the argument supplying its lower bound.
struct Threshold<'db, DB: DatabaseLike> {
    helper: &'db DB::Function,
    argument: usize,
    type_name: Cow<'db, str>,
    labels: Vec<&'db str>,
    strict: bool,
}

/// An attribute and the threshold admitting its row to an authority arm.
struct Arm<'db, DB: DatabaseLike> {
    column: &'db DB::Column,
    key: &'db DB::Column,
    threshold: usize,
    rank: usize,
}

/// Resolves a stored column with the catalog's lifetime.
fn column<'db, DB: DatabaseLike>(
    database: &'db DB,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    expression: &Expr,
) -> Result<Option<&'db DB::Column>, LookupError> {
    let Some(ColumnDefinition::Base { table, column, .. }) =
        scope.resolve_column_definition(expression)?
    else {
        return Ok(None);
    };
    let table = database
        .table_by_stored_identity(
            table.stored_table_schema().as_deref(),
            &table.stored_table_name(),
        )
        .unwrap();
    Ok(table
        .columns(database)?
        .find(|candidate| candidate.stored_column_name() == column.stored_column_name()))
}

/// Reads enum threshold comparisons in a helper's credential-filtered selects.
struct Thresholds<'a, 'db, 'query, DB: DatabaseLike> {
    database: &'db DB,
    deployment: &'a Deployment,
    helper: &'db DB::Function,
    root: &'a ColumnScope<'query, 'db, DB>,
    found: Vec<Threshold<'db, DB>>,
}

impl<DB: DatabaseLike> Thresholds<'_, '_, '_, DB> {
    /// Records enum comparisons from one credential-filtered select.
    fn select(&mut self, select: &Select) -> Result<(), LookupError> {
        let scope = self.root.scope_for_select(select).unwrap();
        let conditions = filters(select);
        let mut credential_tables = Vec::new();
        for condition in &conditions {
            if let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = condition
            {
                for (operand, other) in [(left, right), (right, left)] {
                    if is_credential_value(self.deployment, other)
                        && let Some(subject) = column(self.database, &scope, operand)?
                    {
                        credential_tables.push(subject.table(self.database));
                    }
                }
            }
        }
        for condition in conditions {
            let Expr::BinaryOp {
                left,
                op: operator,
                right,
            } = condition
            else {
                continue;
            };
            let (attribute, parameter_value, strict) = match operator {
                BinaryOperator::GtEq => (left, right, false),
                BinaryOperator::Gt => (left, right, true),
                BinaryOperator::LtEq => (right, left, false),
                BinaryOperator::Lt => (right, left, true),
                _ => continue,
            };
            let Some(argument) = parameter(self.database, self.helper, parameter_value) else {
                continue;
            };
            let Some(attribute) = column(self.database, &scope, attribute)? else {
                continue;
            };
            if !credential_tables
                .iter()
                .any(|table| std::ptr::eq(*table, attribute.table(self.database)))
            {
                continue;
            }
            let data_type = attribute.data_type(self.database);
            let Some(enumeration) = data_type.enumeration(self.database) else {
                continue;
            };
            let type_name = data_type.name(self.database);
            if self
                .helper
                .argument_type_names(self.database)
                .nth(argument)
                .is_none_or(|name| name != type_name)
            {
                continue;
            }
            self.found.push(Threshold {
                helper: self.helper,
                argument,
                type_name,
                labels: enumeration
                    .into_members()
                    .map(sql_traits::traits::EnumerationMember::label)
                    .collect(),
                strict,
            });
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for Thresholds<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        selects(&query.body)
            .into_iter()
            .try_for_each(|select| self.select(select))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Reads a literal label through casts and parentheses.
fn label(expression: &Expr) -> Option<&str> {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => label(inner),
        Expr::Value(value) => match &value.value {
            Value::SingleQuotedString(value) => Some(value),
            _ => None,
        },
        _ => None,
    }
}

/// Finds the threshold supplied by a set-returning helper call.
fn bound<DB: DatabaseLike>(
    database: &DB,
    thresholds: &[Threshold<'_, DB>],
    query: &Query,
) -> Result<Option<(usize, usize)>, LookupError> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Ok(None);
    };
    if !select.from.is_empty() || select.selection.is_some() {
        return Ok(None);
    }
    let [SelectItem::UnnamedExpr(Expr::Function(call))] = select.projection.as_slice() else {
        return Ok(None);
    };
    let FunctionArguments::List(arguments) = &call.args else {
        return Ok(None);
    };
    for helper in database.functions_reached_by(call, IdentifierCase::Folded)? {
        for (position, threshold) in thresholds.iter().enumerate() {
            if !std::ptr::eq(helper, threshold.helper) {
                continue;
            }
            let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(argument))) =
                arguments.args.get(threshold.argument)
            else {
                continue;
            };
            let Some(label) = label(argument) else {
                continue;
            };
            if let Some(rank) = threshold.labels.iter().position(|member| *member == label) {
                let rank = rank + usize::from(threshold.strict);
                if rank < threshold.labels.len() {
                    return Ok(Some((position, rank)));
                }
            }
        }
    }
    Ok(None)
}

/// Returns the row key and subquery of a set-membership condition.
fn membership(expression: &Expr) -> Option<(&Expr, &Query)> {
    let key = match expression {
        Expr::In { expr, .. } => expr,
        Expr::AnyOp { left, .. } => left,
        _ => return None,
    };
    Some((key, compared_set(expression)?))
}

/// Collects boolean attributes and the enum sets admitting their rows.
struct Arms<'a, 'db, 'query, DB: DatabaseLike> {
    database: &'db DB,
    root: &'a ColumnScope<'query, 'db, DB>,
    thresholds: &'a [Threshold<'db, DB>],
    found: Vec<Arm<'db, DB>>,
}

impl<DB: DatabaseLike> Arms<'_, '_, '_, DB> {
    /// Records attributes sharing a row with a threshold membership test.
    fn select(&mut self, select: &Select) -> Result<(), LookupError> {
        let scope = self.root.scope_for_select(select).unwrap();
        let conditions = filters(select);
        for condition in &conditions {
            let Some((key, query)) = membership(condition) else {
                continue;
            };
            let Some(key) = column(self.database, &scope, key)? else {
                continue;
            };
            let Some((threshold, rank)) = bound(self.database, self.thresholds, query)? else {
                continue;
            };
            for tested in conditions
                .iter()
                .flat_map(|condition| tested_columns(condition))
            {
                let Some(attribute) = column(self.database, &scope, tested)? else {
                    continue;
                };
                if std::ptr::eq(attribute.table(self.database), key.table(self.database))
                    && ["bool", "boolean"].iter().any(|name| {
                        attribute
                            .data_type(self.database)
                            .name(self.database)
                            .eq_ignore_ascii_case(name)
                    })
                {
                    self.found.push(Arm {
                        column: attribute,
                        key,
                        threshold,
                        rank,
                    });
                }
            }
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for Arms<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        selects(&query.body)
            .into_iter()
            .try_for_each(|select| self.select(select))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Reads subqueries of policy and scalar helper expressions.
struct ExpressionArms<'a, 'db, DB: DatabaseLike> {
    database: &'db DB,
    thresholds: &'a [Threshold<'db, DB>],
    found: Vec<Arm<'db, DB>>,
}

impl<DB: DatabaseLike> Visitor for ExpressionArms<'_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        let result = (|| {
            let root = ColumnScope::from_query(query, self.database, IdentifierCase::Folded)?;
            let mut collector = Arms {
                database: self.database,
                root: &root,
                thresholds: self.thresholds,
                found: Vec::new(),
            };
            for select in selects(&query.body) {
                collector.select(select)?;
            }
            self.found.extend(collector.found);
            Ok(())
        })();
        result.map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Checks whether a write policy admits a threshold at or below an arm.
fn writable<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    thresholds: &[Threshold<'_, DB>],
    arm: &Arm<'_, DB>,
) -> Result<bool, LookupError> {
    let table = arm.column.table(database);
    let scope = ColumnScope::for_table(table, database, IdentifierCase::Folded);
    for policy in table.policies(database)? {
        if policy.policy_type() == CreatePolicyType::Restrictive
            || !Command::Update.covered_by(policy.command())
            || withheld(
                database,
                deployment,
                table,
                policy,
                Command::Update,
                arm.column,
            )?
        {
            continue;
        }
        for position in applied(database, policy, Command::Update)? {
            if position.stage != Stage::Filter {
                continue;
            }
            for condition in conjuncts(position.expression) {
                let Some((key, query)) = membership(condition) else {
                    continue;
                };
                let Some(ColumnDefinition::Base { column: key, .. }) =
                    scope.resolve_column_definition(key)?
                else {
                    continue;
                };
                if !std::ptr::eq(key, arm.key) {
                    continue;
                }
                if let Some((threshold, rank)) = bound(database, thresholds, query)?
                    && thresholds[threshold].type_name == thresholds[arm.threshold].type_name
                    && rank <= arm.rank
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Reports boolean authority attributes writable at or below the enum threshold they enable, allowing callers to widen their own authority.
///
/// The rule does not run on SQLite, which has no row-level security policies
/// or privileges.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
/// let mut constrainer: GenericConstrainer<ParserDB> = AuthorityAttributeWritableBelowThreshold::default().into();
/// constrainer.set_deployment(Deployment::example());
/// let schema = "CREATE ROLE authenticated;
/// CREATE TYPE role AS ENUM ('reader', 'writer', 'admin');
/// CREATE TABLE docs (id UUID PRIMARY KEY, writers_can_share BOOLEAN);
/// CREATE TABLE grants (doc_id UUID, user_id UUID, role role);
/// CREATE FUNCTION docs_with(min_role role) RETURNS SETOF UUID LANGUAGE sql AS $$
/// SELECT doc_id FROM grants WHERE user_id = current_setting('app.user_id', true)::uuid AND role >= min_role $$;
/// CREATE FUNCTION sharable_docs() RETURNS SETOF UUID LANGUAGE sql AS $$
/// SELECT id FROM docs WHERE writers_can_share AND id IN (SELECT docs_with('writer')) $$;
/// ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
/// ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
/// CREATE POLICY share ON grants FOR INSERT TO authenticated WITH CHECK (doc_id IN (SELECT sharable_docs()));
/// CREATE POLICY edit ON docs FOR UPDATE TO authenticated USING (id IN (SELECT docs_with('writer')));
/// GRANT UPDATE ON docs TO authenticated;";
/// let bad = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// let good = ParserDB::parse::<PostgreSqlDialect>(&schema.replace("USING (id IN (SELECT docs_with('writer')))", "USING (id IN (SELECT docs_with('admin')))")).unwrap();
/// assert!(constrainer.validate_schema(&bad).is_err());
/// assert!(constrainer.validate_schema(&good).is_ok());
/// ```
pub struct AuthorityAttributeWritableBelowThreshold<DB>(PhantomData<DB>);

impl<DB> Default for AuthorityAttributeWritableBelowThreshold<DB> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<AuthorityAttributeWritableBelowThreshold<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: AuthorityAttributeWritableBelowThreshold<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for AuthorityAttributeWritableBelowThreshold<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(AuthorityAttributeWritableBelowThreshold),
            group: LintGroup::Suspicious,
            rationale: "A caller who can change an authority attribute at the enum threshold it enables can grant themselves that authority. Enum labels are ordered by their declaration.",
            source: Some("https://www.postgresql.org/docs/17/datatype-enum.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: BAD,
                good: GOOD,
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Credentials]
    }
}

impl<DB: DatabaseLike> SchemaRule for AuthorityAttributeWritableBelowThreshold<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let mut queries = Vec::new();
        for table in database.tables() {
            for policy in table.policies(database)? {
                for (_, expression) in walked_clauses(database, policy)? {
                    if let Some(expression) = expression {
                        queries.push(expression);
                    }
                }
            }
        }
        let mut bodies = Vec::new();
        let mut scalar_helpers = Vec::new();
        for helper in policy_functions(database)? {
            if let Some(body) = sql_query_body(database, helper)? {
                bodies.push((helper, body));
            } else {
                scalar_helpers.push(helper);
            }
        }
        let mut thresholds = Vec::new();
        for (helper, body) in &bodies {
            let root = ColumnScope::from_query(body, database, IdentifierCase::Folded)?;
            let mut collector = Thresholds {
                database,
                deployment,
                helper,
                root: &root,
                found: Vec::new(),
            };
            walk(body.as_ref(), &mut collector)
                .break_value()
                .map_or(Ok(()), Err)?;
            thresholds.extend(collector.found);
        }
        if thresholds.is_empty() {
            return Ok(());
        }
        let mut arms = Vec::new();
        for (_, body) in &bodies {
            let root = ColumnScope::from_query(body, database, IdentifierCase::Folded)?;
            let mut collector = Arms {
                database,
                root: &root,
                thresholds: &thresholds,
                found: Vec::new(),
            };
            walk(body.as_ref(), &mut collector)
                .break_value()
                .map_or(Ok(()), Err)?;
            arms.extend(collector.found);
        }
        let mut expressions = ExpressionArms {
            database,
            thresholds: &thresholds,
            found: Vec::new(),
        };
        for expression in queries {
            walk(expression, &mut expressions)
                .break_value()
                .map_or(Ok(()), Err)?;
        }
        for helper in scalar_helpers {
            function_body(database, helper, |node| {
                node.walk(&mut expressions)
                    .break_value()
                    .map_or(Ok(()), Err)
            })?;
        }
        arms.extend(expressions.found);
        let mut findings: Vec<(&DB::Column, &str)> = Vec::new();
        for arm in arms {
            if findings
                .iter()
                .any(|(column, _)| std::ptr::eq(*column, arm.column))
                || !writable(database, deployment, &thresholds, &arm)?
            {
                continue;
            }
            findings.push((arm.column, thresholds[arm.threshold].labels[arm.rank]));
        }
        for (column, label) in findings {
            reporter.column(column,
                format!("Attribute '{}' on table '{}' is writable at or below declared enum threshold '{label}', whose authority it enables.", column.column_name(), column.table(database).table_name()),
                "Require a higher enum threshold for updates or withhold UPDATE on this column.".to_owned())?;
        }
        Ok(())
    }
}

const BAD: &str = "CREATE ROLE authenticated;
CREATE TYPE role AS ENUM ('reader', 'writer', 'admin');
CREATE TABLE docs (id UUID PRIMARY KEY, writers_can_share BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE doc_grants (doc_id UUID NOT NULL REFERENCES docs (id), user_id UUID NOT NULL, role role NOT NULL, PRIMARY KEY (doc_id, user_id));
CREATE FUNCTION docs_with(min_role role) RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
 SELECT g.doc_id FROM public.doc_grants g WHERE g.user_id = current_setting('app.user_id', true)::uuid AND g.role >= min_role
$$;
CREATE FUNCTION sharable_docs() RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
 SELECT id FROM public.docs_with('admin') AS id
 UNION
 SELECT d.id FROM public.docs d WHERE d.writers_can_share AND d.id IN (SELECT public.docs_with('writer'))
$$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT TO authenticated USING (id IN (SELECT docs_with('reader')));
CREATE POLICY docs_update ON docs FOR UPDATE TO authenticated USING (id IN (SELECT docs_with('writer'))) WITH CHECK (id IN (SELECT docs_with('writer')));
CREATE POLICY grants_share ON doc_grants FOR INSERT TO authenticated WITH CHECK (doc_id IN (SELECT sharable_docs()));
GRANT SELECT, UPDATE ON docs TO authenticated;
GRANT INSERT ON doc_grants TO authenticated;";

const GOOD: &str = "CREATE ROLE authenticated;
CREATE TYPE role AS ENUM ('reader', 'writer', 'admin');
CREATE TABLE docs (id UUID PRIMARY KEY, writers_can_share BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE doc_grants (doc_id UUID NOT NULL REFERENCES docs (id), user_id UUID NOT NULL, role role NOT NULL, PRIMARY KEY (doc_id, user_id));
CREATE FUNCTION docs_with(min_role role) RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
 SELECT g.doc_id FROM public.doc_grants g WHERE g.user_id = current_setting('app.user_id', true)::uuid AND g.role >= min_role
$$;
CREATE FUNCTION sharable_docs() RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
 SELECT id FROM public.docs_with('admin') AS id
 UNION
 SELECT d.id FROM public.docs d WHERE d.writers_can_share AND d.id IN (SELECT public.docs_with('writer'))
$$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT TO authenticated USING (id IN (SELECT docs_with('reader')));
CREATE POLICY docs_update ON docs FOR UPDATE TO authenticated USING (id IN (SELECT docs_with('admin'))) WITH CHECK (id IN (SELECT docs_with('admin')));
CREATE POLICY grants_share ON doc_grants FOR INSERT TO authenticated WITH CHECK (doc_id IN (SELECT sharable_docs()));
GRANT SELECT, UPDATE ON docs TO authenticated;
GRANT INSERT ON doc_grants TO authenticated;";
