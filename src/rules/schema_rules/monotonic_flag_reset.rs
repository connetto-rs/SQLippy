//! Submodule providing the `MonotonicFlagReset` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{
        ActingRole, ColumnDefinition, ColumnScope, IdentifierCase, PolicyExpression, TargetName,
    },
    traits::{ColumnLike, DataTypeLike, DatabaseLike, PolicyLike, TableLike, TriggerLike},
    utils::{identifier_resolution::normalize_identifier, scalar_family::ScalarFamily},
};
use sqlparser::ast::{
    CreatePolicyType, Expr, TriggerEvent, TriggerObject, TriggerObjectKind, TriggerPeriod,
    UnaryOperator, Visitor,
};

use crate::{
    deployment::Declaration,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::body_statements,
        policy_support::{Command, applies_to, conjuncts, held_by_name, is_column_reference},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Records references to both transition rows for one irreversible column.
struct TransitionReads<'column> {
    column: &'column str,
    old: bool,
    new: bool,
}

impl Visitor for TransitionReads<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::CompoundIdentifier(parts) = expression
            && let [row, column] = parts.as_slice()
            && normalize_identifier(&column.value, column.quote_style.is_some()) == self.column
        {
            match normalize_identifier(&row.value, row.quote_style.is_some()).as_ref() {
                "old" => self.old = true,
                "new" => self.new = true,
                _ => {}
            }
        }
        ControlFlow::Continue(())
    }
}

/// Whether a row trigger reads both transition values before updates of the column.
fn guarded<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    column: &str,
) -> Result<bool, LookupError> {
    for trigger in table.triggers(database)? {
        if trigger.timing() != Some(TriggerPeriod::Before)
            || !matches!(trigger.orientation(), Some(TriggerObjectKind::For(TriggerObject::Row) | TriggerObjectKind::ForEach(TriggerObject::Row)))
            || !trigger.events().iter().any(|event| matches!(event, TriggerEvent::Update(columns)
                if columns.is_empty() || columns.iter().any(|name| normalize_identifier(&name.value, name.quote_style.is_some()) == column)))
        { continue; }
        let Some(function) = trigger.function(database) else {
            continue;
        };
        let mut reads = TransitionReads {
            column,
            old: false,
            new: false,
        };
        for statement in body_statements(function) {
            let _ = walk(&statement, &mut reads);
        }
        if reads.old && reads.new {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a policy's old-row predicate requires the column's initial state.
fn initial_only<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    column: &DB::Column,
    policy: &DB::Policy,
) -> Result<bool, LookupError> {
    let Some(expression) = policy
        .using_clause(database)?
        .as_ref()
        .map(PolicyExpression::expression)
    else {
        return Ok(false);
    };
    let scope = ColumnScope::for_table(table, database, IdentifierCase::Folded);
    let data_type = column.data_type(database);
    let family = data_type
        .base_type(database)
        .unwrap_or(data_type)
        .scalar_family(database);
    for conjunct in conjuncts(expression) {
        let mut candidate = match (family, conjunct) {
            (_, Expr::IsNull(inner))
            | (
                Some(ScalarFamily::Bool),
                Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    expr: inner,
                },
            ) => inner.as_ref(),
            _ => continue,
        };
        while let Expr::Nested(inner) = candidate {
            candidate = inner;
        }
        if is_column_reference(candidate)
            && matches!(scope.resolve_column_definition(candidate)?, Some(ColumnDefinition::Base { table: found_table, column: found_column, .. })
                if database.table_id(found_table) == database.table_id(table)
                    && found_column.stored_column_name() == column.stored_column_name())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Reports client-writable irreversible columns without transition protection.
///
/// A policy cannot compare `OLD` with `NEW`, so protecting transitions requires a trigger or excluding set rows in `USING`.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
/// let mut constrainer: GenericConstrainer<ParserDB> = MonotonicFlagReset::default().into();
/// constrainer.set_deployment(Deployment::example());
/// let schema = "CREATE ROLE authenticated;
/// CREATE TABLE tokens (id INT, revoked_at TIMESTAMPTZ);
/// GRANT UPDATE ON tokens TO authenticated;
/// ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;";
/// let bad = ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} CREATE POLICY own ON tokens FOR UPDATE USING (true);")).unwrap();
/// assert!(constrainer.validate_schema(&bad).is_err());
/// let good = ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} CREATE POLICY own ON tokens FOR UPDATE USING (revoked_at IS NULL);")).unwrap();
/// assert!(constrainer.validate_schema(&good).is_ok());
/// ```
pub struct MonotonicFlagReset<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for MonotonicFlagReset<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<MonotonicFlagReset<DB>> for GenericConstrainer<DB> {
    fn from(rule: MonotonicFlagReset<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for MonotonicFlagReset<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(MonotonicFlagReset),
            group: LintGroup::Suspicious,
            rationale: "Policies cannot compare OLD with NEW, so a writable irreversible column needs a transition trigger or a USING predicate excluding rows already set.",
            source: Some("https://www.postgresql.org/docs/17/sql-createpolicy.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE authenticated;
CREATE TABLE tokens (id INT, revoked_at TIMESTAMPTZ);
GRANT SELECT, UPDATE ON tokens TO authenticated;
ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON tokens TO authenticated USING (true);",
                good: "CREATE ROLE authenticated;
CREATE TABLE tokens (id INT, revoked_at TIMESTAMPTZ);
GRANT SELECT, UPDATE ON tokens TO authenticated;
ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON tokens TO authenticated USING (true);
CREATE FUNCTION preserve_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL THEN RAISE EXCEPTION 'revocation is permanent'; END IF; RETURN NEW; END $$;
CREATE TRIGGER preserve_revocation BEFORE UPDATE ON tokens FOR EACH ROW EXECUTE FUNCTION preserve_revocation();",
            },
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::IrreversibleColumns]
    }
}

impl<DB: DatabaseLike> SchemaRule for MonotonicFlagReset<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        for (schema, table_name, column_name) in deployment.irreversible_columns() {
            let target = TargetName::new(table_name, true).with_schema(schema, true);
            let Some(table) = database.table_by_target(target, IdentifierCase::AsWritten)? else {
                continue;
            };
            let Some(column) = table.column(column_name, database, IdentifierCase::AsWritten)?
            else {
                continue;
            };
            if guarded(database, table, column_name)? {
                continue;
            }
            let mut writable = false;
            for name in deployment.app_roles().chain(deployment.anonymous_roles()) {
                let role = database
                    .role(name)
                    .map_or(ActingRole::Public, ActingRole::Declared);
                if !table.privileges(role, database)?.update.on_column(column) {
                    continue;
                }
                if !table.has_row_level_security(database)? {
                    writable = true;
                    break;
                }
                let held = held_by_name(database, name);
                let mut restrictive_initial = false;
                let mut permissive_reset = false;
                for policy in table.policies(database)? {
                    if Command::Update.covered_by(policy.command())
                        && applies_to(database, policy, &held)
                    {
                        let initial = initial_only(database, table, column, policy)?;
                        if policy.policy_type() == CreatePolicyType::Restrictive {
                            restrictive_initial |= initial;
                        } else {
                            permissive_reset |= !initial;
                        }
                    }
                }
                writable = permissive_reset && !restrictive_initial;
                if writable {
                    break;
                }
            }
            if writable {
                reporter.table(table,
                    format!("Clients can reset irreversible column '{column_name}' on '{table_name}'."),
                    format!("Protect '{column_name}' with a BEFORE UPDATE row trigger reading OLD and NEW, or require its initial state in every permissive UPDATE USING clause."))?;
            }
        }
        Ok(())
    }
}
