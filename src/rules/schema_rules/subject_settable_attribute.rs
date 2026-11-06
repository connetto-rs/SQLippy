//! Submodule providing the `SubjectSettableAttribute` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, PolicyLike, TableLike},
};
use sqlparser::ast::{
    BinaryOperator, CreatePolicyType, Expr, InTarget, Query, UnaryOperator, Value, Visit, Visitor,
};

use crate::{
    deployment::{Declaration, Deployment},
    error::{Interruption, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::{
        authority_support::{TableColumn, authority_columns, credential_compared, is_literal},
        policy_support::{
            Command, Stage, applied, conjuncts, covers, is_column_reference, policy_roles,
        },
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Finds, outside sublinks, a comparison of a column of the policy's table
/// with a declared credential.
struct SubjectTest<'s, 'db, DB: DatabaseLike> {
    database: &'db DB,
    deployment: &'s Deployment,
    scope: &'s ColumnScope<'db, 'db, DB>,
    depth: usize,
    found: bool,
}

impl<DB: DatabaseLike> Visitor for SubjectTest<'_, '_, DB> {
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
        if self.depth > 0 {
            return ControlFlow::Continue(());
        }
        credential_compared(self.database, self.deployment, self.scope, expression).map_or_else(
            ControlFlow::Break,
            |compared| {
                self.found |= !compared.is_empty();
                ControlFlow::Continue(())
            },
        )
    }
}

/// Whether the expression compares a column of the policy's table with a
/// declared credential outside its sublinks, admitting the row's subject.
fn admits_subject<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    scope: &ColumnScope<'_, '_, DB>,
    expression: &Expr,
) -> Result<bool, LookupError> {
    let mut test = SubjectTest {
        database,
        deployment,
        scope,
        depth: 0,
        found: false,
    };
    expression
        .visit(&mut test)
        .break_value()
        .map_or(Ok(()), Err)?;
    Ok(test.found)
}

/// Whether the expression is the literal `true`, parenthesised or cast.
fn is_true(expression: &Expr) -> bool {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => is_true(inner),
        Expr::Value(value) => matches!(value.value, Value::Boolean(true)),
        _ => false,
    }
}

/// Whether the expression names `attribute` of the policy's table.
fn names_attribute<DB: DatabaseLike>(
    database: &DB,
    scope: &ColumnScope<'_, '_, DB>,
    attribute: &TableColumn,
    expression: &Expr,
) -> Result<bool, LookupError> {
    if let Expr::Nested(inner) = expression {
        return names_attribute(database, scope, attribute, inner);
    }
    Ok(is_column_reference(expression)
        && matches!(scope.resolve_column_definition(expression)?,
            Some(ColumnDefinition::Base { table, column, .. })
                if database.table_id(table) == Some(attribute.0)
                    && column.stored_column_name() == attribute.1))
}

/// Whether a top-level `AND` conjunct of the expression pins `attribute` to
/// literals other than `true` with `=` or `IN`, or tests it false.
fn fixes<DB: DatabaseLike>(
    database: &DB,
    scope: &ColumnScope<'_, '_, DB>,
    attribute: &TableColumn,
    expression: &Expr,
) -> Result<bool, LookupError> {
    let pinned = |value: &Expr| is_literal(value) && !is_true(value);
    for conjunct in conjuncts(expression) {
        let fixed = match conjunct {
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: column,
            }
            | Expr::IsFalse(column) => names_attribute(database, scope, attribute, column)?,
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => {
                (pinned(right) && names_attribute(database, scope, attribute, left)?)
                    || (pinned(left) && names_attribute(database, scope, attribute, right)?)
            }
            Expr::In {
                expr: column,
                target: InTarget::List(list),
                negated: false,
                ..
            } => list.iter().all(pinned) && names_attribute(database, scope, attribute, column)?,
            _ => false,
        };
        if fixed {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a restrictive policy for `command` covering `roles` fixes
/// `attribute` in its new-row clause.
fn guarded<DB: DatabaseLike>(
    database: &DB,
    scope: &ColumnScope<'_, '_, DB>,
    restrictive: &[&DB::Policy],
    roles: Option<&[String]>,
    command: Command,
    attribute: &TableColumn,
) -> Result<bool, LookupError> {
    for guard in restrictive {
        if !command.covered_by(guard.command())
            || !covers(database, policy_roles(database, guard).as_deref(), roles)
        {
            continue;
        }
        for check in applied(database, guard, command) {
            if check.stage == Stage::Check && fixes(database, scope, attribute, check.expression)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Whether the schema proves that every role writing through `policy` lacks
/// `command`'s privilege on `attribute` of `table`, for an `INSERT` or an
/// `UPDATE`.
///
/// The writers are the policy's roles, or the declared client roles for a
/// policy applying to `PUBLIC`. A writer the schema never creates may hold
/// the privilege from outside it.
fn withheld<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    table: &DB::Table,
    policy: &DB::Policy,
    command: Command,
    attribute: &DB::Column,
) -> Result<bool, LookupError> {
    let writers = policy_roles(database, policy).unwrap_or_else(|| {
        deployment
            .app_roles()
            .chain(deployment.anonymous_roles())
            .map(str::to_owned)
            .collect()
    });
    if writers.is_empty() {
        return Ok(false);
    }
    for writer in writers {
        let Some(role) = database.role(&writer) else {
            return Ok(false);
        };
        let possible = table.possible_privileges(role, database)?;
        let privilege = if command == Command::Insert {
            &possible.insert
        } else {
            &possible.update
        };
        if privilege.on_column(attribute) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Struct defining a rule that reports a write policy on an authority table
/// letting the row's own subject set an attribute column other policies test
/// to grant access.
///
/// An authority table is one a policy reads, in a sublink or in a
/// set-returning `LANGUAGE sql` helper it calls, by comparing a column with a
/// declared credential. Its attribute columns are the ones that read compares
/// with a literal or tests as a boolean, such as `profiles.is_admin`. A
/// permissive `INSERT` or `UPDATE` policy whose new-row clause compares a
/// column of the row with a credential admits the row's subject, and when no
/// top-level conjunct pins an attribute column to literals other than `true`
/// or tests it false, the subject can set it and grant themselves what the
/// reading policies grant.
///
/// A restrictive policy for the same command covering the policy's roles
/// closes the gap when it fixes the column. So does the source proving that
/// the policy's roles, or the declared client roles for a policy applying to
/// `PUBLIC`, lack the command's privilege on the column. A parsed schema
/// proves it with a `REVOKE` of the table-wide privilege that names no
/// grantor or names the table's owner and no grant of the column, and a
/// catalog proves it with its access list. A guarding trigger is not
/// recognised and takes an allowance.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = SubjectSettableAttribute::default().into();
/// constrainer.set_deployment(
///     Deployment::default()
///         .with_app_role("app_user")
///         .with_credential("current_setting('app.user_id', true)")
///         .unwrap(),
/// );
/// let schema = "CREATE ROLE app_user;
///     CREATE TABLE profiles (id TEXT PRIMARY KEY, display_name TEXT, is_admin BOOL);
///     CREATE TABLE docs (id INT);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///     ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY docs_admin ON docs USING (EXISTS (SELECT 1 FROM profiles p
///       WHERE p.id = current_setting('app.user_id', true) AND p.is_admin));
///     CREATE POLICY own ON profiles FOR UPDATE USING (id = current_setting('app.user_id', true));";
///
/// let open = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&open).is_err());
///
/// let withheld = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} REVOKE UPDATE ON profiles FROM app_user;
///      GRANT UPDATE (display_name) ON profiles TO app_user;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&withheld).is_ok());
/// ```
pub struct SubjectSettableAttribute<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for SubjectSettableAttribute<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<SubjectSettableAttribute<DB>> for GenericConstrainer<DB> {
    fn from(rule: SubjectSettableAttribute<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for SubjectSettableAttribute<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "SubjectSettableAttribute",
            group: LintGroup::Suspicious,
            rationale: "Policies test an authority table's attribute columns to decide what the caller may reach, so a write policy that lets a row's subject set them lets the subject grant themselves that access.",
            source: Some(
                "https://supabase.com/docs/guides/database/postgres/column-level-security",
            ),
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Credentials]
    }
}

impl<DB: DatabaseLike> SchemaRule for SubjectSettableAttribute<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let attributes = authority_columns(database, deployment)?.attributes;
        let tables = database
            .tables()
            .filter_map(|table| database.table_id(table).map(|id| (table, id)));
        for (table, id) in tables {
            let mut columns = Vec::new();
            for column in table.columns(database)? {
                let attribute = (id, column.stored_column_name().into_owned());
                if attributes.contains(&attribute) {
                    columns.push((column, attribute));
                }
            }
            if columns.is_empty() {
                continue;
            }
            let scope = ColumnScope::for_table(table, database, IdentifierCase::Folded);
            let (restrictive, permissive): (Vec<&DB::Policy>, Vec<&DB::Policy>) = table
                .policies(database)?
                .partition(|policy| policy.policy_type() == CreatePolicyType::Restrictive);
            for policy in permissive {
                let roles = policy_roles(database, policy);
                let mut sites: Vec<PolicySite<DB>> = Vec::new();
                let mut free: Vec<&str> = Vec::new();
                let mut commands: Vec<&str> = Vec::new();
                for (command, keyword) in [(Command::Insert, "INSERT"), (Command::Update, "UPDATE")]
                {
                    if !command.covered_by(policy.command()) {
                        continue;
                    }
                    for position in applied(database, policy, command) {
                        if position.stage != Stage::Check
                            || !admits_subject(database, deployment, &scope, position.expression)?
                        {
                            continue;
                        }
                        for (column, attribute) in &columns {
                            if fixes(database, &scope, attribute, position.expression)?
                                || guarded(
                                    database,
                                    &scope,
                                    &restrictive,
                                    roles.as_deref(),
                                    command,
                                    attribute,
                                )?
                                || withheld(database, deployment, table, policy, command, column)?
                            {
                                continue;
                            }
                            if !free.contains(&column.column_name()) {
                                free.push(column.column_name());
                            }
                            if !commands.contains(&keyword) {
                                commands.push(keyword);
                            }
                            if !sites.iter().any(|site| site.clause == position.clause) {
                                sites.push(PolicySite {
                                    table: Box::new(table.clone()),
                                    policy: Box::new(policy.clone()),
                                    clause: position.clause,
                                    expression: position.expression.to_string(),
                                });
                            }
                        }
                    }
                }
                if sites.is_empty() {
                    continue;
                }
                let (name, table_name) = (policy.name(), table.table_name());
                let free = free
                    .iter()
                    .map(|column| format!("'{column}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let commands = commands.join(" and ");
                reporter.policies(
                    sites,
                    format!(
                        "Policy '{name}' on '{table_name}' lets the row's own subject set {free}, which policies test to grant access, so a caller can grant themselves that access."
                    ),
                    format!(
                        "Fix {free} in the new-row clause of '{name}', for example with AND NOT <column> or AND <column> = '<value>', or revoke table-wide {commands} on '{table_name}' from the policy's roles and grant them only the columns they may write."
                    ),
                )?;
            }
        }
        Ok(())
    }
}
