//! Submodule providing the `UndeletableReference` rule.

use std::{borrow::Cow, collections::HashSet, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{ActingRole, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, TableLike, TriggerLike},
};
use sqlparser::ast::{
    AssignmentTarget, FromTable, FunctionSecurity, ObjectName, ReferentialAction, Statement,
    TableFactor, TableWithJoins, TriggerEvent, TriggerPeriod, Visitor,
};

use crate::{
    deployment::Declaration,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::stored_table,
        expression_site_support::{is_null_literal, parsed_body_statements},
        function_rules::unreadable_body,
        key_support::checks_every_row_of,
        walk_support::walk,
    },
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports a `NO ACTION` foreign key whose
/// referenced table a declared client role may delete from while it has no
/// way to clear the referencing rows.
///
/// The role is a declared app or anonymous role, or `PUBLIC`, holding
/// `DELETE` on the referenced table, inherited grants included. The
/// referencing rows count as clearable when the source does not prove the
/// role lacks `DELETE` on the referencing table, or `UPDATE` on
/// a nullable column of the key, when the role may execute a `SECURITY
/// DEFINER` function, or a `BEFORE DELETE` trigger on the referenced table
/// runs one, whose body or a function it calls deletes from the referencing
/// table or sets a key column to `NULL`, and, when the key is deferrable, when
/// a chain of `ON DELETE CASCADE` foreign keys leads from the referenced table
/// to the referencing one or a cascading key of the referencing table on the
/// referenced one checks every row the key holds. An immediate check runs
/// ahead of the cascades of a chain, and ahead of a cascading key on its own
/// columns created after it, an order a restore does not keep. A body that
/// runs dynamic SQL or does not parse counts as clearing. `ON DELETE
/// RESTRICT` states that the block is intended and is not reported.
///
/// The rule is inactive until the deployment declares a client role.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = UndeletableReference::default().into();
/// constrainer.set_deployment(Deployment::default().with_app_role("app"));
/// let schema = "CREATE ROLE app;
///     CREATE TABLE accounts (id INT PRIMARY KEY);
///     GRANT DELETE ON accounts TO app;";
/// let blocked = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE TABLE notes (account_id INT NOT NULL REFERENCES accounts (id));
///      REVOKE DELETE ON notes FROM app;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&blocked).is_err());
/// let cascading = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE TABLE notes (account_id INT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE);
///      REVOKE DELETE ON notes FROM app;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&cascading).is_ok());
/// ```
pub struct UndeletableReference<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UndeletableReference<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UndeletableReference<DB>> for GenericConstrainer<DB> {
    fn from(rule: UndeletableReference<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UndeletableReference<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UndeletableReference),
            group: LintGroup::Suspicious,
            rationale: "A role that may delete a parent row but cannot clear the rows referencing it with NO ACTION is refused that deletion whenever one referencing row exists.",
            source: Some(
                "https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-FK",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE authenticated;\n\
CREATE TABLE accounts (id integer PRIMARY KEY);\n\
CREATE TABLE notes (id integer PRIMARY KEY, account_id integer NOT NULL REFERENCES accounts (id));\n\
GRANT DELETE ON accounts TO authenticated;\n\
REVOKE DELETE ON notes FROM authenticated;",
                good: "CREATE ROLE authenticated;\n\
CREATE TABLE accounts (id integer PRIMARY KEY);\n\
CREATE TABLE notes (id integer PRIMARY KEY, account_id integer NOT NULL REFERENCES accounts (id) ON DELETE CASCADE);\n\
GRANT DELETE ON accounts TO authenticated;\n\
REVOKE DELETE ON notes FROM authenticated;",
            },
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::ClientRoles]
    }
}

/// Whether `ON DELETE CASCADE` foreign keys may clear the rows `foreign_key`
/// holds before its check runs. An immediate check runs ahead of the cascades
/// of a chain, and ahead of a cascading key of `child` on `parent` created
/// after it, an order a restore does not keep, so cascades count only when
/// `foreign_key` is deferrable, which lets the role defer the check to
/// commit. They then count through a chain leading from `parent` to `child`,
/// or through a cascading key of `child` on `parent` itself that checks every
/// row `foreign_key` holds.
fn cascades<DB: DatabaseLike>(
    database: &DB,
    parent: &DB::Table,
    child: &DB::Table,
    foreign_key: &DB::ForeignKey,
) -> Result<bool, LookupError> {
    if !foreign_key.deferral(database).is_deferrable() {
        return Ok(false);
    }
    let mut reached = vec![parent];
    let mut pending = vec![parent];
    while let Some(table) = pending.pop() {
        for host in database.tables() {
            for cascading in host.foreign_keys(database)? {
                if cascading.on_delete(database) != ReferentialAction::Cascade
                    || cascading.referenced_table(database)? != table
                {
                    continue;
                }
                if host == child {
                    if table != parent || checks_every_row_of(database, cascading, foreign_key)? {
                        return Ok(true);
                    }
                } else if !reached.contains(&host) {
                    reached.push(host);
                    pending.push(host);
                }
            }
        }
    }
    Ok(false)
}

/// Finds a statement deleting from `child` or setting a column of
/// `foreign_key` to `NULL` in it, resolving names on `path`.
struct Clearing<'a, DB: DatabaseLike> {
    database: &'a DB,
    child: &'a DB::Table,
    foreign_key: &'a DB::ForeignKey,
    path: Option<&'a [(Cow<'a, str>, bool)]>,
}

impl<DB: DatabaseLike> Clearing<'_, DB> {
    /// Whether `item` names `child`.
    fn names_child(&self, item: &TableWithJoins) -> Result<bool, LookupError> {
        let TableFactor::Table { name, .. } = &item.relation else {
            return Ok(false);
        };
        Ok(stored_table(self.database, name, self.path)? == Some(self.child))
    }

    /// Whether `column` names a host column of `foreign_key`.
    fn names_key_column(&self, column: &ObjectName) -> Result<bool, LookupError> {
        let Some(ident) = column.0.last().and_then(|part| part.as_ident()) else {
            return Ok(false);
        };
        Ok(self.foreign_key.host_columns(self.database)?.any(|host| {
            IdentifierCase::AsWritten.identifiers_match(
                host.column_name(),
                host.column_name_is_quoted(),
                &ident.value,
                ident.quote_style.is_some(),
            )
        }))
    }

    /// Whether `statement` clears referencing rows of `child`.
    fn clears(&self, statement: &Statement) -> Result<bool, LookupError> {
        match statement {
            Statement::Delete(delete) => {
                let (FromTable::WithFromKeyword(items) | FromTable::WithoutKeyword(items)) =
                    &delete.from;
                for item in items {
                    if self.names_child(item)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Statement::Update(update) if self.names_child(&update.table)? => {
                for assignment in &update.assignments {
                    if !is_null_literal(&assignment.value) {
                        continue;
                    }
                    let columns = match &assignment.target {
                        AssignmentTarget::ColumnName(column) => std::slice::from_ref(column),
                        AssignmentTarget::Tuple(columns) => columns.as_slice(),
                    };
                    for column in columns {
                        if self.names_key_column(column)? {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }
}

impl<DB: DatabaseLike> Visitor for Clearing<'_, DB> {
    type Break = Result<(), LookupError>;

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        match self.clears(statement) {
            Ok(false) => ControlFlow::Continue(()),
            Ok(true) => ControlFlow::Break(Ok(())),
            Err(error) => ControlFlow::Break(Err(error)),
        }
    }
}

/// Whether the body of `function` may delete the rows of `child` that
/// `foreign_key` holds or set one of its columns to `NULL`. A body that runs
/// dynamic SQL or does not parse counts as clearing.
fn body_clears<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
    child: &DB::Table,
    foreign_key: &DB::ForeignKey,
) -> Result<bool, LookupError> {
    match function
        .dynamic_execution_sites(database)
        .and_then(|sites| sites.sites().map(|sites| sites.is_empty()))
    {
        Ok(true) => {}
        Ok(false) => return Ok(true),
        Err(error) if unreadable_body(&error) => return Ok(true),
        Err(error) => return Err(error),
    }
    let (statements, path): (Cow<'_, [Statement]>, _) =
        match function.atomic_statements(database)? {
            Some(statements) => (statements, None),
            None => match parsed_body_statements(function) {
                Some(statements) => (Cow::Owned(statements), function.search_path(database)?),
                None => return Ok(true),
            },
        };
    let mut clearing = Clearing {
        database,
        child,
        foreign_key,
        path: path.as_deref(),
    };
    for statement in statements.iter() {
        if let ControlFlow::Break(found) = walk(statement, &mut clearing) {
            found?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `function` runs as its owner and its body, or a function it
/// reaches through its calls, which the owner then runs too, may delete the
/// rows of `child` that `foreign_key` holds or set one of its columns to
/// `NULL`.
fn clears<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
    child: &DB::Table,
    foreign_key: &DB::ForeignKey,
) -> Result<bool, LookupError> {
    if function.security_mode() != FunctionSecurity::Definer {
        return Ok(false);
    }
    let mut pending = vec![function];
    let mut visited = HashSet::new();
    while let Some(function) = pending.pop() {
        if !visited.insert(function) || function.target_name().schema() == Some("pg_catalog") {
            continue;
        }
        if body_clears(database, function, child, foreign_key)? {
            return Ok(true);
        }
        match function.referenced_functions(database) {
            Ok(called) => pending.extend(called),
            Err(error) if unreadable_body(&error) => return Ok(true),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// The acting role for a declared role, or `PUBLIC` for `None`.
fn acting<R>(role: Option<&R>) -> ActingRole<'_, R> {
    role.map_or(ActingRole::Public, ActingRole::Declared)
}

/// Whether `role`, `PUBLIC` for `None`, may clear the rows of `child` that
/// `foreign_key` holds before deleting from `parent`, as far as the source
/// can tell.
fn may_clear<DB: DatabaseLike>(
    database: &DB,
    role: Option<&DB::Role>,
    parent: &DB::Table,
    child: &DB::Table,
    foreign_key: &DB::ForeignKey,
) -> Result<bool, LookupError> {
    let possible = child.possible_privileges(acting(role), database)?;
    if possible.delete {
        return Ok(true);
    }
    for column in foreign_key.host_columns(database)? {
        if column.is_nullable(database)? && possible.update.on_column(column) {
            return Ok(true);
        }
    }
    let functions = database
        .functions()
        .filter(|function| function.target_name().schema() != Some("pg_catalog"));
    for function in functions {
        let executable = match role {
            Some(role) => function.can_execute(role, database)?,
            None => function.is_executable_by_public(database)?,
        };
        if executable && clears(database, function, child, foreign_key)? {
            return Ok(true);
        }
    }
    for trigger in parent.triggers(database)? {
        if matches!(trigger.timing(), Some(TriggerPeriod::Before))
            && trigger
                .events()
                .iter()
                .any(|event| matches!(event, TriggerEvent::Delete))
            && let Some(function) = trigger.function(database)
            && clears(database, function, child, foreign_key)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

impl<DB: DatabaseLike> ForeignKeyRule for UndeletableReference<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if foreign_key.on_delete(database) != ReferentialAction::NoAction {
            return Ok(());
        }
        let child = foreign_key.host_table(database);
        let parent = foreign_key.referenced_table(database)?;
        let deployment = reporter.deployment();
        let mut roles: Vec<(String, Option<&DB::Role>)> = deployment
            .app_roles()
            .chain(deployment.anonymous_roles())
            .filter_map(|name| {
                database
                    .role(name)
                    .map(|role| (format!("'{name}'"), Some(role)))
            })
            .collect();
        roles.push(("PUBLIC".to_owned(), None));
        let mut deleting = Vec::new();
        for (name, role) in roles {
            if parent.privileges(acting(role), database)?.delete {
                deleting.push((name, role));
            }
        }
        if deleting.is_empty() || cascades(database, parent, child, foreign_key)? {
            return Ok(());
        }
        let mut blocked = Vec::new();
        for (name, role) in deleting {
            if !may_clear(database, role, parent, child, foreign_key)? {
                blocked.push(name);
            }
        }
        if blocked.is_empty() {
            return Ok(());
        }
        let (child_name, parent_name) = (child.table_name(), parent.table_name());
        let blocked = blocked.join(", ");
        reporter.foreign_key(
            foreign_key,
            format!(
                "{blocked} may delete from '{parent_name}' but cannot clear the rows of '{child_name}' referencing it with NO ACTION, so one such row refuses the deletion."
            ),
            format!(
                "Declare ON DELETE CASCADE or SET NULL, grant DELETE on '{child_name}', or give {blocked} a SECURITY DEFINER function deleting the referencing rows. Write ON DELETE RESTRICT if the block is intended."
            ),
        )?;
        Ok(())
    }
}
