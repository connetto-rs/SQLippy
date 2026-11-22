//! Submodule providing the `UndeletableReference` rule.

use std::{borrow::Cow, collections::HashSet, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::IdentifierCase,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, TableLike, TriggerLike},
};
use sqlparser::ast::{
    AssignmentTarget, Expr, FromTable, FunctionSecurity, ObjectName, ReferentialAction, Statement,
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
        policy_support::{acting, client_roles},
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
/// table or sets a key column to `NULL`, when the role may delete a row every
/// referencing row descends from through `ON DELETE CASCADE` keys, and, when
/// the key is deferrable, when a chain of `ON DELETE CASCADE` foreign keys
/// leads from the referenced table to the referencing one. An immediate check
/// runs ahead of the cascades of a chain, and may run ahead of the cascade
/// removing a referencing row whenever the deletion of its ancestor also
/// cascades into the referenced table, such as the referenced table's own
/// row, so such an ancestor counts only when the key is deferrable. A body
/// that runs dynamic SQL or does not parse counts as clearing. `ON DELETE
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

/// Whether a chain of `ON DELETE CASCADE` foreign keys leading from `parent`
/// to `child` may clear the rows `foreign_key` holds before its check runs.
/// An immediate check runs ahead of the cascades of a chain, so they count
/// only when `foreign_key` is deferrable, which lets the role defer the check
/// to commit. A cascading key of `child` on `parent` itself is left to
/// [`may_delete_ancestor`], which asks whether it holds every row.
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
                    if table != parent {
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

/// Tables whose deletions may cascade into `table`, `table` included.
fn cascade_sources<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
) -> Result<Vec<&'db DB::Table>, LookupError> {
    let mut sources = vec![table];
    let mut pending = vec![table];
    while let Some(table) = pending.pop() {
        for cascading in table.foreign_keys(database)? {
            if cascading.on_delete(database) != ReferentialAction::Cascade {
                continue;
            }
            let source = cascading.referenced_table(database)?;
            if !sources.contains(&source) {
                sources.push(source);
                pending.push(source);
            }
        }
    }
    Ok(sources)
}

/// Whether every row of its table that is not `NULL` in `held` references a
/// row through `cascading`. Each nullable column of `cascading` must be one
/// of `held`, unless `cascading` is `MATCH FULL` and shares one, which keeps
/// the rest from being `NULL` too.
fn holds_every_row<DB: DatabaseLike>(
    database: &DB,
    cascading: &DB::ForeignKey,
    held: &[&DB::Column],
) -> Result<bool, LookupError> {
    let (mut shares, mut uncovered) = (false, false);
    for column in cascading.host_columns(database)? {
        if held.contains(&column) {
            shares = true;
        } else if column.is_nullable(database)? {
            uncovered = true;
        }
    }
    Ok(!uncovered || shares && cascading.match_full(database))
}

/// Whether `role`, `PUBLIC` for `None`, may delete the rows of `child` that
/// `foreign_key` holds by deleting a row they descend from through `ON
/// DELETE CASCADE` keys, each row on the way referencing the next through
/// its key. A deletion that also cascades into `parent` may check a row of
/// `child` before its own cascade removes it, so such an ancestor counts
/// only when `foreign_key` is deferrable.
fn may_delete_ancestor<DB: DatabaseLike>(
    database: &DB,
    role: Option<&DB::Role>,
    parent: &DB::Table,
    child: &DB::Table,
    foreign_key: &DB::ForeignKey,
) -> Result<bool, LookupError> {
    let excluded = if foreign_key.deferral(database).is_deferrable() {
        Vec::new()
    } else {
        cascade_sources(database, parent)?
    };
    let key_columns: Vec<_> = foreign_key.host_columns(database)?.collect();
    let mut reached = vec![child];
    let mut pending = vec![child];
    while let Some(table) = pending.pop() {
        let held = if table == child {
            key_columns.as_slice()
        } else {
            &[]
        };
        for cascading in table.foreign_keys(database)? {
            if cascading.on_delete(database) != ReferentialAction::Cascade
                || !holds_every_row(database, cascading, held)?
            {
                continue;
            }
            let ancestor = cascading.referenced_table(database)?;
            if reached.contains(&ancestor) || excluded.contains(&ancestor) {
                continue;
            }
            if ancestor.privileges(acting(role), database)?.delete {
                return Ok(true);
            }
            reached.push(ancestor);
            pending.push(ancestor);
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
                    let (columns, values) = match (&assignment.target, &assignment.value) {
                        (AssignmentTarget::Tuple(columns), Expr::Tuple(values)) => {
                            (columns.as_slice(), values.as_slice())
                        }
                        (AssignmentTarget::Tuple(columns), value) => {
                            (columns.as_slice(), std::slice::from_ref(value))
                        }
                        (AssignmentTarget::ColumnName(column), value) => {
                            (std::slice::from_ref(column), std::slice::from_ref(value))
                        }
                    };
                    for (column, value) in columns.iter().zip(values) {
                        if is_null_literal(value) && self.names_key_column(column)? {
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
    // A data-modifying statement may stand only at the top level, so a
    // `RETURN` expression body never deletes or updates rows.
    if function.body_expression(database)?.is_some() {
        return Ok(false);
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
        // `body_clears` already counted a body it cannot read as clearing.
        pending.extend(function.referenced_functions(database)?);
    }
    Ok(false)
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
    if may_delete_ancestor(database, role, parent, child, foreign_key)? {
        return Ok(true);
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
        let mut deleting = Vec::new();
        for (name, role) in client_roles(database, reporter.deployment()) {
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
