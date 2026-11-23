//! Submodule providing the `DefinerMaintainedColumnClientWritable` rule.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    ops::ControlFlow,
};

use sql_traits::{
    errors::LookupError,
    structs::ActingRole,
    traits::{ColumnLike, DatabaseLike, FunctionLike, TableLike},
};
use sqlparser::ast::{
    Assignment, AssignmentTarget, DoUpdate, Expr, FunctionSecurity, Ident, Insert, Merge,
    MergeAction, MergeUpdateExpr, MergeUpdateKind, ObjectName, OnConflict, OnConflictAction,
    OnInsert, Statement, TableFactor, TableObject, Update, Visitor,
};

use crate::{
    deployment::Declaration,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::{same_name, stored_column, stored_table},
        function_body_support::function_body,
        policy_support::unnested,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

/// The table an assignment list rewrites, with the alias its rows are read
/// through.
struct Target<'statement> {
    name: &'statement ObjectName,
    alias: Option<&'statement Ident>,
}

impl Target<'_> {
    /// Whether `value` reads the target row's own `column`, written bare or
    /// under the alias, or under a trailing part of the table name when the
    /// table has no alias.
    fn keeps(&self, column: &Ident, value: &Expr) -> bool {
        match unnested(value) {
            Expr::Identifier(read) => same_name(read, column),
            Expr::CompoundIdentifier(parts) => {
                parts.split_last().is_some_and(|(read, qualifier)| {
                    same_name(read, column) && self.exposed_as(qualifier)
                })
            }
            _ => false,
        }
    }

    /// Whether `qualifier` names the target relation.
    fn exposed_as(&self, qualifier: &[Ident]) -> bool {
        match self.alias {
            Some(alias) => matches!(qualifier, [written] if same_name(written, alias)),
            None => {
                !qualifier.is_empty()
                    && qualifier.len() <= self.name.0.len()
                    && self.name.0.iter().rev().zip(qualifier.iter().rev()).all(
                        |(part, written)| {
                            part.as_ident().is_some_and(|part| same_name(part, written))
                        },
                    )
            }
        }
    }
}

/// Collects columns explicitly assigned by definer statements.
struct Maintained<'database, 'path, DB: DatabaseLike> {
    database: &'database DB,
    path: Option<&'path [(Cow<'database, str>, bool)]>,
    columns: BTreeSet<(usize, String)>,
}

impl<DB: DatabaseLike> Maintained<'_, '_, DB> {
    /// Records a write to a stored column.
    fn record(&mut self, table: &ObjectName, name: &Ident) -> Result<(), LookupError> {
        let Some(table) = stored_table(self.database, table, self.path)? else {
            return Ok(());
        };
        if let Some(column) = stored_column(self.database, table, None, name)?
            && let Some(position) = self.database.table_id(table)
        {
            self.columns
                .insert((position, column.stored_column_name().into_owned()));
        }
        Ok(())
    }

    /// Records every column an assignment list sets to a value other than
    /// its own, since a self-assignment only takes a new row version.
    fn assignments(
        &mut self,
        target: &Target<'_>,
        assignments: &[Assignment],
    ) -> Result<(), LookupError> {
        for assignment in assignments {
            let (columns, values) = match (&assignment.target, unnested(&assignment.value)) {
                (AssignmentTarget::ColumnName(column), _) => (
                    std::slice::from_ref(column),
                    std::slice::from_ref(&assignment.value),
                ),
                (AssignmentTarget::Tuple(columns), Expr::Tuple(values)) => {
                    (columns.as_slice(), values.as_slice())
                }
                (AssignmentTarget::Tuple(columns), _) => (columns.as_slice(), &[][..]),
            };
            for (position, column) in columns.iter().enumerate() {
                if let Some(name) = column.0.first().and_then(|part| part.as_ident())
                    && !(column.0.len() == 1
                        && values
                            .get(position)
                            .is_some_and(|value| target.keeps(name, value)))
                {
                    self.record(target.name, name)?;
                }
            }
        }
        Ok(())
    }

    /// Reads the assignments that rewrite an existing row, from updates,
    /// upserts and merges, while the columns an insert lists only create a row.
    fn statement(&mut self, statement: &Statement) -> Result<(), LookupError> {
        match statement {
            Statement::Insert(Insert {
                table: TableObject::TableName(name),
                table_alias,
                on:
                    Some(OnInsert::OnConflict(OnConflict {
                        action: OnConflictAction::DoUpdate(DoUpdate { assignments, .. }),
                        ..
                    })),
                ..
            }) => self.assignments(
                &Target {
                    name,
                    alias: table_alias.as_ref().map(|alias| &alias.alias),
                },
                assignments,
            ),
            Statement::Update(Update {
                table, assignments, ..
            }) => match &table.relation {
                TableFactor::Table { name, alias, .. } => self.assignments(
                    &Target {
                        name,
                        alias: alias.as_ref().map(|alias| &alias.name),
                    },
                    assignments,
                ),
                _ => Ok(()),
            },
            Statement::Merge(Merge {
                table: TableFactor::Table { name, alias, .. },
                clauses,
                ..
            }) => {
                let target = Target {
                    name,
                    alias: alias.as_ref().map(|alias| &alias.name),
                };
                clauses.iter().try_for_each(|clause| match &clause.action {
                    MergeAction::Update(MergeUpdateExpr {
                        kind: MergeUpdateKind::Set(assignments),
                        ..
                    }) => self.assignments(&target, assignments),
                    _ => Ok(()),
                })
            }
            _ => Ok(()),
        }
    }
}

impl<DB: DatabaseLike> Visitor for Maintained<'_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        self.statement(statement)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Reports definer-maintained columns clients can forge with direct writes.
///
/// The rule does not run on SQLite, which has no roles or privileges, and is
/// inactive until the deployment declares a client role.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
/// let mut constrainer: GenericConstrainer<ParserDB> = DefinerMaintainedColumnClientWritable::default().into();
/// constrainer.set_deployment(Deployment::example());
/// let schema = "CREATE ROLE authenticated;
/// CREATE TABLE folders (id INT PRIMARY KEY, depth INT, label TEXT);
/// CREATE FUNCTION set_depth() RETURNS VOID LANGUAGE sql SECURITY DEFINER AS $$ UPDATE folders SET depth = 1 $$;";
/// let bad = ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} GRANT UPDATE ON folders TO authenticated;")).unwrap();
/// let good = ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} GRANT UPDATE (label) ON folders TO authenticated;")).unwrap();
/// assert!(constrainer.validate_schema(&bad).is_err());
/// assert!(constrainer.validate_schema(&good).is_ok());
/// ```
pub struct DefinerMaintainedColumnClientWritable<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DefinerMaintainedColumnClientWritable<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DefinerMaintainedColumnClientWritable<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: DefinerMaintainedColumnClientWritable<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DefinerMaintainedColumnClientWritable<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DefinerMaintainedColumnClientWritable),
            group: LintGroup::Suspicious,
            rationale: "A client with INSERT or UPDATE on a definer-maintained column can forge its value without using the maintaining function.",
            source: Some("https://www.postgresql.org/docs/17/ddl-priv.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE authenticated; CREATE TABLE folders (id INT PRIMARY KEY, label TEXT, depth INT); CREATE FUNCTION set_depth() RETURNS VOID LANGUAGE sql SECURITY DEFINER AS $$ UPDATE folders SET depth = 1 $$; GRANT INSERT, UPDATE ON folders TO authenticated;",
                good: "CREATE ROLE authenticated; CREATE TABLE folders (id INT PRIMARY KEY, label TEXT, depth INT); CREATE FUNCTION set_depth() RETURNS VOID LANGUAGE sql SECURITY DEFINER AS $$ UPDATE folders SET depth = 1 $$; GRANT INSERT (id, label), UPDATE (label) ON folders TO authenticated;",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::ClientRoles]
    }
}

impl<DB: DatabaseLike> SchemaRule for DefinerMaintainedColumnClientWritable<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        let mut maintained = BTreeMap::new();
        for function in database
            .functions()
            .filter(|function| function.security_mode() == FunctionSecurity::Definer)
        {
            let path = function.search_path(database)?;
            let mut visitor = Maintained {
                database,
                path: path.as_deref(),
                columns: BTreeSet::new(),
            };
            function_body(database, function, |node| {
                node.walk(&mut visitor).break_value().map_or(Ok(()), Err)
            })?;
            for column in visitor.columns {
                maintained.entry(column).or_insert(function);
            }
        }
        for (position, table) in database.tables().enumerate() {
            let columns: Vec<_> = table
                .columns(database)?
                .filter_map(|column| {
                    maintained.iter().find_map(|((owner, name), function)| {
                        (*owner == position && name == column.stored_column_name().as_ref())
                            .then_some((column, *function))
                    })
                })
                .collect();
            if columns.is_empty() {
                continue;
            }
            let roles = reporter
                .deployment()
                .app_roles()
                .chain(reporter.deployment().anonymous_roles())
                .filter_map(|name| database.role(name))
                .map(ActingRole::Declared)
                .chain(std::iter::once(ActingRole::Public));
            let mut writable = BTreeSet::new();
            for role in roles {
                let held = table.privileges(role, database)?;
                for (column, _) in &columns {
                    if held.insert.on_column(column) || held.update.on_column(column) {
                        writable.insert(column.column_name());
                    }
                }
            }
            for (column, function) in &columns {
                if writable.contains(column.column_name()) {
                    reporter.table(table, format!("Clients can write column '{}' on table '{}', maintained by function '{}'.", column.column_name(), table.table_name(), signature::<DB>(function, database)), "Revoke its INSERT and UPDATE privileges from client roles and grant only client-maintained columns, or allow the table for intentional mixed writers.".to_owned())?;
                }
            }
        }
        Ok(())
    }
}
