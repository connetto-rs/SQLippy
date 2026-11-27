//! Submodule providing the `ForeignKeyExistenceOracle` rule.

use std::borrow::Cow;

use sql_traits::{
    errors::LookupError,
    structs::{ConstraintDeferral, RowStatement, RowVersion},
    traits::{
        ColumnLike, DataTypeLike, DatabaseLike, ForeignKeyLike, IndexLike, TableIndexLike,
        TableLike, TriggerLike,
    },
};
use sqlparser::ast::{
    BinaryOperator, ConflictTarget, Expr, InTarget, ObjectNamePart, OnConflict, OnConflictAction,
    OnInsert, Query, SetExpr, Statement, TableObject, TriggerEvent, TriggerPeriod, UnaryOperator,
    Value,
};
use sqlparser_plpgsql::embedded::{Block, Loop, LoopControl, Node, NodeKind, Target};

use crate::{
    deployment::Deployment,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::{checked_literals, same_identity, stored_name},
        cte_support::stored_table,
        existence_oracle_support::{
            Confinement, hides_rows, principal_columns, row_security, writes_free_key,
            writes_whole_key,
        },
        expression_site_support::is_null_literal,
        function_reach_support::Reach,
        key_check_guard_support::{KeyCheck, key_check},
        literal_support::{literal, string_value},
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        policy_support::{acting, client_roles},
        trigger_support::{
            WritesTable, Written, evaluated, fires_for_clients, fires_on_insert, names_new_field,
            names_record, new_field_write, row_trigger, shadows_new, stored, stored_parts,
        },
        type_support::underlying_type,
    },
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports a foreign key into a row-level-security
/// table whose referencing columns a client role may write while the
/// referenced table hides rows from it.
///
/// PostgreSQL checks a foreign key past row-level security, so the role learns
/// whether a key it cannot read exists from whether its write succeeds or fails
/// with `23503`. The roles are the declared app and anonymous roles and
/// `PUBLIC`. A role writes the key when it may insert every referencing column,
/// or update one while every other is updatable or `NOT NULL`, and the
/// referencing table's policies let the write through. The referenced table
/// hides rows when its `SELECT` policies for the role do not admit every row.
/// A write is excused when the check the referencing table applies to the
/// written row confines every key column, each in a restrictive policy or in
/// every permissive one, with `=`, `= ANY` or `IN` to a subquery reading the
/// referenced table, or with an `EXISTS` over the referenced table equating
/// its column with the key column. Such a subquery runs under the role's own
/// policies and fails alike for a hidden and a missing key. Confining the key
/// columns that the key maps onto a unique key of the referenced table is
/// enough when one subquery draws them all from the same row of that table,
/// which is then the only row the key can match. A check that forces a key
/// column `NULL` also confines the key, since PostgreSQL then looks up no
/// row, whether it tests the column `IS NULL` or the referencing table's
/// enforced and validated checks force it, as `kind IN ('folder', 'project')`
/// does under `CHECK ((kind = 'owned') = (created_by_id IS NOT NULL))` with
/// `kind` `NOT NULL`. A write is also excused when the check makes every row
/// the key can match readable, which holds when every restrictive and at
/// least one permissive `SELECT` policy of the referenced table tests the
/// columns the
/// key maps onto as the check tests their key columns, or tests one against a
/// set the check confines its key column within, as written, as the body of
/// a helper taking no argument selects it, as an arm of a helper's body
/// selects it, one the body joins by `UNION` or one seeding the `WITH
/// RECURSIVE` walk the body returns, read with the literals the call passes
/// for the helper's parameters, declared with
/// [`Deployment::with_set_within`](crate::deployment::Deployment::with_set_within),
/// or read off a ladder of the schema, where a helper called with a higher
/// label of an enum parameter returns only rows it returns for a lower one,
/// as the rule `exposed_definer_over_protected_table` reads it. A body
/// selecting the one column of a call returning a set of one column, through
/// an alias naming that column, as `SELECT g.id FROM f() g (id)`, selects
/// the call.
/// A check may draw the key from the rows of a set-returning `LANGUAGE sql`
/// helper, as `IN (SELECT helper())`, `= ANY (ARRAY(SELECT helper()))` or
/// `IN (SELECT ... FROM helper())`. Every arm of the helper's body must then
/// draw the key column from a set the referenced policies admit, or draw the
/// key from one row of the referenced table its filters make readable, or
/// draw the key column from a row of a table a referenced policy reads the
/// key from, which the role reads and which meets that read's filters.
/// Foreign keys carry the filters of the row an arm draws the key from onto
/// the matched row along a chain linking the two. Each link is an enforced,
/// validated and not deferrable foreign key that checks the row holding its
/// host columns, pairing columns compared by identity, or two rows of one
/// table holding the same values in a unique key, which are one row. A
/// helper called in the body is read as its own arms. Inside a helper that
/// runs as its owner, a filter counts only when it reads no table and calls
/// only definers and built-ins that read neither the acting role nor its
/// privileges, and a helper setting a parameter other than its search path
/// counts for nothing. An arm of the check that leaves a key column `NULL`,
/// by itself or under the referencing table's checks, needs neither, since
/// PostgreSQL checks no key holding a
/// `NULL`. A write is also excused when the referencing table's `BEFORE` row
/// triggers, on every path that keeps the row, insert the referenced row from
/// `NEW` with `ON CONFLICT DO NOTHING` and leave the key unchanged afterwards,
/// while every unique index of the
/// referenced table takes that conflict and spans the referenced columns.
/// The key then finds its row whether or not it existed. A write is also
/// excused when the referencing table's `BEFORE` row triggers hold every
/// row whose key PostgreSQL checks to a condition that makes every row the
/// key can match readable, as a check would. A trigger holds the row to a
/// condition when, running with its caller's rights, it raises or returns
/// `NULL` unless `NEW`'s key columns meet it, and its `WHEN` skips only rows
/// holding a `NULL` key column or, on `UPDATE`, an unchanged key, neither of
/// which PostgreSQL checks. An `ASSERT` holds nothing, since a session may
/// turn assertions off.
/// A write is also excused when its check pins a key column to a principal
/// accessor the deployment declares, as `namespace_id = (SELECT
/// authz.caller_namespace())` in a top-level `AND` term of a restrictive
/// policy or of every permissive one, while the key compares that column by
/// identity with a referenced column that every client role holding `INSERT`
/// or `UPDATE` on it writes only so pinned. Only rows of the writer's own
/// principal then hold the value the key looks up.
///
/// An insert is also excused when every referenced row the key can match
/// already holds a referencing row with the same values of a unique key of
/// the referencing table, since PostgreSQL then refuses the insert with
/// `23505` before it checks the foreign key, and the unique key is the one
/// telling the role whether that row exists, as
/// [`UniqueKeyExistenceOracle`](crate::prelude::UniqueKeyExistenceOracle)
/// reports. That holds when a `NOT DEFERRABLE` key of the referenced table
/// references unique columns among the foreign key's referencing columns,
/// from columns whose value, generated or plain, is the matched row's key
/// for every value the referencing table lets its key columns take, and the
/// role may neither delete a referencing row nor update a column of that
/// unique key, either of which would let one statement move the covering
/// row aside before inserting. A function or trigger that deletes a
/// covering row partway through the inserting statement is not modelled.
/// The rule does not run on SQLite, which has no row-level security.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = ForeignKeyExistenceOracle::default().into();
/// constrainer.set_deployment(Deployment::default().with_app_role("app"));
/// let schema = "CREATE ROLE app;
///     CREATE TABLE secrets (id INT PRIMARY KEY);
///     ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
///     CREATE TABLE notes (id INT PRIMARY KEY, secret_id INT REFERENCES secrets (id));
///     GRANT INSERT ON notes TO app;";
/// let probing = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&probing).is_err());
/// let confined = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
///      CREATE POLICY notes_insert ON notes FOR INSERT TO app
///        WITH CHECK (secret_id IN (SELECT id FROM secrets));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&confined).is_ok());
/// ```
pub struct ForeignKeyExistenceOracle<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ForeignKeyExistenceOracle<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ForeignKeyExistenceOracle<DB>> for GenericConstrainer<DB> {
    fn from(rule: ForeignKeyExistenceOracle<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ForeignKeyExistenceOracle<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(ForeignKeyExistenceOracle),
            group: LintGroup::Pedantic,
            rationale: "Referential integrity checks bypass row-level security, so a role that may write a foreign key learns whether a row it cannot read exists from whether its write fails.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE authenticated;\n\
CREATE TABLE secrets (id INT PRIMARY KEY);\n\
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;\n\
CREATE TABLE notes (id INT PRIMARY KEY, secret_id INT REFERENCES secrets (id));\n\
GRANT INSERT ON notes TO authenticated;",
                good: "CREATE ROLE authenticated;\n\
CREATE TABLE secrets (id INT PRIMARY KEY);\n\
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;\n\
CREATE TABLE notes (id INT PRIMARY KEY, secret_id INT REFERENCES secrets (id));\n\
GRANT INSERT ON notes TO authenticated;\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY notes_insert ON notes FOR INSERT TO authenticated WITH CHECK (secret_id IN (SELECT id FROM secrets));",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

/// A unique index of the referenced table, as an `ON CONFLICT` clause meets
/// it.
struct UniqueKey {
    /// The constraint it backs, as PostgreSQL stores its name.
    constraint: Option<String>,
    columns: Vec<String>,
    /// Whether it keys plain columns under no predicate, so a target naming
    /// its columns infers it.
    inferable: bool,
    /// Whether a conflict on it means a row holding the referenced values
    /// exists.
    spans_key: bool,
}

impl UniqueKey {
    /// Reads `index` against the referenced columns of `pairs`.
    fn new<DB: DatabaseLike, I: TableIndexLike<DB = DB>>(
        database: &DB,
        index: &I,
        pairs: &[(Cow<'_, str>, Cow<'_, str>)],
    ) -> Result<Self, LookupError> {
        let columns: Vec<String> = index
            .columns(database)?
            .map(|column| column.stored_column_name().into_owned())
            .collect();
        let simple = index.is_simple(database)?;
        Ok(Self {
            constraint: index.constraint_name(database)?.map(Cow::into_owned),
            inferable: simple && index.predicate().is_none(),
            spans_key: simple
                && pairs
                    .iter()
                    .all(|(_, referenced)| columns.iter().any(|column| column == referenced)),
            columns,
        })
    }
}

/// Decides whether the referencing table's `BEFORE` row triggers insert the
/// row a written key refers to before PostgreSQL checks the key, so the check
/// passes whether or not the row existed.
struct TriggerWrite<'a, DB: DatabaseLike> {
    database: &'a DB,
    parent: &'a DB::Table,
    /// Each referencing column with the referenced column it names.
    pairs: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    /// The referenced table's columns in order, which an `INSERT` naming no
    /// columns fills.
    parent_columns: Vec<Cow<'a, str>>,
    unique_keys: Vec<UniqueKey>,
}

impl<'a, DB: DatabaseLike> TriggerWrite<'a, DB> {
    /// `None` when no trigger can write the referenced row: a referencing
    /// column is generated, which `NEW` holds no value for before the row is
    /// stored, or a `BEFORE INSERT` row trigger of the referenced table may
    /// change or skip the written row.
    fn new(
        database: &'a DB,
        foreign_key: &'a DB::ForeignKey,
        parent: &'a DB::Table,
    ) -> Result<Option<Self>, LookupError> {
        let mut pairs = Vec::new();
        for (host, referenced) in foreign_key
            .host_columns(database)?
            .zip(foreign_key.referenced_columns(database)?)
        {
            if host.generation_expression().is_some() {
                return Ok(None);
            }
            pairs.push((host.stored_column_name(), referenced.stored_column_name()));
        }
        for trigger in parent.triggers(database)? {
            if row_trigger(trigger, TriggerPeriod::Before)
                && fires_on_insert(trigger)
                && fires_for_clients(database, trigger)?
            {
                return Ok(None);
            }
        }
        let mut unique_keys = Vec::new();
        for index in parent.unique_indices(database)? {
            unique_keys.push(UniqueKey::new(database, index, &pairs)?);
        }
        for index in parent.indices(database)? {
            if index.is_unique() {
                unique_keys.push(UniqueKey::new(database, index, &pairs)?);
            }
        }
        Ok(Some(Self {
            database,
            parent,
            parent_columns: parent
                .columns(database)?
                .map(ColumnLike::stored_column_name)
                .collect(),
            pairs,
            unique_keys,
        }))
    }

    /// Whether `ON CONFLICT` with `target` takes every conflict the insert
    /// can meet, each on an index whose conflict leaves a row holding the key.
    /// A target names the indexes that take its conflicts, and any other
    /// raises `23505`.
    fn absorbs(&self, target: Option<&ConflictTarget>) -> bool {
        self.unique_keys.iter().all(|key| {
            key.spans_key
                && match target {
                    None => true,
                    Some(ConflictTarget::Columns { columns, .. }) => {
                        key.inferable
                            && columns.iter().all(|named| {
                                key.columns.iter().any(|column| *column == stored(named))
                            })
                            && key
                                .columns
                                .iter()
                                .all(|column| columns.iter().any(|named| stored(named) == *column))
                    }
                    Some(ConflictTarget::OnConstraint(name)) => name
                        .0
                        .last()
                        .and_then(ObjectNamePart::as_ident)
                        .is_some_and(|ident| key.constraint.as_deref() == Some(&*stored(ident))),
                }
        })
    }

    /// Whether `statement` inserts a row into the referenced table holding
    /// `NEW`'s key, with every conflict it can meet taken by `DO NOTHING`.
    fn writes_key(&self, statement: &Statement) -> bool {
        let Statement::Insert(insert) = statement else {
            return false;
        };
        let (
            TableObject::TableName(name),
            Some(OnInsert::OnConflict(OnConflict {
                conflict_target,
                action: OnConflictAction::DoNothing,
            })),
            Some(source),
        ) = (&insert.table, &insert.on, &insert.source)
        else {
            return false;
        };
        let SetExpr::Values(values) = source.body.as_ref() else {
            return false;
        };
        if source.with.is_some()
            || source.order_by.is_some()
            || source.limit_clause.is_some()
            || source.fetch.is_some()
            || !matches!(stored_table(self.database, name, None), Ok(Some(table)) if table == self.parent)
            || !self.absorbs(conflict_target.as_ref())
        {
            return false;
        }
        let named: Vec<Cow<'_, str>>;
        let columns = if insert.columns.is_empty() {
            &self.parent_columns
        } else {
            named = insert
                .columns
                .iter()
                .map(|column| stored_parts(column).pop().unwrap_or_default())
                .collect();
            &named
        };
        values.rows.iter().any(|row| {
            self.pairs.iter().all(|(host, referenced)| {
                columns
                    .iter()
                    .position(|column| column == referenced)
                    .and_then(|at| row.content.get(at))
                    .is_some_and(|value| names_new_field(value, host))
            })
        })
    }

    /// Whether `trigger` fires on the command, `Some(true)` when it fires on
    /// every row the command writes a key column of.
    fn fires(&self, trigger: &DB::Trigger, update: bool) -> Option<bool> {
        trigger
            .events()
            .iter()
            .filter_map(|event| match (event, update) {
                (TriggerEvent::Insert, false) => Some(true),
                (TriggerEvent::Update(columns), true) => Some(
                    columns.is_empty()
                        || self
                            .pairs
                            .iter()
                            .all(|(host, _)| columns.iter().any(|column| stored(column) == *host)),
                ),
                _ => None,
            })
            .max()
            .map(|every_row| every_row && trigger.condition().is_none())
    }

    /// Whether every row a client writes into `child`, by an `UPDATE` when
    /// `update` is set and an `INSERT` otherwise, reaches the key check with
    /// its referenced row present.
    fn settles(&self, child: &DB::Table, update: bool) -> Result<bool, LookupError> {
        let mut triggers = Vec::new();
        for trigger in child.triggers(self.database)? {
            if row_trigger(trigger, TriggerPeriod::Before)
                && fires_for_clients(self.database, trigger)?
                && let Some(always) = self.fires(trigger, update)
            {
                triggers.push((trigger, always));
            }
        }
        // PostgreSQL fires the triggers of one event in the order of their
        // names.
        triggers.sort_by(|(left, _), (right, _)| left.name().cmp(right.name()));
        let mut reach = Reach::new(self.database, WritesTable::new(self.database, self.parent));
        let mut present = false;
        for (trigger, always) in triggers {
            let after = trigger
                .function(self.database)
                .and_then(plpgsql_block)
                .is_some_and(|block| {
                    let mut flow = KeyFlow {
                        writer: self,
                        reach: &mut reach,
                        returned: None,
                        followed: true,
                    };
                    walk_block(&mut flow, &block, Present(present));
                    flow.followed && flow.returned.unwrap_or(true)
                });
            present = after && (always || present);
        }
        Ok(present)
    }
}

/// Whether a path has the referenced row of `NEW`'s key present.
#[derive(Clone, Copy)]
struct Present(bool);

impl FlowState for Present {
    fn join(&mut self, other: Self) {
        self.0 &= other.0;
    }
}

/// Follows a trigger function's paths to the rows it returns, tracking
/// whether the referenced row of `NEW`'s key is present on each.
struct KeyFlow<'r, 'a, DB: DatabaseLike> {
    writer: &'r TriggerWrite<'a, DB>,
    reach: &'r mut Reach<'a, DB, WritesTable<'a, DB>>,
    /// Whether every path returning `NEW` had the row present, `None` until
    /// one returns it.
    returned: Option<bool>,
    /// Whether `NEW` names the trigger row throughout the body.
    followed: bool,
}

impl<DB: DatabaseLike> KeyFlow<'_, '_, DB> {
    /// Whether writing `targets` may change a referencing column of `NEW`.
    fn rewrites<'t>(&self, targets: impl IntoIterator<Item = &'t Target>) -> bool {
        targets.into_iter().any(|target| {
            self.writer
                .pairs
                .iter()
                .any(|(host, _)| !matches!(new_field_write(target, host), Written::Elsewhere))
        })
    }
}

impl<DB: DatabaseLike> FlowVisitor for KeyFlow<'_, '_, DB> {
    type State = Present;

    fn enter(&mut self, block: &Block, _state: &mut Present) {
        self.followed &= !shadows_new(block);
    }

    fn repeat(&mut self, repeated: &Loop, state: &mut Present) {
        match &repeated.control {
            LoopControl::Range { variable, .. } | LoopControl::Cursor { variable, .. } => {
                self.followed &= variable != "new";
            }
            LoopControl::Query { targets, .. }
            | LoopControl::Dynamic { targets, .. }
            | LoopControl::Array { targets, .. } => {
                state.0 &= !self.rewrites(targets);
            }
            LoopControl::Unconditional | LoopControl::While(_) => {}
        }
    }

    fn query(&mut self, query: &Query, state: &mut Present) {
        state.0 &= self.reach.occurrences(query).is_empty();
    }

    fn statement(&mut self, statement: &Statement, state: &mut Present) {
        if self.writer.writes_key(statement) {
            state.0 = true;
        } else {
            state.0 &= self.reach.occurrences(statement).is_empty();
        }
    }

    fn step(&mut self, node: &Node, state: &mut Present) {
        let rewritten = match &node.kind {
            NodeKind::Assignment(assignment) => self.rewrites([&assignment.target]),
            NodeKind::Statement { into, .. } => into
                .as_ref()
                .is_some_and(|into| self.rewrites(&into.targets)),
            NodeKind::Dynamic { .. } => true,
            NodeKind::Fetch(fetch) => self.rewrites(&fetch.targets),
            NodeKind::Diagnostics(diagnostics) => {
                self.rewrites(diagnostics.items.iter().map(|item| &item.target))
            }
            NodeKind::Return { value } => {
                let value = value.as_deref().and_then(evaluated);
                if !value.is_some_and(is_null_literal) {
                    let kept = state.0 && value.is_some_and(|value| names_record(value, "new"));
                    self.returned = Some(self.returned.unwrap_or(true) && kept);
                }
                false
            }
            _ => false,
        };
        state.0 &= !rewritten;
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for ForeignKeyExistenceOracle<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if !foreign_key.is_enforced(database) {
            return Ok(());
        }
        let parent = foreign_key.referenced_table(database)?;
        if !parent.has_row_level_security(database)? {
            return Ok(());
        }
        let child = foreign_key.host_table(database);
        let key_columns: Vec<&DB::Column> = foreign_key.host_columns(database)?.collect();
        let confinement = confinement(
            database,
            reporter.deployment(),
            foreign_key,
            parent,
            &key_columns,
        )?;
        let covering = covering_columns(database, foreign_key)?;
        let (insert_settled, update_settled) =
            match TriggerWrite::new(database, foreign_key, parent)? {
                Some(trigger_write) => (
                    trigger_write.settles(child, false)?,
                    trigger_write.settles(child, true)?,
                ),
                None => (false, false),
            };
        let insert_check = key_check(database, foreign_key, false)?;
        let update_check = key_check(database, foreign_key, true)?;
        let mut probes = Vec::new();
        for (name, role) in client_roles(database, reporter.deployment()) {
            let Some(read) = row_security(database, parent, RowStatement::Select, role)? else {
                continue;
            };
            if !hides_rows(database, parent, role, &read)? {
                continue;
            }
            let held = child.privileges(acting(role), database)?;
            // A covered key answers an insert with its unique key, unless the
            // role can move a covering row aside in the same statement.
            let covered = covering.as_ref().is_some_and(|covering| {
                !held.delete && !covering.iter().any(|column| held.update.on_column(column))
            });
            let mut commands = Vec::new();
            if !insert_settled
                && !covered
                && let KeyCheck::Meeting(guards) = &insert_check
                && writes_whole_key(database, key_columns.iter().copied(), &held.insert, false)?
                && writes_free_key(
                    &confinement,
                    child,
                    RowStatement::Insert { returning: false },
                    RowVersion::Inserted,
                    role,
                    Some(&read),
                    guards,
                )?
            {
                commands.push("INSERT");
            }
            if !update_settled
                && let KeyCheck::Meeting(guards) = &update_check
                && writes_whole_key(database, key_columns.iter().copied(), &held.update, true)?
                && writes_free_key(
                    &confinement,
                    child,
                    RowStatement::Update { reads: false },
                    RowVersion::Updated,
                    role,
                    Some(&read),
                    guards,
                )?
            {
                commands.push("UPDATE");
            }
            if !commands.is_empty() {
                probes.push(format!("{name} through {}", commands.join(" and ")));
            }
        }
        if probes.is_empty() {
            return Ok(());
        }
        let child_name = child.table_name();
        let parent_name = parent.table_name();
        reporter.foreign_key(
            foreign_key,
            format!(
                "A foreign key of '{child_name}' into '{parent_name}' tells {} whether a row of '{parent_name}' it cannot read exists, since the key is checked past row-level security.",
                probes.join(", ")
            ),
            format!("Keep the key server-written, confine it in the WITH CHECK of '{child_name}' to rows the writer may point at, such as `IN (SELECT ... FROM {parent_name})` or the set the SELECT policies of '{parent_name}' test the column the key maps onto against, pin a key column there to a declared principal accessor, or let the writer read every row of '{parent_name}'."),
        )?;
        Ok(())
    }
}

/// The confinement of the key columns of `foreign_key` into `parent`, also
/// settling a key pinned to a principal accessor in a column the key
/// compares by identity with a column of `parent` holding each value only in
/// rows of one principal, as [`principal_columns`] decides.
fn confinement<'db, DB: DatabaseLike>(
    database: &'db DB,
    deployment: &'db Deployment,
    foreign_key: &'db DB::ForeignKey,
    parent: &'db DB::Table,
    key_columns: &[&'db DB::Column],
) -> Result<Confinement<'db, DB>, LookupError> {
    let referenced_columns: Vec<&DB::Column> = foreign_key.referenced_columns(database)?.collect();
    let pinned = principal_columns(database, deployment, parent, &referenced_columns)?;
    let mut principal = Vec::new();
    for (&column, &referenced) in key_columns.iter().zip(&referenced_columns) {
        if pinned.contains(&referenced.stored_column_name())
            && same_identity(database, column, referenced)?
        {
            principal.push(column.stored_column_name());
        }
    }
    Ok(Confinement::new(
        database,
        deployment,
        foreign_key.host_table(database),
        key_columns
            .iter()
            .copied()
            .map(ColumnLike::stored_column_name)
            .collect(),
        parent,
        referenced_columns
            .into_iter()
            .map(ColumnLike::stored_column_name)
            .collect(),
        true,
    )?
    .with_principal_columns(principal))
}

/// The columns of a unique key of the referencing table that every row of
/// the referenced table `foreign_key` can match already holds in some
/// referencing row, through a `NOT DEFERRABLE` key of the referenced table
/// into those columns, or `None` when no such key covers every matchable
/// row. The columns must be among the foreign key's referencing columns, and
/// for every value the referencing table lets those take, the reverse key's
/// columns must hold the matched row's values of them.
fn covering_columns<'db, DB: DatabaseLike>(
    database: &'db DB,
    foreign_key: &'db DB::ForeignKey,
) -> Result<Option<Vec<&'db DB::Column>>, LookupError> {
    let child = foreign_key.host_table(database);
    let parent = foreign_key.referenced_table(database)?;
    let key: Vec<&DB::Column> = foreign_key.host_columns(database)?.collect();
    let referenced: Vec<Cow<'_, str>> = foreign_key
        .referenced_columns(database)?
        .map(ColumnLike::stored_column_name)
        .collect();
    // The values each textual key column can hold, when the referencing table
    // lists them. Other types compare by value, which literals as written do
    // not settle.
    let mut domains: Vec<Option<Vec<String>>> = Vec::with_capacity(key.len());
    for column in &key {
        domains.push(
            if !underlying_type(database, column.data_type(database)).is_textual(database) {
                None
            } else if let Some(generated) = column.generation_expression() {
                match evaluate(generated, &[]) {
                    Some(Known::Literal(value)) => Some(vec![value]),
                    _ => None,
                }
            } else {
                checked_literals(database, column)?
                    .map(|values| values.into_iter().map(str::to_owned).collect())
            },
        );
    }
    for reverse in parent.foreign_keys(database)? {
        if reverse.referenced_table(database)? != child
            || reverse.deferral(database) != ConstraintDeferral::NotDeferrable
            || !reverse.is_validated(database)?
        {
            continue;
        }
        let covered: Vec<&DB::Column> = reverse.referenced_columns(database)?.collect();
        let Some(targets) = covered
            .iter()
            .map(|column| key.iter().position(|key| key == column))
            .collect::<Option<Vec<usize>>>()
        else {
            continue;
        };
        let holders: Vec<&DB::Column> = reverse.host_columns(database)?.collect();
        if every_assignment(&domains, &mut Vec::new(), &mut |values| {
            let known: Vec<(&str, Known)> = referenced
                .iter()
                .zip(values)
                .enumerate()
                .map(|(position, (column, value))| {
                    (
                        column.as_ref(),
                        value.map_or(Known::Key(position), |value| {
                            Known::Literal(value.to_owned())
                        }),
                    )
                })
                .collect();
            holders.iter().zip(&targets).all(|(holder, target)| {
                let held = match holder.generation_expression() {
                    Some(generated) => evaluate(generated, &known),
                    None => lookup(&holder.stored_column_name(), &known),
                };
                held == Some(Known::Key(*target))
            })
        }) {
            return Ok(Some(covered));
        }
    }
    Ok(None)
}

/// Whether `check` holds for every assignment of a value from each listed
/// domain, a key column whose domain is not listed taking `None`.
fn every_assignment<'v>(
    domains: &'v [Option<Vec<String>>],
    chosen: &mut Vec<Option<&'v str>>,
    check: &mut impl FnMut(&[Option<&'v str>]) -> bool,
) -> bool {
    let Some(domain) = domains.get(chosen.len()) else {
        return check(chosen);
    };
    match domain {
        None => {
            chosen.push(None);
            let holds = every_assignment(domains, chosen, check);
            chosen.pop();
            holds
        }
        Some(values) => values.iter().all(|value| {
            chosen.push(Some(value));
            let holds = every_assignment(domains, chosen, check);
            chosen.pop();
            holds
        }),
    }
}

/// A value a column of the matched row is known to hold.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Known {
    /// A string literal, as written.
    Literal(String),
    /// The value of the key column at this position.
    Key(usize),
    /// `NULL`.
    Null,
}

/// The value `known` gives the column whose stored name is `column`.
fn lookup(column: &str, known: &[(&str, Known)]) -> Option<Known> {
    known
        .iter()
        .find(|(name, _)| *name == column)
        .map(|(_, value)| value.clone())
}

/// The value `expression` yields over a row whose columns hold `known`,
/// when literals, columns and `CASE` settle it.
fn evaluate(expression: &Expr, known: &[(&str, Known)]) -> Option<Known> {
    if let Some(value) = literal(expression) {
        return match value {
            Value::Null => Some(Known::Null),
            value => string_value(value).map(|text| Known::Literal(text.to_owned())),
        };
    }
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => evaluate(inner, known),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            lookup(&stored_name(expression)?, known)
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            for when in conditions {
                let holds = match operand {
                    Some(operand) => equal(
                        &evaluate(operand, known)?,
                        &evaluate(&when.condition, known)?,
                    )?,
                    None => truth(&when.condition, known)?,
                };
                if holds {
                    return evaluate(&when.result, known);
                }
            }
            else_result
                .as_ref()
                .map_or(Some(Known::Null), |result| evaluate(result, known))
        }
        _ => None,
    }
}

/// Whether `condition` holds over a row whose columns hold `known`, when
/// equalities between settled values decide it.
fn truth(condition: &Expr, known: &[(&str, Known)]) -> Option<bool> {
    match condition {
        Expr::Nested(inner) => truth(inner, known),
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => truth(expr, known).map(|holds| !holds),
        Expr::BinaryOp { left, op, right } => match op {
            BinaryOperator::And => Some(truth(left, known)? && truth(right, known)?),
            BinaryOperator::Or => Some(truth(left, known)? || truth(right, known)?),
            BinaryOperator::Eq => equal(&evaluate(left, known)?, &evaluate(right, known)?),
            BinaryOperator::NotEq => {
                equal(&evaluate(left, known)?, &evaluate(right, known)?).map(|equal| !equal)
            }
            _ => None,
        },
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated,
            ..
        } => {
            let value = evaluate(expr, known)?;
            let mut found = false;
            for item in list {
                found |= equal(&value, &evaluate(item, known)?)?;
            }
            Some(found != *negated)
        }
        _ => None,
    }
}

/// Whether two settled values are equal, when their values decide it.
fn equal(left: &Known, right: &Known) -> Option<bool> {
    match (left, right) {
        (Known::Literal(left), Known::Literal(right)) => Some(left == right),
        (Known::Key(left), Known::Key(right)) if left == right => Some(true),
        _ => None,
    }
}
