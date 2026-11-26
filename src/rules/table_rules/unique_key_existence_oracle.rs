//! Submodule providing the `UniqueKeyExistenceOracle` rule.

use sql_traits::{
    errors::LookupError,
    structs::{RowStatement, RowVersion},
    traits::{ColumnLike, DatabaseLike, IndexLike, TableIndexLike, TableLike},
};

use crate::{
    deployment::Deployment,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        consumed_key_support::consumptions,
        existence_oracle_support::{
            Confinement, hides_rows, principal_columns, row_security, writes_free_key,
            writes_whole_key,
        },
        policy_support::{acting, client_roles},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

rule_definition!(
    /// Struct defining a rule that reports a unique key whose columns a client
    /// role may write while the table hides rows from it.
    ///
    /// PostgreSQL checks a unique key past row-level security and column
    /// privileges, so the role learns whether a row it cannot read holds a
    /// key from whether its write fails with `23505`. The roles are the
    /// declared app and anonymous roles and `PUBLIC`. The table hides rows
    /// when the role may not read every key column, or when its `SELECT`
    /// policies for the role do not admit every row. A role writes the key
    /// when it may insert every key column, or update one while every other
    /// is updatable or `NOT NULL`, and the table's policies let the write
    /// through. A write is excused when its check confines the key to rows
    /// the role reads, as
    /// [`ForeignKeyExistenceOracle`](crate::prelude::ForeignKeyExistenceOracle)
    /// excuses a foreign key into the same table. A write is also excused
    /// when its check pins a key column to a principal accessor the
    /// deployment declares, as `namespace_id = (SELECT
    /// authz.caller_namespace())` in a top-level `AND` term of a restrictive
    /// policy or of every permissive one, and every client role holding
    /// `INSERT` or `UPDATE` on that column pins it so in each check of that
    /// write. Only rows of the writer's own principal then hold the key it
    /// writes. A write is also excused
    /// when its check draws a key column from a set-returning `LANGUAGE sql`
    /// helper, as `IN (SELECT helper())`, `= ANY (ARRAY(SELECT helper()))` or
    /// `IN (SELECT ... FROM helper())`, and every arm of the helper's body
    /// keeps only values no row of the table holds. An arm keeps them when
    /// it yields the column from a row under `NOT EXISTS (SELECT ... FROM
    /// table t WHERE t.key = row.column)` or `row.column NOT IN (SELECT key
    /// FROM table)`, testing nothing else of the table but `key IS NOT
    /// NULL`, with rights that read every row of the table. It also keeps
    /// them when it yields the column from a row of another table under a
    /// filter that an `AFTER INSERT` row trigger of the table makes false for
    /// the row each stored key names. The trigger's PL/pgSQL function must run
    /// `UPDATE other SET ... WHERE column = NEW.key` on every path that
    /// returns with a non-`NULL` key, write that table nowhere else, set each
    /// tested column from literals and `NEW`'s fields, and read every row of
    /// that table, and the trigger's `WHEN` may only skip a `NULL` key. A
    /// further `AND` condition of that `WHERE` may read only columns the
    /// trigger sets, and the filter must imply it. The function may run
    /// `DELETE FROM other WHERE column = NEW.key` in place of the `UPDATE`,
    /// or `PERFORM` a call to a `LANGUAGE sql` function whose body is one
    /// such statement, read with the call's arguments in place of its
    /// parameters and under the called function's rights when it is a
    /// definer. A strict called function may only take the key as its
    /// arguments, since it skips its body on a `NULL` one. An `AFTER INSERT`
    /// statement trigger declaring `REFERENCING NEW TABLE AS new_rows` may
    /// run the `UPDATE` or `DELETE` with `WHERE column IN (SELECT key FROM
    /// new_rows)` and literal values, on every path and under no `WHEN`. A
    /// stored key then fails the check before PostgreSQL looks it up, as
    /// long as no client role can bring the named row back. No client role
    /// may update a column the trigger sets or the column naming the row,
    /// nor update the key unless the trigger also fires on that update, and
    /// no `BEFORE UPDATE` row trigger of the other table may change the
    /// write, nor a `BEFORE DELETE` one the deletion. After a deletion, no
    /// client role may insert into the other table. Where client roles can
    /// insert into the other table, the naming column must be unique, since
    /// a second row could name the key again. Where they can also delete or
    /// truncate its rows, one statement could remove a named row and insert
    /// it again in its original state, so the excuse then also needs a
    /// foreign key from the key column onto the naming column with `ON
    /// DELETE RESTRICT`, `CASCADE` or `SET NULL`, since `NO ACTION` accepts
    /// the re-created row at the end of the statement. A function a client
    /// calls that writes the other table is not followed. A unique key over
    /// an expression is not checked. The rule does not run on SQLite.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> = UniqueKeyExistenceOracle::default().into();
    /// constrainer.set_deployment(Deployment::default().with_app_role("app"));
    /// let probing = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE ROLE app;
    ///      CREATE TABLE events (id INT PRIMARY KEY, body TEXT);
    ///      GRANT INSERT ON events TO app;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&probing).is_err());
    /// let generated = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE ROLE app;
    ///      CREATE TABLE events (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, body TEXT);
    ///      GRANT INSERT (body) ON events TO app;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&generated).is_ok());
    /// ```
    UniqueKeyExistenceOracle,
    register_table_rule,
    LintGroup::Pedantic,
    "Unique keys are checked past row-level security and column privileges, so a role that may write a key learns whether a row it cannot read holds it from whether its write fails.",
    Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
    RuleExample {
        bad: "CREATE ROLE authenticated;\n\
CREATE TABLE events (id INT PRIMARY KEY, body TEXT);\n\
GRANT INSERT ON events TO authenticated;",
        good: "CREATE ROLE authenticated;\n\
CREATE TABLE events (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, body TEXT);\n\
GRANT INSERT (body) ON events TO authenticated;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> TableRule for UniqueKeyExistenceOracle<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for key in table.unique_indices(database)? {
            if key.is_simple(database)?
                && let Some(message) = probes(database, reporter.deployment(), table, key)?
            {
                reporter.unique_index(key, message, resolution(table.table_name()))?;
            }
        }
        for key in table.indices(database)?.filter(|index| index.is_unique()) {
            if key.is_simple(database)?
                && let Some(message) = probes(database, reporter.deployment(), table, key)?
            {
                reporter.index(key, message, resolution(table.table_name()))?;
            }
        }
        Ok(())
    }
}

/// How to close the oracle on the table named `name`.
fn resolution(name: &str) -> String {
    format!(
        "Let the server choose the key of '{name}', such as from an identity or a random default, confine it in the WITH CHECK of '{name}' to values the writer may read, pin a key column there to a declared principal accessor, or let the writer read every row of '{name}'."
    )
}

/// The message reporting the client roles that write `key` of `table` over
/// rows they cannot read, or `None` when no role does.
fn probes<'db, DB: DatabaseLike, I: TableIndexLike<DB = DB>>(
    database: &'db DB,
    deployment: &'db Deployment,
    table: &'db DB::Table,
    key: &'db I,
) -> Result<Option<String>, LookupError> {
    let columns: Vec<&DB::Column> = key.columns(database)?.collect();
    let names: Vec<_> = columns
        .iter()
        .map(|column| column.stored_column_name())
        .collect();
    let confinement = Confinement::new(
        database,
        deployment,
        table,
        names.clone(),
        table,
        names,
        key.nulls_distinct(),
    )?
    .with_consumptions(consumptions(database, deployment, table)?)
    .with_principal_columns(principal_columns(database, deployment, table, &columns)?);
    let mut probes = Vec::new();
    for (name, role) in client_roles(database, deployment) {
        let held = table.privileges(acting(role), database)?;
        let read = if columns.iter().all(|column| held.select.on_column(column)) {
            let Some(read) = row_security(database, table, RowStatement::Select, role)? else {
                continue;
            };
            if !hides_rows(database, table, role, &read)? {
                continue;
            }
            Some(read)
        } else {
            None
        };
        let mut commands = Vec::new();
        if writes_whole_key(database, columns.iter().copied(), &held.insert, false)?
            && writes_free_key(
                &confinement,
                table,
                RowStatement::Insert { returning: false },
                RowVersion::Inserted,
                role,
                read.as_ref(),
                &[],
            )?
        {
            commands.push("INSERT");
        }
        if writes_whole_key(database, columns.iter().copied(), &held.update, true)?
            && writes_free_key(
                &confinement,
                table,
                RowStatement::Update { reads: false },
                RowVersion::Updated,
                role,
                read.as_ref(),
                &[],
            )?
        {
            commands.push("UPDATE");
        }
        if !commands.is_empty() {
            probes.push(format!("{name} through {}", commands.join(" and ")));
        }
    }
    if probes.is_empty() {
        return Ok(None);
    }
    let list = columns
        .iter()
        .copied()
        .map(ColumnLike::column_name)
        .collect::<Vec<_>>()
        .join(", ");
    let name = table.table_name();
    Ok(Some(format!(
        "A unique key of '{name}' on ({list}) tells {} whether a row of '{name}' it cannot read holds a key, since the key is checked past row-level security.",
        probes.join(", ")
    )))
}
