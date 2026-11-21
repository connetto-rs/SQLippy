//! Submodule providing the rule reporting a binary-replicated table whose
//! replica identity makes PostgreSQL refuse its updates and deletes.

use sql_traits::{
    structs::ReplicaIdentity,
    traits::{DatabaseLike, TableLike},
};

use crate::{
    deployment::Declaration,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::grant_support::is_binary_replicated,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

rule_definition!(
    /// Struct defining a rule that reports a binary-replicated table whose
    /// replica identity is `NOTHING`, `DEFAULT` without a primary key, or
    /// `USING INDEX` naming an index since dropped.
    ///
    /// A partitioned table is never reported, because PostgreSQL checks the
    /// replica identity of the partition a row lands in, and selecting one
    /// selects every partition below it.
    ///
    /// The rule does not run on SQLite, which has no logical replication.
    ///
    /// [`Deployment::with_binary_replication_table`](crate::deployment::Deployment::with_binary_replication_table) or [`Deployment::with_binary_replication_all_tables`](crate::deployment::Deployment::with_binary_replication_all_tables) selects the tables to check, and the rule is inactive until one of them does or [`Deployment::without_binary_replication_tables`](crate::deployment::Deployment::without_binary_replication_tables) declares that no table is binary-replicated.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> =
    ///     UnstreamableReplicaIdentity::default().into();
    /// constrainer.set_deployment(Deployment::default().with_binary_replication_all_tables());
    /// let silenced = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE notes (id UUID PRIMARY KEY); ALTER TABLE notes REPLICA IDENTITY NOTHING;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&silenced).is_err());
    /// let keyed = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE notes (id UUID PRIMARY KEY);")
    ///     .unwrap();
    /// assert!(constrainer.validate_schema(&keyed).is_ok());
    /// ```
    UnstreamableReplicaIdentity,
    register_table_rule,
    LintGroup::Correctness,
    "A table with no replica identity, through NOTHING, a DEFAULT identity without a primary key or a dropped identity index, has every UPDATE and DELETE refused once a publication publishes them.",
    Some("https://www.postgresql.org/docs/current/logical-replication-publication.html"),
    RuleExample {
        bad: "CREATE TABLE events (id UUID PRIMARY KEY, body TEXT);\n\
ALTER TABLE events REPLICA IDENTITY NOTHING;",
        good: "CREATE TABLE events (id UUID PRIMARY KEY, body TEXT);",
    },
    Basis::Declared,
    &[Engine::PostgreSql],
    &[Declaration::BinaryReplicationTables]
);

impl<DB: DatabaseLike> TableRule for UnstreamableReplicaIdentity<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if table.is_partitioned() || !is_binary_replicated(database, reporter.deployment(), table)?
        {
            return Ok(());
        }
        let cause = match table.replica_identity(database)? {
            ReplicaIdentity::Nothing => "is `NOTHING`",
            ReplicaIdentity::Default if !table.has_primary_key(database)? => {
                "is `DEFAULT` and the table has no primary key"
            }
            ReplicaIdentity::Index(None) => "names an index that was dropped",
            ReplicaIdentity::Default | ReplicaIdentity::Full | ReplicaIdentity::Index(Some(_)) => {
                return Ok(());
            }
        };
        let name = table.table_name();
        reporter.table(
            table,
            format!("Table '{name}' is binary-replicated, but its replica identity {cause}, so PostgreSQL refuses its updates and deletes once a publication publishes them."),
            format!("Add a primary key to '{name}' and set `ALTER TABLE {name} REPLICA IDENTITY DEFAULT`, or set `REPLICA IDENTITY FULL`."),
        )
    }
}
