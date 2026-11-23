//! Replica identities of binary-replicated tables, observed through
//! `unstreamable_replica_identity`.

use sqlippy::prelude::*;

use super::common::{ROLES, findings, parse};

const SCHEMA: &str = "
    CREATE TABLE keyed (id INT PRIMARY KEY);
    CREATE TABLE unkeyed (id INT);
    CREATE TABLE silenced (id INT PRIMARY KEY);
    ALTER TABLE silenced REPLICA IDENTITY NOTHING;
    CREATE TABLE full_rows (id INT);
    ALTER TABLE full_rows REPLICA IDENTITY FULL;
    CREATE TABLE indexed (id INT NOT NULL);
    CREATE UNIQUE INDEX indexed_id ON indexed (id);
    ALTER TABLE indexed REPLICA IDENTITY USING INDEX indexed_id;
    CREATE TABLE keyed_index (id INT PRIMARY KEY);
    ALTER TABLE keyed_index REPLICA IDENTITY USING INDEX keyed_index_pkey;
    CREATE TABLE dropped (id INT NOT NULL);
    CREATE UNIQUE INDEX dropped_id ON dropped (id);
    ALTER TABLE dropped REPLICA IDENTITY USING INDEX dropped_id;
    DROP INDEX dropped_id;
    CREATE TABLE events (id INT) PARTITION BY RANGE (id);
    CREATE TABLE events_low PARTITION OF events FOR VALUES FROM (0) TO (10);
    CREATE TABLE events_high PARTITION OF events FOR VALUES FROM (10) TO (20);
    ALTER TABLE events_high REPLICA IDENTITY FULL;";

/// Tables `unstreamable_replica_identity` reports under `deployment`, sorted.
fn reported(deployment: Deployment) -> Vec<String> {
    let mut tables: Vec<String> =
        findings(UnstreamableReplicaIdentity::default(), deployment, SCHEMA)
            .into_iter()
            .map(|(rule, level, object)| {
                assert_eq!(rule, "unstreamable_replica_identity");
                assert_eq!(level, Level::Deny);
                object
            })
            .collect();
    tables.sort_unstable();
    tables
}

#[test]
fn identities_that_refuse_updates_and_deletes_are_reported() {
    assert_eq!(
        reported(Deployment::default().with_binary_replication_all_tables()),
        ["dropped", "events_low", "silenced", "unkeyed"]
    );
}

#[test]
fn only_selected_tables_are_checked() {
    assert_eq!(
        reported(
            Deployment::default()
                .with_binary_replication_table("public", "silenced")
                .with_binary_replication_table("public", "keyed")
        ),
        ["silenced"]
    );
}

#[test]
fn a_selected_partitioned_table_checks_its_partitions_and_not_itself() {
    assert_eq!(
        reported(Deployment::default().with_binary_replication_table("public", "events")),
        ["events_low"]
    );
}

#[test]
fn the_rule_is_inactive_without_binary_replicated_tables() {
    let constrainer: GenericConstrainer<ParserDB> = UnstreamableReplicaIdentity::default().into();
    let inactive = constrainer.inactive_rules(Engine::PostgreSql);
    assert_eq!(inactive.len(), 1);
    assert_eq!(inactive[0].rule().name, "unstreamable_replica_identity");
    assert_eq!(inactive[0].missing(), Declaration::BinaryReplicationTables);
    assert!(
        constrainer
            .validate_schema(&parse(&format!("{ROLES}{SCHEMA}")))
            .is_ok()
    );
}
