//! Live PostgreSQL catalogs loaded through `pg_diesel`.

use std::time::Duration;

use diesel::{Connection, PgConnection, connection::SimpleConnection};
use pg_diesel::{PgDieselDatabase, database::PgDieselDatabaseBuilder};
use testcontainers::{
    Container, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

/// Database name of every live catalog.
const DATABASE: &str = "catalog";

/// A fresh PostgreSQL 18 and a connection to it.
pub(super) fn postgres() -> (Container<GenericImage>, PgConnection) {
    let container = GenericImage::new("postgres", "18-alpine")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", "user")
        .with_env_var("POSTGRES_PASSWORD", "password")
        .with_env_var("POSTGRES_DB", DATABASE)
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .expect("PostgreSQL starts");
    let host = container.get_host().expect("container host");
    let port = container
        .get_host_port_ipv4(5432)
        .expect("published PostgreSQL port");
    let connection = PgConnection::establish(&format!(
        "host={host} port={port} user=user password=password dbname={DATABASE} connect_timeout=10 options='-c statement_timeout=30000'"
    )).expect("PostgreSQL connection");
    (container, connection)
}

/// Applies `sql` to a fresh PostgreSQL 18 and loads the catalog of `schema`.
pub(super) fn catalog(schema: &str, sql: &str) -> (Container<GenericImage>, PgDieselDatabase) {
    let (container, mut connection) = postgres();
    connection.batch_execute(sql).expect("fixture applies");
    let database = PgDieselDatabase::try_from(
        PgDieselDatabaseBuilder::default()
            .connection(&mut connection)
            .catalog(DATABASE)
            .schema(schema),
    )
    .expect("live catalog loads");
    (container, database)
}
