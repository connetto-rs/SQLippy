//! Binary replication findings from a live PostgreSQL catalog.

use std::time::Duration;

use diesel::{Connection, PgConnection, connection::SimpleConnection};
use pg_diesel::{PgDieselDatabase, database::PgDieselDatabaseBuilder};
use sqlippy::prelude::*;
use testcontainers::{
    Container, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};

const FAILING_COLUMNS: [(&str, &str, &str); 6] = [
    ("c_acl_arr", "aclitem[]", "aclitem"),
    ("c_range", "nosendrange", "nosend"),
    ("c_comp", "comp_nosend", "nosend"),
    ("c_d_range", "d_range", "nosend"),
    ("c_d_comp", "d_comp", "nosend"),
    ("c_d_aclarr", "d_aclarr", "aclitem"),
];

const FIXTURE_SQL: &str = r"
CREATE SCHEMA binrep;
SET search_path = binrep;

CREATE TYPE nosend;
CREATE FUNCTION nosend_in(cstring) RETURNS nosend LANGUAGE internal IMMUTABLE STRICT AS 'int4in';
CREATE FUNCTION nosend_out(nosend) RETURNS cstring LANGUAGE internal IMMUTABLE STRICT AS 'int4out';
CREATE TYPE nosend (INPUT = nosend_in, OUTPUT = nosend_out, INTERNALLENGTH = 4, PASSEDBYVALUE);

CREATE TYPE withsend;
CREATE FUNCTION withsend_in(cstring) RETURNS withsend LANGUAGE internal IMMUTABLE STRICT AS 'int4in';
CREATE FUNCTION withsend_out(withsend) RETURNS cstring LANGUAGE internal IMMUTABLE STRICT AS 'int4out';
CREATE FUNCTION withsend_send(withsend) RETURNS bytea LANGUAGE internal IMMUTABLE STRICT AS 'int4send';
CREATE FUNCTION withsend_recv(internal) RETURNS withsend LANGUAGE internal IMMUTABLE STRICT AS 'int4recv';
CREATE TYPE withsend (INPUT = withsend_in, OUTPUT = withsend_out, SEND = withsend_send, RECEIVE = withsend_recv, INTERNALLENGTH = 4, PASSEDBYVALUE);

CREATE FUNCTION nosend_lt(nosend, nosend) RETURNS bool LANGUAGE internal IMMUTABLE STRICT AS 'int4lt';
CREATE FUNCTION nosend_le(nosend, nosend) RETURNS bool LANGUAGE internal IMMUTABLE STRICT AS 'int4le';
CREATE FUNCTION nosend_eq(nosend, nosend) RETURNS bool LANGUAGE internal IMMUTABLE STRICT AS 'int4eq';
CREATE FUNCTION nosend_ge(nosend, nosend) RETURNS bool LANGUAGE internal IMMUTABLE STRICT AS 'int4ge';
CREATE FUNCTION nosend_gt(nosend, nosend) RETURNS bool LANGUAGE internal IMMUTABLE STRICT AS 'int4gt';
CREATE FUNCTION nosend_cmp(nosend, nosend) RETURNS int LANGUAGE internal IMMUTABLE STRICT AS 'btint4cmp';
CREATE OPERATOR < (LEFTARG = nosend, RIGHTARG = nosend, FUNCTION = nosend_lt);
CREATE OPERATOR <= (LEFTARG = nosend, RIGHTARG = nosend, FUNCTION = nosend_le);
CREATE OPERATOR = (LEFTARG = nosend, RIGHTARG = nosend, FUNCTION = nosend_eq);
CREATE OPERATOR >= (LEFTARG = nosend, RIGHTARG = nosend, FUNCTION = nosend_ge);
CREATE OPERATOR > (LEFTARG = nosend, RIGHTARG = nosend, FUNCTION = nosend_gt);
CREATE OPERATOR CLASS nosend_ops DEFAULT FOR TYPE nosend USING btree AS
    OPERATOR 1 <, OPERATOR 2 <=, OPERATOR 3 =, OPERATOR 4 >=, OPERATOR 5 >,
    FUNCTION 1 nosend_cmp(nosend, nosend);

CREATE TYPE nosendrange AS RANGE (SUBTYPE = nosend);
CREATE TYPE comp_nosend AS (a INT, b nosend);
CREATE TYPE comp_ok AS (a INT, b TEXT[], c int4range);

CREATE DOMAIN d_acl AS aclitem;
CREATE DOMAIN d_aclarr AS aclitem[];
CREATE DOMAIN d_range AS nosendrange;
CREATE DOMAIN d_comp AS comp_nosend;

CREATE TABLE t (
    c_acl aclitem,
    c_d_acl d_acl,
    c_int4_arr int4[],
    c_int4_range int4range,
    c_comp_ok comp_ok,
    c_withsend withsend,
    c_withsend_arr withsend[],
    c_acl_arr aclitem[],
    c_range nosendrange,
    c_comp comp_nosend,
    c_d_range d_range,
    c_d_comp d_comp,
    c_d_aclarr d_aclarr
);

CREATE TABLE other (
    c_acl_arr aclitem[]
);
";

fn catalog() -> (Container<GenericImage>, PgDieselDatabase) {
    let container = GenericImage::new("postgres", "18-alpine")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", "user")
        .with_env_var("POSTGRES_PASSWORD", "password")
        .with_env_var("POSTGRES_DB", "binrep")
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .expect("PostgreSQL starts");
    let host = container.get_host().expect("container host");
    let port = container
        .get_host_port_ipv4(5432)
        .expect("published PostgreSQL port");
    let mut connection = PgConnection::establish(&format!(
        "host={host} port={port} user=user password=password dbname=binrep connect_timeout=10 options='-c statement_timeout=30000'"
    )).expect("PostgreSQL connection");
    connection
        .batch_execute(FIXTURE_SQL)
        .expect("fixture applies");
    let database = PgDieselDatabase::try_from(
        PgDieselDatabaseBuilder::default()
            .connection(&mut connection)
            .catalog("binrep")
            .schema("binrep"),
    )
    .expect("live catalog loads");
    (container, database)
}

#[test]
fn selected_live_columns_report_nested_failures_and_accept_text_fallback() {
    let (_container, database) = catalog();
    let mut constrainer: GenericConstrainer<PgDieselDatabase> = BinarySendFailure::default().into();
    constrainer.register_column_rule(Box::new(UnknownBinarySend::default()));
    constrainer.set_rule_level("binary_send_failure", Level::Deny);
    constrainer.set_deployment(Deployment::default().with_binary_replication_table("binrep", "t"));
    let findings: Vec<_> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation,
            other => panic!("unexpected diagnostic {other}"),
        })
        .collect();
    let mut actual: Vec<_> = findings.iter().map(|v| v.object()).collect();
    actual.sort_unstable();
    let mut expected: Vec<_> = FAILING_COLUMNS
        .iter()
        .map(|(column, _, _)| format!("t.{column}"))
        .collect();
    expected.sort_unstable();
    assert_eq!(actual, expected);
    for (column, declared, inner) in FAILING_COLUMNS {
        let object = format!("t.{column}");
        let finding = findings.iter().find(|v| v.object() == object).unwrap();
        assert_eq!(finding.rule().name, "binary_send_failure");
        assert_eq!(finding.level(), Level::Deny);
        for name in [&object, declared, inner] {
            assert!(
                finding.message().contains(name),
                "missing {name} in {finding}"
            );
        }
    }
}
