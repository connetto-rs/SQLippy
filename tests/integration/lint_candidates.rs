//! Exposed definer functions, extensions and sequences, filtering views,
//! tables without policies, overlapping permissive policies, `reg*` columns
//! and disabled autovacuum, observed through the public constrainer API. On
//! PostgreSQL 17.11 and 18.6, a role read no row of a table with row-level
//! security and no policy, called a definer function and `nextval` granted
//! by default or to `PUBLIC`, and saw a hidden row through a leaky function
//! on a view without `security_barrier` but not on one with it.

use crate::rule_findings::findings;
use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Objects `rule` reports at warn, registered alone under `deployment`.
fn objects<R>(rule: R, deployment: Deployment, sql: &str) -> Vec<String>
where
    R: sql_rules::lint::Rule + Into<GenericConstrainer<ParserDB>>,
{
    let name = rule.metadata().name;
    let mut constrainer = rule.into();
    constrainer.set_deployment(deployment);
    findings(&constrainer, name, sql)
        .into_iter()
        .map(|(level, object, _)| {
            assert_eq!(level, Level::Warn);
            object
        })
        .collect()
}

fn exposed() -> Deployment {
    Deployment::default()
        .with_exposed_schema("public")
        .with_anonymous_role("anon")
        .with_app_role("app")
}

const ROLES: &str =
    "CREATE ROLE anon; CREATE ROLE app; CREATE ROLE reporting; CREATE SCHEMA private;";

#[test]
fn exposed_definer_functions_are_reported() {
    let definer = |name: &str| {
        format!(
            "CREATE FUNCTION {name}() RETURNS INT LANGUAGE sql SECURITY DEFINER SET search_path = '' AS 'SELECT 1';"
        )
    };
    assert_eq!(
        objects(
            SecurityDefinerFunctionExposed::default(),
            exposed(),
            &format!(
                "{ROLES}
                 {} {}
                 REVOKE EXECUTE ON FUNCTION for_app() FROM PUBLIC; GRANT EXECUTE ON FUNCTION for_app() TO app;
                 {} REVOKE EXECUTE ON FUNCTION closed() FROM PUBLIC; GRANT EXECUTE ON FUNCTION closed() TO reporting;
                 {}
                 CREATE FUNCTION invoker() RETURNS INT LANGUAGE sql AS 'SELECT 1';",
                definer("open"),
                definer("for_app"),
                definer("closed"),
                definer("private.hidden"),
            )
        ),
        ["for_app()", "open()"]
    );
}

#[test]
fn extensions_in_exposed_schemas_are_reported() {
    assert_eq!(
        objects(
            ExtensionInExposedSchema::default(),
            exposed(),
            "CREATE SCHEMA extensions;
             CREATE EXTENSION pgcrypto WITH SCHEMA public;
             CREATE EXTENSION citext;
             CREATE EXTENSION hstore WITH SCHEMA extensions;"
        ),
        ["citext", "pgcrypto"]
    );
}

#[test]
fn sequences_a_client_role_reaches_are_reported() {
    assert_eq!(
        objects(
            ReachableSequence::default(),
            exposed(),
            &format!(
                "{ROLES}
                 CREATE SEQUENCE public.shown;
                 CREATE SEQUENCE private.granted; GRANT USAGE ON SEQUENCE private.granted TO anon;
                 CREATE SEQUENCE private.selected; GRANT SELECT ON SEQUENCE private.selected TO app;
                 CREATE SEQUENCE private.kept; GRANT USAGE ON SEQUENCE private.kept TO reporting;
                 CREATE SEQUENCE private.taken; GRANT USAGE ON SEQUENCE private.taken TO anon;
                   REVOKE USAGE ON SEQUENCE private.taken FROM anon;
                 CREATE TABLE private.tickets (id BIGSERIAL);
                 GRANT USAGE ON SEQUENCE private.tickets_id_seq TO PUBLIC;"
            )
        ),
        ["granted", "selected", "tickets_id_seq", "shown"]
    );
}

#[test]
fn filtering_views_clients_reach_without_a_barrier_are_reported() {
    assert_eq!(
        objects(
            SecurityBarrierMissingOnFilteringView::default(),
            exposed(),
            &format!(
                "{ROLES}
                 CREATE TABLE private.phones (person TEXT, phone TEXT);
                 CREATE VIEW public.exposed AS SELECT person FROM private.phones WHERE phone NOT LIKE '412%';
                 CREATE VIEW private.granted AS SELECT person FROM private.phones WHERE phone <> '';
                 GRANT SELECT ON private.granted TO app;
                 CREATE VIEW private.ungranted AS SELECT person FROM private.phones WHERE phone <> '';
                 CREATE VIEW public.barrier WITH (security_barrier = true)
                   AS SELECT person FROM private.phones WHERE phone <> '';
                 CREATE VIEW public.unfiltered AS SELECT person FROM private.phones;"
            )
        ),
        ["granted", "exposed"]
    );
}

#[test]
fn tables_with_row_level_security_and_no_policy_are_reported() {
    assert_eq!(
        objects(
            RowLevelSecurityWithoutPolicies::default(),
            Deployment::default(),
            "CREATE TABLE audit (id INT); ALTER TABLE audit ENABLE ROW LEVEL SECURITY;
             CREATE TABLE covered (id INT); ALTER TABLE covered ENABLE ROW LEVEL SECURITY;
             CREATE POLICY read ON covered USING (true);
             CREATE TABLE open (id INT);"
        ),
        ["audit"]
    );
}

#[test]
fn permissive_policies_sharing_a_role_and_command_are_reported_once() {
    let found = findings(
        &GenericConstrainer::from(MultiplePermissivePolicies::default()),
        "MultiplePermissivePolicies",
        "CREATE ROLE staff; CREATE ROLE manager IN ROLE staff; CREATE ROLE other;
         CREATE TABLE orders (owner TEXT, is_admin BOOL); ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
         CREATE POLICY own ON orders FOR SELECT USING (owner = current_user);
         CREATE POLICY admin ON orders FOR SELECT USING (is_admin);
         CREATE POLICY staff_write ON orders FOR UPDATE TO staff USING (true);
         CREATE POLICY manager_write ON orders FOR UPDATE TO manager USING (true);
         CREATE POLICY other_write ON orders FOR UPDATE TO other USING (true);
         CREATE POLICY gate ON orders AS RESTRICTIVE FOR SELECT USING (true);",
    );
    let messages: Vec<&str> = found
        .iter()
        .map(|(_, _, message)| message.as_str())
        .collect();
    assert_eq!(
        messages,
        [
            "Permissive policies 'admin', 'own' on 'orders' all apply to SELECT for every role, so each row evaluates every one of them.",
            "Permissive policies 'manager_write', 'staff_write' on 'orders' all apply to UPDATE for role 'manager', so each row evaluates every one of them.",
        ]
    );
}

#[test]
fn validation_stops_at_the_first_overlap() {
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE orders (owner TEXT); ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
         CREATE POLICY a ON orders USING (true); CREATE POLICY b ON orders USING (true);",
    )
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = MultiplePermissivePolicies::default().into();
    assert!(constrainer.validate_schema(&database).is_err());
}

#[test]
fn unsupported_reg_columns_and_disabled_autovacuum_are_reported() {
    assert_eq!(
        objects(
            RegColumnType::default(),
            Deployment::default(),
            "CREATE TABLE ns_map (ns REGNAMESPACE, kind REGCLASS, proc REGPROCEDURE, name TEXT);"
        ),
        ["ns_map.ns", "ns_map.proc"]
    );
    assert_eq!(
        objects(
            AutovacuumDisabledTable::default(),
            Deployment::default(),
            "CREATE TABLE off_table (id INT) WITH (autovacuum_enabled = false);
             CREATE TABLE zero (id INT) WITH (autovacuum_enabled = 0);
             CREATE TABLE on_table (id INT) WITH (autovacuum_enabled = true);
             CREATE TABLE tuned (id INT) WITH (fillfactor = 70);
             CREATE TABLE plain (id INT);"
        ),
        ["off_table", "zero"]
    );
}

#[test]
fn the_default_constrainer_applies_each_group() {
    let sql = "CREATE TABLE audit (id INT); ALTER TABLE audit ENABLE ROW LEVEL SECURITY;
        CREATE TABLE staging (id INT) WITH (autovacuum_enabled = false);
        CREATE TABLE phones (phone TEXT);
        CREATE VIEW visible AS SELECT phone FROM phones WHERE phone <> '';
        GRANT SELECT ON visible TO PUBLIC;";
    let constrainer = DefaultConstrainer::<ParserDB>::default();
    let counts: Vec<(&str, usize)> = [
        "RowLevelSecurityWithoutPolicies",
        "AutovacuumDisabledTable",
        "SecurityBarrierMissingOnFilteringView",
    ]
    .into_iter()
    .map(|rule| (rule, findings(&constrainer, rule, sql).len()))
    .collect();
    assert_eq!(
        counts,
        [
            ("RowLevelSecurityWithoutPolicies", 1),
            ("AutovacuumDisabledTable", 1),
            ("SecurityBarrierMissingOnFilteringView", 0)
        ]
    );
}
