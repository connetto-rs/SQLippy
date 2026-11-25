//! Tenant-key equality on request-selected joins.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const TABLES: &str = "CREATE TABLE resources (id TEXT PRIMARY KEY, organization_id TEXT, rank INT);
CREATE TABLE caps (id TEXT PRIMARY KEY, organization_id TEXT, rank INT, resource_id TEXT REFERENCES resources(id));";

/// Checks a function body through the public API.
fn reported(body: &str, arguments: &str) -> bool {
    let mut constrainer: GenericConstrainer<ParserDB> = CrossTenantCap::default().into();
    constrainer.set_deployment(Deployment::example());
    let schema = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{TABLES} CREATE FUNCTION capped_rank({arguments}) RETURNS INT LANGUAGE sql AS $$ {body} $$;"
    )).unwrap();
    constrainer.validate_schema(&schema).is_err()
}

/// Parameter, credential and request-setting pins require matching tenant keys.
#[test]
fn cross_tenant_caps_require_tenant_equality() {
    for pin in [
        "cap_id",
        "$2",
        "current_setting('app.user_id', true)",
        "current_setting('app.installation_id', true)",
    ] {
        let body = format!(
            "SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.id = {pin}"
        );
        assert!(reported(&body, "resource_id TEXT, cap_id TEXT"), "{pin}");
        assert!(
            !reported(
                &format!("{body} AND caps.organization_id = resources.organization_id"),
                "resource_id TEXT, cap_id TEXT"
            ),
            "{pin}"
        );
    }
}

/// An ordinary foreign-key join has no request-selected row.
#[test]
fn cross_tenant_caps_ignore_unpinned_joins() {
    assert!(!reported(
        "SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.resource_id = resources.id",
        ""
    ));
}

/// An alias or a cast does not conceal a request pin.
#[test]
fn cross_tenant_caps_resolve_aliases_and_casts() {
    assert!(reported(
        "SELECT LEAST(resource.rank, cap.rank) FROM resources resource JOIN caps cap ON cap.id = (cap_id::TEXT)",
        "cap_id TEXT"
    ));
    assert!(!reported(
        "SELECT LEAST(resource.rank, cap.rank) FROM resources resource JOIN caps cap ON cap.id = cap_id AND resource.organization_id = cap.organization_id",
        "cap_id TEXT"
    ));
}

/// A disjunction cannot prove tenant equality.
#[test]
fn cross_tenant_caps_require_a_conjunct() {
    assert!(reported(
        "SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.id = cap_id WHERE caps.organization_id = resources.organization_id OR resources.rank > 1",
        "cap_id TEXT"
    ));
}

/// Pinning an ordinary attribute does not select a keyed row.
#[test]
fn cross_tenant_caps_ignore_non_key_pins() {
    assert!(!reported(
        "SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.rank = cap_rank",
        "cap_rank INT"
    ));
}

/// Bound SQL and procedural selects retain their request pins.
#[test]
fn cross_tenant_caps_read_function_body_forms() {
    for definition in [
        "LANGUAGE sql RETURN (SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.id = cap_id)",
        "LANGUAGE plpgsql AS $$ BEGIN RETURN (SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.id = cap_id); END $$",
        "LANGUAGE sql BEGIN ATOMIC SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps ON caps.id = cap_id; END",
    ] {
        let mut constrainer: GenericConstrainer<ParserDB> = CrossTenantCap::default().into();
        constrainer.set_deployment(Deployment::example());
        let schema = ParserDB::parse::<PostgreSqlDialect>(&format!(
            "{TABLES} CREATE FUNCTION capped_rank(cap_id TEXT) RETURNS INT {definition};"
        ))
        .unwrap();
        assert!(
            constrainer.validate_schema(&schema).is_err(),
            "{definition}"
        );
    }
}

/// Outer joins still require tenant equality for caller-selected caps.
#[test]
fn cross_tenant_caps_check_outer_join_pins() {
    for join in ["LEFT JOIN", "RIGHT JOIN", "FULL JOIN"] {
        let body = format!(
            "SELECT LEAST(resources.rank, caps.rank) FROM resources {join} caps ON caps.id = cap_id"
        );
        assert!(reported(&body, "cap_id TEXT"));
        assert!(!reported(
            &format!("{body} AND caps.organization_id = resources.organization_id"),
            "cap_id TEXT"
        ));
    }
}

#[test]
fn using_and_natural_joins_equate_tenant_keys() {
    for join in ["JOIN caps USING (organization_id)", "NATURAL JOIN caps"] {
        assert!(
            !reported(
                &format!(
                    "SELECT LEAST(resources.rank, caps.rank) FROM resources {join} WHERE resources.id = resource_id AND caps.id = cap_id"
                ),
                "resource_id TEXT, cap_id TEXT"
            ),
            "{join}"
        );
    }
    assert!(reported(
        "SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps USING (rank) WHERE caps.id = cap_id",
        "cap_id TEXT"
    ));
}

#[test]
fn comma_and_cross_joins_still_require_tenant_equality() {
    for from in ["resources, caps", "resources CROSS JOIN caps"] {
        assert!(reported(
            &format!("SELECT LEAST(resources.rank, caps.rank) FROM {from} WHERE caps.id = cap_id"),
            "cap_id TEXT"
        ));
        assert!(!reported(
            &format!(
                "SELECT LEAST(resources.rank, caps.rank) FROM {from} WHERE caps.id = cap_id AND caps.organization_id = resources.organization_id"
            ),
            "cap_id TEXT"
        ));
    }
}

#[test]
fn positional_parameters_pin_only_existing_arguments() {
    assert!(reported(
        "SELECT caps.rank FROM resources JOIN caps ON caps.id = $1",
        "cap_id TEXT"
    ));
    assert!(!reported(
        "SELECT caps.rank FROM resources JOIN caps ON caps.id = $2",
        "cap_id TEXT"
    ));
}

#[test]
fn missing_tenant_declaration_explains_inactive_rule() {
    let constrainer: GenericConstrainer<ParserDB> = CrossTenantCap::default().into();
    let database = ParserDB::parse::<PostgreSqlDialect>(TABLES).unwrap();
    let diagnostics = constrainer.diagnostics(&database);
    let [Error::Inactive(inactive)] = diagnostics.as_slice() else {
        panic!("{diagnostics:?}");
    };
    assert_eq!(inactive.rule().name, "cross_tenant_cap");
    assert_eq!(inactive.missing(), Declaration::TenantKeys);
    assert!(diagnostics[0].to_string().contains("tenant keys"));
}

#[test]
fn unstored_relations_do_not_supply_tenant_keys() {
    for from in [
        "resources JOIN missing_caps caps ON caps.id = cap_id",
        "resources JOIN external.caps caps ON caps.id = cap_id",
    ] {
        assert!(!reported(
            &format!("SELECT resources.rank FROM {from}"),
            "cap_id TEXT"
        ));
    }
}

#[test]
fn natural_join_with_absent_declared_key_does_not_prove_equality() {
    let mut constrainer: GenericConstrainer<ParserDB> = CrossTenantCap::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_tenant_key("public", "resources", ["missing"])
            .with_tenant_key("public", "caps", ["organization_id"]),
    );
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{TABLES} CREATE FUNCTION capped_rank(cap_id TEXT) RETURNS INT LANGUAGE sql AS $$ SELECT caps.rank FROM resources NATURAL JOIN caps WHERE caps.id = cap_id $$;"
    )).unwrap();
    assert_eq!(constrainer.diagnostics(&database).len(), 1);
}

#[test]
fn invalid_parameter_positions_do_not_pin_rows() {
    for placeholder in ["$0", "$184467440737095516160"] {
        assert!(!reported(
            &format!("SELECT caps.rank FROM resources JOIN caps ON caps.id = {placeholder}"),
            "cap_id TEXT"
        ));
    }
}

#[test]
fn natural_join_resolves_renamed_tenant_keys() {
    assert!(!reported(
        "SELECT cap.rank FROM resources resource(resource_id, tenant, rank) NATURAL JOIN caps cap(cap_id, tenant, rank, owner_id) WHERE cap.cap_id = wanted",
        "wanted TEXT"
    ));
    assert!(reported(
        "SELECT cap.rank FROM resources resource(resource_id, tenant, rank) NATURAL JOIN caps cap(cap_id, other_tenant, rank, owner_id) WHERE cap.cap_id = wanted",
        "wanted TEXT"
    ));
}

#[test]
fn composite_tenant_keys_require_every_column_equal() {
    let tenant = ["organization_namespace_id", "organization_id"];
    let mut constrainer: GenericConstrainer<ParserDB> = CrossTenantCap::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_tenant_key("public", "resources", tenant)
            .with_tenant_key("public", "caps", tenant),
    );
    let reported = |from: &str| {
        let schema = ParserDB::parse::<PostgreSqlDialect>(&format!(
            "CREATE TABLE resources (id TEXT PRIMARY KEY, organization_namespace_id TEXT,
               organization_id TEXT, rank INT);
             CREATE TABLE caps (id TEXT PRIMARY KEY, organization_namespace_id TEXT,
               organization_id TEXT, rank INT);
             CREATE FUNCTION capped_rank(cap_id TEXT) RETURNS INT LANGUAGE sql AS $$
               SELECT LEAST(resources.rank, caps.rank) FROM {from} $$;"
        ))
        .unwrap();
        constrainer.validate_schema(&schema).is_err()
    };
    for from in [
        "resources JOIN caps ON caps.id = cap_id AND caps.organization_id = resources.organization_id",
        "resources JOIN caps USING (organization_id) WHERE caps.id = cap_id",
        "resources JOIN caps ON caps.id = cap_id
           AND caps.organization_id = resources.organization_namespace_id
           AND caps.organization_namespace_id = resources.organization_id",
    ] {
        assert!(reported(from), "{from}");
    }
    for from in [
        "resources JOIN caps ON caps.id = cap_id
           AND caps.organization_id = resources.organization_id
           AND resources.organization_namespace_id = caps.organization_namespace_id",
        "resources JOIN caps USING (organization_namespace_id, organization_id) WHERE caps.id = cap_id",
        "resources JOIN caps USING (organization_id)
           WHERE caps.id = cap_id AND caps.organization_namespace_id = resources.organization_namespace_id",
        "resources NATURAL JOIN caps WHERE caps.id = cap_id",
    ] {
        assert!(!reported(from), "{from}");
    }
}

#[test]
fn tenant_keys_of_different_lengths_are_never_equal() {
    let mut constrainer: GenericConstrainer<ParserDB> = CrossTenantCap::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_tenant_key(
                "public",
                "resources",
                ["organization_namespace_id", "organization_id"],
            )
            .with_tenant_key("public", "caps", ["organization_id"]),
    );
    let schema = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE resources (id TEXT PRIMARY KEY, organization_namespace_id TEXT,
           organization_id TEXT, rank INT);
         CREATE TABLE caps (id TEXT PRIMARY KEY, organization_id TEXT, rank INT);
         CREATE FUNCTION capped_rank(cap_id TEXT) RETURNS INT LANGUAGE sql AS $$
           SELECT LEAST(resources.rank, caps.rank) FROM resources JOIN caps
             ON caps.id = cap_id AND caps.organization_id = resources.organization_id $$;",
    )
    .unwrap();
    assert!(constrainer.validate_schema(&schema).is_err());
}
