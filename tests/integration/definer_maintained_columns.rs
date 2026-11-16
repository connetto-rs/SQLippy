//! Client privileges on columns assigned by a definer.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const TABLE: &str = "CREATE ROLE authenticated; CREATE ROLE editors; CREATE ROLE anon;
CREATE TABLE folders (id INT PRIMARY KEY, label TEXT, depth INT);";

/// Checks inferred maintenance and effective client grants.
fn reported(body: &str, grants: &str, security: &str) -> bool {
    let mut constrainer: GenericConstrainer<ParserDB> =
        DefinerMaintainedColumnClientWritable::default().into();
    constrainer.set_deployment(Deployment::example());
    let schema = ParserDB::parse::<PostgreSqlDialect>(&format!("{TABLE} CREATE FUNCTION set_depth() RETURNS VOID LANGUAGE sql SECURITY {security} AS $$ {body} $$; {grants}")).unwrap();
    constrainer.validate_schema(&schema).is_err()
}

/// Table and column grants reach clients directly and through memberships.
#[test]
fn definer_maintained_columns_reject_client_grants() {
    for grants in [
        "GRANT INSERT, UPDATE ON folders TO authenticated;",
        "GRANT UPDATE (depth) ON folders TO authenticated;",
        "GRANT INSERT (depth) ON folders TO authenticated;",
        "GRANT UPDATE (depth) ON folders TO PUBLIC;",
        "GRANT UPDATE (depth) ON folders TO anon;",
        "GRANT editors TO authenticated; GRANT UPDATE (depth) ON folders TO editors;",
    ] {
        assert!(
            reported("UPDATE folders SET depth = 1", grants, "DEFINER"),
            "{grants}"
        );
        assert!(
            reported(
                "INSERT INTO folders (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET depth = 1",
                grants,
                "DEFINER"
            ),
            "{grants}"
        );
    }
}

/// Narrow grants, revocations and invoker maintenance do not expose the column.
#[test]
fn definer_maintained_columns_accept_withheld_privileges() {
    for grants in [
        "GRANT INSERT (id, label), UPDATE (label) ON folders TO authenticated;",
        "GRANT UPDATE ON folders TO authenticated; REVOKE UPDATE ON folders FROM authenticated;",
        "GRANT UPDATE (depth) ON folders TO editors;",
        "GRANT editors TO authenticated WITH INHERIT FALSE; GRANT UPDATE ON folders TO editors;",
        "",
    ] {
        assert!(
            !reported("UPDATE folders SET depth = 1", grants, "DEFINER"),
            "{grants}"
        );
    }
    assert!(!reported(
        "UPDATE folders SET depth = 1",
        "GRANT UPDATE ON folders TO authenticated;",
        "INVOKER"
    ));
}

/// Column revocation cannot remove a table-wide privilege.
#[test]
fn definer_maintained_columns_keep_table_grants() {
    assert!(reported(
        "UPDATE folders SET depth = 1",
        "GRANT UPDATE ON folders TO authenticated; REVOKE UPDATE (depth) ON folders FROM authenticated;",
        "DEFINER"
    ));
}

/// Only columns assigned by the definer are maintained.
#[test]
fn definer_maintained_columns_ignore_reads() {
    assert!(!reported(
        "UPDATE folders SET label = depth::TEXT",
        "GRANT UPDATE (depth) ON folders TO authenticated;",
        "DEFINER"
    ));
}

/// A definer creating a row keeps none of the values it inserts.
#[test]
fn definer_maintained_columns_ignore_created_rows() {
    for body in [
        "INSERT INTO folders (id, depth) VALUES (1, 1)",
        "INSERT INTO folders (id, depth) VALUES (1, 1) ON CONFLICT DO NOTHING",
        "INSERT INTO folders (id, depth) VALUES (1, 1) ON CONFLICT (id) DO UPDATE SET label = 'root'",
    ] {
        assert!(
            !reported(
                body,
                "GRANT INSERT (id, depth), UPDATE (id, depth) ON folders TO authenticated;",
                "DEFINER"
            ),
            "{body}"
        );
    }
}

/// Intentional mixed writers use the table allowance.
#[test]
fn definer_maintained_columns_allow_mixed_writers() {
    let mut constrainer: GenericConstrainer<ParserDB> =
        DefinerMaintainedColumnClientWritable::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.allow_table(
        "definer_maintained_column_client_writable",
        TargetName::new("folders", false),
    );
    let schema = ParserDB::parse::<PostgreSqlDialect>(&format!("{TABLE} CREATE FUNCTION set_depth() RETURNS VOID LANGUAGE sql SECURITY DEFINER AS $$ UPDATE folders SET depth = 1 $$; GRANT UPDATE ON folders TO authenticated;")).unwrap();
    assert!(constrainer.validate_schema(&schema).is_ok());
}

/// Both procedural and atomic bodies retain their maintenance assignments.
#[test]
fn definer_maintained_columns_read_function_body_forms() {
    for definition in [
        "LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN UPDATE folders SET depth = 1; END $$",
        "LANGUAGE sql SECURITY DEFINER BEGIN ATOMIC UPDATE folders SET depth = 1; END",
    ] {
        let mut constrainer: GenericConstrainer<ParserDB> =
            DefinerMaintainedColumnClientWritable::default().into();
        constrainer.set_deployment(Deployment::example());
        let schema = ParserDB::parse::<PostgreSqlDialect>(&format!("{TABLE} CREATE FUNCTION set_depth() RETURNS VOID {definition}; GRANT UPDATE ON folders TO authenticated;")).unwrap();
        assert!(
            constrainer.validate_schema(&schema).is_err(),
            "{definition}"
        );
    }
}

#[test]
fn tuple_assignments_maintain_each_target_column() {
    for column in ["depth", "label"] {
        assert!(reported(
            "UPDATE folders SET (depth, label) = (1, 'root')",
            &format!("GRANT UPDATE ({column}) ON folders TO authenticated;"),
            "DEFINER"
        ));
    }
    assert!(!reported(
        "UPDATE folders SET (depth, label) = (1, 'root')",
        "GRANT UPDATE (id) ON folders TO authenticated;",
        "DEFINER"
    ));
}

#[test]
fn unresolved_maintenance_targets_do_not_claim_stored_columns() {
    for body in [
        "UPDATE missing_folders SET depth = 1",
        "UPDATE external.folders SET depth = 1",
        "UPDATE folders SET missing = 1",
        "UPDATE (SELECT * FROM folders) selected SET depth = 1",
    ] {
        assert!(
            !reported(body, "GRANT UPDATE ON folders TO authenticated;", "DEFINER"),
            "{body}"
        );
    }
}
