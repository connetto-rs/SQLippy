//! Owner-rights and materialized views a client role reaches, whatever their
//! sources.

use crate::common::{finding, findings, supabase};
use sqlippy::prelude::*;

const DOCS: &str = "CREATE TABLE plain (id INT PRIMARY KEY);
    CREATE TABLE docs (id INT PRIMARY KEY);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

#[test]
fn an_owner_rights_view_a_client_reads_is_reported() {
    for sql in [
        "CREATE VIEW ids AS SELECT id FROM plain; GRANT SELECT ON ids TO PUBLIC;",
        "CREATE VIEW ids AS SELECT id FROM plain; GRANT ALL ON ids TO anon;",
        "CREATE VIEW ids AS SELECT id FROM plain; GRANT SELECT (id) ON ids TO authenticated;",
        "CREATE VIEW ids AS SELECT id FROM docs; GRANT SELECT ON ids TO anon;",
    ] {
        assert_eq!(
            findings(
                OwnerRightsViewExposed::default(),
                supabase(),
                &format!("{DOCS}{sql}")
            ),
            [finding("owner_rights_view_exposed", Level::Warn, "ids")],
            "{sql}"
        );
    }
}

#[test]
fn an_exposed_schema_reaches_an_owner_rights_view_without_a_grant() {
    let sql = format!("{DOCS}CREATE VIEW ids AS SELECT id FROM plain;");
    assert_eq!(
        findings(
            OwnerRightsViewExposed::default(),
            supabase().with_exposed_schema("public"),
            &sql
        ),
        [finding("owner_rights_view_exposed", Level::Warn, "ids")]
    );
    assert_eq!(
        findings(OwnerRightsViewExposed::default(), supabase(), &sql),
        []
    );
}

#[test]
fn an_invoker_unread_or_materialized_view_is_not_an_owner_rights_exposure() {
    for sql in [
        "CREATE VIEW ids WITH (security_invoker = true) AS SELECT id FROM plain; GRANT SELECT ON ids TO PUBLIC;",
        "CREATE VIEW ids AS SELECT id FROM plain; GRANT SELECT ON ids TO reporting;",
        "CREATE VIEW ids AS SELECT id FROM plain; GRANT INSERT ON ids TO anon;",
        "CREATE MATERIALIZED VIEW ids AS SELECT id FROM plain; GRANT SELECT ON ids TO PUBLIC;",
    ] {
        assert_eq!(
            findings(
                OwnerRightsViewExposed::default(),
                supabase(),
                &format!("{DOCS}{sql}")
            ),
            [],
            "{sql}"
        );
    }
}

#[test]
fn a_materialized_view_over_open_sources_a_client_reads_is_reported() {
    for sql in [
        "CREATE MATERIALIZED VIEW ids AS SELECT id FROM plain; GRANT SELECT ON ids TO PUBLIC;",
        "CREATE MATERIALIZED VIEW ids AS SELECT 42 AS id; GRANT SELECT ON ids TO authenticated;",
        "CREATE MATERIALIZED VIEW ids AS SELECT id FROM plain; GRANT SELECT (id) ON ids TO anon;",
    ] {
        assert_eq!(
            findings(
                MaterializedViewExposed::default(),
                supabase(),
                &format!("{DOCS}{sql}")
            ),
            [finding("materialized_view_exposed", Level::Warn, "ids")],
            "{sql}"
        );
    }
    assert_eq!(
        findings(
            MaterializedViewExposed::default(),
            supabase().with_exposed_schema("public"),
            &format!("{DOCS}CREATE MATERIALIZED VIEW ids AS SELECT id FROM plain;")
        ),
        [finding("materialized_view_exposed", Level::Warn, "ids")]
    );
}

#[test]
fn a_kept_or_protected_source_materialized_view_is_not_reported() {
    for sql in [
        "CREATE MATERIALIZED VIEW ids AS SELECT id FROM plain;",
        "CREATE MATERIALIZED VIEW ids AS SELECT id FROM plain; GRANT SELECT ON ids TO reporting;",
        "CREATE MATERIALIZED VIEW ids AS SELECT id FROM docs; GRANT SELECT ON ids TO PUBLIC;",
    ] {
        assert_eq!(
            findings(
                MaterializedViewExposed::default(),
                supabase(),
                &format!("{DOCS}{sql}")
            ),
            [],
            "{sql}"
        );
    }
}
