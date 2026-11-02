//! Materialized views, cascades, child tables, bypassing roles and role-keyed
//! policies that get around row-level security, observed through the public
//! constrainer API.

mod common;

use common::{finding, findings, parse, supabase};
use sql_rules::prelude::*;

const DOCS: &str = "
    CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    CREATE TABLE plain (id INT PRIMARY KEY);";

#[test]
fn a_materialized_view_over_a_protected_table_reached_by_a_client_is_reported() {
    for sql in [
        "CREATE MATERIALIZED VIEW doc_owners AS SELECT owner FROM docs; GRANT SELECT ON doc_owners TO anon;",
        "CREATE MATERIALIZED VIEW doc_owners AS SELECT owner FROM docs; GRANT SELECT ON doc_owners TO PUBLIC;",
        "CREATE MATERIALIZED VIEW doc_owners AS SELECT p.id FROM plain p JOIN docs d ON d.id = p.id;
         GRANT SELECT ON doc_owners TO authenticated;",
    ] {
        assert_eq!(
            findings(ReachableMaterializedView::default(), supabase(), &format!("{DOCS}{sql}")),
            [finding("ReachableMaterializedView", Level::Warn, "doc_owners")],
            "{sql}"
        );
    }
}

#[test]
fn a_materialized_view_in_an_exposed_schema_is_reached_without_a_grant() {
    let sql = format!("{DOCS}CREATE MATERIALIZED VIEW doc_owners AS SELECT owner FROM docs;");
    assert_eq!(
        findings(
            ReachableMaterializedView::default(),
            supabase().with_exposed_schema("public"),
            &sql,
        ),
        [finding(
            "ReachableMaterializedView",
            Level::Warn,
            "doc_owners"
        )]
    );
    assert_eq!(
        findings(ReachableMaterializedView::default(), supabase(), &sql),
        []
    );
}

#[test]
fn a_materialized_view_kept_from_clients_or_over_open_tables_is_not_reported() {
    for sql in [
        "CREATE MATERIALIZED VIEW doc_owners AS SELECT owner FROM docs; GRANT SELECT ON doc_owners TO reporting;",
        "CREATE MATERIALIZED VIEW doc_owners AS SELECT id FROM plain; GRANT SELECT ON doc_owners TO anon;",
        "CREATE VIEW doc_owners AS SELECT owner FROM docs; GRANT SELECT ON doc_owners TO anon;",
    ] {
        assert_eq!(
            findings(
                ReachableMaterializedView::default(),
                supabase(),
                &format!("{DOCS}{sql}")
            ),
            [],
            "{sql}"
        );
    }
}

const PARENTS: &str = "CREATE TABLE parents (id INT PRIMARY KEY);";

#[test]
fn a_cascading_delete_into_a_table_with_a_delete_policy_is_reported() {
    for policy in [
        "CREATE POLICY kids_delete ON kids FOR DELETE USING (false);",
        "CREATE POLICY kids_all ON kids USING (false);",
    ] {
        assert_eq!(
            findings(
                CascadeIntoRowLevelSecurityTable::default(),
                Deployment::default(),
                &format!(
                    "{PARENTS}
                     CREATE TABLE kids (id INT, parent_id INT REFERENCES parents (id) ON DELETE CASCADE);
                     ALTER TABLE kids ENABLE ROW LEVEL SECURITY;
                     {policy}"
                ),
            ),
            [finding(
                "CascadeIntoRowLevelSecurityTable",
                Level::Warn,
                "kids (unnamed foreign key)"
            )],
            "{policy}"
        );
    }
}

#[test]
fn every_referential_action_that_rewrites_rows_past_their_policies_is_reported() {
    for (action, policy) in [
        ("ON DELETE SET NULL", "FOR UPDATE USING (false)"),
        ("ON DELETE SET DEFAULT", "FOR UPDATE USING (false)"),
        ("ON UPDATE CASCADE", "FOR UPDATE USING (false)"),
        ("ON UPDATE SET NULL", "FOR UPDATE USING (false)"),
        ("ON UPDATE SET DEFAULT", "USING (false)"),
    ] {
        assert_eq!(
            findings(
                CascadeIntoRowLevelSecurityTable::default(),
                Deployment::default(),
                &format!(
                    "{PARENTS}
                     CREATE TABLE kids (id INT, parent_id INT DEFAULT 0 REFERENCES parents (id) {action});
                     ALTER TABLE kids ENABLE ROW LEVEL SECURITY;
                     CREATE POLICY kids_write ON kids {policy};"
                ),
            ),
            [finding(
                "CascadeIntoRowLevelSecurityTable",
                Level::Warn,
                "kids (unnamed foreign key)"
            )],
            "{action}"
        );
    }
}

#[test]
fn an_action_whose_command_has_no_policy_is_not_reported() {
    for (action, policy) in [
        ("ON DELETE SET NULL", "FOR DELETE USING (false)"),
        ("ON UPDATE CASCADE", "FOR DELETE USING (false)"),
        ("ON DELETE CASCADE", "FOR UPDATE USING (false)"),
        ("ON DELETE RESTRICT ON UPDATE RESTRICT", "USING (false)"),
    ] {
        assert_eq!(
            findings(
                CascadeIntoRowLevelSecurityTable::default(),
                Deployment::default(),
                &format!(
                    "{PARENTS}
                     CREATE TABLE kids (id INT, parent_id INT REFERENCES parents (id) {action});
                     ALTER TABLE kids ENABLE ROW LEVEL SECURITY;
                     CREATE POLICY kids_write ON kids {policy};"
                ),
            ),
            [],
            "{action} with {policy}"
        );
    }
}

#[test]
fn a_foreign_key_that_cascades_past_no_delete_policy_is_not_reported() {
    for sql in [
        "CREATE TABLE kids (id INT, parent_id INT REFERENCES parents (id));
         ALTER TABLE kids ENABLE ROW LEVEL SECURITY;
         CREATE POLICY kids_delete ON kids FOR DELETE USING (false);",
        "CREATE TABLE kids (id INT, parent_id INT REFERENCES parents (id) ON DELETE CASCADE);
         CREATE POLICY kids_delete ON kids FOR DELETE USING (false);",
        "CREATE TABLE kids (id INT, parent_id INT REFERENCES parents (id) ON DELETE CASCADE);
         ALTER TABLE kids ENABLE ROW LEVEL SECURITY;
         CREATE POLICY kids_read ON kids FOR SELECT USING (true);",
    ] {
        assert_eq!(
            findings(
                CascadeIntoRowLevelSecurityTable::default(),
                Deployment::default(),
                &format!("{PARENTS}{sql}"),
            ),
            [],
            "{sql}"
        );
    }
}

#[test]
fn a_child_without_row_level_security_under_a_protected_ancestor_is_reported() {
    let parents = "
        CREATE TABLE events (at DATE, owner TEXT) PARTITION BY RANGE (at);
        ALTER TABLE events ENABLE ROW LEVEL SECURITY;
        CREATE TABLE logs (at DATE, owner TEXT);
        ALTER TABLE logs ENABLE ROW LEVEL SECURITY;";
    assert_eq!(
        findings(
            ChildWithoutRowLevelSecurity::default(),
            Deployment::default(),
            &format!(
                "{parents}
                 CREATE TABLE events_2026 PARTITION OF events
                     FOR VALUES FROM ('2026-01-01') TO ('2027-01-01') PARTITION BY RANGE (at);
                 CREATE TABLE events_2026_h1 PARTITION OF events_2026
                     FOR VALUES FROM ('2026-01-01') TO ('2026-07-01');
                 CREATE TABLE logs_child () INHERITS (logs);"
            ),
        ),
        [
            finding("ChildWithoutRowLevelSecurity", Level::Warn, "events_2026"),
            finding(
                "ChildWithoutRowLevelSecurity",
                Level::Warn,
                "events_2026_h1"
            ),
            finding("ChildWithoutRowLevelSecurity", Level::Warn, "logs_child"),
        ]
    );
}

#[test]
fn a_protected_child_or_a_child_of_an_open_parent_is_not_reported() {
    assert_eq!(
        findings(
            ChildWithoutRowLevelSecurity::default(),
            Deployment::default(),
            "CREATE TABLE logs (at DATE, owner TEXT);
             ALTER TABLE logs ENABLE ROW LEVEL SECURITY;
             CREATE TABLE logs_child () INHERITS (logs);
             ALTER TABLE logs_child ENABLE ROW LEVEL SECURITY;
             CREATE TABLE notes (at DATE);
             CREATE TABLE notes_child () INHERITS (notes);
             CREATE TABLE drafts () INHERITS (notes);
             CREATE TABLE notes_draft () INHERITS (notes_child, drafts);",
        ),
        []
    );
}

#[test]
fn a_client_role_that_bypasses_row_level_security_is_denied() {
    for attribute in ["BYPASSRLS", "SUPERUSER"] {
        assert_eq!(
            findings(
                ClientRoleBypassesRowLevelSecurity::default(),
                Deployment::default().with_app_role("app_user"),
                &format!("CREATE ROLE app_user {attribute}; CREATE ROLE migrator BYPASSRLS;"),
            ),
            [finding(
                "ClientRoleBypassesRowLevelSecurity",
                Level::Deny,
                "app_user"
            )],
            "{attribute}"
        );
    }
}

#[test]
fn a_client_role_that_can_set_a_bypassing_role_is_reported() {
    assert_eq!(
        findings(
            SettableMembershipInBypassingRole::default(),
            Deployment::default().with_app_role("app_user"),
            "CREATE ROLE bypasser BYPASSRLS;
             CREATE ROLE staff NOINHERIT IN ROLE bypasser;
             CREATE ROLE app_user IN ROLE staff;
             CREATE ROLE other IN ROLE bypasser;",
        ),
        [finding(
            "SettableMembershipInBypassingRole",
            Level::Warn,
            "app_user"
        )]
    );
    assert_eq!(
        findings(
            SettableMembershipInBypassingRole::default(),
            Deployment::default().with_app_role("app_user"),
            "CREATE ROLE staff;
             CREATE ROLE readers IN ROLE staff;
             CREATE ROLE writers IN ROLE staff;
             CREATE ROLE app_user IN ROLE readers, writers;",
        ),
        []
    );
}

#[test]
fn bypass_rules_wait_for_a_declared_client_role() {
    let mut constrainer: GenericConstrainer<ParserDB> =
        ClientRoleBypassesRowLevelSecurity::default().into();
    constrainer.register_schema_rule(Box::new(SettableMembershipInBypassingRole::default()));
    assert_eq!(
        constrainer
            .inactive_rules()
            .iter()
            .map(|inactive| (inactive.rule().name, inactive.missing()))
            .collect::<Vec<_>>(),
        [
            (
                "ClientRoleBypassesRowLevelSecurity",
                Declaration::ClientRoles
            ),
            (
                "SettableMembershipInBypassingRole",
                Declaration::ClientRoles
            ),
        ]
    );
    let shown = constrainer.inactive_rules()[0].to_string();
    assert!(shown.contains("anonymous or app roles"), "{shown}");
    constrainer.set_deployment(Deployment::default().with_anonymous_role("anon"));
    assert!(constrainer.inactive_rules().is_empty());
}

#[test]
fn a_policy_to_the_creating_role_names_its_to_list() {
    let mut constrainer: GenericConstrainer<ParserDB> = PolicyToCreatingRole::default().into();
    constrainer.set_deployment(Deployment::default());
    let diagnostics = constrainer.diagnostics(&parse(&format!(
        "{DOCS}CREATE POLICY mine ON docs TO CURRENT_USER USING (true);"
    )));
    let [Error::Violation(violation)] = diagnostics.as_slice() else {
        panic!("expected one violation");
    };
    let Location::Policies(sites) = violation.location() else {
        panic!("expected policy sites");
    };
    assert_eq!(
        sites
            .iter()
            .map(|site| (site.clause(), site.expression()))
            .collect::<Vec<_>>(),
        [(PolicyClause::To, "CURRENT_USER")]
    );
    assert!(
        sites[0].to_string().contains("TO: CURRENT_USER"),
        "{}",
        sites[0]
    );
}

#[test]
fn a_policy_to_the_creating_role_is_reported_in_any_deployment() {
    for role in ["CURRENT_USER", "SESSION_USER", "CURRENT_ROLE"] {
        assert_eq!(
            findings(
                PolicyToCreatingRole::default(),
                Deployment::default(),
                &format!("{DOCS}CREATE POLICY mine ON docs TO {role} USING (true);"),
            ),
            [finding("PolicyToCreatingRole", Level::Warn, "docs.mine")],
            "{role}"
        );
    }
    assert_eq!(
        findings(
            PolicyToCreatingRole::default(),
            Deployment::default(),
            &format!("{DOCS}CREATE POLICY mine ON docs TO authenticated USING (true);"),
        ),
        []
    );
}

#[test]
fn a_role_keyed_clause_is_reported_only_when_the_deployment_is_pooled() {
    let sql = format!(
        "{DOCS}CREATE POLICY mine ON docs USING (owner = current_user);
         CREATE POLICY theirs ON docs FOR UPDATE USING (true) WITH CHECK (owner = session_user);"
    );
    assert_eq!(
        findings(
            RoleKeyedPolicyWhenPooled::default(),
            Deployment::default().with_pooled(true),
            &sql,
        ),
        [
            finding("RoleKeyedPolicyWhenPooled", Level::Warn, "docs.mine"),
            finding("RoleKeyedPolicyWhenPooled", Level::Warn, "docs.theirs"),
        ]
    );
    assert_eq!(
        findings(
            RoleKeyedPolicyWhenPooled::default(),
            Deployment::default().with_pooled(false),
            &sql,
        ),
        []
    );
    let constrainer: GenericConstrainer<ParserDB> = RoleKeyedPolicyWhenPooled::default().into();
    assert_eq!(
        constrainer
            .inactive_rules()
            .iter()
            .map(InactiveRule::missing)
            .collect::<Vec<_>>(),
        [Declaration::Pooled]
    );
    let shown = constrainer.inactive_rules()[0].to_string();
    assert!(shown.contains("pooled"), "{shown}");
}

#[test]
fn a_credential_keyed_clause_is_not_role_keyed() {
    assert_eq!(
        findings(
            RoleKeyedPolicyWhenPooled::default(),
            Deployment::default().with_pooled(true),
            &format!(
                "{DOCS}CREATE POLICY mine ON docs USING (owner = current_setting('app.user_id', true));"
            ),
        ),
        []
    );
}
