//! Foreign keys that tell a client role whether a row it cannot read exists,
//! observed through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

const SECRETS: &str = "CREATE ROLE app;
    CREATE TABLE secrets (id INT PRIMARY KEY);
    ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
    CREATE POLICY secrets_none ON secrets FOR SELECT TO app USING (false);";

const NOTES: &str = "CREATE TABLE notes (
        id INT PRIMARY KEY,
        secret_id INT CONSTRAINT notes_secret REFERENCES secrets (id)
    );";

/// Object and message of every finding on `sql`, after the secrets table.
fn reported(sql: &str) -> Vec<(String, String)> {
    let mut constrainer: GenericConstrainer<ParserDB> = ForeignKeyExistenceOracle::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("app"));
    findings(
        &constrainer,
        "foreign_key_existence_oracle",
        &format!("{SECRETS} {sql}"),
    )
    .into_iter()
    .map(|(_, object, message)| (object, message))
    .collect()
}

/// Objects of every finding on `sql`, after the secrets table.
fn objects(sql: &str) -> Vec<String> {
    reported(sql)
        .into_iter()
        .map(|(object, _)| object)
        .collect()
}

#[test]
fn a_key_the_writer_may_insert_into_hidden_rows_is_reported() {
    let findings = reported(&format!("{NOTES} GRANT INSERT ON notes TO app;"));
    assert_eq!(findings.len(), 1);
    let (object, message) = &findings[0];
    assert_eq!(object, "notes.notes_secret");
    assert!(message.contains("'app'"), "{message}");
    assert!(message.contains("INSERT"), "{message}");
    assert_eq!(
        objects(
            "CREATE TABLE notes (id INT PRIMARY KEY,
               secret_id INT CONSTRAINT notes_secret REFERENCES secrets (id) NOT ENFORCED);
             GRANT INSERT ON notes TO app;"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_parent_read_through_policies_the_writer_cannot_evaluate_hides_every_row() {
    for (granted, expected) in [
        ("GRANT SELECT ON flags TO app;", vec![]),
        ("", vec!["refs.refs_shown"]),
    ] {
        assert_eq!(
            objects(&format!(
                "CREATE TABLE flags (id INT);
                 CREATE TABLE shown (id INT PRIMARY KEY);
                 ALTER TABLE shown ENABLE ROW LEVEL SECURITY;
                 GRANT SELECT ON shown TO app;
                 CREATE POLICY shown_all ON shown FOR SELECT TO app USING (true);
                 CREATE POLICY shown_flagged ON shown FOR SELECT TO app
                   USING (EXISTS (SELECT 1 FROM flags));
                 CREATE TABLE refs (id INT PRIMARY KEY,
                   shown_id INT CONSTRAINT refs_shown REFERENCES shown (id));
                 GRANT INSERT ON refs TO app;
                 {granted}"
            )),
            expected,
            "{granted}"
        );
    }
}

#[test]
fn updating_the_key_columns_alone_is_enough() {
    assert_eq!(
        objects(&format!(
            "{NOTES} GRANT UPDATE (secret_id) ON notes TO app;"
        )),
        ["notes.notes_secret"]
    );
    assert_eq!(
        objects(&format!("{NOTES} GRANT INSERT ON notes TO PUBLIC;")),
        ["notes.notes_secret"]
    );
}

#[test]
fn a_writer_that_cannot_set_the_key_is_clean() {
    assert_eq!(objects(NOTES), Vec::<String>::new());
    assert_eq!(
        objects(&format!(
            "{NOTES} GRANT INSERT (id), UPDATE (id), SELECT ON notes TO app;"
        )),
        Vec::<String>::new()
    );
    let composite = "CREATE TABLE pairs (a INT, b INT, PRIMARY KEY (a, b));
        ALTER TABLE pairs ENABLE ROW LEVEL SECURITY;
        CREATE TABLE links (a INT, b INT, CONSTRAINT links_pair FOREIGN KEY (a, b) REFERENCES pairs (a, b));
        GRANT INSERT (a) ON links TO app;";
    assert_eq!(objects(composite), Vec::<String>::new());
}

#[test]
fn a_referenced_table_the_writer_reads_whole_is_clean() {
    assert_eq!(
        objects(&format!(
            "CREATE POLICY secrets_all ON secrets FOR SELECT TO app USING (true);
             {NOTES} GRANT INSERT ON notes TO app;"
        )),
        Vec::<String>::new()
    );
    let open = "CREATE TABLE shown (id INT PRIMARY KEY);
        CREATE TABLE refs (shown_id INT CONSTRAINT refs_shown REFERENCES shown (id));
        GRANT INSERT ON refs TO app;";
    assert_eq!(objects(open), Vec::<String>::new());
    assert_eq!(
        objects(&format!(
            "CREATE POLICY secrets_all ON secrets FOR SELECT TO app USING (true);
             CREATE POLICY secrets_any ON secrets AS RESTRICTIVE FOR SELECT TO app USING (true);
             {NOTES} GRANT INSERT ON notes TO app;"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn an_owner_reads_every_row_and_a_recursive_read_hides_them_all() {
    assert_eq!(
        objects(&format!(
            "ALTER TABLE secrets OWNER TO app;
             {NOTES} GRANT INSERT ON notes TO app;"
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        objects(&format!(
            "CREATE POLICY secrets_self ON secrets FOR SELECT TO app
               USING (id IN (SELECT id FROM secrets));
             {NOTES} GRANT INSERT ON notes TO app;"
        )),
        ["notes.notes_secret"]
    );
    assert_eq!(
        objects(&format!(
            "CREATE POLICY secrets_self ON secrets FOR SELECT TO app
               USING (id IN (SELECT id FROM secrets));
             {NOTES} GRANT INSERT ON notes TO app;
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (true);"
        )),
        ["notes.notes_secret"]
    );
}

#[test]
fn a_restrictive_policy_still_hides_rows_behind_a_true_one() {
    assert_eq!(
        objects(&format!(
            "CREATE POLICY secrets_all ON secrets FOR SELECT TO app USING (true);
             CREATE POLICY secrets_mine ON secrets AS RESTRICTIVE FOR SELECT TO app USING (id > 0);
             {NOTES} GRANT INSERT ON notes TO app;"
        )),
        ["notes.notes_secret"]
    );
}

#[test]
fn row_security_refusing_the_write_is_clean() {
    assert_eq!(
        objects(&format!(
            "{NOTES} GRANT INSERT, UPDATE ON notes TO app;
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_read ON notes FOR SELECT TO app USING (true);"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn a_write_whose_policies_the_schema_cannot_settle_is_not_reported() {
    assert_eq!(
        objects(&format!(
            "{NOTES} GRANT INSERT ON notes TO app;
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_write ON notes FOR INSERT TO CURRENT_USER WITH CHECK (true);"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn a_check_confining_the_key_to_rows_the_writer_reads_is_clean() {
    for check in [
        "secret_id IN (SELECT id FROM secrets)",
        "secret_id = ANY (ARRAY(SELECT id FROM secrets)) AND id > 0",
        "secret_id IN (SELECT id FROM secrets) OR (id > 0 AND secret_id = (SELECT id FROM secrets))",
        "EXISTS (SELECT 1 FROM secrets s WHERE s.id = notes.secret_id)",
        "EXISTS (SELECT 1 FROM secrets s WHERE s.id = notes.secret_id AND s.id > 0)",
    ] {
        assert_eq!(
            objects(&format!(
                "{NOTES} GRANT INSERT ON notes TO app;
                 ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK ({check});"
            )),
            Vec::<String>::new(),
            "{check}"
        );
    }
}

#[test]
fn a_function_confines_the_key_to_the_rows_the_referenced_policies_admit_through_it() {
    let named = "CREATE POLICY secrets_named ON secrets FOR SELECT TO app
        USING (id = ANY (ARRAY(SELECT allowed_secrets())) OR id = caller_secret());";
    for check in [
        "secret_id = ANY (ARRAY(SELECT allowed_secrets()))",
        "secret_id IN (SELECT allowed_secrets())",
        "secret_id = (SELECT caller_secret())",
        "secret_id = caller_secret() AND id > 0",
        "caller_secret() = secret_id",
        "secret_id = caller_secret() OR secret_id = ANY (ARRAY(SELECT allowed_secrets()))",
    ] {
        for (policies, expected) in [(named, vec![]), ("", vec!["notes.notes_secret"])] {
            assert_eq!(
                objects(&format!(
                    "CREATE FUNCTION allowed_secrets() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT 1 $$;
                     CREATE FUNCTION caller_secret() RETURNS INT LANGUAGE sql AS $$ SELECT 1 $$;
                     {policies}
                     {NOTES} GRANT INSERT ON notes TO app;
                     ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
                     CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK ({check});"
                )),
                expected,
                "{check} after {policies}"
            );
        }
    }
}

#[test]
fn a_check_leaving_the_key_free_is_reported() {
    for policies in [
        "CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (id > 0);",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (secret_id = id);",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (secret_id = ANY (ARRAY(SELECT id FROM notes)));",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (secret_id NOT IN (SELECT id FROM secrets));",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (secret_id IN (SELECT id FROM secrets) OR id > 0);",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (secret_id IN (SELECT id FROM secrets UNION SELECT id FROM notes));",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK ((secret_id, id) IN (SELECT secret_id, 1));",
        // A second permissive arm admits the row without confining the key.
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (secret_id IN (SELECT id FROM secrets));
         CREATE POLICY notes_admin ON notes FOR INSERT TO app WITH CHECK (true);",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (secret_id = abs(secret_id));",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (secret_id = coalesce(secret_id, 0));",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (secret_id IN (SELECT s FROM generate_series(secret_id, secret_id) AS s));",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (EXISTS (SELECT 1 FROM notes n WHERE n.id = notes.secret_id));",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (EXISTS (SELECT 1 FROM secrets));",
        "CREATE POLICY notes_write ON notes FOR INSERT TO app
           WITH CHECK (EXISTS (SELECT 1 FROM secrets s WHERE s.id = notes.secret_id UNION SELECT 1));",
    ] {
        assert_eq!(
            objects(&format!(
                "{NOTES} GRANT INSERT ON notes TO app;
                 ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
                 {policies}"
            )),
            ["notes.notes_secret"],
            "{policies}"
        );
    }
}

const PAIRS: &str = "CREATE TABLE pairs (a INT, b INT, PRIMARY KEY (a, b));
    ALTER TABLE pairs ENABLE ROW LEVEL SECURITY;";

#[test]
fn a_composite_key_needs_every_column_confined() {
    for (check, expected) in [
        ("a IN (SELECT a FROM pairs)", vec!["links.links_pair"]),
        (
            "b = ANY (ARRAY(SELECT b FROM pairs))",
            vec!["links.links_pair"],
        ),
        ("(a, b) IN (SELECT a, b FROM pairs)", vec![]),
        (
            "a IN (SELECT a FROM pairs) AND b IN (SELECT b FROM pairs)",
            vec![],
        ),
        (
            "(a, b) IN (SELECT a, b FROM pairs) OR a IN (SELECT a FROM pairs)",
            vec!["links.links_pair"],
        ),
    ] {
        assert_eq!(
            objects(&format!(
                "{PAIRS}
                 CREATE TABLE links (a INT, b INT, CONSTRAINT links_pair FOREIGN KEY (a, b) REFERENCES pairs (a, b));
                 GRANT INSERT ON links TO app;
                 ALTER TABLE links ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY links_write ON links FOR INSERT TO app WITH CHECK ({check});"
            )),
            expected,
            "{check}"
        );
    }
}

#[test]
fn updating_one_column_of_a_key_completed_by_a_stored_one_is_reported() {
    for (a, expected) in [
        ("a INT NOT NULL", vec!["links.links_pair"]),
        ("a INT", vec![]),
    ] {
        assert_eq!(
            objects(&format!(
                "{PAIRS}
                 CREATE TABLE links ({a}, b INT, CONSTRAINT links_pair FOREIGN KEY (a, b) REFERENCES pairs (a, b));
                 GRANT UPDATE (b) ON links TO app;"
            )),
            expected,
            "{a}"
        );
    }
}

#[test]
fn a_restrictive_check_confines_every_arm() {
    assert_eq!(
        objects(&format!(
            "{NOTES} GRANT INSERT ON notes TO app;
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (true);
             CREATE POLICY notes_key ON notes AS RESTRICTIVE FOR INSERT TO app
               WITH CHECK (secret_id IN (SELECT id FROM secrets));"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn an_update_reported_through_its_own_check() {
    assert_eq!(
        objects(&format!(
            "{NOTES} GRANT INSERT, UPDATE ON notes TO app;
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_insert ON notes FOR INSERT TO app
               WITH CHECK (secret_id IN (SELECT id FROM secrets));
             CREATE POLICY notes_update ON notes FOR UPDATE TO app USING (true);"
        )),
        ["notes.notes_secret"]
    );
}

const RESOURCES: &str = "CREATE TABLE resources (
        id INT PRIMARY KEY,
        organization_id INT NOT NULL,
        owner_id INT NOT NULL,
        UNIQUE (organization_id, id)
    );
    ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
    CREATE POLICY resources_select ON resources FOR SELECT TO app USING (owner_id = 1);
    CREATE TABLE grants (
        id INT PRIMARY KEY,
        organization_id INT NOT NULL,
        resource_id INT NOT NULL,
        CONSTRAINT grants_resource FOREIGN KEY (organization_id, resource_id)
            REFERENCES resources (organization_id, id)
    );
    GRANT INSERT ON grants TO app;
    ALTER TABLE grants ENABLE ROW LEVEL SECURITY;";

#[test]
fn a_check_pinning_a_unique_referenced_column_to_a_readable_row_is_clean() {
    for (check, expected) in [
        ("resource_id IN (SELECT id FROM resources)", vec![]),
        (
            "resource_id IN (SELECT resource.id FROM resources resource WHERE resource.owner_id = 1)",
            vec![],
        ),
        (
            "resource_id = ANY (ARRAY(SELECT id FROM resources))",
            vec![],
        ),
        ("resource_id = ANY (SELECT id FROM resources)", vec![]),
        (
            "resource_id = ANY (ARRAY[1, 2])",
            vec!["grants.grants_resource"],
        ),
        ("resource_id = (SELECT id FROM resources LIMIT 1)", vec![]),
        ("(resource_id, id) IN (SELECT id, 1 FROM resources)", vec![]),
        // The wildcard expands to three columns, so `resource_id` meets `organization_id`.
        (
            "(id, resource_id, id, id) IN (SELECT *, id FROM resources)",
            vec!["grants.grants_resource"],
        ),
        (
            "id > 0 AND resource_id IN (SELECT id FROM resources)",
            vec![],
        ),
        (
            "EXISTS (SELECT 1 FROM resources resource WHERE resource.id = grants.resource_id)",
            vec![],
        ),
        (
            "resource_id IN (SELECT owner_id FROM resources)",
            vec!["grants.grants_resource"],
        ),
        (
            "organization_id IN (SELECT organization_id FROM resources)",
            vec!["grants.grants_resource"],
        ),
        (
            "resource_id IN (SELECT id FROM grants)",
            vec!["grants.grants_resource"],
        ),
        (
            "resource_id IN (SELECT id FROM resources UNION SELECT 1)",
            vec!["grants.grants_resource"],
        ),
        // The projected name resolves to the written row, which resources lacks.
        (
            "resource_id IN (SELECT resource_id FROM resources)",
            vec!["grants.grants_resource"],
        ),
        (
            "EXISTS (SELECT 1 FROM resources resource WHERE resource.owner_id = grants.resource_id)",
            vec!["grants.grants_resource"],
        ),
    ] {
        assert_eq!(
            objects(&format!(
                "{RESOURCES}
                 CREATE POLICY grants_insert ON grants FOR INSERT TO app WITH CHECK ({check});"
            )),
            expected,
            "{check}"
        );
    }
}

#[test]
fn a_composite_unique_subset_is_pinned_only_from_one_row() {
    for (deferral, check, expected) in [
        ("", "(a, b) IN (SELECT a, b FROM slots)", vec![]),
        (
            " DEFERRABLE INITIALLY DEFERRED",
            "(a, b) IN (SELECT a, b FROM slots)",
            vec!["uses.uses_slot"],
        ),
        ("", "(b, a) IN (SELECT s.b, s.a FROM slots s)", vec![]),
        (
            "",
            "EXISTS (SELECT 1 FROM slots s WHERE s.a = uses.a AND uses.b = s.b)",
            vec![],
        ),
        (
            "",
            "(a, b) IN (SELECT b, a FROM slots)",
            vec!["uses.uses_slot"],
        ),
        (
            "",
            "a IN (SELECT a FROM slots) AND b IN (SELECT b FROM slots)",
            vec!["uses.uses_slot"],
        ),
        (
            "",
            "(a, b) IN (SELECT x.a, y.b FROM slots x, slots y)",
            vec!["uses.uses_slot"],
        ),
        (
            "",
            "EXISTS (SELECT 1 FROM slots x, slots y WHERE x.a = uses.a AND y.b = uses.b)",
            vec!["uses.uses_slot"],
        ),
    ] {
        assert_eq!(
            objects(&format!(
                "CREATE TABLE slots (a INT, b INT, c INT, UNIQUE (a, b){deferral}, UNIQUE (a, b, c));
                 ALTER TABLE slots ENABLE ROW LEVEL SECURITY;
                 CREATE TABLE uses (a INT, b INT, c INT,
                     CONSTRAINT uses_slot FOREIGN KEY (a, b, c) REFERENCES slots (a, b, c));
                 GRANT INSERT ON uses TO app;
                 ALTER TABLE uses ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY uses_write ON uses FOR INSERT TO app WITH CHECK ({check});"
            )),
            expected,
            "{deferral} {check}"
        );
    }
}

#[test]
fn an_arm_forcing_a_key_column_null_checks_nothing() {
    for match_kind in ["", "MATCH SIMPLE", "MATCH FULL"] {
        for (check, expected) in [
            (
                "invitation_id IS NULL OR (organization_id, invitation_id) IN (SELECT organization_id, id FROM invitations)",
                vec![],
            ),
            ("invitation_id IS NULL", vec![]),
            (
                "invitation_id IS NULL OR id > 0",
                vec!["memberships.memberships_invitation"],
            ),
            (
                "note IS NULL OR (organization_id, invitation_id) IN (SELECT organization_id, id FROM invitations)",
                vec!["memberships.memberships_invitation"],
            ),
            (
                "invitation_id IS NOT NULL OR (organization_id, invitation_id) IN (SELECT organization_id, id FROM invitations)",
                vec!["memberships.memberships_invitation"],
            ),
        ] {
            assert_eq!(
                objects(&format!(
                    "CREATE TABLE invitations (organization_id INT, id INT, PRIMARY KEY (organization_id, id));
                     ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
                     CREATE TABLE memberships (id INT PRIMARY KEY, organization_id INT NOT NULL, invitation_id INT, note TEXT,
                         CONSTRAINT memberships_invitation FOREIGN KEY (organization_id, invitation_id)
                             REFERENCES invitations (organization_id, id) {match_kind});
                     GRANT INSERT ON memberships TO app;
                     ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
                     CREATE POLICY memberships_write ON memberships FOR INSERT TO app WITH CHECK ({check});"
                )),
                expected,
                "{match_kind} {check}"
            );
        }
    }
}

#[test]
fn an_arm_whose_table_checks_force_a_key_column_null_checks_nothing() {
    let pinned = "(kind IN ('folder', 'project') AND id > 0)
        OR (kind = 'owned' AND created_by_id = caller_id())
        OR kind = 'root'";
    let discriminated = "CHECK ((kind = 'owned') = (created_by_id IS NOT NULL))";
    for (kind, check, policy, expected) in [
        ("kind TEXT NOT NULL", discriminated, pinned, vec![]),
        ("kind TEXT", discriminated, pinned, vec![]),
        (
            "kind TEXT NOT NULL",
            "CHECK (kind = 'owned' OR created_by_id IS NULL)",
            pinned,
            vec![],
        ),
        (
            "kind TEXT NOT NULL",
            discriminated,
            "kind IN ('folder', 'owned') OR (kind = 'owned' AND created_by_id = caller_id())",
            vec!["items.items_creator"],
        ),
        (
            "kind TEXT NOT NULL",
            "CHECK ((kind = 'owned') = (created_by_id IS NOT NULL)) NOT ENFORCED",
            pinned,
            vec!["items.items_creator"],
        ),
    ] {
        assert_eq!(
            objects(&format!(
                "CREATE FUNCTION caller_id() RETURNS INT LANGUAGE sql STABLE AS
                   $$ SELECT current_setting('app.user_id')::int $$;
                 CREATE TABLE people (id INT PRIMARY KEY);
                 ALTER TABLE people ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY people_select ON people FOR SELECT TO app USING (id = caller_id());
                 CREATE TABLE items (id INT PRIMARY KEY, {kind},
                   created_by_id INT CONSTRAINT items_creator REFERENCES people (id), {check});
                 ALTER TABLE items ENABLE ROW LEVEL SECURITY;
                 GRANT INSERT ON items TO app;
                 CREATE POLICY items_insert ON items FOR INSERT TO app WITH CHECK ({policy});"
            )),
            expected,
            "{kind} {check} {policy}"
        );
    }
}

#[test]
fn an_arm_whose_table_checks_force_one_column_of_a_composite_key_null_checks_nothing() {
    for (check, expected) in [
        ("kind = 'owned' OR owner_id IS NULL", vec![]),
        ("kind = 'owned' OR owner_id > 0", vec!["items.items_owner"]),
    ] {
        assert_eq!(
            objects(&format!(
                "CREATE TABLE members (team_id INT, id INT, PRIMARY KEY (team_id, id));
                 ALTER TABLE members ENABLE ROW LEVEL SECURITY;
                 CREATE TABLE items (id INT PRIMARY KEY, kind TEXT NOT NULL, team_id INT, owner_id INT,
                   CONSTRAINT items_owner FOREIGN KEY (team_id, owner_id) REFERENCES members (team_id, id),
                   CHECK ({check}));
                 ALTER TABLE items ENABLE ROW LEVEL SECURITY;
                 GRANT INSERT ON items TO app;
                 CREATE POLICY items_insert ON items FOR INSERT TO app WITH CHECK (kind = 'folder');"
            )),
            expected,
            "{check}"
        );
    }
}

const SLOTS_READ: &str = "template_id = ANY (ARRAY(SELECT readable('reader')))";

/// A typed template whose slot key reaches slots `readable` admits, after a
/// restrictive policy hiding blocked organizations, with the objects
/// `helpers` defines ahead of the tables.
fn slot_schema(readable: &str, check: &str, key: &str, referenced: &str, helpers: &str) -> String {
    format!(
        "CREATE ROLE app;
         CREATE FUNCTION readable(level TEXT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;
         CREATE FUNCTION reader_ids() RETURNS INT[] LANGUAGE sql STABLE AS $$ SELECT ARRAY[1] $$;
         CREATE FUNCTION blocking() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;
         {helpers}
         CREATE TABLE slots (id INT PRIMARY KEY, template_id INT NOT NULL, organization_id INT NOT NULL,
             UNIQUE (id, template_id), UNIQUE (id, template_id, organization_id));
         ALTER TABLE slots ENABLE ROW LEVEL SECURITY;
         CREATE POLICY slots_select ON slots FOR SELECT TO app USING ({readable});
         CREATE POLICY slots_blocked ON slots AS RESTRICTIVE FOR ALL TO app
             USING (NOT (organization_id = ANY (ARRAY(SELECT blocking()))));
         CREATE TABLE typed_templates (id INT PRIMARY KEY, organization_id INT NOT NULL, slot_id INT NOT NULL,
             CONSTRAINT typed_slot FOREIGN KEY ({key}) REFERENCES slots ({referenced}));
         ALTER TABLE typed_templates ENABLE ROW LEVEL SECURITY;
         CREATE POLICY typed_insert ON typed_templates FOR INSERT TO app WITH CHECK ({check});
         CREATE POLICY typed_blocked ON typed_templates AS RESTRICTIVE FOR ALL TO app
             USING (NOT (organization_id = ANY (ARRAY(SELECT blocking()))))
             WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT blocking()))));
         GRANT SELECT ON slots TO app;
         GRANT INSERT ON typed_templates TO app;"
    )
}

#[test]
fn a_key_column_confined_to_the_set_its_referenced_rows_are_read_through_is_clean() {
    let whole = (
        "slot_id, id, organization_id",
        "id, template_id, organization_id",
    );
    for (check, (key, referenced), declared, expected) in [
        (
            "id = ANY (ARRAY(SELECT readable('reader')))",
            whole,
            false,
            vec![],
        ),
        ("id IN (SELECT readable('reader'))", whole, false, vec![]),
        (
            "id IS NULL OR id = ANY (ARRAY(SELECT readable('reader')))",
            whole,
            false,
            vec![],
        ),
        (
            "slot_id IS NULL OR id = ANY (ARRAY(SELECT readable('reader')))",
            whole,
            false,
            vec![],
        ),
        (
            "id IS NOT NULL OR id = ANY (ARRAY(SELECT readable('reader')))",
            whole,
            false,
            vec!["typed_templates.typed_slot"],
        ),
        (
            "id = ANY (ARRAY(SELECT readable('writer')))",
            whole,
            true,
            vec![],
        ),
        (
            "id = ANY (ARRAY(SELECT readable('writer')))",
            whole,
            false,
            vec!["typed_templates.typed_slot"],
        ),
        (
            "id = ANY (ARRAY(SELECT readable('reader')))",
            ("slot_id, id", "id, template_id"),
            false,
            vec!["typed_templates.typed_slot"],
        ),
        (
            "id = ANY (ARRAY(SELECT readable('any')))",
            whole,
            true,
            vec!["typed_templates.typed_slot"],
        ),
        (
            "id = ANY (ARRAY(SELECT readable('reader'))) OR id > 0",
            whole,
            false,
            vec!["typed_templates.typed_slot"],
        ),
    ] {
        let mut deployment = Deployment::default().with_app_role("app");
        if declared {
            deployment = deployment
                .with_set_within("readable('writer')", "readable('editor')")
                .unwrap()
                .with_set_within("readable('editor')", "readable('reader')")
                .unwrap();
        }
        let mut constrainer: GenericConstrainer<ParserDB> =
            ForeignKeyExistenceOracle::default().into();
        constrainer.set_deployment(deployment);
        let objects: Vec<String> = findings(
            &constrainer,
            "foreign_key_existence_oracle",
            &slot_schema(SLOTS_READ, check, key, referenced, ""),
        )
        .into_iter()
        .map(|(_, object, _)| object)
        .collect();
        assert_eq!(objects, expected, "{check} on ({key})");
    }
}

#[test]
fn a_referenced_policy_implied_through_the_key_part_by_part_is_clean() {
    let blocked = "NOT (organization_id = ANY (ARRAY(SELECT blocking())))";
    let both = format!("({SLOTS_READ}) AND ({blocked})");
    let reader = "id = ANY (ARRAY(SELECT readable('reader')))";
    for (readable, check, expected) in [
        (both.as_str(), reader.to_owned(), vec![]),
        (both.as_str(), format!("{reader} AND {blocked}"), vec![]),
        (
            "(template_id = ANY (reader_ids()))",
            "id = ANY (reader_ids())".to_owned(),
            vec![],
        ),
        (
            "template_id IN (SELECT readable('reader') LIMIT 1)",
            "id IN (SELECT readable('reader'))".to_owned(),
            vec!["typed_templates.typed_slot"],
        ),
    ] {
        let mut constrainer: GenericConstrainer<ParserDB> =
            ForeignKeyExistenceOracle::default().into();
        constrainer.set_deployment(Deployment::default().with_app_role("app"));
        let objects: Vec<String> = findings(
            &constrainer,
            "foreign_key_existence_oracle",
            &slot_schema(
                readable,
                &check,
                "slot_id, id, organization_id",
                "id, template_id, organization_id",
                "",
            ),
        )
        .into_iter()
        .map(|(_, object, _)| object)
        .collect();
        assert_eq!(objects, expected, "{check} into {readable}");
    }
}

/// The typed templates [`slot_schema`] reports under `readable` and `check`,
/// beside `walk()`, a helper selecting `body` over `steps`, which links each
/// template to the templates below it, `seeded()`, a walk from
/// `readable('reader')`, and `leveled(level)`, a walk from `readable(level)`.
fn walked_slots(readable: &str, body: &str, check: &str) -> Vec<String> {
    let seeded = walk_from("SELECT readable('reader')", "SELECT walked.id FROM walked");
    let leveled = walk_from("SELECT readable(level)", "SELECT walked.id FROM walked");
    let sql = slot_schema(
        readable,
        check,
        "slot_id, id, organization_id",
        "id, template_id, organization_id",
        &format!(
            "CREATE TABLE steps (parent_id INT NOT NULL, child_id INT NOT NULL);
             GRANT SELECT ON steps TO app;
             CREATE FUNCTION readable_rows(level TEXT) RETURNS TABLE (template INT)
               LANGUAGE sql STABLE AS $$ SELECT 1 $$;
             CREATE FUNCTION readable_pairs(level TEXT) RETURNS TABLE (template INT, organization INT)
               LANGUAGE sql STABLE AS $$ SELECT 1, 1 $$;
             CREATE FUNCTION seeded() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ {seeded} $$;
             CREATE FUNCTION leveled(level TEXT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$ {leveled} $$;
             CREATE FUNCTION walk() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ {body} $$;"
        ),
    );
    let mut constrainer: GenericConstrainer<ParserDB> = ForeignKeyExistenceOracle::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("app"));
    findings(&constrainer, "foreign_key_existence_oracle", &sql)
        .into_iter()
        .map(|(_, object, _)| object)
        .collect()
}

const WALKED: &str = "template_id = ANY (ARRAY(SELECT walk()))";

/// A recursive walk over `steps` from the arms `seeds`, reselected by
/// `outer`.
fn walk_from(seeds: &str, outer: &str) -> String {
    format!(
        "WITH RECURSIVE walked (id) AS ({seeds} UNION SELECT step.child_id FROM steps step
         JOIN walked ON walked.id = step.parent_id) {outer}"
    )
}

const READER: &str = "id = ANY (ARRAY(SELECT readable('reader')))";

#[test]
fn a_key_confined_to_the_seed_of_a_recursive_helper_the_referenced_rows_are_read_through_is_clean()
{
    let aliased = "SELECT granted.id FROM readable('reader') granted (id)";
    let outer = "SELECT walked.id FROM walked";
    for (body, check) in [
        (aliased.to_owned(), READER),
        (walk_from("SELECT readable('reader')", outer), READER),
        (walk_from(aliased, outer), READER),
        (
            walk_from(&format!("SELECT readable('writer') UNION {aliased}"), outer),
            READER,
        ),
        (walk_from("(SELECT readable('reader'))", outer), READER),
        (walk_from(aliased, "SELECT id FROM walked"), READER),
        (walk_from(aliased, "SELECT * FROM walked"), READER),
        (
            walk_from(aliased, "SELECT renamed.other FROM walked renamed (other)"),
            READER,
        ),
        (
            format!(
                "WITH RECURSIVE unread (id) AS (SELECT 1),
                 walked (id) AS ({aliased} UNION SELECT step.child_id FROM steps step
                 JOIN walked ON walked.id = step.parent_id) {outer}"
            ),
            READER,
        ),
        (walk_from("SELECT seeded()", outer), READER),
        (format!("SELECT readable('writer') UNION {aliased}"), READER),
        (
            format!("SELECT step.child_id FROM steps step UNION ({aliased})"),
            READER,
        ),
        (
            "SELECT granted.id FROM readable_rows('reader') granted (id)".to_owned(),
            "id IN (SELECT readable_rows('reader'))",
        ),
    ] {
        assert_eq!(
            walked_slots(WALKED, &body, check),
            Vec::<String>::new(),
            "{body} under {check}"
        );
    }
    assert_eq!(
        walked_slots(
            "template_id = ANY (ARRAY(SELECT leveled('reader')))",
            aliased,
            READER
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_key_a_recursive_helper_may_not_reach_is_reported() {
    let seed = "SELECT readable('reader')";
    let pairs = "id IN (SELECT readable_pairs('reader'))";
    for (readable, body, check) in [
        (
            WALKED,
            walk_from("SELECT readable('writer')", "SELECT walked.id FROM walked"),
            READER,
        ),
        (
            WALKED,
            walk_from(seed, "SELECT walked.id FROM walked WHERE walked.id > 0"),
            READER,
        ),
        (
            WALKED,
            walk_from(seed, "SELECT walked.id FROM walked LIMIT 1"),
            READER,
        ),
        (
            WALKED,
            walk_from(seed, "SELECT step.child_id FROM steps step"),
            READER,
        ),
        (WALKED, walk_from(seed, "VALUES (1)"), READER),
        (
            WALKED,
            walk_from(seed, "SELECT walked.id FROM walked, steps"),
            READER,
        ),
        (
            WALKED,
            walk_from(
                seed,
                "SELECT walked.id FROM walked TABLESAMPLE BERNOULLI (50)",
            ),
            READER,
        ),
        (
            WALKED,
            walk_from(seed, "SELECT walked.id + 1 FROM walked"),
            READER,
        ),
        (
            WALKED,
            "WITH RECURSIVE walked (id) AS (SELECT readable('reader') INTERSECT
             SELECT step.child_id FROM steps step) SELECT walked.id FROM walked"
                .to_owned(),
            READER,
        ),
        (
            WALKED,
            "WITH RECURSIVE walked (id) AS (SELECT step.child_id FROM steps step UNION
             SELECT granted.id FROM readable('reader') granted (id) JOIN walked ON walked.id = granted.id)
             SELECT walked.id FROM walked"
                .to_owned(),
            READER,
        ),
        (
            WALKED,
            "SELECT granted.id FROM readable('reader') granted (id) WHERE granted.id > 0".to_owned(),
            READER,
        ),
        (
            WALKED,
            "SELECT granted.id FROM reader_ids() granted (id)".to_owned(),
            "id = ANY (reader_ids())",
        ),
        (
            WALKED,
            "SELECT granted.id FROM readable_pairs('reader') granted (id)".to_owned(),
            pairs,
        ),
        (
            WALKED,
            "SELECT granted.id FROM readable_pairs('reader') granted (id, organization)".to_owned(),
            pairs,
        ),
        (
            SLOTS_READ,
            walk_from(seed, "SELECT walked.id FROM walked"),
            "id = ANY (ARRAY(SELECT walk()))",
        ),
        (
            "template_id = ANY (ARRAY(SELECT leveled('writer')))",
            walk_from(seed, "SELECT walked.id FROM walked"),
            READER,
        ),
        (
            WALKED,
            "SELECT readable('reader') INTERSECT SELECT step.child_id FROM steps step".to_owned(),
            READER,
        ),
    ] {
        assert_eq!(
            walked_slots(readable, &body, check),
            vec!["typed_templates.typed_slot"],
            "{body} under {check}"
        );
    }
}

/// The typed templates [`slot_schema`] reports when the slots policy states
/// `readable`, the check states `check` and `helpers` defines the helpers
/// both read.
fn read_through(readable: &str, check: &str, helpers: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = ForeignKeyExistenceOracle::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("app"));
    findings(
        &constrainer,
        "foreign_key_existence_oracle",
        &slot_schema(
            readable,
            check,
            "slot_id, id, organization_id",
            "id, template_id, organization_id",
            helpers,
        ),
    )
    .into_iter()
    .map(|(_, object, _)| object)
    .collect()
}

/// `walk()` selecting `body`, declared with `header` before `AS`.
fn walk(header: &str, body: &str) -> String {
    format!(
        "CREATE FUNCTION walk() RETURNS SETOF INT LANGUAGE sql STABLE {header} AS $$ {body} $$;"
    )
}

#[test]
fn a_helper_body_is_read_only_where_it_yields_what_the_check_reads() {
    let reader = "SELECT readable('reader')";
    let counted = "SELECT readable((SELECT count(*) FROM levels)::text)";
    let levels = "CREATE TABLE levels (id INT); GRANT SELECT ON levels TO app;";
    let counted_check = format!("id = ANY (ARRAY({counted}))");
    let rows = "CREATE FUNCTION readable_rows(level TEXT) RETURNS TABLE (template INT)
        LANGUAGE sql STABLE AS $$ SELECT 1 $$;";
    let rows_read = "template_id IN (SELECT share.template FROM readable_rows('reader') share)";
    let rows_check = "id IN (SELECT readable_rows('reader'))";
    let walked = WALKED;
    for (readable, check, helpers, expected) in [
        (walked, READER, walk("", reader), vec![]),
        (
            walked,
            READER,
            walk("SET work_mem = '64kB'", reader),
            vec!["typed_templates.typed_slot"],
        ),
        (
            walked,
            READER,
            walk("SET search_path = public, pg_temp", reader),
            vec![],
        ),
        (
            walked,
            READER,
            walk("SET search_path = pg_catalog, pg_temp", reader),
            vec!["typed_templates.typed_slot"],
        ),
        (
            walked,
            counted_check.as_str(),
            format!("{levels} {}", walk("", counted)),
            vec![],
        ),
        (
            walked,
            counted_check.as_str(),
            format!("{levels} {}", walk("SECURITY DEFINER", counted)),
            vec!["typed_templates.typed_slot"],
        ),
        (rows_read, rows_check, rows.to_owned(), vec![]),
        (
            rows_read,
            rows_check,
            format!(
                "{rows} CREATE FUNCTION readable_rows(level INT) RETURNS TABLE (template INT)
                   LANGUAGE sql STABLE AS $$ SELECT 1 $$;"
            ),
            vec!["typed_templates.typed_slot"],
        ),
    ] {
        assert_eq!(
            read_through(readable, check, &helpers),
            expected,
            "{helpers} under {check}"
        );
    }
}

const GRANTEES: &str = "CREATE TABLE grantees (id INT, kind TEXT, PRIMARY KEY (id, kind));
    ALTER TABLE grantees ENABLE ROW LEVEL SECURITY;";

const USERS: &str = "CREATE TABLE users (
        id INT PRIMARY KEY,
        kind TEXT NOT NULL,
        CONSTRAINT users_grantee FOREIGN KEY (id, kind) REFERENCES grantees (id, kind)
    );
    GRANT INSERT ON users TO app;";

const WRITTEN: &str =
    "INSERT INTO grantees (id, kind) VALUES (NEW.id, NEW.kind) ON CONFLICT (id, kind) DO NOTHING;";

const BEFORE_INSERT: &str = "CREATE TRIGGER write_grantee BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION write_grantee();";

/// A trigger function on `users` running `body` and returning `NEW`.
fn writer(body: &str) -> String {
    format!(
        "CREATE FUNCTION write_grantee() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
         BEGIN {body} RETURN NEW; END $$;"
    )
}

/// A `BEFORE INSERT` trigger on `users` named `name` that sets `NEW.kind`.
fn kind_rewriter(name: &str) -> String {
    format!(
        "CREATE FUNCTION {name}() RETURNS TRIGGER LANGUAGE plpgsql AS $$
         BEGIN NEW.kind := 'team'; RETURN NEW; END $$;
         CREATE TRIGGER {name} BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION {name}();"
    )
}

#[test]
fn a_before_trigger_writing_the_referenced_row_from_new_is_clean() {
    for body in [
        WRITTEN,
        "INSERT INTO public.grantees (kind, id) VALUES (NEW.kind, NEW.id) ON CONFLICT DO NOTHING;",
        "INSERT INTO grantees (id, kind) VALUES ((NEW.id), NEW.kind)
           ON CONFLICT ON CONSTRAINT grantees_pkey DO NOTHING;",
        "IF NEW.id < 0 THEN RETURN NULL; END IF; INSERT INTO grantees (id, kind) VALUES (NEW.id, NEW.kind)
           ON CONFLICT (kind, id) DO NOTHING; NEW.created := true;",
        "INSERT INTO grantees VALUES (NEW.id, 'user'), (NEW.id, NEW.kind) ON CONFLICT DO NOTHING;",
        &format!("FOR i IN 1..2 LOOP NULL; END LOOP; WHILE false LOOP NULL; END LOOP; {WRITTEN}"),
    ] {
        assert_eq!(
            objects(&format!(
                "{GRANTEES} {USERS} ALTER TABLE users ADD COLUMN created BOOLEAN;
                 {} {BEFORE_INSERT}",
                writer(body)
            )),
            Vec::<String>::new(),
            "{body}"
        );
    }
    // Triggers fire in name order, so this rewrite reaches the written row.
    assert_eq!(
        objects(&format!(
            "{GRANTEES} {USERS} {} {BEFORE_INSERT} {}",
            writer(WRITTEN),
            kind_rewriter("rewrite_kind")
        )),
        Vec::<String>::new()
    );
    // An AFTER trigger and a plain index on the parent leave the written row alone.
    assert_eq!(
        objects(&format!(
            "{GRANTEES} {USERS} {} {BEFORE_INSERT}
             CREATE INDEX grantees_kind ON grantees (kind);
             CREATE FUNCTION note_grantee() RETURNS TRIGGER LANGUAGE plpgsql AS $$
             BEGIN RETURN NULL; END $$;
             CREATE TRIGGER note_grantee AFTER INSERT ON grantees FOR EACH ROW EXECUTE FUNCTION note_grantee();",
            writer(WRITTEN)
        )),
        Vec::<String>::new()
    );
}

#[test]
fn a_trigger_write_that_can_fail_or_miss_the_key_is_reported() {
    for body in [
        "INSERT INTO grantees (id, kind) VALUES (NEW.id, NEW.kind);",
        "INSERT INTO grantees (id, kind) VALUES (NEW.id, 'user') ON CONFLICT DO NOTHING;",
        "INSERT INTO grantees (id, kind) VALUES (NEW.id, NEW.kind::varchar(1)) ON CONFLICT DO NOTHING;",
        "INSERT INTO grantees (id, kind) (SELECT NEW.id, NEW.kind) ON CONFLICT DO NOTHING;",
        "INSERT INTO grantees (id, kind) SELECT id, kind FROM grantees ON CONFLICT DO NOTHING;",
        &format!("IF NEW.kind = 'user' THEN {WRITTEN} END IF;"),
        &format!("{WRITTEN} NEW.kind := 'team';"),
        &format!("{WRITTEN} SELECT 'team' INTO NEW.kind;"),
        &format!("{WRITTEN} DELETE FROM grantees WHERE id = NEW.id;"),
        &format!("BEGIN {WRITTEN} PERFORM 1 / 0; EXCEPTION WHEN division_by_zero THEN NULL; END;"),
        "EXECUTE 'INSERT INTO grantees VALUES ($1, $2) ON CONFLICT DO NOTHING' USING NEW.id, NEW.kind;",
        &format!("DECLARE new RECORD; BEGIN {WRITTEN} END;"),
        &format!("FOR new IN 1..1 LOOP {WRITTEN} END LOOP;"),
        &format!("{WRITTEN} FOR NEW.kind IN SELECT 'team' LOOP NULL; END LOOP;"),
        &format!(
            "DECLARE cur CURSOR FOR SELECT 'team'; BEGIN {WRITTEN} OPEN cur; FETCH cur INTO NEW.kind; CLOSE cur; END;"
        ),
        &format!("{WRITTEN} GET DIAGNOSTICS NEW.kind = ROW_COUNT;"),
    ] {
        assert_eq!(
            objects(&format!(
                "{GRANTEES} {USERS} {} {BEFORE_INSERT}",
                writer(body)
            )),
            ["users.users_grantee"],
            "{body}"
        );
    }
    assert_eq!(
        objects(&format!(
            "{GRANTEES} {USERS}
             CREATE FUNCTION forget_grantee(target INT) RETURNS VOID LANGUAGE plpgsql AS $$
             BEGIN DELETE FROM grantees WHERE id = target; END $$;
             {} {BEFORE_INSERT}",
            writer(&format!("{WRITTEN} PERFORM forget_grantee(NEW.id);"))
        )),
        ["users.users_grantee"]
    );
}

#[test]
fn a_parent_that_can_refuse_or_skip_the_written_row_is_reported() {
    let skipping = "CREATE FUNCTION skip_grantee() RETURNS TRIGGER LANGUAGE plpgsql AS $$
        BEGIN RETURN NULL; END $$;
        CREATE TRIGGER skip_grantee BEFORE INSERT ON grantees FOR EACH ROW EXECUTE FUNCTION skip_grantee();";
    for (parent, body) in [
        ("CREATE UNIQUE INDEX grantees_id ON grantees (id);", WRITTEN),
        (
            "CREATE UNIQUE INDEX grantees_id ON grantees (id);",
            "INSERT INTO grantees (id, kind) VALUES (NEW.id, NEW.kind) ON CONFLICT DO NOTHING;",
        ),
        (
            "CREATE UNIQUE INDEX grantees_kind ON grantees (lower(kind), id);",
            WRITTEN,
        ),
        (skipping, WRITTEN),
    ] {
        assert_eq!(
            objects(&format!(
                "{GRANTEES} {parent} {USERS} {} {BEFORE_INSERT}",
                writer(body)
            )),
            ["users.users_grantee"],
            "{parent} {body}"
        );
    }
}

#[test]
fn a_trigger_that_may_not_write_the_row_first_is_reported() {
    let rewriting = format!("{BEFORE_INSERT} {}", kind_rewriter("write_kind"));
    for (users, trigger) in [
        (
            USERS,
            "CREATE TRIGGER write_grantee AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION write_grantee();",
        ),
        (
            USERS,
            "CREATE TRIGGER write_grantee BEFORE INSERT ON users FOR EACH ROW
               WHEN (NEW.kind = 'user') EXECUTE FUNCTION write_grantee();",
        ),
        (USERS, rewriting.as_str()),
        (
            "CREATE TABLE users (
                 id INT PRIMARY KEY,
                 kind TEXT GENERATED ALWAYS AS ('user') STORED,
                 CONSTRAINT users_grantee FOREIGN KEY (id, kind) REFERENCES grantees (id, kind)
             );
             GRANT INSERT ON users TO app;",
            BEFORE_INSERT,
        ),
    ] {
        assert_eq!(
            objects(&format!("{GRANTEES} {users} {} {trigger}", writer(WRITTEN))),
            ["users.users_grantee"],
            "{users} {trigger}"
        );
    }
}

#[test]
fn a_trigger_covers_the_writes_it_fires_on() {
    let update_only = ["'app' through UPDATE whether"];
    for (events, expected) in [
        ("INSERT", &update_only[..]),
        ("INSERT OR UPDATE", &[]),
        ("INSERT OR UPDATE OF kind", &update_only),
        ("INSERT OR UPDATE OF kind, id", &[]),
    ] {
        let findings = reported(&format!(
            "{GRANTEES} {USERS} GRANT UPDATE ON users TO app; {}
             CREATE TRIGGER write_grantee BEFORE {events} ON users FOR EACH ROW
               EXECUTE FUNCTION write_grantee();",
            writer(WRITTEN)
        ));
        assert_eq!(findings.len(), expected.len(), "{events}: {findings:?}");
        for ((_, message), probe) in findings.iter().zip(expected) {
            assert!(message.contains(probe), "{events}: {message}");
        }
    }
}

const PERFORMED_RUNS: &str = "CREATE FUNCTION caller_id() RETURNS INT LANGUAGE sql STABLE AS
        $$ SELECT current_setting('app.user_id')::int $$;
    CREATE TABLE people (id INT PRIMARY KEY);
    ALTER TABLE people ENABLE ROW LEVEL SECURITY;
    CREATE POLICY people_select ON people FOR SELECT TO app USING (id = caller_id());
    CREATE TABLE runs (
        id INT PRIMARY KEY,
        performed_by_id INT CONSTRAINT runs_performer REFERENCES people (id),
        note TEXT
    );
    ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
    CREATE POLICY runs_select ON runs FOR SELECT TO app USING (true);
    CREATE POLICY runs_update ON runs FOR UPDATE TO app USING (true) WITH CHECK (true);
    GRANT SELECT, UPDATE (performed_by_id, note) ON runs TO app;";

const NAMES_OTHER: &str = "IF NEW.performed_by_id IS DISTINCT FROM caller_id() THEN
        RAISE EXCEPTION 'performer % is not the caller', NEW.performed_by_id;
    END IF;";

const PERFORMER_SET: &str = "WHEN (NEW.performed_by_id IS DISTINCT FROM OLD.performed_by_id AND NEW.performed_by_id IS NOT NULL)";

/// Objects of every finding on the runs schema, with `extra` after it and a
/// trigger `runs_performer` firing `BEFORE {events}` for each row under
/// `when`, running `body` before it returns `NEW` with `header` on its
/// function.
fn confined_runs(header: &str, body: &str, events: &str, when: &str, extra: &str) -> Vec<String> {
    objects(&format!(
        "{PERFORMED_RUNS} {extra}
         CREATE FUNCTION require_performer() RETURNS TRIGGER LANGUAGE plpgsql {header} AS $$
         BEGIN {body} RETURN NEW; END $$;
         CREATE TRIGGER runs_performer BEFORE {events} ON runs FOR EACH ROW {when}
           EXECUTE FUNCTION require_performer();"
    ))
}

#[test]
fn a_before_trigger_confining_the_key_to_readable_rows_is_clean() {
    let unchanged_first = format!(
        "IF NEW.performed_by_id IS NOT DISTINCT FROM OLD.performed_by_id THEN RETURN NEW; END IF; {NAMES_OTHER}"
    );
    for (body, events, when) in [
        (NAMES_OTHER, "UPDATE OF performed_by_id", PERFORMER_SET),
        (NAMES_OTHER, "UPDATE OF performed_by_id, note", ""),
        (NAMES_OTHER, "INSERT OR UPDATE", "WHEN (NEW.performed_by_id IS NOT NULL)"),
        (
            "IF NEW.performed_by_id IS NOT NULL AND NEW.performed_by_id IS DISTINCT FROM caller_id() THEN
               RAISE EXCEPTION 'not the caller';
             END IF;",
            "UPDATE",
            "",
        ),
        (
            "IF NEW.performed_by_id IS NULL OR NEW.performed_by_id = caller_id() THEN RETURN NEW; END IF;
             RAISE EXCEPTION 'not the caller';",
            "UPDATE",
            "",
        ),
        (unchanged_first.as_str(), "UPDATE OF performed_by_id", ""),
        (
            "IF NEW.performed_by_id IS DISTINCT FROM caller_id() THEN RETURN NULL; END IF;",
            "UPDATE",
            "",
        ),
        (
            &format!("NEW.note := trim(NEW.note); {NAMES_OTHER} RAISE NOTICE 'checked';"),
            "UPDATE",
            "",
        ),
        (
            "IF NOT (NEW.performed_by_id IS DISTINCT FROM caller_id()) THEN RETURN NEW; END IF;
             RAISE EXCEPTION 'not the caller';",
            "UPDATE",
            "",
        ),
        (
            &format!("FOR i IN 1..2 LOOP NULL; END LOOP; ASSERT NEW.note IS NOT NULL; {NAMES_OTHER}"),
            "DELETE OR UPDATE",
            "WHEN ((OLD.performed_by_id) IS DISTINCT FROM NEW.performed_by_id)",
        ),
        (
            "IF NEW.performed_by_id IS DISTINCT FROM caller_id() AND NEW.performed_by_id IS NOT NULL THEN
               RAISE EXCEPTION 'not the caller';
             END IF;",
            "UPDATE",
            "",
        ),
        (
            "IF NEW.performed_by_id = caller_id() THEN RETURN NEW; END IF;
             IF NEW.performed_by_id IS NULL THEN RETURN NEW; END IF;
             RAISE EXCEPTION 'not the caller';",
            "UPDATE",
            "",
        ),
        (
            &format!(
                "DECLARE note_row RECORD;
                 BEGIN FOR note_row IN SELECT note FROM runs LOOP NULL; END LOOP; END;
                 {NAMES_OTHER}"
            ),
            "UPDATE",
            "",
        ),
    ] {
        assert_eq!(
            confined_runs("", body, events, when, ""),
            Vec::<String>::new(),
            "{events} {when} {body}"
        );
    }
    let inserting = "CREATE POLICY runs_insert ON runs FOR INSERT TO app
          WITH CHECK (performed_by_id IS NULL OR performed_by_id = caller_id());
        GRANT INSERT ON runs TO app;";
    assert_eq!(
        confined_runs(
            "",
            NAMES_OTHER,
            "UPDATE OF performed_by_id",
            PERFORMER_SET,
            inserting
        ),
        Vec::<String>::new()
    );
    // A trigger confines an insert the same way, the insert check letting any key through.
    let unchecked_insert = "CREATE POLICY runs_insert ON runs FOR INSERT TO app WITH CHECK (true);
        GRANT INSERT ON runs TO app;";
    for (events, expected) in [
        ("INSERT OR UPDATE", Vec::<String>::new()),
        ("UPDATE", vec!["runs.runs_performer".to_owned()]),
    ] {
        assert_eq!(
            confined_runs("", NAMES_OTHER, events, "", unchecked_insert),
            expected,
            "{events}"
        );
    }
}

#[test]
fn a_before_trigger_keeping_unchecked_rows_on_their_own_paths_is_clean() {
    for (body, events, when) in [
        ("RAISE EXCEPTION 'runs are closed';", "UPDATE", ""),
        (
            "IF NEW.performed_by_id IS NULL THEN RETURN NEW; END IF; RAISE EXCEPTION 'performers are fixed';",
            "UPDATE",
            "",
        ),
        (
            "IF NEW.performed_by_id IS NULL THEN
               IF NEW.note IS NULL THEN RETURN NEW; END IF;
               RETURN NEW;
             END IF;
             RAISE EXCEPTION 'performers are fixed';",
            "UPDATE",
            "",
        ),
        (
            "IF (NEW.performed_by_id IS NULL) THEN RETURN NEW; END IF;
             IF NEW.performed_by_id = caller_id() THEN RETURN NEW; END IF;
             RAISE EXCEPTION 'not the caller';",
            "UPDATE",
            "",
        ),
        (
            "IF NEW.performed_by_id IS NULL AND NEW.note IS NULL THEN RETURN NEW; END IF;
             IF NEW.performed_by_id = caller_id() THEN RETURN NEW; END IF;
             RAISE EXCEPTION 'not the caller';",
            "UPDATE",
            "",
        ),
        (
            "IF NOT NEW.performed_by_id IS NOT NULL THEN RETURN NEW; END IF;
             RAISE EXCEPTION 'performers are fixed';",
            "UPDATE",
            "",
        ),
    ] {
        assert_eq!(
            confined_runs("", body, events, when, ""),
            Vec::<String>::new(),
            "{body}"
        );
    }
}

#[test]
fn a_before_trigger_pinned_to_its_path_or_repeated_is_clean() {
    assert_eq!(
        confined_runs("SET search_path = public", NAMES_OTHER, "UPDATE", "", ""),
        Vec::<String>::new()
    );
    assert_eq!(
        objects(&format!(
            "{PERFORMED_RUNS}
             CREATE FUNCTION require_performer() RETURNS TRIGGER LANGUAGE plpgsql AS $$
             BEGIN {NAMES_OTHER} RETURN NEW; END $$;
             CREATE TRIGGER runs_performer BEFORE UPDATE ON runs FOR EACH ROW
               EXECUTE FUNCTION require_performer();
             CREATE TRIGGER runs_performer_again BEFORE UPDATE ON runs FOR EACH ROW
               EXECUTE FUNCTION require_performer();"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn a_trigger_off_the_checked_write_may_rewrite_the_key() {
    let reassign = "CREATE FUNCTION reassign() RETURNS TRIGGER LANGUAGE plpgsql AS $$
        BEGIN NEW.performed_by_id := 2; RETURN NEW; END $$;";
    for trigger in [
        "AFTER UPDATE ON runs FOR EACH ROW",
        "BEFORE UPDATE ON runs FOR EACH STATEMENT",
        "BEFORE INSERT OR DELETE ON runs FOR EACH ROW",
    ] {
        let extra = format!(
            "{reassign} CREATE TRIGGER runs_reassign {trigger} EXECUTE FUNCTION reassign();"
        );
        assert_eq!(
            confined_runs("", NAMES_OTHER, "UPDATE", "", &extra),
            Vec::<String>::new(),
            "{trigger}"
        );
    }
    let disabled = format!(
        "{reassign} CREATE TRIGGER runs_reassign BEFORE UPDATE ON runs FOR EACH ROW
           EXECUTE FUNCTION reassign();
         ALTER TABLE runs DISABLE TRIGGER runs_reassign;"
    );
    assert_eq!(
        confined_runs("", NAMES_OTHER, "UPDATE", "", &disabled),
        Vec::<String>::new()
    );
}

#[test]
fn a_before_trigger_that_lets_another_key_through_is_reported() {
    let rewriter = "CREATE FUNCTION reassign() RETURNS TRIGGER LANGUAGE plpgsql AS $$
        BEGIN NEW.performed_by_id := 2; RETURN NEW; END $$;
        CREATE TRIGGER runs_reassign BEFORE UPDATE ON runs FOR EACH ROW EXECUTE FUNCTION reassign();";
    for (header, body, events, when, extra) in [
        (
            "",
            "IF NEW.performed_by_id <> caller_id() THEN RAISE EXCEPTION 'not the caller'; END IF;".to_owned(),
            "UPDATE",
            "",
            "",
        ),
        (
            "",
            "IF NOT (NEW.performed_by_id = caller_id()) THEN RAISE EXCEPTION 'not the caller'; END IF;".to_owned(),
            "UPDATE",
            "",
            "",
        ),
        (
            "",
            "ASSERT NEW.performed_by_id IS NOT DISTINCT FROM caller_id();".to_owned(),
            "UPDATE",
            "",
            "",
        ),
        (
            "",
            "IF NEW.performed_by_id IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'not the first'; END IF;".to_owned(),
            "UPDATE",
            "",
            "",
        ),
        (
            "",
            "IF NEW.performed_by_id IS DISTINCT FROM caller_id() THEN RAISE NOTICE 'not the caller'; END IF;".to_owned(),
            "UPDATE",
            "",
            "",
        ),
        (
            "",
            format!("BEGIN {NAMES_OTHER} EXCEPTION WHEN raise_exception THEN NULL; END;"),
            "UPDATE",
            "",
            "",
        ),
        (
            "",
            format!("{NAMES_OTHER} NEW.performed_by_id := NEW.performed_by_id + 1;"),
            "UPDATE",
            "",
            "",
        ),
        (
            "",
            format!("IF NEW.note IS NULL THEN RETURN NEW; END IF; {NAMES_OTHER}"),
            "UPDATE",
            "",
            "",
        ),
        ("", NAMES_OTHER.to_owned(), "UPDATE OF note", "", ""),
        (
            "",
            NAMES_OTHER.to_owned(),
            "UPDATE",
            "WHEN (NEW.performed_by_id <> OLD.performed_by_id)",
            "",
        ),
        ("", NAMES_OTHER.to_owned(), "UPDATE", "WHEN (NEW.note IS NOT NULL)", ""),
        ("", NAMES_OTHER.to_owned(), "INSERT", "", ""),
        (
            "",
            format!("FOR new IN 1..1 LOOP NULL; END LOOP; {NAMES_OTHER}"),
            "UPDATE",
            "",
            "",
        ),
        ("SECURITY DEFINER", NAMES_OTHER.to_owned(), "UPDATE", "", ""),
        ("SET app.user_id = '1'", NAMES_OTHER.to_owned(), "UPDATE", "", ""),
        ("", NAMES_OTHER.to_owned(), "UPDATE", "", rewriter),
    ] {
        assert_eq!(
            confined_runs(header, &body, events, when, extra),
            ["runs.runs_performer"],
            "{header} {events} {when} {body} {extra}"
        );
    }
}

#[test]
fn a_before_trigger_reading_the_key_only_in_part_is_reported() {
    for (header, body, when, extra) in [
        ("", NAMES_OTHER, "WHEN (NEW.performed_by_id = caller_id())", ""),
        (
            "",
            "IF NEW.performed_by_id = caller_id() OR NEW.performed_by_id = 0 THEN RETURN NEW; END IF;
             RAISE EXCEPTION 'not the caller';",
            "",
            "",
        ),
        (
            "",
            "IF NEW.note IS NULL AND NEW.performed_by_id IS DISTINCT FROM caller_id() THEN
               RAISE EXCEPTION 'not the caller';
             END IF;",
            "",
            "",
        ),
        (
            "",
            "IF NEW.performed_by_id = caller_id() AND NEW.performed_by_id > 0 THEN
               RAISE EXCEPTION 'the caller';
             END IF;",
            "",
            "",
        ),
        (
            "",
            "IF NEW.performed_by_id IS NULL OR NEW.note IS NULL THEN RETURN NEW; END IF;
             RAISE EXCEPTION 'performers are fixed';",
            "",
            "",
        ),
        (
            "",
            "DECLARE new runs;
             BEGIN
               IF new.performed_by_id IS DISTINCT FROM caller_id() THEN RAISE EXCEPTION 'not the caller'; END IF;
             END;",
            "",
            "",
        ),
        (
            "",
            "IF NEW.performed_by_id IS DISTINCT FROM OLD.id THEN RAISE EXCEPTION 'not the run'; END IF;",
            "",
            "",
        ),
        (
            "",
            "IF NEW.performed_by_id IS NOT DISTINCT FROM NEW.performed_by_id THEN RETURN NEW; END IF;
             RAISE EXCEPTION 'not the run';",
            "",
            "",
        ),
        (
            "SET search_path = shadow, public",
            NAMES_OTHER,
            "",
            "CREATE SCHEMA shadow;
             CREATE FUNCTION shadow.caller_id() RETURNS INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;",
        ),
        (
            "",
            NAMES_OTHER,
            "",
            "CREATE FUNCTION native_stamp() RETURNS TRIGGER LANGUAGE c AS 'stamp', 'native_stamp';
             CREATE TRIGGER runs_stamp BEFORE UPDATE ON runs FOR EACH ROW EXECUTE FUNCTION native_stamp();",
        ),
        (
            "",
            NAMES_OTHER,
            "",
            "CREATE TRIGGER runs_suppress BEFORE UPDATE ON runs FOR EACH ROW
               EXECUTE FUNCTION suppress_redundant_updates_trigger();",
        ),
    ] {
        assert_eq!(
            confined_runs(header, body, "UPDATE", when, extra),
            ["runs.runs_performer"],
            "{header} {when} {body} {extra}"
        );
    }
}

#[test]
fn a_before_trigger_writing_the_key_after_testing_it_is_reported() {
    for write in [
        "SELECT 2 INTO NEW.performed_by_id;",
        "EXECUTE 'SELECT 1';",
        "DECLARE performers CURSOR FOR SELECT 2;
         BEGIN OPEN performers; FETCH performers INTO NEW.performed_by_id; END;",
        "GET DIAGNOSTICS NEW.performed_by_id = ROW_COUNT;",
    ] {
        assert_eq!(
            confined_runs("", &format!("{NAMES_OTHER} {write}"), "UPDATE", "", ""),
            ["runs.runs_performer"],
            "{write}"
        );
    }
}

#[test]
fn a_trigger_testing_one_column_of_a_composite_key_leaves_it_checked() {
    for (when, probe) in [
        ("", "'app' through INSERT whether"),
        (
            "WHEN (NEW.id IS DISTINCT FROM OLD.id)",
            "'app' through INSERT and UPDATE whether",
        ),
    ] {
        let findings = reported(&format!(
            "{GRANTEES} {USERS} GRANT UPDATE ON users TO app;
             CREATE FUNCTION require_grantee() RETURNS TRIGGER LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'grantees are fixed'; RETURN NEW; END $$;
             CREATE TRIGGER users_grantee BEFORE UPDATE ON users FOR EACH ROW {when}
               EXECUTE FUNCTION require_grantee();"
        ));
        assert_eq!(findings.len(), 1, "{when}: {findings:?}");
        assert!(findings[0].1.contains(probe), "{when}: {}", findings[0].1);
    }
}

/// Object of every finding of the rule on `sql`, under `deployment`.
fn objects_under(deployment: Deployment, sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = ForeignKeyExistenceOracle::default().into();
    constrainer.set_deployment(deployment);
    findings(&constrainer, "foreign_key_existence_oracle", sql)
        .into_iter()
        .map(|(_, object, _)| object)
        .collect()
}

/// Grants whose resource key a definer helper hands out, with `body` as the
/// helper's query and `readable` as the security of the set function.
fn sharable_schema(readable: &str, header: &str, body: &str, check: &str) -> String {
    format!(
        "CREATE ROLE app;
         CREATE FUNCTION readable(level TEXT) RETURNS SETOF INT LANGUAGE sql STABLE {readable} AS $$ SELECT 1 $$;
         CREATE FUNCTION sharable() RETURNS TABLE (resource_id INT, role TEXT)
         LANGUAGE sql STABLE SECURITY DEFINER {header} AS $$ {body} $$;
         CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL, UNIQUE (organization_id, id));
         ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
         CREATE POLICY resources_read ON resources FOR SELECT TO app USING (id IN (SELECT readable('reader')));
         CREATE TABLE grants (organization_id INT, resource_id INT, role TEXT,
           CONSTRAINT grants_resource FOREIGN KEY (organization_id, resource_id) REFERENCES resources (organization_id, id));
         ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
         CREATE POLICY grants_write ON grants FOR INSERT TO app WITH CHECK ({check});
         GRANT SELECT ON resources TO app;
         GRANT INSERT ON grants TO app;"
    )
}

#[test]
fn a_key_column_a_definer_helper_draws_from_a_readable_set_is_clean() {
    let writer = "SELECT resource.id, 'writer'::text FROM readable('writer') resource(id)";
    let filtered = "SELECT resource.id, 'reader'::text FROM resources resource
        WHERE resource.organization_id > 0 AND resource.id IN (SELECT readable('writer'))";
    let paired =
        "(resource_id, role) IN (SELECT share.resource_id, share.role FROM sharable() share)";
    let definer = "SECURITY DEFINER";
    let path = "SET search_path = pg_catalog, public, pg_temp";
    let expanded = "SELECT resource.id, allowed.role FROM readable('writer') resource(id)
        CROSS JOIN unnest(ARRAY['writer', 'reader']) allowed(role) WHERE now() IS NOT NULL";
    for (readable, header, body, check, expected) in [
        (definer, "", writer, paired, vec![]),
        (definer, path, writer, paired, vec![]),
        // Built-ins resolve to the catalog, and an array expansion reads no key.
        (definer, path, expanded, paired, vec![]),
        (
            definer,
            "",
            &format!("{writer} UNION {filtered}"),
            paired,
            vec![],
        ),
        (
            definer,
            "",
            writer,
            "(resource_id, role) IN (SELECT * FROM sharable())",
            vec![],
        ),
        (
            definer,
            "",
            writer,
            "resource_id IN (SELECT share.resource_id FROM sharable() share WHERE share.role = 'writer')",
            vec![],
        ),
        // An arm drawing from every resource leaves the key unconfined.
        (
            definer,
            "",
            &format!("{writer} UNION SELECT resource.id, 'reader' FROM resources resource"),
            paired,
            vec!["grants.grants_resource"],
        ),
        // Inside the definer, an invoker set runs as the helper's owner.
        ("", "", writer, paired, vec!["grants.grants_resource"]),
        // A setting the helper changes may change what the set yields.
        (
            definer,
            "SET app.level = 'admin'",
            writer,
            paired,
            vec!["grants.grants_resource"],
        ),
        // A search path that leaves out the set's schema reaches another set.
        (
            definer,
            "SET search_path = pg_catalog",
            writer,
            paired,
            vec!["grants.grants_resource"],
        ),
        // The key column pairs with the role, which no set confines.
        (
            definer,
            "",
            writer,
            "(role, resource_id) IN (SELECT share.resource_id, share.role FROM sharable() share)",
            vec!["grants.grants_resource"],
        ),
        (
            definer,
            "",
            "SELECT 1, 'writer'::text FROM readable('writer') resource(id)",
            paired,
            vec!["grants.grants_resource"],
        ),
        (
            definer,
            "",
            "SELECT resource.id, 'writer'::text FROM readable('writer') resource(id) LIMIT 1",
            paired,
            vec![],
        ),
        (
            definer,
            "",
            "SELECT resource.id, 'writer'::text FROM readable('any') resource(id)",
            paired,
            vec!["grants.grants_resource"],
        ),
    ] {
        let deployment = Deployment::default()
            .with_app_role("app")
            .with_set_within("readable('writer')", "readable('reader')")
            .unwrap();
        assert_eq!(
            objects_under(deployment, &sharable_schema(readable, header, body, check)),
            expected,
            "{readable} {header} {body} under {check}"
        );
    }
}

#[test]
fn a_definer_helper_without_a_declared_relation_between_sets_is_reported() {
    let writer = "SELECT resource.id, 'writer'::text FROM readable('writer') resource(id)";
    let paired =
        "(resource_id, role) IN (SELECT share.resource_id, share.role FROM sharable() share)";
    assert_eq!(
        objects_under(
            Deployment::default().with_app_role("app"),
            &sharable_schema("SECURITY DEFINER", "", writer, paired)
        ),
        ["grants.grants_resource"]
    );
}

#[test]
fn a_key_confined_to_a_helper_called_with_a_higher_role_is_clean() {
    let schema = |comparison: &str| {
        format!(
            "CREATE ROLE app;
             CREATE TYPE level AS ENUM ('reader', 'writer', 'admin');
             CREATE TABLE grants (resource_id INT, level level);
             CREATE FUNCTION readable(minimum level) RETURNS SETOF INT LANGUAGE sql STABLE AS $$
               SELECT permission.resource_id FROM grants permission WHERE {comparison} $$;
             CREATE TABLE resources (id INT PRIMARY KEY);
             ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
             CREATE POLICY resources_read ON resources FOR SELECT TO app
               USING (id IN (SELECT readable('reader')));
             CREATE TABLE notes (id INT PRIMARY KEY,
               resource_id INT NOT NULL CONSTRAINT notes_resource REFERENCES resources (id));
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_insert ON notes FOR INSERT TO app
               WITH CHECK (resource_id IN (SELECT readable('writer')));
             GRANT SELECT ON resources, grants TO app;
             GRANT INSERT ON notes TO app;"
        )
    };
    let deployment = || Deployment::default().with_app_role("app");
    assert_eq!(
        objects_under(deployment(), &schema("permission.level >= minimum")),
        Vec::<String>::new()
    );
    assert_eq!(
        objects_under(deployment(), &schema("permission.level <= minimum")),
        ["notes.notes_resource"]
    );
}

#[test]
fn a_definer_helper_calling_a_name_another_schema_declares_is_reported() {
    let schema = sharable_schema(
        "SECURITY DEFINER",
        "SET search_path = public, other",
        "SELECT resource.id, 'writer'::text FROM readable('writer') resource(id)",
        "(resource_id, role) IN (SELECT share.resource_id, share.role FROM sharable() share)",
    );
    let deployment = || {
        Deployment::default()
            .with_app_role("app")
            .with_set_within("readable('writer')", "readable('reader')")
            .unwrap()
    };
    assert_eq!(objects_under(deployment(), &schema), Vec::<String>::new());
    assert_eq!(
        objects_under(
            deployment(),
            &format!(
                "{schema} CREATE SCHEMA other;
                 CREATE FUNCTION other.readable(level INT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 2 $$;"
            )
        ),
        ["grants.grants_resource"]
    );
}

/// Memberships whose organization and invitation a definer helper hands out
/// from the invitations addressed to the caller.
fn pending_schema(email: &str, pending: &str, organizations_read: &str) -> String {
    format!(
        "CREATE ROLE app;
         CREATE FUNCTION founded() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT 1 $$;
         CREATE FUNCTION caller_email() RETURNS TEXT LANGUAGE sql STABLE {email} AS $$ SELECT 'caller' $$;
         CREATE FUNCTION blocking() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT 1 $$;
         CREATE FUNCTION capped(level TEXT) RETURNS TABLE (organization_id INT, kind TEXT)
           LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT 1, 'organization' $$;
         CREATE TABLE organizations (id INT PRIMARY KEY);
         CREATE TABLE invitations (organization_id INT REFERENCES organizations (id), id INT PRIMARY KEY,
           email TEXT, accepted BOOLEAN, UNIQUE (organization_id, id));
         CREATE FUNCTION pending() RETURNS TABLE (organization_id INT, id INT)
         LANGUAGE sql STABLE SECURITY DEFINER AS $$ {pending} $$;
         ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
         ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
         CREATE POLICY invitations_read ON invitations FOR SELECT TO app
           USING (email = (SELECT caller_email())
             AND (organization_id, 'organization') IN (SELECT * FROM capped('reader')));
         CREATE POLICY invitations_blocked ON invitations AS RESTRICTIVE FOR ALL TO app
           USING (NOT (organization_id = ANY (ARRAY(SELECT blocking()))));
         CREATE POLICY organizations_read ON organizations FOR SELECT TO app
           USING (id = ANY (ARRAY(SELECT founded()))
             OR id = ANY (ARRAY(SELECT invitation.organization_id FROM invitations invitation {organizations_read})));
         CREATE POLICY organizations_blocked ON organizations AS RESTRICTIVE FOR ALL TO app
           USING (NOT (id = ANY (ARRAY(SELECT blocking()))));
         CREATE TABLE memberships (organization_id INT, invitation_id INT,
           CONSTRAINT memberships_organization FOREIGN KEY (organization_id) REFERENCES organizations (id),
           CONSTRAINT memberships_invitation FOREIGN KEY (organization_id, invitation_id) REFERENCES invitations (organization_id, id));
         ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
         CREATE POLICY memberships_write ON memberships FOR INSERT TO app
           WITH CHECK ((organization_id = ANY (ARRAY(SELECT founded())) AND invitation_id IS NULL)
             OR ((organization_id, invitation_id) IN (SELECT * FROM pending())
               AND (organization_id, 'organization') IN (SELECT * FROM capped('writer'))));
         CREATE POLICY memberships_blocked ON memberships AS RESTRICTIVE FOR ALL TO app
           USING (NOT (organization_id = ANY (ARRAY(SELECT blocking()))))
           WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT blocking()))));
         GRANT SELECT ON organizations, invitations TO app;
         GRANT INSERT ON memberships TO app;"
    )
}

#[test]
fn a_key_a_definer_helper_draws_from_one_readable_row_is_clean() {
    let caller = "SELECT invitation.organization_id, invitation.id FROM invitations invitation
        WHERE invitation.email = caller_email() AND invitation.accepted IS NULL";
    let open = "WHERE invitation.accepted IS NULL";
    let definer = "SECURITY DEFINER";
    let both = vec![
        "memberships.memberships_organization",
        "memberships.memberships_invitation",
    ];
    for (email, pending, organizations_read, capped, expected) in [
        (definer, caller, open, true, vec![]),
        (definer, caller, "", true, vec![]),
        // The capped set the check confines the organization to is not within the one reads test.
        (definer, caller, open, false, both.clone()),
        // An invitation addressed to anyone is not one the caller reads.
        (
            definer,
            "SELECT invitation.organization_id, invitation.id FROM invitations invitation
             WHERE invitation.accepted IS NULL",
            open,
            true,
            both.clone(),
        ),
        // Inside the definer, the invoker email function runs as the helper's owner.
        ("", caller, open, true, both.clone()),
        // The organization's read needs an unaccepted invitation, which the helper leaves open.
        (
            definer,
            "SELECT invitation.organization_id, invitation.id FROM invitations invitation
             WHERE invitation.email = caller_email()",
            open,
            true,
            vec!["memberships.memberships_organization"],
        ),
        // The organization comes from another invitation than the one the key names, which no
        // organization read covers. The invitation key still matches only the caller's invitation.
        (
            definer,
            "SELECT other.organization_id, invitation.id FROM invitations invitation, invitations other
             WHERE invitation.email = caller_email() AND invitation.accepted IS NULL",
            open,
            true,
            vec!["memberships.memberships_organization"],
        ),
        // An expansion whose columns are not listed shifts every output after it.
        (
            definer,
            "SELECT number.*, invitation.organization_id FROM unnest(ARRAY[2]) number, invitations invitation
             WHERE invitation.email = caller_email() AND invitation.accepted IS NULL",
            open,
            true,
            both.clone(),
        ),
    ] {
        let mut deployment = Deployment::default().with_app_role("app");
        if capped {
            deployment = deployment
                .with_set_within("capped('writer')", "capped('reader')")
                .unwrap();
        }
        assert_eq!(
            objects_under(deployment, &pending_schema(email, pending, organizations_read)),
            expected,
            "{email} {pending} reading {organizations_read}"
        );
    }
}

/// Memberships whose organization pair a definer helper draws as `pending`
/// from invitations, under an organizations read of `organizations_read`.
fn pending_pair_schema(pending: &str, organizations_read: &str) -> String {
    format!(
        "CREATE ROLE app;
         CREATE FUNCTION caller_email() RETURNS TEXT LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT 'caller' $$;
         CREATE TABLE organizations (namespace_id INT, id INT, PRIMARY KEY (namespace_id, id));
         CREATE TABLE invitations (id INT PRIMARY KEY, organization_namespace_id INT, organization_id INT,
           email TEXT, accepted BOOLEAN,
           FOREIGN KEY (organization_namespace_id, organization_id) REFERENCES organizations (namespace_id, id));
         CREATE FUNCTION pending() RETURNS TABLE (organization_namespace_id INT, organization_id INT, id INT)
         LANGUAGE sql STABLE SECURITY DEFINER AS $$ {pending} $$;
         ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
         ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
         CREATE POLICY invitations_read ON invitations FOR SELECT TO app
           USING (email = (SELECT caller_email()));
         CREATE POLICY organizations_read ON organizations FOR SELECT TO app USING ({organizations_read});
         CREATE TABLE memberships (organization_namespace_id INT, organization_id INT, invitation_id INT,
           CONSTRAINT memberships_organization FOREIGN KEY (organization_namespace_id, organization_id)
             REFERENCES organizations (namespace_id, id));
         ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
         CREATE POLICY memberships_write ON memberships FOR INSERT TO app
           WITH CHECK ((organization_namespace_id, organization_id, invitation_id) IN (SELECT * FROM pending()));
         GRANT SELECT ON organizations, invitations TO app;
         GRANT INSERT ON memberships TO app;"
    )
}

#[test]
fn a_key_pair_a_policy_row_value_reads_from_one_readable_row_is_clean() {
    let caller = "SELECT invitation.organization_namespace_id, invitation.organization_id, invitation.id
        FROM invitations invitation WHERE invitation.email = caller_email() AND invitation.accepted IS NULL";
    let pair = "(namespace_id, id) IN (SELECT invitation.organization_namespace_id, invitation.organization_id
        FROM invitations invitation WHERE invitation.accepted IS NULL)";
    let reported = vec!["memberships.memberships_organization"];
    for (pending, organizations_read, expected) in [
        (caller, pair, vec![]),
        (
            caller,
            "(id, namespace_id) IN (SELECT organization_id, organization_namespace_id FROM invitations)",
            vec![],
        ),
        // The row value pairs its columns by position, so swapped columns admit another organization.
        (
            caller,
            "(namespace_id, id) IN (SELECT organization_id, organization_namespace_id FROM invitations)",
            reported.clone(),
        ),
        // The organization's read needs an unaccepted invitation, which the helper leaves open.
        (
            "SELECT invitation.organization_namespace_id, invitation.organization_id, invitation.id
             FROM invitations invitation WHERE invitation.email = caller_email()",
            pair,
            reported.clone(),
        ),
        // Two readable invitations combine into the key of an organization neither names.
        (
            "SELECT other.organization_namespace_id, invitation.organization_id, invitation.id
             FROM invitations invitation, invitations other
             WHERE invitation.email = caller_email() AND invitation.accepted IS NULL
               AND other.email = caller_email() AND other.accepted IS NULL",
            pair,
            reported.clone(),
        ),
        // A tested value outside the key leaves the read unproven.
        (
            caller,
            "(namespace_id, id, 1) IN (SELECT organization_namespace_id, organization_id, id FROM invitations)",
            reported.clone(),
        ),
        // A projection the reading cannot pair with the tested columns leaves the read unproven.
        (
            caller,
            "(namespace_id, id) IN (SELECT * FROM invitations)",
            reported.clone(),
        ),
        (
            caller,
            "id IN (SELECT * FROM invitations)",
            reported.clone(),
        ),
        (
            caller,
            "(namespace_id, id) IN (SELECT organization_namespace_id, organization_id + 0 FROM invitations)",
            reported.clone(),
        ),
    ] {
        assert_eq!(
            objects_under(
                Deployment::default().with_app_role("app"),
                &pending_pair_schema(pending, organizations_read)
            ),
            expected,
            "{pending} reading {organizations_read}"
        );
    }
}

/// Resources each of whose kinds a child table covers, through reverse keys
/// on generated columns, with `edge` as the kinds the edges cover.
fn covered_schema(reverse: &str, edge: &str, privileges: &str) -> String {
    format!(
        "CREATE ROLE app;
         CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL, kind TEXT NOT NULL,
           CHECK (kind IN ('ownable', 'folder', 'project')), UNIQUE (organization_id, id, kind),
           ownable_id INT GENERATED ALWAYS AS (CASE WHEN kind = 'ownable' THEN id END) STORED,
           edge_id INT GENERATED ALWAYS AS (CASE WHEN kind IN ({edge}) THEN id END) STORED);
         ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
         CREATE POLICY resources_read ON resources FOR SELECT TO app USING (false);
         CREATE TABLE ownables (id INT PRIMARY KEY, organization_id INT NOT NULL,
           kind TEXT GENERATED ALWAYS AS ('ownable'::text) STORED NOT NULL,
           CONSTRAINT ownables_resource FOREIGN KEY (organization_id, id, kind)
             REFERENCES resources (organization_id, id, kind) DEFERRABLE INITIALLY DEFERRED);
         CREATE TABLE resource_parents (id INT PRIMARY KEY, organization_id INT NOT NULL,
           resource_kind TEXT NOT NULL CHECK (resource_kind IN ('folder', 'project')),
           CONSTRAINT edges_resource FOREIGN KEY (organization_id, id, resource_kind)
             REFERENCES resources (organization_id, id, kind) DEFERRABLE INITIALLY DEFERRED);
         ALTER TABLE resources ADD CONSTRAINT resources_ownable FOREIGN KEY (ownable_id) REFERENCES ownables (id) {reverse};
         ALTER TABLE resources ADD CONSTRAINT resources_edge FOREIGN KEY (edge_id) REFERENCES resource_parents (id) {reverse};
         GRANT SELECT ON resources TO app;
         {privileges}"
    )
}

#[test]
fn a_key_whose_every_matchable_row_its_primary_key_already_holds_is_clean_on_insert() {
    let insert = "GRANT INSERT ON ownables, resource_parents TO app;";
    let both = vec![
        "ownables.ownables_resource",
        "resource_parents.edges_resource",
    ];
    for (reverse, edge, privileges, expected) in [
        ("", "'folder', 'project'", insert.to_owned(), vec![]),
        ("NOT DEFERRABLE", "'folder', 'project'", insert.to_owned(), vec![]),
        // A deferred reverse key lets a transaction leave a hidden row uncovered.
        ("DEFERRABLE", "'folder', 'project'", insert.to_owned(), both.clone()),
        // An unvalidated reverse key leaves the rows it predates uncovered.
        ("NOT VALID", "'folder', 'project'", insert.to_owned(), both.clone()),
        // A reverse key PostgreSQL never checks covers no row.
        ("NOT ENFORCED", "'folder', 'project'", insert.to_owned(), both.clone()),
        // A project has no edge, so a hidden project answers the edge's key.
        (
            "",
            "'folder'",
            insert.to_owned(),
            vec!["resource_parents.edges_resource"],
        ),
        // Deleting a covering row and inserting it again in one statement reaches the key.
        (
            "",
            "'folder', 'project'",
            format!("{insert} GRANT SELECT, DELETE ON ownables TO app;"),
            vec!["ownables.ownables_resource"],
        ),
        // A delete confined to rows whose resource the deleter reads still moves a covering row aside.
        (
            "",
            "'folder', 'project'",
            format!(
                "{insert} GRANT SELECT, DELETE ON ownables TO app;
                 ALTER TABLE ownables ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY ownables_insert ON ownables FOR INSERT TO app WITH CHECK (true);
                 CREATE POLICY ownables_delete ON ownables FOR DELETE TO app
                   USING ((organization_id, id, kind) IN (SELECT organization_id, id, kind FROM resources));"
            ),
            vec!["ownables.ownables_resource"],
        ),
        // The covering key does not reach an update of the key.
        (
            "",
            "'folder', 'project'",
            format!("{insert} GRANT UPDATE (organization_id) ON ownables TO app;"),
            vec!["ownables.ownables_resource"],
        ),
        // A cascade from another table removes a covering row only after the statement's unique check.
        (
            "",
            "'folder', 'project'",
            format!(
                "{insert} CREATE TABLE owners (id INT PRIMARY KEY);
                 ALTER TABLE ownables ADD CONSTRAINT ownables_owner FOREIGN KEY (organization_id)
                   REFERENCES owners (id) ON DELETE CASCADE;
                 GRANT SELECT, DELETE ON owners TO app;"
            ),
            vec![],
        ),
    ] {
        assert_eq!(
            objects_under(
                Deployment::default().with_app_role("app"),
                &covered_schema(reverse, edge, &privileges)
            ),
            expected,
            "{reverse} over {edge} with {privileges}"
        );
    }
    assert_eq!(
        objects_under(
            Deployment::default().with_app_role("app"),
            &covered_schema("", "'folder', 'project'", insert).replace(
                "CHECK (resource_kind IN ('folder', 'project'))",
                "CHECK (resource_kind IN ('folder', 'project')) NOT ENFORCED"
            )
        ),
        ["resource_parents.edges_resource"]
    );
    // Moving a covering row's key away and inserting it again in one statement reaches the key.
    let mut constrainer: GenericConstrainer<ParserDB> = ForeignKeyExistenceOracle::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("app"));
    let messages: Vec<String> = findings(
        &constrainer,
        "foreign_key_existence_oracle",
        &covered_schema(
            "",
            "'folder', 'project'",
            "GRANT INSERT ON ownables, resource_parents TO app; GRANT UPDATE (id) ON ownables TO app;",
        ),
    )
    .into_iter()
    .map(|(_, _, message)| message)
    .collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains("INSERT and UPDATE"), "{}", messages[0]);
}

#[test]
fn a_key_whose_matchable_rows_no_reverse_key_covers_is_reported() {
    let uncovered = "CREATE ROLE app;
        CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL, kind TEXT NOT NULL,
          UNIQUE (organization_id, id, kind));
        ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
        CREATE TABLE ownables (id INT PRIMARY KEY, organization_id INT NOT NULL,
          kind TEXT GENERATED ALWAYS AS ('ownable'::text) STORED,
          CONSTRAINT ownables_resource FOREIGN KEY (organization_id, id, kind)
            REFERENCES resources (organization_id, id, kind));
        GRANT INSERT ON ownables TO app;";
    assert_eq!(
        objects_under(Deployment::default().with_app_role("app"), uncovered),
        ["ownables.ownables_resource"]
    );
    // A kind compared by value, which `'01'` matches as `1`, leaves its resource uncovered.
    let numeric = "CREATE ROLE app;
        CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL, kind INT NOT NULL,
          UNIQUE (organization_id, id, kind),
          ownable_id INT GENERATED ALWAYS AS (CASE WHEN kind = '01' THEN NULL ELSE id END) STORED);
        ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
        CREATE TABLE ownables (id INT PRIMARY KEY, organization_id INT NOT NULL,
          kind INT NOT NULL CHECK (kind IN ('1')),
          CONSTRAINT ownables_resource FOREIGN KEY (organization_id, id, kind)
            REFERENCES resources (organization_id, id, kind) DEFERRABLE INITIALLY DEFERRED);
        ALTER TABLE resources ADD CONSTRAINT resources_ownable FOREIGN KEY (ownable_id) REFERENCES ownables (id);
        GRANT INSERT ON ownables TO app;";
    assert_eq!(
        objects_under(Deployment::default().with_app_role("app"), numeric),
        ["ownables.ownables_resource"]
    );
}

const RUNS: &str = "CREATE ROLE app;
    CREATE ROLE authz_owner;
    CREATE SCHEMA authz;
    CREATE TABLE organization_blocks (organization_id UUID NOT NULL, principal_id UUID NOT NULL,
      PRIMARY KEY (organization_id, principal_id));
    ALTER TABLE organization_blocks ENABLE ROW LEVEL SECURITY;
    ALTER TABLE organization_blocks FORCE ROW LEVEL SECURITY;
    CREATE TABLE resources (id UUID PRIMARY KEY, organization_id UUID NOT NULL,
      UNIQUE (organization_id, id));
    ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
    ALTER TABLE resources FORCE ROW LEVEL SECURITY;
    CREATE TABLE grants (resource_id UUID NOT NULL REFERENCES resources (id), grantee_id UUID NOT NULL,
      role TEXT NOT NULL, PRIMARY KEY (resource_id, grantee_id));
    ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
    ALTER TABLE grants FORCE ROW LEVEL SECURITY;
    CREATE FUNCTION authz.caller_id() RETURNS UUID LANGUAGE sql STABLE
      SET search_path = pg_catalog, pg_temp AS $$ SELECT current_setting('app.user_id')::uuid $$;
    CREATE FUNCTION authz.blocking_organizations() RETURNS SETOF UUID
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
      SELECT block.organization_id FROM public.organization_blocks block
      WHERE block.principal_id = authz.caller_id() $$;
    CREATE FUNCTION authz.readable_resources() RETURNS SETOF UUID
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
      SELECT resource.id FROM public.resources resource
      WHERE resource.id IN (SELECT grant_row.resource_id FROM public.grants grant_row
          WHERE grant_row.grantee_id = authz.caller_id())
        AND NOT (resource.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))) $$;
    ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
    ALTER FUNCTION authz.readable_resources() OWNER TO authz_owner;
    REVOKE EXECUTE ON FUNCTION authz.blocking_organizations(), authz.readable_resources() FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION authz.blocking_organizations(), authz.readable_resources() TO app;
    GRANT SELECT ON organization_blocks, resources, grants TO authz_owner;
    CREATE POLICY resources_select ON resources FOR SELECT TO app
      USING (id = ANY (ARRAY(SELECT authz.readable_resources())));
    CREATE POLICY resources_blocked ON resources AS RESTRICTIVE FOR ALL TO app
      USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
    CREATE TABLE templates (id UUID PRIMARY KEY, organization_id UUID NOT NULL,
      FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id));
    ALTER TABLE templates ENABLE ROW LEVEL SECURITY;
    ALTER TABLE templates FORCE ROW LEVEL SECURITY;
    CREATE POLICY templates_select ON templates FOR SELECT TO app
      USING (id = ANY (ARRAY(SELECT authz.readable_resources())));
    CREATE POLICY templates_blocked ON templates AS RESTRICTIVE FOR ALL TO app
      USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
      WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
    CREATE TABLE runs (id UUID PRIMARY KEY, organization_id UUID NOT NULL,
      template_id UUID NOT NULL,
      CONSTRAINT runs_template_id_fkey FOREIGN KEY (template_id) REFERENCES templates (id),
      CONSTRAINT runs_resource FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id));
    CREATE INDEX ON runs (template_id);
    ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE runs FORCE ROW LEVEL SECURITY;
    CREATE POLICY runs_select ON runs FOR SELECT TO app
      USING (id = ANY (ARRAY(SELECT authz.readable_resources())));
    CREATE POLICY runs_insert ON runs FOR INSERT TO app
      WITH CHECK (id = ANY (ARRAY(SELECT authz.readable_resources()))
        AND template_id = ANY (ARRAY(SELECT authz.readable_resources())));
    CREATE POLICY runs_blocked ON runs AS RESTRICTIVE FOR ALL TO app
      USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
      WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
    GRANT SELECT ON templates, runs TO app;
    GRANT INSERT ON runs TO app;";

const RESOURCES_WITH: [(&str, &str); 4] = [
    (
        "authz.readable_resources() RETURNS",
        "authz.resources_with(min_role TEXT) RETURNS",
    ),
    (
        "WHERE grant_row.grantee_id = authz.caller_id())",
        "WHERE grant_row.grantee_id = authz.caller_id() AND grant_row.role = min_role)",
    ),
    ("authz.readable_resources()", "authz.resources_with(TEXT)"),
    (
        "SELECT authz.resources_with(TEXT)",
        "SELECT authz.resources_with('reader')",
    ),
];

const IN_SUBQUERY: [(&str, &str); 1] = [(
    "template_id = ANY (ARRAY(SELECT authz.readable_resources()))",
    "template_id IN (SELECT authz.readable_resources())",
)];

/// Objects of every finding on [`RUNS`] after the edits of `spelling`, then
/// of `helper`, then `extra`, each replacing every occurrence of its text.
fn runs_findings(
    spelling: &[(&str, &str)],
    helper: &[(&str, &str)],
    extra: &[(&str, &str)],
) -> Vec<String> {
    let mut sql = RUNS.to_owned();
    for (from, to) in spelling.iter().chain(helper).chain(extra) {
        assert!(sql.contains(from), "{from}");
        sql = sql.replace(from, to);
    }
    objects_under(Deployment::default().with_app_role("app"), &sql)
}

#[test]
fn a_key_a_helper_confines_to_rows_whose_restrictive_read_it_implies_is_clean() {
    for spelling in [&[][..], &IN_SUBQUERY] {
        for helper in [&[][..], &RESOURCES_WITH] {
            assert_eq!(
                runs_findings(spelling, helper, &[]),
                Vec::<String>::new(),
                "{spelling:?} {helper:?}"
            );
        }
    }
}

#[test]
fn a_key_a_helper_confines_to_rows_a_restrictive_read_may_hide_is_reported() {
    let unblocked = (
        "\n        AND NOT (resource.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations())))",
        "",
    );
    for spelling in [&[][..], &IN_SUBQUERY] {
        for helper in [&[][..], &RESOURCES_WITH] {
            assert_eq!(
                runs_findings(spelling, helper, &[unblocked]),
                ["runs.runs_template_id_fkey"],
                "{spelling:?} {helper:?}"
            );
        }
    }
}

const PINNED: &str = "namespace_id = (SELECT authz.caller_namespace())";

/// Teams whose subtype key into the grantees `app` reads only through its
/// teams, with `check` the insert check of `app`, each `(from, to)` of
/// `edits` applied and `extra` appended.
fn subtype_schema(check: &str, edits: &[(&str, &str)], extra: &str) -> String {
    let mut sql = format!(
        "CREATE ROLE app;
         CREATE SCHEMA authz;
         CREATE TABLE namespaces (id UUID PRIMARY KEY, user_id UUID UNIQUE NOT NULL);
         CREATE FUNCTION authz.caller_namespace() RETURNS UUID LANGUAGE sql STABLE AS $$
             SELECT namespace.id FROM namespaces namespace
             WHERE namespace.user_id = NULLIF(current_setting('app.user_id', true), '')::UUID
         $$;
         CREATE TABLE grantees (
             namespace_id UUID NOT NULL,
             id UUID NOT NULL,
             kind TEXT NOT NULL,
             PRIMARY KEY (namespace_id, id),
             UNIQUE (namespace_id, id, kind)
         );
         ALTER TABLE grantees ENABLE ROW LEVEL SECURITY;
         CREATE TABLE teams (
             namespace_id UUID NOT NULL,
             id UUID NOT NULL,
             kind TEXT NOT NULL DEFAULT 'team' CHECK (kind = 'team'),
             member_id UUID NOT NULL,
             PRIMARY KEY (namespace_id, id),
             CONSTRAINT teams_grantee FOREIGN KEY (namespace_id, id, kind)
                 REFERENCES grantees (namespace_id, id, kind)
         );
         ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
         GRANT SELECT ON grantees TO app;
         GRANT SELECT, INSERT ON teams TO app;
         CREATE POLICY teams_select ON teams FOR SELECT TO app
             USING (member_id = NULLIF(current_setting('app.user_id', true), '')::UUID);
         CREATE POLICY teams_insert ON teams FOR INSERT TO app WITH CHECK ({check});
         CREATE POLICY grantees_select ON grantees FOR SELECT TO app
             USING ((namespace_id, id) IN (SELECT team.namespace_id, team.id FROM teams team));
         {extra}"
    );
    for (from, to) in edits {
        assert!(sql.contains(from), "{from}");
        sql = sql.replace(from, to);
    }
    sql
}

/// Objects of every finding on [`subtype_schema`], under a deployment
/// declaring `authz.caller_namespace()` a principal accessor.
fn pinned_subtypes(check: &str, edits: &[(&str, &str)], extra: &str) -> Vec<String> {
    objects_under(
        Deployment::default()
            .with_app_role("app")
            .with_principal_accessor("authz.caller_namespace()")
            .unwrap(),
        &subtype_schema(check, edits, extra),
    )
}

#[test]
fn a_key_pinned_to_the_writers_principal_matches_only_its_own_rows() {
    assert_eq!(
        objects_under(
            Deployment::default().with_app_role("app"),
            &subtype_schema(PINNED, &[], "")
        ),
        ["teams.teams_grantee"]
    );
    for extra in [
        "",
        "CREATE POLICY teams_pinned ON teams AS RESTRICTIVE FOR INSERT TO app
             WITH CHECK (authz.caller_namespace() = teams.namespace_id);",
        &format!(
            "GRANT UPDATE (namespace_id, id) ON teams TO app;
             CREATE POLICY teams_update ON teams FOR UPDATE TO app
                 USING (true) WITH CHECK ({PINNED});"
        ),
        &format!(
            "GRANT INSERT ON grantees TO app;
             CREATE POLICY grantees_insert ON grantees FOR INSERT TO app
                 WITH CHECK ({PINNED});"
        ),
        "CREATE FUNCTION insert_grantee() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
         BEGIN
             INSERT INTO grantees (namespace_id, id, kind) VALUES (NEW.namespace_id, NEW.id, NEW.kind)
                 ON CONFLICT (namespace_id, id, kind) DO NOTHING;
             RETURN NEW;
         END
         $$;
         CREATE TRIGGER teams_grantee AFTER INSERT ON teams
             FOR EACH ROW EXECUTE FUNCTION insert_grantee();",
    ] {
        assert_eq!(pinned_subtypes(PINNED, &[], extra), Vec::<String>::new(), "{extra}");
    }
    assert_eq!(
        pinned_subtypes(
            "true",
            &[],
            &format!(
                "CREATE POLICY teams_pinned ON teams AS RESTRICTIVE FOR INSERT TO app
                 WITH CHECK ({PINNED});"
            )
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_key_that_may_match_rows_of_another_principal_is_reported() {
    for check in [
        "namespace_id IS NOT NULL",
        "namespace_id = (SELECT authz.caller_namespace()) OR member_id IS NOT NULL",
    ] {
        assert_eq!(
            pinned_subtypes(check, &[], ""),
            ["teams.teams_grantee"],
            "{check}"
        );
    }
    for extra in [
        "GRANT INSERT ON grantees TO app;
         CREATE POLICY grantees_insert ON grantees FOR INSERT TO app WITH CHECK (true);",
        "GRANT UPDATE (namespace_id) ON grantees TO app;
         CREATE POLICY grantees_move ON grantees FOR UPDATE TO app USING (true);",
        "GRANT UPDATE (namespace_id) ON teams TO app;
         CREATE POLICY teams_move ON teams FOR UPDATE TO app USING (true);",
    ] {
        assert_eq!(
            pinned_subtypes(PINNED, &[], extra),
            ["teams.teams_grantee"],
            "{extra}"
        );
    }
    let outside_the_key = [
        (
            "member_id UUID NOT NULL,",
            "member_id UUID NOT NULL,\n             grantee_namespace_id UUID NOT NULL,",
        ),
        (
            "FOREIGN KEY (namespace_id, id, kind)",
            "FOREIGN KEY (grantee_namespace_id, id, kind)",
        ),
    ];
    let unlike = [
        (
            "CREATE SCHEMA authz;",
            "CREATE SCHEMA authz;
             CREATE COLLATION folded (provider = icu, locale = 'und-u-ks-level2', deterministic = false);",
        ),
        ("RETURNS UUID", "RETURNS TEXT"),
        (
            "namespace_id UUID NOT NULL",
            "namespace_id TEXT COLLATE folded NOT NULL",
        ),
    ];
    for edits in [&outside_the_key[..], &unlike] {
        assert_eq!(
            pinned_subtypes(PINNED, edits, ""),
            ["teams.teams_grantee"],
            "{edits:?}"
        );
    }
}
