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

const SLOTS_READ: &str = "template_id = ANY (ARRAY(SELECT readable('reader')))";

/// A typed template whose slot key reaches slots `readable` admits, after a
/// restrictive policy hiding blocked organizations.
fn slot_schema(readable: &str, check: &str, key: &str, referenced: &str) -> String {
    format!(
        "CREATE ROLE app;
         CREATE FUNCTION readable(level TEXT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;
         CREATE FUNCTION reader_ids() RETURNS INT[] LANGUAGE sql STABLE AS $$ SELECT ARRAY[1] $$;
         CREATE FUNCTION blocking() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;
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
            &slot_schema(SLOTS_READ, check, key, referenced),
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
            ),
        )
        .into_iter()
        .map(|(_, object, _)| object)
        .collect();
        assert_eq!(objects, expected, "{check} into {readable}");
    }
}

const BLOCKED: &str = "NOT (organization_id = ANY (ARRAY(SELECT blocking())))";

const PARENT_READ: &str = "parent_id = ANY (ARRAY(SELECT resources_with('reader')))";

const RESOURCES: &str =
    "id INT PRIMARY KEY, organization_id INT NOT NULL, UNIQUE (organization_id, id)";

const PARENT_RESOURCE: &str = "organization_id INT NOT NULL,
    FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id)";

/// Parents hidden by `blocked` and read through `resources_with`, whose
/// columns past `id` are `parent`, and children whose insert check is
/// `check`.
fn blocked_parents(resources: &str, parent: &str, blocked: &str, check: &str) -> String {
    format!(
        "CREATE ROLE app;
         CREATE FUNCTION resources_with(level TEXT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;
         CREATE FUNCTION blocking() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;
         CREATE TABLE resources ({resources});
         CREATE TABLE parents (id INT PRIMARY KEY, {parent});
         ALTER TABLE parents ENABLE ROW LEVEL SECURITY;
         CREATE POLICY parents_select ON parents FOR SELECT TO app
             USING (id = ANY (ARRAY(SELECT resources_with('reader'))));
         CREATE POLICY parents_blocked ON parents AS RESTRICTIVE FOR ALL TO app USING ({blocked});
         CREATE TABLE children (id INT PRIMARY KEY, organization_id INT NOT NULL,
             parent_id INT NOT NULL CONSTRAINT children_parent REFERENCES parents (id));
         ALTER TABLE children ENABLE ROW LEVEL SECURITY;
         CREATE POLICY children_insert ON children FOR INSERT TO app WITH CHECK ({check});
         CREATE POLICY children_blocked ON children AS RESTRICTIVE FOR ALL TO app
             USING ({BLOCKED}) WITH CHECK ({BLOCKED});
         GRANT SELECT ON parents TO app;
         GRANT INSERT ON children TO app;"
    )
}

/// Whether the key of the children into `blocked_parents` is reported, with
/// `resources_with('writer')` within `resources_with('reader')`, and the
/// reader set declared to yield `resources.id` of rows meeting `BLOCKED`
/// when `declared` is set.
fn blocked_parent_reported(
    declared: bool,
    resources: &str,
    parent: &str,
    blocked: &str,
    check: &str,
) -> bool {
    let mut deployment = Deployment::default()
        .with_app_role("app")
        .with_set_within("resources_with('writer')", "resources_with('reader')")
        .unwrap();
    if declared {
        deployment = deployment
            .with_set_satisfying(
                "resources_with('reader')",
                "public",
                "resources",
                "id",
                BLOCKED,
            )
            .unwrap();
    }
    let mut constrainer: GenericConstrainer<ParserDB> = ForeignKeyExistenceOracle::default().into();
    constrainer.set_deployment(deployment);
    let objects: Vec<String> = findings(
        &constrainer,
        "foreign_key_existence_oracle",
        &blocked_parents(resources, parent, blocked, check),
    )
    .into_iter()
    .map(|(_, object, _)| object)
    .collect();
    match objects.as_slice() {
        [] => false,
        [object] if object == "children.children_parent" => true,
        _ => panic!("unexpected findings {objects:?}"),
    }
}

const NULLABLE_PARENT_RESOURCE: &str = "organization_id INT,
    FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id)";

#[test]
fn a_referenced_policy_a_declared_set_satisfies_through_the_referenced_table_is_clean() {
    let matched_fully = format!("{NULLABLE_PARENT_RESOURCE} MATCH FULL");
    let null_arm = format!("parent_id IS NULL OR {PARENT_READ}");
    let writer = "parent_id = ANY (ARRAY(SELECT resources_with('writer')))";
    for (parent, check) in [
        (PARENT_RESOURCE, PARENT_READ),
        (PARENT_RESOURCE, null_arm.as_str()),
        (PARENT_RESOURCE, writer),
        (matched_fully.as_str(), PARENT_READ),
    ] {
        assert!(
            !blocked_parent_reported(true, RESOURCES, parent, BLOCKED, check),
            "{check} into ({parent})"
        );
    }
}

#[test]
fn a_referenced_policy_no_declared_set_satisfies_through_the_referenced_table_is_reported() {
    let shared_id =
        "id INT NOT NULL, organization_id INT NOT NULL, PRIMARY KEY (organization_id, id)";
    let unrelated = "parent_id = ANY (ARRAY(SELECT resources_with('any')))";
    for (declared, resources, parent, blocked, check) in [
        (false, RESOURCES, PARENT_RESOURCE, BLOCKED, PARENT_READ),
        (
            true,
            RESOURCES,
            NULLABLE_PARENT_RESOURCE,
            BLOCKED,
            PARENT_READ,
        ),
        (
            true,
            RESOURCES,
            "organization_id INT NOT NULL",
            BLOCKED,
            PARENT_READ,
        ),
        (
            true,
            RESOURCES,
            PARENT_RESOURCE,
            "organization_id <> 0",
            PARENT_READ,
        ),
        (true, shared_id, PARENT_RESOURCE, BLOCKED, PARENT_READ),
        (true, RESOURCES, PARENT_RESOURCE, BLOCKED, unrelated),
    ] {
        assert!(
            blocked_parent_reported(declared, resources, parent, blocked, check),
            "{check} into ({parent}) over ({resources}), {blocked}"
        );
    }
}
