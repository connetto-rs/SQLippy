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
    for (check, expected) in [
        ("(a, b) IN (SELECT a, b FROM slots)", vec![]),
        ("(b, a) IN (SELECT s.b, s.a FROM slots s)", vec![]),
        (
            "EXISTS (SELECT 1 FROM slots s WHERE s.a = uses.a AND uses.b = s.b)",
            vec![],
        ),
        ("(a, b) IN (SELECT b, a FROM slots)", vec!["uses.uses_slot"]),
        (
            "a IN (SELECT a FROM slots) AND b IN (SELECT b FROM slots)",
            vec!["uses.uses_slot"],
        ),
        (
            "(a, b) IN (SELECT x.a, y.b FROM slots x, slots y)",
            vec!["uses.uses_slot"],
        ),
        (
            "EXISTS (SELECT 1 FROM slots x, slots y WHERE x.a = uses.a AND y.b = uses.b)",
            vec!["uses.uses_slot"],
        ),
    ] {
        assert_eq!(
            objects(&format!(
                "CREATE TABLE slots (a INT, b INT, c INT, UNIQUE (a, b), UNIQUE (a, b, c));
                 ALTER TABLE slots ENABLE ROW LEVEL SECURITY;
                 CREATE TABLE uses (a INT, b INT, c INT,
                     CONSTRAINT uses_slot FOREIGN KEY (a, b, c) REFERENCES slots (a, b, c));
                 GRANT INSERT ON uses TO app;
                 ALTER TABLE uses ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY uses_write ON uses FOR INSERT TO app WITH CHECK ({check});"
            )),
            expected,
            "{check}"
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
                "id IS NULL OR (organization_id, invitation_id) IN (SELECT organization_id, id FROM invitations)",
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
                     CREATE TABLE memberships (id INT PRIMARY KEY, organization_id INT NOT NULL, invitation_id INT,
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
