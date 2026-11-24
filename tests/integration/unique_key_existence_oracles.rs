//! Unique keys that tell a client role whether a row it cannot read exists,
//! observed through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

/// Object and message of every finding on `sql`.
fn reported(sql: &str) -> Vec<(String, String)> {
    reported_under(Deployment::default(), sql)
}

/// Object and message of every finding on `sql` under `deployment`, with
/// `app` an app role.
fn reported_under(deployment: Deployment, sql: &str) -> Vec<(String, String)> {
    let mut constrainer: GenericConstrainer<ParserDB> = UniqueKeyExistenceOracle::default().into();
    constrainer.set_deployment(deployment.with_app_role("app"));
    findings(
        &constrainer,
        "unique_key_existence_oracle",
        &format!("CREATE ROLE app; {sql}"),
    )
    .into_iter()
    .map(|(_, object, message)| (object, message))
    .collect()
}

/// Objects of every finding on `sql`.
fn objects(sql: &str) -> Vec<String> {
    objects_under(Deployment::default(), sql)
}

/// Objects of every finding on `sql` under `deployment`.
fn objects_under(deployment: Deployment, sql: &str) -> Vec<String> {
    reported_under(deployment, sql)
        .into_iter()
        .map(|(object, _)| object)
        .collect()
}

const NOTES: &str = "CREATE TABLE notes (id INT CONSTRAINT notes_pkey PRIMARY KEY, body TEXT,
        slug TEXT DEFAULT 'x', CONSTRAINT notes_slug UNIQUE (slug));
    ALTER TABLE notes ENABLE ROW LEVEL SECURITY;";

#[test]
fn a_key_the_writer_inserts_over_rows_it_cannot_read_is_reported() {
    let findings = reported(&format!(
        "{NOTES} CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (true);
         GRANT INSERT (id, body), SELECT ON notes TO app;"
    ));
    assert_eq!(findings.len(), 1, "{findings:?}");
    let (object, message) = &findings[0];
    assert_eq!(object, "notes.notes_pkey");
    assert!(message.contains("'app'"), "{message}");
    assert!(message.contains("INSERT"), "{message}");
}

#[test]
fn an_insert_only_table_hides_every_row() {
    assert_eq!(
        objects(
            "CREATE TABLE events (id INT CONSTRAINT events_pkey PRIMARY KEY);
             GRANT INSERT ON events TO app;"
        ),
        ["events.events_pkey"]
    );
    assert_eq!(
        objects(
            "CREATE TABLE events (id INT CONSTRAINT events_pkey PRIMARY KEY);
             GRANT INSERT, SELECT ON events TO app;"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        objects(
            "CREATE TABLE events (id INT CONSTRAINT events_pkey PRIMARY KEY, body TEXT);
             GRANT INSERT, SELECT (body) ON events TO app;"
        ),
        ["events.events_pkey"]
    );
}

#[test]
fn a_key_the_writer_cannot_choose_is_clean() {
    assert_eq!(
        objects(&format!(
            "{NOTES} CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (true);
             GRANT INSERT (body) ON notes TO app;"
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        objects(&format!(
            "{NOTES} GRANT INSERT ON notes TO app;
             CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK (false);"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn updating_a_key_column_reaches_the_key() {
    assert_eq!(
        objects(&format!(
            "{NOTES} CREATE POLICY notes_update ON notes FOR UPDATE TO app USING (true);
             GRANT UPDATE (slug) ON notes TO app;"
        )),
        ["notes.notes_slug"]
    );
}

#[test]
fn a_key_confined_to_rows_the_writer_reads_is_clean() {
    for (check, expected) in [
        ("id IN (SELECT readable())", vec![]),
        ("id IN (SELECT readable()) OR id IS NULL", vec![]),
        ("id > 0", vec!["notes.notes_pkey"]),
    ] {
        assert_eq!(
            objects(&format!(
                "CREATE FUNCTION readable() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;
                 {NOTES}
                 CREATE POLICY notes_read ON notes FOR SELECT TO app USING (id IN (SELECT readable()));
                 CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK ({check});
                 GRANT INSERT (id, body), SELECT ON notes TO app;"
            )),
            expected,
            "{check}"
        );
    }
}

#[test]
fn a_null_key_a_unique_key_compares_reaches_the_key() {
    for (nulls, expected) in [("", vec![]), ("NULLS NOT DISTINCT", vec!["tags.tags_slug"])] {
        assert_eq!(
            objects(&format!(
                "CREATE FUNCTION readable() RETURNS SETOF TEXT LANGUAGE sql STABLE AS $$ SELECT 'a' $$;
                 CREATE TABLE tags (slug TEXT, CONSTRAINT tags_slug UNIQUE {nulls} (slug));
                 ALTER TABLE tags ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY tags_read ON tags FOR SELECT TO app USING (slug IN (SELECT readable()));
                 CREATE POLICY tags_write ON tags FOR INSERT TO app
                   WITH CHECK (slug IN (SELECT readable()) OR slug IS NULL);
                 GRANT INSERT, SELECT ON tags TO app;"
            )),
            expected,
            "{nulls}"
        );
    }
}

/// A `grants` table whose rows `app` reads under `read` and inserts under
/// `check`, beside helpers projecting the resources a caller may share.
fn grants(read: &str, check: &str) -> String {
    format!(
        "CREATE TABLE resources (id INT PRIMARY KEY, owner_id INT NOT NULL);
         CREATE FUNCTION sharable_grants() RETURNS TABLE (resource_id INT, role TEXT)
           LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT resource.id, 'writer'::text
           FROM resources resource WHERE resource.owner_id = current_setting('app.user_id')::int $$;
         CREATE FUNCTION other_grants() RETURNS TABLE (resource_id INT, role TEXT)
           LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT resource.id, 'reader'::text
           FROM resources resource $$;
         CREATE FUNCTION sharable_resources() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER
           AS $$ SELECT share.resource_id FROM sharable_grants() share $$;
         CREATE FUNCTION shared_by(owner INT) RETURNS SETOF INT LANGUAGE sql STABLE STRICT
           SECURITY DEFINER AS $$ SELECT share.resource_id FROM sharable_grants() share $$;
         CREATE TABLE grants (resource_id INT, grantee_id INT, role TEXT,
           PRIMARY KEY (resource_id, grantee_id));
         ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
         CREATE POLICY grants_read ON grants FOR SELECT TO app USING ({read});
         CREATE POLICY grants_write ON grants FOR INSERT TO app WITH CHECK ({check});
         GRANT SELECT, INSERT ON grants TO app;"
    )
}

const SHARED: &str = "resource_id IN (SELECT share.resource_id FROM sharable_grants() share)";
const OTHER: &str = "resource_id IN (SELECT share.resource_id FROM other_grants() share)";
const RESOURCES: &str = "resource_id IN (SELECT sharable_resources())";

#[test]
fn a_key_drawn_from_the_projected_helper_column_it_is_read_through_is_clean() {
    let pair = "(resource_id, role) IN (SELECT share.resource_id, share.role FROM sharable_grants() share)";
    for (read, check) in [
        (SHARED, SHARED),
        (RESOURCES, pair),
        (SHARED, RESOURCES),
        (RESOURCES, SHARED),
        (RESOURCES, RESOURCES),
    ] {
        assert_eq!(
            objects(&grants(read, check)),
            Vec::<String>::new(),
            "{read} / {check}"
        );
    }
}

const INVITATIONS: &str = "CREATE TABLE invitations (id INT PRIMARY KEY, email TEXT NOT NULL,
        accepted BOOLEAN NOT NULL DEFAULT false, accepted_by INT);
    CREATE TABLE memberships (user_id INT PRIMARY KEY, nickname INT,
        invitation_id INT CONSTRAINT memberships_invitation UNIQUE REFERENCES invitations (id));
    CREATE FUNCTION pending() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER AS $$
      SELECT id FROM invitations WHERE email = current_setting('app.email') AND NOT accepted
    $$;
    CREATE FUNCTION accept_invitation() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
    BEGIN
      UPDATE invitations SET accepted = true WHERE id = NEW.invitation_id;
      RETURN NULL;
    END $$;
    CREATE TRIGGER memberships_accept AFTER INSERT ON memberships
      FOR EACH ROW EXECUTE FUNCTION accept_invitation();
    ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
    CREATE POLICY memberships_read ON memberships FOR SELECT TO app
      USING (user_id = current_setting('app.user_id')::int);
    CREATE POLICY memberships_write ON memberships FOR INSERT TO app
      WITH CHECK (user_id = current_setting('app.user_id')::int AND invitation_id IN (SELECT pending()));
    GRANT SELECT, INSERT ON memberships TO app;";

/// Whether the invitation key of `INVITATIONS`, with each `(from, to)`
/// replacement applied once, is reported.
fn reports_invitation_key(edits: &[(&str, &str)]) -> bool {
    let mut sql = INVITATIONS.to_owned();
    for (from, to) in edits {
        assert!(sql.contains(from), "{from}");
        sql = sql.replacen(from, to, 1);
    }
    objects(&sql).contains(&"memberships.memberships_invitation".to_owned())
}

const RENAMING: (&str, &str) = (
    "GRANT SELECT, INSERT ON memberships TO app",
    "CREATE POLICY memberships_rename ON memberships FOR UPDATE TO app
       USING (true) WITH CHECK (invitation_id IN (SELECT pending()));
     GRANT SELECT, INSERT, UPDATE (invitation_id) ON memberships TO app",
);

const RE_CREATING: (&str, &str) = (
    "GRANT SELECT, INSERT ON memberships",
    "GRANT DELETE, INSERT ON invitations TO app; GRANT SELECT, INSERT ON memberships",
);

#[test]
fn a_key_a_trigger_takes_out_of_the_checked_set_is_clean() {
    for edits in [
        &[][..],
        &[(
            "invitation_id IN (SELECT pending())",
            "invitation_id IN (SELECT pending_id FROM pending() AS pending_id)",
        )],
        &[
            ("AND NOT accepted", "AND accepted_by IS NULL"),
            ("SET accepted = true", "SET accepted_by = NEW.user_id"),
            (
                "FOR EACH ROW EXECUTE",
                "FOR EACH ROW WHEN (NEW.invitation_id IS NOT NULL) EXECUTE",
            ),
            (
                "invitation_id IN (SELECT pending())",
                "(invitation_id IS NULL OR invitation_id = ANY (ARRAY(SELECT pending())))",
            ),
        ],
        &[
            (
                "REFERENCES invitations (id)",
                "REFERENCES invitations (id) ON DELETE RESTRICT",
            ),
            RE_CREATING,
        ],
        &[
            (
                "AFTER INSERT ON memberships",
                "AFTER INSERT OR UPDATE OF invitation_id ON memberships",
            ),
            RENAMING,
        ],
        &[(
            "WHERE id = NEW.invitation_id",
            "WHERE invitations.id = NEW.invitation_id",
        )],
        &[
            (
                "CREATE FUNCTION accept_invitation",
                "CREATE TABLE audit (id INT); CREATE FUNCTION accept_invitation",
            ),
            (
                "RETURN NULL;",
                "INSERT INTO audit VALUES (NEW.user_id); RETURN NULL;",
            ),
        ],
        &[(
            "CREATE TRIGGER memberships_accept",
            "CREATE FUNCTION stamp() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
             CREATE TRIGGER invitations_stamp BEFORE INSERT ON invitations FOR EACH ROW EXECUTE FUNCTION stamp();
             CREATE TRIGGER memberships_accept",
        )],
        &[(
            "GRANT SELECT, INSERT ON memberships",
            "GRANT INSERT ON invitations TO app; GRANT SELECT, INSERT ON memberships",
        )],
    ] {
        assert!(!reports_invitation_key(edits), "{edits:?}");
    }
}

#[test]
fn a_key_drawn_from_another_set_than_the_readable_one_is_reported() {
    for (read, check) in [
        (SHARED, OTHER),
        (OTHER, RESOURCES),
        (
            "resource_id IN (SELECT share.resource_id FROM sharable_grants() share WHERE share.role = 'reader')",
            SHARED,
        ),
        ("resource_id IN (SELECT shared_by(NULL))", SHARED),
    ] {
        assert_eq!(
            objects(&grants(read, check)),
            vec!["grants.grants_pkey"],
            "{read} / {check}"
        );
    }
}

#[test]
fn a_projected_helper_column_is_declared_within_a_set_as_a_field_of_the_call() {
    let deployment = Deployment::default()
        .with_set_within("(other_grants()).resource_id", "sharable_resources()")
        .unwrap();
    assert_eq!(
        objects_under(deployment, &grants(RESOURCES, OTHER)),
        Vec::<String>::new()
    );
}

#[test]
fn a_key_the_trigger_leaves_in_the_checked_set_is_reported() {
    for edits in [
        &[("SET accepted = true", "SET accepted = false")][..],
        &[("WHERE id = NEW.invitation_id", "WHERE id = NEW.user_id")],
        &[(
            "UPDATE invitations SET accepted = true WHERE id = NEW.invitation_id;",
            "IF NEW.user_id > 0 THEN UPDATE invitations SET accepted = true WHERE id = NEW.invitation_id; END IF;",
        )],
        &[(
            "RETURN NULL;",
            "UPDATE invitations SET accepted = false WHERE id = NEW.invitation_id; RETURN NULL;",
        )],
        &[(
            "FOR EACH ROW EXECUTE",
            "FOR EACH ROW WHEN (NEW.user_id > 0) EXECUTE",
        )],
        &[("AND NOT accepted", "")],
        &[
            ("AND NOT accepted", "AND accepted_by IS NULL"),
            ("SET accepted = true", "SET accepted_by = NEW.nickname"),
        ],
        &[(
            "GRANT SELECT, INSERT ON memberships",
            "GRANT UPDATE (accepted) ON invitations TO app; GRANT SELECT, INSERT ON memberships",
        )],
        &[RE_CREATING],
        &[RENAMING],
        &[(
            "ALTER TABLE memberships",
            "CREATE ROLE writer; ALTER FUNCTION accept_invitation() OWNER TO writer;
             GRANT SELECT, UPDATE (accepted) ON invitations TO writer;
             ALTER TABLE invitations ENABLE ROW LEVEL SECURITY; ALTER TABLE memberships",
        )],
        &[(
            "CREATE TRIGGER memberships_accept",
            "CREATE FUNCTION keep() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$;
             CREATE TRIGGER invitations_keep BEFORE UPDATE ON invitations FOR EACH ROW EXECUTE FUNCTION keep();
             CREATE TRIGGER memberships_accept",
        )],
        &[(
            "SELECT id FROM invitations WHERE",
            "SELECT accepted_by FROM invitations WHERE",
        )],
        &[("AFTER INSERT ON memberships", "AFTER UPDATE ON memberships")],
        &[("WHERE id = NEW.invitation_id", "WHERE id = OLD.invitation_id")],
        &[
            ("nickname INT,", "nickname INT, id INT,"),
            (
                "WHERE id = NEW.invitation_id",
                "WHERE NEW.id = NEW.invitation_id",
            ),
        ],
        &[
            (
                "CREATE FUNCTION accept_invitation",
                "CREATE FUNCTION reopen(INT) RETURNS VOID LANGUAGE sql AS $$
                   UPDATE invitations SET accepted = false WHERE id = $1 $$;
                 CREATE FUNCTION accept_invitation",
            ),
            (
                "RETURN NULL;",
                "PERFORM reopen(NEW.invitation_id); RETURN NULL;",
            ),
        ],
        &[
            (
                "CREATE FUNCTION accept_invitation",
                "CREATE FUNCTION reopened(INT) RETURNS BOOLEAN LANGUAGE sql AS $$
                   UPDATE invitations SET accepted = false WHERE id = $1 RETURNING true $$;
                 CREATE FUNCTION accept_invitation",
            ),
            ("BEGIN", "DECLARE done BOOLEAN; BEGIN"),
            (
                "RETURN NULL;",
                "done := reopened(NEW.invitation_id); RETURN NULL;",
            ),
        ],
        &[(
            "RETURN NULL;",
            "EXECUTE 'UPDATE invitations SET accepted = false'; RETURN NULL;",
        )],
        &[
            ("REFERENCES invitations (id)", ""),
            (
                "GRANT SELECT, INSERT ON memberships",
                "GRANT TRUNCATE, INSERT ON invitations TO app; GRANT SELECT, INSERT ON memberships",
            ),
        ],
    ] {
        assert!(reports_invitation_key(edits), "{edits:?}");
    }
}
