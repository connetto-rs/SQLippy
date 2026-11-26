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
fn a_key_confined_to_rows_a_read_policy_the_writer_cannot_evaluate_admits_is_reported() {
    for (granted, expected) in [
        ("GRANT SELECT ON secrets TO app;", vec![]),
        ("", vec!["notes.notes_pkey"]),
    ] {
        assert_eq!(
            objects(&format!(
                "CREATE FUNCTION readable() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT 1 $$;
                 CREATE TABLE secrets (id INT);
                 {NOTES}
                 CREATE POLICY notes_read ON notes FOR SELECT TO app USING (id IN (SELECT readable()));
                 CREATE POLICY notes_secret ON notes FOR SELECT TO app
                   USING (EXISTS (SELECT 1 FROM secrets secret WHERE secret.id = notes.id));
                 CREATE POLICY notes_write ON notes FOR INSERT TO app
                   WITH CHECK (id IN (SELECT readable()));
                 GRANT INSERT (id, body), SELECT ON notes TO app;
                 {granted}"
            )),
            expected,
            "{granted}"
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
fn reports_invitation_key<To: AsRef<str>>(edits: &[(&str, To)]) -> bool {
    let mut sql = INVITATIONS.to_owned();
    for (from, to) in edits {
        assert!(sql.contains(from), "{from}");
        sql = sql.replacen(from, to.as_ref(), 1);
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
        &[(
            "RETURN NULL;",
            "UPDATE memberships SET nickname = 1 WHERE user_id = NEW.user_id; RETURN NULL;",
        )],
        &[("SET accepted = true", "SET accepted = true, email = email")],
        &[(
            "AND NOT accepted",
            "AND accepted IN (SELECT false UNION SELECT true) AND NOT accepted",
        )],
        &[(
            "BEGIN",
            "BEGIN IF NEW.user_id > 0 THEN
               UPDATE invitations SET accepted = true WHERE id = NEW.invitation_id; RETURN NULL;
             END IF;",
        )],
        &[("UPDATE invitations SET", "UPDATE ONLY invitations SET")],
    ] {
        assert!(!reports_invitation_key(edits), "{edits:?}");
    }
}

/// The trigger's `UPDATE` with `WHERE id = NEW.invitation_id` replaced by `selection`.
fn keyed(selection: &str) -> (&'static str, String) {
    ("WHERE id = NEW.invitation_id", format!("WHERE {selection}"))
}

#[test]
fn a_key_an_update_guarded_by_its_own_filter_consumes_is_clean() {
    let pending_by = ("AND NOT accepted", "AND accepted_by IS NULL".to_owned());
    let stamping = (
        "SET accepted = true",
        "SET accepted_by = NEW.user_id".to_owned(),
    );
    let update = "UPDATE invitations SET accepted = true WHERE id = NEW.invitation_id;";
    for edits in [
        vec![keyed("id = NEW.invitation_id AND NOT accepted")],
        vec![keyed("NOT accepted AND invitations.id = NEW.invitation_id")],
        vec![
            pending_by.clone(),
            stamping,
            keyed("id = NEW.invitation_id AND accepted_by IS NULL"),
        ],
        vec![(
            update,
            format!("IF NEW.invitation_id IS NOT NULL THEN {update} END IF;"),
        )],
        vec![(
            update,
            format!("IF (NEW.invitation_id IS NOT NULL) THEN {update} END IF;"),
        )],
        vec![(
            update,
            format!("IF NEW.invitation_id IS NULL THEN RETURN NULL; END IF; {update}"),
        )],
        vec![
            (
                "accepted_by INT);",
                "accepted_by INT, accepted_at TIMESTAMPTZ);".to_owned(),
            ),
            ("AND NOT accepted", "AND accepted_at IS NULL".to_owned()),
            ("SET accepted = true", "SET accepted_at = now()".to_owned()),
        ],
        vec![
            pending_by,
            (
                "SET accepted = true",
                "SET accepted_by = current_setting('app.user_id')::int".to_owned(),
            ),
        ],
    ] {
        assert!(!reports_invitation_key(&edits), "{edits:?}");
    }
}

#[test]
fn a_key_an_update_skips_while_the_check_admits_it_is_reported() {
    let update = "UPDATE invitations SET accepted = true WHERE id = NEW.invitation_id;";
    for edits in [
        vec![keyed("id = NEW.invitation_id AND email = 'x@y'")],
        vec![
            (
                "SET accepted = true",
                "SET accepted = true, accepted_by = NEW.user_id".to_owned(),
            ),
            keyed("id = NEW.invitation_id AND accepted_by = 5"),
        ],
        vec![(
            update,
            format!("IF NEW.invitation_id IS NULL THEN {update} END IF;"),
        )],
        vec![(
            update,
            format!("IF NEW.nickname IS NULL THEN RETURN NULL; END IF; {update}"),
        )],
        vec![(
            update,
            format!("IF NEW.nickname IS NOT NULL THEN {update} END IF;"),
        )],
        vec![
            ("AND NOT accepted", "AND accepted_by IS NULL".to_owned()),
            (
                "SET accepted = true",
                "SET accepted_by = NULLIF(current_setting('app.user_id')::int, NEW.user_id)"
                    .to_owned(),
            ),
        ],
    ] {
        assert!(reports_invitation_key(&edits), "{edits:?}");
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
fn a_key_drawn_from_the_seed_of_a_recursive_helper_it_is_read_through_is_clean() {
    let walked = "CREATE FUNCTION walked_resources() RETURNS SETOF INT LANGUAGE sql STABLE
        SECURITY DEFINER AS $$ WITH RECURSIVE walked (id) AS (
          SELECT share.resource_id FROM sharable_grants() share
          UNION SELECT resource.id FROM resources resource JOIN walked ON walked.id = resource.owner_id
        ) SELECT walked.id FROM walked $$;";
    let read = "resource_id IN (SELECT walked_resources())";
    for (read, check, expected) in [
        (read, SHARED, vec![]),
        (read, RESOURCES, vec![]),
        (read, OTHER, vec!["grants.grants_pkey"]),
        (
            SHARED,
            "resource_id IN (SELECT walked_resources())",
            vec!["grants.grants_pkey"],
        ),
    ] {
        let sql = grants(read, check).replacen(
            "CREATE TABLE grants",
            &format!("{walked} CREATE TABLE grants"),
            1,
        );
        assert_eq!(objects(&sql), expected, "{read} / {check}");
    }
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
        &[
            ("id INT PRIMARY KEY, email", "id INT NOT NULL, email"),
            ("REFERENCES invitations (id)", ""),
            (
                "GRANT SELECT, INSERT ON memberships",
                "GRANT INSERT ON invitations TO app; GRANT SELECT, INSERT ON memberships",
            ),
        ],
    ] {
        assert!(reports_invitation_key(edits), "{edits:?}");
    }
}

#[test]
fn a_trigger_or_helper_the_rule_cannot_read_leaves_the_key_reported() {
    for edits in [
        &[(
            "CREATE TRIGGER memberships_accept AFTER INSERT ON memberships
      FOR EACH ROW EXECUTE FUNCTION accept_invitation()",
            "CREATE FUNCTION accept_native() RETURNS TRIGGER LANGUAGE c AS 'accept', 'accept';
             CREATE TRIGGER memberships_accept AFTER INSERT ON memberships
               FOR EACH ROW EXECUTE FUNCTION accept_native()",
        )][..],
        &[(
            "WHERE id = NEW.invitation_id",
            "WHERE id <> NEW.invitation_id",
        )],
        &[("SET accepted = true", "SET (accepted) = (false)")],
        &[(
            "WHERE id = NEW.invitation_id",
            "WHERE id = NEW.invitation_id + 1",
        )],
        &[("SET accepted = true", "SET accepted = (SELECT false)")],
        &[(
            "WHERE id = NEW.invitation_id",
            "WHERE invite_id = NEW.invitation_id",
        )],
        &[("SET accepted = true", "SET accepted = true, acceptd = true")],
        &[
            ("accepted_by INT);", "accepted_by INT, code INT);"),
            ("SELECT id FROM invitations", "SELECT code FROM invitations"),
            (
                "WHERE id = NEW.invitation_id",
                "WHERE code = NEW.invitation_id",
            ),
            RE_CREATING,
        ],
        &[
            (
                "LANGUAGE sql STABLE SECURITY DEFINER AS $$",
                "LANGUAGE plpgsql STABLE SECURITY DEFINER AS $$ BEGIN RETURN QUERY",
            ),
            ("AND NOT accepted", "AND NOT accepted; END"),
        ],
        &[("AND NOT accepted", "AND NOT accepted UNION SELECT 0")],
    ] {
        assert!(reports_invitation_key(edits), "{edits:?}");
    }
}

/// The trigger's `UPDATE` replaced by `PERFORM {call}` of the function
/// `{signature} ... AS $$ {body} $$`.
fn calling(signature: &str, body: &str, call: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "CREATE FUNCTION accept_invitation",
            format!(
                "CREATE FUNCTION {signature} AS $$ {body} $$; CREATE FUNCTION accept_invitation"
            ),
        ),
        (
            "UPDATE invitations SET accepted = true WHERE id = NEW.invitation_id;",
            format!("PERFORM {call};"),
        ),
    ]
}

/// The trigger's `UPDATE` replaced by `statement`, over invitations no
/// foreign key references.
fn removing(statement: &str) -> Vec<(&'static str, String)> {
    vec![
        ("REFERENCES invitations (id)", String::new()),
        (
            "UPDATE invitations SET accepted = true WHERE id = NEW.invitation_id;",
            format!("{statement};"),
        ),
    ]
}

/// The trigger made a statement trigger reading the inserted rows as
/// `new_rows`, its `UPDATE` selecting the named rows by `selection`.
fn per_statement(selection: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "FOR EACH ROW EXECUTE",
            "REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE".to_owned(),
        ),
        keyed(selection),
    ]
}

const MARK: &str = "mark_accepted(invitation INT) RETURNS VOID LANGUAGE sql SECURITY DEFINER";
const MARKING: &str = "UPDATE invitations SET accepted = true WHERE id = invitation";

#[test]
fn a_key_another_trigger_form_consumes_is_clean() {
    for edits in [
        calling(MARK, MARKING, "mark_accepted(NEW.invitation_id)"),
        calling(
            MARK,
            "UPDATE invitations SET accepted = true WHERE id = $1",
            "mark_accepted(NEW.invitation_id)",
        ),
        calling(
            MARK,
            "UPDATE invitations SET accepted = true WHERE mark_accepted.invitation = id",
            "mark_accepted(NEW.invitation_id)",
        ),
        calling(
            "mark_accepted(invitation INT) RETURNS VOID LANGUAGE sql STRICT",
            MARKING,
            "mark_accepted(NEW.invitation_id)",
        ),
        [
            vec![("AND NOT accepted", "AND accepted_by IS NULL".to_owned())],
            calling(
                "mark_accepted(invitation INT, accepter INT) RETURNS VOID LANGUAGE sql",
                "UPDATE invitations SET accepted_by = accepter WHERE id = invitation",
                "mark_accepted(NEW.invitation_id, NEW.user_id)",
            ),
        ]
        .concat(),
        removing("DELETE FROM invitations WHERE id = NEW.invitation_id"),
        removing("DELETE FROM invitations WHERE NEW.invitation_id = invitations.id"),
        per_statement("id IN (SELECT invitation_id FROM new_rows)"),
        per_statement("id IN (SELECT inserted.invitation_id FROM new_rows AS inserted)"),
        [
            removing("DELETE FROM invitations WHERE id IN (SELECT invitation_id FROM new_rows)"),
            vec![(
                "FOR EACH ROW EXECUTE",
                "REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE".to_owned(),
            )],
        ]
        .concat(),
        calling(
            "mark_accepted(id INT) RETURNS VOID LANGUAGE sql SECURITY DEFINER",
            "UPDATE invitations AS mark_accepted SET accepted = true WHERE mark_accepted.id = $1",
            "mark_accepted(NEW.invitation_id)",
        ),
        calling(
            "mark_accepted(id INT) RETURNS VOID LANGUAGE sql SECURITY DEFINER",
            "UPDATE invitations SET accepted = true WHERE invitations.id = mark_accepted.id",
            "mark_accepted(NEW.invitation_id)",
        ),
        [
            vec![("REFERENCES invitations (id)", String::new())],
            calling(
                "drop_invitation(invitation INT) RETURNS VOID LANGUAGE sql",
                "DELETE FROM invitations WHERE id = invitation",
                "drop_invitation(NEW.invitation_id)",
            ),
        ]
        .concat(),
    ] {
        assert!(!reports_invitation_key(&edits), "{edits:?}");
    }
}

/// The trigger of `INVITATIONS` made to fire on no insert.
fn untriggered() -> (&'static str, String) {
    (
        "AFTER INSERT ON memberships",
        "AFTER DELETE ON memberships".to_owned(),
    )
}

/// The body of `pending()` with its filter replaced by `filter` on the
/// invitation `i` it selects.
fn pending_where(filter: &str) -> (&'static str, String) {
    (
        "SELECT id FROM invitations WHERE email = current_setting('app.email') AND NOT accepted",
        format!("SELECT i.id FROM invitations i WHERE {filter}"),
    )
}

/// The invitation key of `INVITATIONS` comparing `NULL`s, with no foreign key.
fn nulls_not_distinct() -> (&'static str, String) {
    (
        "invitation_id INT CONSTRAINT memberships_invitation UNIQUE REFERENCES invitations (id)",
        "invitation_id INT, CONSTRAINT memberships_invitation UNIQUE NULLS NOT DISTINCT (invitation_id)"
            .to_owned(),
    )
}

#[test]
fn a_key_a_helper_draws_from_values_no_row_holds_is_clean() {
    let unclaimed = "NOT EXISTS (SELECT 1 FROM memberships m WHERE m.invitation_id = i.id)";
    for edits in [
        vec![untriggered(), pending_where(unclaimed)],
        vec![
            untriggered(),
            pending_where(
                "i.email = current_setting('app.email')
                 AND NOT EXISTS (SELECT 1 FROM memberships WHERE invitation_id = i.id)",
            ),
        ],
        vec![
            untriggered(),
            pending_where(
                "i.id NOT IN (SELECT invitation_id FROM memberships WHERE invitation_id IS NOT NULL)",
            ),
        ],
        vec![
            untriggered(),
            pending_where("i.id NOT IN (SELECT m.invitation_id FROM memberships m)"),
        ],
        vec![
            untriggered(),
            pending_where(
                "i.id NOT IN (SELECT invitation_id FROM memberships GROUP BY invitation_id)",
            ),
        ],
        vec![
            untriggered(),
            nulls_not_distinct(),
            ("accepted_by INT);", "accepted_by INT, code INT);".to_owned()),
            (
                "SELECT id FROM invitations WHERE email = current_setting('app.email') AND NOT accepted",
                "SELECT i.code FROM invitations i
                 WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.invitation_id = i.code)"
                    .to_owned(),
            ),
        ],
        vec![(
            "AND NOT accepted",
            format!(
                "AND NOT accepted UNION SELECT i.id FROM invitations i WHERE {unclaimed}"
            ),
        )],
        vec![(
            "SELECT id FROM invitations WHERE email = current_setting('app.email') AND NOT accepted",
            "SELECT i.id FROM invitations i JOIN invitations j ON j.id = i.id
             WHERE i.email = current_setting('app.email') AND NOT i.accepted"
                .to_owned(),
        )],
        vec![(
            "SELECT id FROM invitations WHERE email = current_setting('app.email') AND NOT accepted",
            "SELECT i.id FROM invitations i INNER JOIN invitations j ON j.id = i.id AND NOT i.accepted"
                .to_owned(),
        )],
    ] {
        assert!(!reports_invitation_key(&edits), "{edits:?}");
    }
}

#[test]
fn a_key_another_trigger_form_may_leave_unconsumed_is_reported() {
    for edits in [
        calling(MARK, MARKING, "mark_accepted(NEW.user_id)"),
        calling(
            "mark_accepted(invitation INT, accepted BOOLEAN) RETURNS VOID LANGUAGE sql SECURITY DEFINER",
            "UPDATE invitations SET accepted = accepted WHERE id = invitation",
            "mark_accepted(NEW.invitation_id, true)",
        ),
        calling(
            "mark_accepted(invitation INT, note INT) RETURNS VOID LANGUAGE sql STRICT",
            MARKING,
            "mark_accepted(NEW.invitation_id, NEW.nickname)",
        ),
        calling(
            MARK,
            "UPDATE invitations SET accepted = true WHERE id = invitation;
             UPDATE invitations SET accepted = false WHERE id = invitation",
            "mark_accepted(NEW.invitation_id)",
        ),
        calling(
            "mark_accepted(invitation INT) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER",
            &format!("BEGIN {MARKING}; END"),
            "mark_accepted(NEW.invitation_id)",
        ),
        calling(
            "mark_accepted(invitation INT, flag BOOLEAN DEFAULT false) RETURNS VOID LANGUAGE sql",
            "UPDATE invitations SET accepted = flag WHERE id = invitation",
            "mark_accepted(NEW.invitation_id)",
        ),
        removing("DELETE FROM invitations WHERE id = NEW.user_id"),
        removing("DELETE FROM invitations WHERE id = NEW.invitation_id AND email = 'x@y'"),
        [
            removing("DELETE FROM invitations WHERE id = NEW.invitation_id"),
            vec![(
                "GRANT SELECT, INSERT ON memberships",
                "GRANT INSERT ON invitations TO app; GRANT SELECT, INSERT ON memberships"
                    .to_owned(),
            )],
        ]
        .concat(),
        [
            removing("DELETE FROM invitations WHERE id = NEW.invitation_id"),
            vec![(
                "CREATE TRIGGER memberships_accept",
                "CREATE FUNCTION keep() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
                 CREATE TRIGGER invitations_keep BEFORE DELETE ON invitations
                   FOR EACH ROW EXECUTE FUNCTION keep();
                 CREATE TRIGGER memberships_accept"
                    .to_owned(),
            )],
        ]
        .concat(),
        [
            calling(MARK, MARKING, "mark_accepted(NEW.invitation_id)"),
            vec![(
                "ALTER TABLE memberships",
                "CREATE ROLE writer; ALTER FUNCTION mark_accepted(INT) OWNER TO writer;
                 GRANT SELECT, UPDATE (accepted) ON invitations TO writer;
                 ALTER TABLE invitations ENABLE ROW LEVEL SECURITY; ALTER TABLE memberships"
                    .to_owned(),
            )],
        ]
        .concat(),
    ] {
        assert!(reports_invitation_key(&edits), "{edits:?}");
    }
}

#[test]
fn a_key_a_statement_trigger_may_leave_unconsumed_is_reported() {
    for edits in [
        per_statement("id IN (SELECT user_id FROM new_rows)"),
        per_statement("id IN (SELECT invitation_id FROM new_rows WHERE user_id > 5)"),
        per_statement("id NOT IN (SELECT invitation_id FROM new_rows)"),
        [
            per_statement("id IN (SELECT invitation_id FROM new_rows)"),
            vec![
                ("AND NOT accepted", "AND accepted_by IS NULL".to_owned()),
                (
                    "SET accepted = true",
                    "SET accepted_by = NEW.user_id".to_owned(),
                ),
            ],
        ]
        .concat(),
        vec![
            (
                "FOR EACH ROW EXECUTE",
                "REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT
                   WHEN (current_user <> 'app') EXECUTE"
                    .to_owned(),
            ),
            keyed("id IN (SELECT invitation_id FROM new_rows)"),
        ],
        vec![
            (
                "FOR EACH ROW EXECUTE",
                "FOR EACH STATEMENT EXECUTE".to_owned(),
            ),
            (
                "CREATE FUNCTION accept_invitation",
                "CREATE TABLE new_rows (invitation_id INT); CREATE FUNCTION accept_invitation"
                    .to_owned(),
            ),
            keyed("id IN (SELECT invitation_id FROM new_rows)"),
        ],
        per_statement(
            "id IN (SELECT new_rows.invitation_id FROM new_rows
               JOIN invitations other ON other.id = new_rows.user_id)",
        ),
        per_statement(
            "id IN (SELECT invitation_id FROM new_rows AS inserted (invitation_id, nickname, original))",
        ),
        [
            per_statement("id IN (SELECT invitation_id FROM earlier)"),
            vec![(
                "CREATE FUNCTION accept_invitation",
                "CREATE TABLE earlier (invitation_id INT); CREATE FUNCTION accept_invitation"
                    .to_owned(),
            )],
        ]
        .concat(),
        [
            per_statement("id IN (SELECT invitations.invitation_id FROM new_rows)"),
            vec![(
                "accepted_by INT);",
                "accepted_by INT, invitation_id INT);".to_owned(),
            )],
        ]
        .concat(),
    ] {
        assert!(reports_invitation_key(&edits), "{edits:?}");
    }
}

#[test]
fn a_key_a_helper_draws_from_values_a_row_may_hold_is_reported() {
    for edits in [
        vec![
            untriggered(),
            pending_where(
                "NOT EXISTS (SELECT 1 FROM memberships m WHERE m.invitation_id = i.id AND m.user_id > 5)",
            ),
        ],
        vec![
            untriggered(),
            pending_where("NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = i.id)"),
        ],
        vec![
            untriggered(),
            pending_where("EXISTS (SELECT 1 FROM memberships m WHERE m.invitation_id = i.id)"),
        ],
        vec![
            untriggered(),
            pending_where(
                "NOT EXISTS (SELECT 1 FROM memberships m WHERE m.invitation_id = i.id LIMIT 0)",
            ),
        ],
        vec![
            untriggered(),
            pending_where("i.id NOT IN (SELECT invitation_id FROM memberships WHERE user_id > 5)"),
        ],
        vec![
            untriggered(),
            pending_where(
                "NOT EXISTS (SELECT 1 FROM memberships m JOIN invitations x ON x.email = 'none'
                 WHERE m.invitation_id = i.id)",
            ),
        ],
        vec![
            untriggered(),
            pending_where(
                "NOT EXISTS (SELECT 1 FROM memberships m (invitation_id, nickname, user_id)
                 WHERE m.invitation_id = i.id)",
            ),
        ],
        vec![
            untriggered(),
            pending_where(
                "NOT EXISTS (SELECT 1 FROM memberships m WHERE m.invitation_id = i.id EXCEPT SELECT 1)",
            ),
        ],
        vec![
            untriggered(),
            pending_where(
                "NOT EXISTS (SELECT 1 FROM (SELECT invitation_id FROM memberships WHERE user_id > 50) m
                 WHERE m.invitation_id = i.id)",
            ),
        ],
        vec![
            untriggered(),
            (
                "CREATE FUNCTION pending",
                "CREATE VIEW recent AS SELECT * FROM memberships WHERE user_id > 50;
                 CREATE FUNCTION pending"
                    .to_owned(),
            ),
            pending_where("NOT EXISTS (SELECT 1 FROM recent m WHERE m.invitation_id = i.id)"),
        ],
        vec![
            untriggered(),
            (
                "LANGUAGE sql STABLE SECURITY DEFINER",
                "LANGUAGE sql STABLE".to_owned(),
            ),
            pending_where("NOT EXISTS (SELECT 1 FROM memberships m WHERE m.invitation_id = i.id)"),
        ],
        vec![
            untriggered(),
            (
                "CREATE FUNCTION pending",
                "CREATE TABLE claims (invitation_id INT); CREATE FUNCTION pending".to_owned(),
            ),
            pending_where("NOT EXISTS (SELECT 1 FROM claims c WHERE c.invitation_id = i.id)"),
        ],
        vec![
            untriggered(),
            ("nickname INT,", "nickname INT, id INT,".to_owned()),
            pending_where("NOT EXISTS (SELECT 1 FROM memberships i WHERE i.invitation_id = i.id)"),
        ],
        vec![(
            "SELECT id FROM invitations WHERE email = current_setting('app.email') AND NOT accepted",
            "SELECT i.id FROM invitations i LEFT JOIN invitations j ON NOT i.accepted
             WHERE i.email = current_setting('app.email')"
                .to_owned(),
        )],
    ] {
        assert!(reports_invitation_key(&edits), "{edits:?}");
    }
}

const GRANTS: &str = "CREATE TABLE resources (organization_id INT NOT NULL, owner_id INT NOT NULL,
       id INT PRIMARY KEY, UNIQUE (organization_id, id));
     CREATE TABLE blocks (organization_id INT NOT NULL, user_id INT NOT NULL,
       PRIMARY KEY (organization_id, user_id));
     CREATE FUNCTION blocking() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER AS $$
       SELECT block.organization_id FROM blocks block
       WHERE block.user_id = current_setting('app.user_id')::int $$;
     CREATE FUNCTION resources_with(min_role TEXT) RETURNS SETOF INT
       LANGUAGE sql STABLE STRICT SECURITY DEFINER AS $$ SELECT resource.id FROM resources resource
       WHERE resource.owner_id = current_setting('app.user_id')::int AND min_role <> 'none'
         AND NOT (resource.organization_id = ANY (ARRAY(SELECT blocking()))) $$;
     CREATE FUNCTION sharable_grants() RETURNS TABLE (resource_id INT, role TEXT)
       LANGUAGE sql STABLE SECURITY DEFINER AS $$
       SELECT resource.id, allowed.role FROM resources_with('admin') resource(id)
         CROSS JOIN unnest(ARRAY['reader', 'writer']) allowed(role)
       UNION SELECT shared.id, 'reader' FROM resources shared
         WHERE shared.id IN (SELECT resources_with('writer'))
           AND NOT (shared.organization_id = ANY (ARRAY(SELECT blocking()))) $$;
     CREATE FUNCTION sharable_resources() RETURNS SETOF INT LANGUAGE sql STABLE
       SECURITY DEFINER AS $$ SELECT share.resource_id FROM sharable_grants() share $$;
     CREATE TABLE grants (resource_id INT NOT NULL, organization_id INT NOT NULL,
       grantee_id INT NOT NULL, role TEXT NOT NULL,
       CONSTRAINT grants_pkey PRIMARY KEY (resource_id, grantee_id),
       FOREIGN KEY (organization_id, resource_id) REFERENCES resources (organization_id, id));
     ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
     CREATE POLICY grants_read ON grants FOR SELECT TO app
       USING (resource_id = ANY (ARRAY(SELECT sharable_resources())));
     CREATE POLICY grants_write ON grants FOR INSERT TO app WITH CHECK (
       (resource_id, role) IN (SELECT share.resource_id, share.role FROM sharable_grants() share));
     CREATE POLICY grants_blocked ON grants AS RESTRICTIVE FOR ALL TO app
       USING (NOT (organization_id = ANY (ARRAY(SELECT blocking()))))
       WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT blocking()))));
     GRANT SELECT, INSERT ON grants TO app;";

/// Whether `grants_pkey` is reported on [`GRANTS`] after `edits`, each
/// replacing the first occurrence of its text.
fn reports_grants_key(edits: &[(&str, &str)]) -> bool {
    let mut sql = GRANTS.to_owned();
    for (from, to) in edits {
        assert!(sql.contains(from), "{from}");
        sql = sql.replacen(from, to, 1);
    }
    reports_key(&sql)
}

/// Whether `grants_pkey` is reported on `sql`.
fn reports_key(sql: &str) -> bool {
    objects(sql).contains(&"grants.grants_pkey".to_owned())
}

/// [`GRANTS`] with every exclusion testing the organization against
/// `blocking()` called in `FROM`.
fn grants_blocked_in_from() -> String {
    GRANTS.replace(
        "organization_id = ANY (ARRAY(SELECT blocking()))",
        "organization_id IN (SELECT * FROM blocking())",
    )
}

/// [`grants_blocked_in_from`] with organizations keyed by a namespace too,
/// so each exclusion tests the pair against `blocking()`.
fn grants_blocked_pair() -> String {
    grants_blocked_in_from()
        .replace(
            "(organization_id INT NOT NULL,",
            "(namespace_id INT NOT NULL, organization_id INT NOT NULL,",
        )
        .replace(
            "UNIQUE (organization_id, id)",
            "UNIQUE (namespace_id, organization_id, id)",
        )
        .replace(
            "blocking() RETURNS SETOF INT",
            "blocking() RETURNS TABLE (namespace_id INT, id INT)",
        )
        .replace(
            "SELECT block.organization_id",
            "SELECT block.namespace_id, block.organization_id",
        )
        .replace(
            "grants (resource_id INT NOT NULL,",
            "grants (resource_id INT NOT NULL, namespace_id INT NOT NULL,",
        )
        .replace(
            "(organization_id, resource_id) REFERENCES resources (organization_id, id)",
            "(namespace_id, organization_id, resource_id)
             REFERENCES resources (namespace_id, organization_id, id)",
        )
        .replace(
            "NOT (resource.organization_id",
            "NOT ((resource.namespace_id, resource.organization_id)",
        )
        .replace(
            "NOT (shared.organization_id",
            "NOT ((shared.namespace_id, shared.organization_id)",
        )
        .replace(
            "NOT (organization_id",
            "NOT ((namespace_id, organization_id)",
        )
}

#[test]
fn a_restrictive_read_a_helper_states_through_a_definer_called_in_from_is_clean() {
    for sql in [grants_blocked_in_from(), grants_blocked_pair()] {
        assert!(!reports_key(&sql), "{sql}");
        let filtered = sql.replace(
            "FROM blocking())",
            "FROM blocking() WHERE EXISTS (SELECT 1))",
        );
        assert!(!reports_key(&filtered), "{filtered}");
    }
}

#[test]
fn a_restrictive_read_a_helper_states_through_a_table_or_invoker_in_from_is_reported() {
    for sql in [grants_blocked_in_from(), grants_blocked_pair()] {
        for (from, to) in [
            (
                "STABLE SECURITY DEFINER AS $$\n       SELECT block.",
                "STABLE AS $$\n       SELECT block.",
            ),
            (
                "FROM blocking())",
                "FROM blocking() WHERE EXISTS (SELECT 1 FROM blocks))",
            ),
        ] {
            let edited = sql.replace(from, to);
            assert_ne!(edited, sql, "{from}");
            assert!(reports_key(&edited), "{edited}");
        }
    }
}

#[test]
fn a_restrictive_read_on_a_column_a_foreign_key_pins_to_the_confined_key_is_clean() {
    for edits in [
        &[][..],
        &[
            (
                "CREATE FUNCTION sharable_grants()",
                "CREATE FUNCTION roles() RETURNS SETOF TEXT LANGUAGE sql STABLE AS $$ SELECT 'reader' $$;
                 CREATE FUNCTION sharable_grants()",
            ),
            (
                "FROM resources_with('admin') resource(id)
         CROSS JOIN unnest(ARRAY['reader', 'writer']) allowed(role)",
                "FROM resources resource CROSS JOIN roles() allowed(role)
         WHERE NOT (resource.organization_id = ANY (ARRAY(SELECT blocking())))",
            ),
        ],
        &[(
            "(resource_id, role) IN (SELECT share.resource_id, share.role FROM sharable_grants() share)",
            "resource_id = ANY (ARRAY(SELECT sharable_resources()))",
        )],
    ] {
        assert!(!reports_grants_key(edits), "{edits:?}");
    }
}

#[test]
fn a_restrictive_read_the_referenced_row_does_not_settle_is_reported() {
    for edits in [
        &[(
            "organization_id INT NOT NULL,\n       grantee_id",
            "organization_id INT,\n       grantee_id",
        )][..],
        &[(
            "AND NOT (resource.organization_id",
            "OR NOT (resource.organization_id",
        )],
        &[(
            "id INT PRIMARY KEY,",
            "id INT, PRIMARY KEY (organization_id, id),",
        )],
        &[(
            "FROM resources resource\n",
            "FROM resources resource(id, owner_id, organization_id)\n",
        )],
        &[
            (
                "FROM resources resource\n",
                "FROM resources resource CROSS JOIN resources other\n",
            ),
            (
                "NOT (resource.organization_id = ANY",
                "NOT (other.organization_id = ANY",
            ),
        ],
        &[
            (
                "CREATE TABLE resources (organization_id INT",
                "CREATE TABLE resources (organization_id NUMERIC",
            ),
            (
                "organization_id INT NOT NULL,\n       grantee_id",
                "organization_id NUMERIC NOT NULL,\n       grantee_id",
            ),
        ],
        &[(
            "USING (NOT (organization_id = ANY",
            "USING (NOT (grantee_id = ANY",
        )],
        &[(
            "FROM resources resource\n",
            "FROM resources_with(min_role) resource(id)\n",
        )],
        &[
            (
                "(resource_id, role) IN (SELECT share.resource_id, share.role FROM sharable_grants() share)",
                "resource_id = ANY (ARRAY(SELECT sharable_resources()))",
            ),
            (
                "AND NOT (resource.organization_id",
                "OR NOT (resource.organization_id",
            ),
        ],
    ] {
        assert!(reports_grants_key(edits), "{edits:?}");
    }
}

/// The deployment declaring `accessor` a principal accessor.
fn principal(accessor: &str) -> Deployment {
    Deployment::default()
        .with_principal_accessor(accessor)
        .unwrap()
}

/// Object and message of every finding on organizations whose rows `app`
/// cannot read, under `deployment`, with `check` the insert check of `app`
/// and `extra` appended.
fn reported_occupancy(deployment: Deployment, check: &str, extra: &str) -> Vec<(String, String)> {
    reported_under(
        deployment,
        &format!(
            "CREATE SCHEMA authz;
             CREATE TABLE namespaces (id UUID PRIMARY KEY, user_id UUID UNIQUE NOT NULL);
             CREATE FUNCTION authz.caller_namespace() RETURNS UUID LANGUAGE sql STABLE AS $$
                 SELECT namespace.id FROM namespaces namespace
                 WHERE namespace.user_id = NULLIF(current_setting('app.user_id', true), '')::UUID
             $$;
             CREATE FUNCTION authz.namespace_of(owner UUID) RETURNS UUID LANGUAGE sql STABLE AS $$
                 SELECT owner
             $$;
             CREATE TABLE organizations (
                 namespace_id UUID NOT NULL REFERENCES namespaces (id),
                 id UUID NOT NULL,
                 owner_id UUID,
                 slug TEXT,
                 CONSTRAINT organizations_pkey PRIMARY KEY (namespace_id, id),
                 CONSTRAINT organizations_slug UNIQUE (slug)
             );
             ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
             GRANT SELECT, INSERT (namespace_id, id, owner_id) ON organizations TO app;
             CREATE POLICY organizations_select ON organizations FOR SELECT TO app USING (false);
             CREATE POLICY organizations_insert ON organizations FOR INSERT TO app
                 WITH CHECK ({check});
             {extra}"
        ),
    )
}

/// Objects of [`reported_occupancy`].
fn occupancy(deployment: Deployment, check: &str, extra: &str) -> Vec<String> {
    reported_occupancy(deployment, check, extra)
        .into_iter()
        .map(|(object, _)| object)
        .collect()
}

const CALLER: &str = "authz.caller_namespace()";
const PINNED: &str = "namespace_id = (SELECT authz.caller_namespace())";

#[test]
fn a_key_pinned_to_the_writers_principal_is_clean() {
    for check in [
        PINNED,
        "authz.caller_namespace() = organizations.namespace_id AND id IS NOT NULL",
    ] {
        assert_eq!(
            occupancy(principal(CALLER), check, ""),
            Vec::<String>::new(),
            "{check}"
        );
        assert_eq!(
            occupancy(Deployment::default(), check, ""),
            ["organizations.organizations_pkey"],
            "{check}"
        );
    }
    assert_eq!(
        occupancy(principal("(SELECT authz.caller_namespace())"), PINNED, ""),
        Vec::<String>::new()
    );
    assert_eq!(
        occupancy(
            principal(CALLER),
            "true",
            &format!(
                "CREATE POLICY organizations_pinned ON organizations AS RESTRICTIVE FOR INSERT TO app
                     WITH CHECK ({PINNED});"
            )
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        occupancy(
            principal(CALLER),
            PINNED,
            &format!(
                "GRANT UPDATE (namespace_id, id) ON organizations TO app;
                 CREATE POLICY organizations_update ON organizations FOR UPDATE TO app
                     USING (true) WITH CHECK ({PINNED});"
            )
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_key_the_writer_may_place_outside_its_principal_is_reported() {
    for (accessor, check) in [
        (CALLER, "namespace_id IS NOT NULL"),
        (
            CALLER,
            "namespace_id = (SELECT authz.caller_namespace()) OR id IS NOT NULL",
        ),
        (
            "authz.namespace_of(owner_id)",
            "namespace_id = authz.namespace_of(owner_id)",
        ),
    ] {
        assert_eq!(
            occupancy(principal(accessor), check, ""),
            ["organizations.organizations_pkey"],
            "{check}"
        );
    }
    for extra in [
        "CREATE POLICY organizations_any ON organizations FOR INSERT TO app WITH CHECK (true);",
        "GRANT UPDATE (id) ON organizations TO app;
         CREATE POLICY organizations_update ON organizations FOR UPDATE TO app USING (true);",
    ] {
        assert_eq!(
            occupancy(principal(CALLER), PINNED, extra),
            ["organizations.organizations_pkey"],
            "{extra}"
        );
    }
    assert_eq!(
        occupancy(
            principal(CALLER),
            PINNED,
            "GRANT INSERT (slug) ON organizations TO app;"
        ),
        ["organizations.organizations_slug"]
    );
}

#[test]
fn another_client_role_writing_the_principal_column_freely_reports_the_key() {
    for writes in [
        "GRANT INSERT (namespace_id, id) ON organizations TO importer;
         CREATE POLICY organizations_import ON organizations FOR INSERT TO importer
             WITH CHECK (true);",
        "GRANT UPDATE (namespace_id) ON organizations TO importer;
         CREATE POLICY organizations_move ON organizations FOR UPDATE TO importer
             USING (true);",
    ] {
        let findings = reported_occupancy(
            principal(CALLER).with_app_role("importer"),
            PINNED,
            &format!("CREATE ROLE importer; GRANT SELECT ON organizations TO importer; {writes}"),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        let (object, message) = &findings[0];
        assert_eq!(object, "organizations.organizations_pkey");
        assert!(message.contains("'app' through INSERT"), "{message}");
    }
}
