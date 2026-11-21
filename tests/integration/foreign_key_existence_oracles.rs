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
fn a_check_confining_the_key_to_readable_or_named_rows_is_clean() {
    for check in [
        "secret_id IN (SELECT id FROM secrets)",
        "secret_id = ANY (ARRAY(SELECT allowed_secrets()))",
        "secret_id = (SELECT caller_secret())",
        "secret_id = caller_secret() AND id > 0",
        "caller_secret() = secret_id",
        "secret_id IN (SELECT s FROM allowed_secrets() AS s)",
        "(secret_id, id) IN (SELECT s, 1 FROM allowed_secrets() AS s)",
        "(secret_id, id) IN (SELECT caller_secret(), 1)",
        "secret_id IN (SELECT id FROM secrets) OR (id > 0 AND secret_id = caller_secret())",
        "EXISTS (SELECT 1 FROM secrets s WHERE s.id = notes.secret_id)",
        "(secret_id = caller_secret() OR secret_id IN (SELECT id FROM secrets)) AND id > 0",
        "EXISTS (SELECT 1 FROM secrets s WHERE s.id = notes.secret_id AND s.id > 0)",
    ] {
        assert_eq!(
            objects(&format!(
                "CREATE FUNCTION allowed_secrets() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT 1 $$;
                 CREATE FUNCTION caller_secret() RETURNS INT LANGUAGE sql AS $$ SELECT 1 $$;
                 {NOTES} GRANT INSERT ON notes TO app;
                 ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY notes_write ON notes FOR INSERT TO app WITH CHECK ({check});"
            )),
            Vec::<String>::new(),
            "{check}"
        );
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
