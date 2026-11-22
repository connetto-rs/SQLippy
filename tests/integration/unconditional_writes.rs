//! Write policies through which a client role writes every row.

use crate::common::{GUARDED_SUBTYPE, ROLES, edited, finding, findings, parse, supabase};
use sqlippy::prelude::*;

const PROTECTED: &str =
    "CREATE TABLE docs (id INT, owner TEXT); ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

#[test]
fn a_write_policy_true_for_every_row_of_a_client_role_is_reported() {
    for policy in [
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING (true);",
        "CREATE POLICY w ON docs FOR UPDATE TO authenticated USING (true);",
        "CREATE POLICY w ON docs FOR INSERT TO authenticated WITH CHECK (true);",
        "CREATE POLICY w ON docs FOR INSERT TO authenticated WITH CHECK (1 = 1);",
        "CREATE POLICY w ON docs FOR ALL TO authenticated USING (true);",
        "CREATE POLICY w ON docs FOR DELETE USING (true);",
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING ((true));",
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING (true);
         CREATE POLICY r ON docs AS RESTRICTIVE FOR DELETE TO authenticated USING (true);",
    ] {
        assert_eq!(
            findings(
                UnconditionalClientWritePolicy::default(),
                supabase(),
                &format!("{PROTECTED}{policy}")
            ),
            [finding(
                "unconditional_client_write_policy",
                Level::Warn,
                "docs.w"
            )],
            "{policy}"
        );
    }
}

#[test]
fn a_row_dependent_or_read_only_or_restricted_policy_is_not_reported() {
    for policy in [
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING (owner = current_user);",
        "CREATE POLICY w ON docs FOR SELECT TO authenticated USING (true);",
        "CREATE POLICY w ON docs FOR DELETE TO reporting USING (true);",
        "CREATE POLICY w ON docs FOR UPDATE TO authenticated USING (owner = current_user) WITH CHECK (true);",
        "CREATE POLICY w ON docs FOR DELETE TO authenticated USING (true);
         CREATE POLICY r ON docs AS RESTRICTIVE FOR DELETE TO authenticated USING (owner = current_user);",
    ] {
        assert_eq!(
            findings(
                UnconditionalClientWritePolicy::default(),
                supabase(),
                &format!("{PROTECTED}{policy}")
            ),
            [],
            "{policy}"
        );
    }
}

#[test]
fn a_declared_credential_leaves_anonymous_writes_to_credential_free_write() {
    let sql = format!("{PROTECTED}CREATE POLICY w ON docs FOR DELETE TO anon USING (true);");
    assert_eq!(
        findings(UnconditionalClientWritePolicy::default(), supabase(), &sql),
        [finding(
            "unconditional_client_write_policy",
            Level::Warn,
            "docs.w"
        )]
    );
    assert_eq!(
        findings(
            UnconditionalClientWritePolicy::default(),
            supabase().with_credential("current_user").unwrap(),
            &sql
        ),
        []
    );
}

/// A `users` table whose key an `AFTER INSERT` trigger mints into
/// `grantees`, with `columns` after its key, the trigger's `clause` before
/// `EXECUTE`, `body` as the trigger function's statements before `RETURN
/// NULL` and `rest` after it.
fn minting(columns: &str, clause: &str, body: &str, rest: &str) -> String {
    format!(
        "CREATE TYPE grantee_kind AS ENUM ('user', 'team');
         CREATE TABLE grantees (id UUID PRIMARY KEY, kind grantee_kind NOT NULL, UNIQUE (id, kind));
         CREATE TABLE users (
           id UUID PRIMARY KEY,
           kind grantee_kind GENERATED ALWAYS AS ('user'::grantee_kind) STORED NOT NULL,{columns}
           FOREIGN KEY (id, kind) REFERENCES grantees (id, kind) DEFERRABLE INITIALLY DEFERRED
         );
         ALTER TABLE users ENABLE ROW LEVEL SECURITY;
         GRANT INSERT ON users TO authenticated;
         CREATE FUNCTION insert_grantee() RETURNS TRIGGER
         LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
         BEGIN
           {body}
           RETURN NULL;
         END
         $$;
         CREATE TRIGGER users_grantee {clause} EXECUTE FUNCTION insert_grantee();
         {rest}"
    )
}

const AFTER: &str = "AFTER INSERT ON users FOR EACH ROW";

const MINT: &str = "INSERT INTO public.grantees (id, kind) VALUES (NEW.id, NEW.kind);";

const OPEN_INSERT: &str = "CREATE POLICY i ON users FOR INSERT TO authenticated WITH CHECK (true);";

fn reported(sql: &str) -> Vec<String> {
    findings(UnconditionalClientWritePolicy::default(), supabase(), sql)
        .into_iter()
        .map(|(_, _, object)| object)
        .collect()
}

#[test]
fn an_insert_minting_every_column_of_a_new_principal_is_not_reported() {
    for (clause, body) in [
        (AFTER, MINT),
        ("AFTER INSERT OR UPDATE ON users FOR EACH ROW", MINT),
        (
            AFTER,
            "INSERT INTO public.grantees VALUES ((NEW.id), NEW.kind);",
        ),
        (
            AFTER,
            "INSERT INTO public.grantees (kind, id) VALUES (NEW.kind, NEW.id) RETURNING id;",
        ),
        (
            AFTER,
            "BEGIN INSERT INTO public.grantees (id, kind) VALUES (NEW.id, NEW.kind);
             EXCEPTION WHEN unique_violation THEN RAISE; END;",
        ),
        (
            AFTER,
            "IF NEW.id IS NULL THEN RAISE EXCEPTION 'no id'; END IF;
             INSERT INTO public.grantees (id, kind) VALUES (NEW.id, NEW.kind);",
        ),
    ] {
        assert_eq!(
            reported(&minting("", clause, body, OPEN_INSERT)),
            Vec::<String>::new(),
            "{clause} {body}"
        );
    }
}

#[test]
fn an_insert_whose_key_may_name_an_existing_row_is_reported() {
    for (columns, clause, rest) in [
        ("", "AFTER INSERT ON users FOR EACH ROW WHEN (NEW.id IS NOT NULL)", ""),
        (" display_name TEXT,", AFTER, ""),
        (" created_by_id UUID REFERENCES users (id),", AFTER, ""),
        ("", "BEFORE INSERT ON users FOR EACH ROW", ""),
        ("", "AFTER UPDATE ON users FOR EACH ROW", ""),
        ("", AFTER, "ALTER TABLE users DISABLE TRIGGER users_grantee;"),
        (
            "",
            AFTER,
            "CREATE FUNCTION skip() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
             CREATE TRIGGER skip BEFORE INSERT ON grantees FOR EACH ROW EXECUTE FUNCTION skip();",
        ),
    ] {
        let sql = minting(columns, clause, MINT, &format!("{rest}{OPEN_INSERT}"));
        assert_eq!(reported(&sql), ["users.i"], "{columns} {clause} {rest}");
    }
    assert_eq!(
        reported(
            "CREATE TABLE tags (id INT PRIMARY KEY, name TEXT);
             ALTER TABLE tags ENABLE ROW LEVEL SECURITY;
             GRANT INSERT ON tags TO authenticated;
             CREATE POLICY i ON tags FOR INSERT TO authenticated WITH CHECK (true);"
        ),
        ["tags.i"]
    );
}

#[test]
fn a_trigger_function_that_may_not_mint_the_new_key_is_reported() {
    for body in [
        "",
        "INSERT INTO public.grantees (id, kind) VALUES (NEW.id, NEW.kind) ON CONFLICT DO NOTHING;",
        "IF NEW.id IS NOT NULL THEN INSERT INTO public.grantees (id, kind) VALUES (NEW.id, NEW.kind); END IF;",
        "INSERT INTO public.grantees (id, kind) VALUES (gen_random_uuid(), NEW.kind);",
        "BEGIN INSERT INTO public.grantees (id, kind) VALUES (NEW.id, NEW.kind);
         EXCEPTION WHEN unique_violation THEN NULL; END;",
        "INSERT INTO public.grantees (id, kind) SELECT NEW.id, NEW.kind;",
        "INSERT INTO public.grantees (id, kind) VALUES (NEW.id, NEW.kind), (NEW.id, NEW.kind);",
        "INSERT INTO public.grantees (id) VALUES (NEW.id);",
        "INSERT INTO public.users (id, kind) VALUES (NEW.id, NEW.kind);",
        &format!("NEW.id := gen_random_uuid(); {MINT}"),
        &format!("DECLARE new RECORD; BEGIN {MINT} END;"),
        &format!("DECLARE fresh ALIAS FOR NEW; BEGIN fresh.id := gen_random_uuid(); {MINT} END;"),
        &format!("SELECT gen_random_uuid() INTO NEW.id; {MINT}"),
        &format!("EXECUTE 'SELECT gen_random_uuid()' INTO NEW.id; {MINT}"),
        &format!(
            "DECLARE c CURSOR FOR SELECT gen_random_uuid();
             BEGIN OPEN c; FETCH c INTO NEW.id; {MINT} END;"
        ),
        &format!("GET DIAGNOSTICS NEW.id = ROW_COUNT; {MINT}"),
    ] {
        let sql = minting("", AFTER, body, OPEN_INSERT);
        assert_eq!(reported(&sql), ["users.i"], "{body}");
    }
}

#[test]
fn a_minting_table_stays_reported_for_updates_and_deletes() {
    let sql = minting(
        "",
        AFTER,
        MINT,
        "CREATE POLICY a ON users FOR ALL TO authenticated USING (true);",
    );
    let mut constrainer: GenericConstrainer<ParserDB> =
        UnconditionalClientWritePolicy::default().into();
    constrainer.set_deployment(supabase());
    let messages: Vec<String> = constrainer
        .diagnostics(&parse(&format!("{ROLES}{sql}")))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    assert_eq!(
        messages,
        [
            "Policy 'a' on 'users' lets role 'authenticated' UPDATE, DELETE every row, since its clause is true whatever the row holds."
        ]
    );
}

/// `GUARDED_SUBTYPE` under `edits`, with `users` open to inserts by
/// `authenticated`.
fn guarded_insert(edits: &[(&str, &str)]) -> String {
    format!(
        "{}
         ALTER TABLE users ENABLE ROW LEVEL SECURITY;
         GRANT INSERT ON users TO authenticated;
         {OPEN_INSERT}",
        edited(GUARDED_SUBTYPE, edits)
    )
}

#[test]
fn an_insert_whose_guarded_before_write_mints_the_key_is_not_reported() {
    for edits in [
        &[][..],
        &[(" ON CONFLICT (id, kind) DO NOTHING", "")],
        &[(
            "WHEN (OLD.id IS DISTINCT FROM NEW.id)",
            "WHEN ((OLD.id, OLD.kind) IS DISTINCT FROM (NEW.id, NEW.kind))",
        )],
        &[(
            "DELETE FROM grantees WHERE id = OLD.id;",
            "DELETE FROM grantees WHERE id = OLD.id AND kind = OLD.kind;",
        )],
    ] {
        assert_eq!(
            reported(&guarded_insert(edits)),
            Vec::<String>::new(),
            "{edits:?}"
        );
    }
}

#[test]
fn an_insert_whose_guarded_before_write_may_adopt_a_parent_is_reported() {
    const REMOVED: &str = "CREATE TRIGGER users_grantee_removed AFTER DELETE ON users
      FOR EACH ROW EXECUTE FUNCTION delete_grantee();";
    const REKEYED: &str = "CREATE TRIGGER users_grantee_rekeyed AFTER UPDATE ON users
      FOR EACH ROW WHEN (OLD.id IS DISTINCT FROM NEW.id) EXECUTE FUNCTION delete_grantee();";
    const DELETED: &str = "DELETE FROM grantees WHERE id = OLD.id;";
    for edits in [
        &[(
            "AFTER INSERT OR UPDATE ON grantees",
            "AFTER INSERT ON grantees",
        )][..],
        &[(
            "AFTER INSERT OR UPDATE ON grantees",
            "AFTER INSERT OR UPDATE OF kind ON grantees",
        )],
        &[(REMOVED, "")],
        &[(REKEYED, "")],
        &[("AFTER UPDATE ON users", "AFTER UPDATE OF id ON users")],
        &[(
            "WHEN (OLD.id IS DISTINCT FROM NEW.id)",
            "WHEN (OLD.id <> NEW.id)",
        )],
        &[(
            "WHEN (OLD.id IS DISTINCT FROM NEW.id)",
            "WHEN (OLD.kind IS DISTINCT FROM NEW.kind)",
        )],
        &[(DELETED, "DELETE FROM grantees WHERE id = NEW.id;")],
        &[(DELETED, "DELETE FROM grantees WHERE id <> OLD.id;")],
        &[(
            DELETED,
            "BEGIN DELETE FROM grantees WHERE id = OLD.id; EXCEPTION WHEN OTHERS THEN NULL; END;",
        )],
        &[(
            "      id UUID PRIMARY KEY,\n      kind grantee_kind NOT NULL DEFAULT 'user'",
            "      id UUID NOT NULL,\n      kind grantee_kind NOT NULL DEFAULT 'user'",
        )],
        &[(
            "ON CONFLICT (id, kind) DO NOTHING",
            "ON CONFLICT (id, kind) DO UPDATE SET kind = EXCLUDED.kind",
        )],
        &[(
            "DEFERRABLE INITIALLY DEFERRED",
            "DEFERRABLE INITIALLY IMMEDIATE",
        )],
    ] {
        assert_eq!(reported(&guarded_insert(edits)), ["users.i"], "{edits:?}");
    }
}
