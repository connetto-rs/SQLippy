//! `NO ACTION` references a client role can delete the parent of but never
//! clear, observed through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

const ACCOUNTS: &str = "CREATE ROLE app;
    CREATE TABLE accounts (id INT PRIMARY KEY);
    GRANT DELETE ON accounts TO app;";

const NOTES: &str =
    "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL REFERENCES accounts (id));
    REVOKE DELETE ON notes FROM app;";

fn reported(sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = UndeletableReference::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("app"));
    findings(
        &constrainer,
        "undeletable_reference",
        &format!("{ACCOUNTS} {sql}"),
    )
    .into_iter()
    .map(|(_, _, message)| message)
    .collect()
}

#[test]
fn a_reference_the_role_cannot_clear_is_reported() {
    for sql in [
        NOTES.to_owned(),
        // An invoker function runs with the role's own missing DELETE.
        format!(
            "{NOTES} CREATE FUNCTION purge(a INT) RETURNS VOID LANGUAGE sql
               AS $$ DELETE FROM notes WHERE account_id = a $$;"
        ),
        // A definer function that only reads clears nothing.
        format!(
            "{NOTES} CREATE FUNCTION count_notes() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               AS $$ SELECT count(*) FROM notes $$;"
        ),
        // A definer function the role cannot execute.
        format!(
            "{NOTES} CREATE FUNCTION purge(a INT) RETURNS VOID LANGUAGE sql SECURITY DEFINER
               AS $$ DELETE FROM notes WHERE account_id = a $$;
             REVOKE EXECUTE ON FUNCTION purge(INT) FROM PUBLIC;"
        ),
        // An AFTER DELETE trigger runs once the deletion has been refused.
        format!(
            "{NOTES} CREATE FUNCTION purge() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
               AS $$ BEGIN DELETE FROM notes WHERE account_id = OLD.id; RETURN OLD; END $$;
             REVOKE EXECUTE ON FUNCTION purge() FROM PUBLIC;
             CREATE TRIGGER accounts_purge AFTER DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION purge();"
        ),
        // A nullable key the role may not update.
        "CREATE TABLE notes (account_id INT REFERENCES accounts (id));
         REVOKE DELETE, UPDATE ON notes FROM app;"
            .to_owned(),
        // An updatable key that cannot hold NULL.
        "CREATE TABLE notes (account_id INT NOT NULL REFERENCES accounts (id));
         REVOKE DELETE ON notes FROM app;
         GRANT UPDATE (account_id) ON notes TO app;"
            .to_owned(),
        // A cascading sibling key clears only the rows that reference through it.
        "CREATE TABLE notes (id INT PRIMARY KEY,
           author_id INT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
           reviewer_id INT NOT NULL REFERENCES accounts (id));
         REVOKE DELETE ON notes FROM app;"
            .to_owned(),
        // An immediate check runs before the cascades of a chain.
        "CREATE TABLE projects (id INT PRIMARY KEY, account_id INT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE);
         CREATE TABLE notes (account_id INT NOT NULL REFERENCES accounts (id),
           project_id INT NOT NULL REFERENCES projects (id) ON DELETE CASCADE);
         REVOKE DELETE ON notes FROM app;
         REVOKE DELETE ON projects FROM app;"
            .to_owned(),
        // An immediate check may run before a cascading key on the same columns.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL REFERENCES accounts (id),
           FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE);
         REVOKE DELETE ON notes FROM app;"
            .to_owned(),
        // MATCH SIMPLE leaves rows with a NULL extra column to the wider cascade.
        "CREATE TABLE tenant_accounts (id INT PRIMARY KEY REFERENCES accounts (id),
           tenant_id INT NOT NULL, UNIQUE (id, tenant_id));
         CREATE TABLE notes (account_id INT NOT NULL, tenant_id INT,
           FOREIGN KEY (account_id, tenant_id) REFERENCES tenant_accounts (id, tenant_id) ON DELETE CASCADE,
           FOREIGN KEY (account_id) REFERENCES tenant_accounts (id) DEFERRABLE INITIALLY DEFERRED);
         REVOKE DELETE ON notes FROM app;
         GRANT DELETE ON tenant_accounts TO app;"
            .to_owned(),
    ] {
        let messages = reported(&sql);
        assert_eq!(messages.len(), 1, "{sql}");
        assert!(messages[0].contains("'app'"), "{}", messages[0]);
    }
}

#[test]
fn delete_inherited_through_a_role_is_counted() {
    let mut constrainer: GenericConstrainer<ParserDB> = UndeletableReference::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("app"));
    let sql = format!(
        "CREATE ROLE writer; CREATE ROLE app; GRANT writer TO app;
         CREATE TABLE accounts (id INT PRIMARY KEY);
         GRANT DELETE ON accounts TO writer;
         {NOTES}"
    );
    assert_eq!(
        findings(&constrainer, "undeletable_reference", &sql).len(),
        1
    );
}

#[test]
fn a_reference_with_a_cleanup_path_passes() {
    for sql in [
        // Referential actions that clear or deliberately keep the rows.
        "CREATE TABLE notes (account_id INT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE);
         REVOKE DELETE ON notes FROM app;"
            .to_owned(),
        "CREATE TABLE notes (account_id INT REFERENCES accounts (id) ON DELETE SET NULL);
         REVOKE DELETE ON notes FROM app;"
            .to_owned(),
        "CREATE TABLE notes (account_id INT NOT NULL REFERENCES accounts (id) ON DELETE RESTRICT);
         REVOKE DELETE ON notes FROM app;"
            .to_owned(),
        // Nothing proves the role lacks DELETE on the referencing table.
        "CREATE TABLE notes (account_id INT NOT NULL REFERENCES accounts (id));".to_owned(),
        // A nullable key the role may set to NULL.
        "CREATE TABLE notes (account_id INT REFERENCES accounts (id));
         REVOKE DELETE ON notes FROM app;"
            .to_owned(),
        // A deferred check runs after the cascades of a chain.
        "CREATE TABLE projects (id INT PRIMARY KEY, account_id INT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE);
         CREATE TABLE notes (account_id INT NOT NULL REFERENCES accounts (id) DEFERRABLE INITIALLY DEFERRED,
           project_id INT NOT NULL REFERENCES projects (id) ON DELETE CASCADE);
         REVOKE DELETE ON notes FROM app;
         REVOKE DELETE ON projects FROM app;"
            .to_owned(),
        // A deferrable check the role may defer past a cascading key on every column.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL REFERENCES accounts (id) DEFERRABLE,
           FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE);
         REVOKE DELETE ON notes FROM app;"
            .to_owned(),
        // The rows a partly nullable MATCH FULL key holds are never partly NULL.
        "CREATE TABLE regional_accounts (id INT REFERENCES accounts (id), tenant_id INT,
           region INT NOT NULL, PRIMARY KEY (id, tenant_id), UNIQUE (id, tenant_id, region));
         CREATE TABLE docs (a INT, b INT, region INT NOT NULL,
           FOREIGN KEY (a, b, region) REFERENCES regional_accounts (id, tenant_id, region) ON DELETE CASCADE,
           FOREIGN KEY (a, b) REFERENCES regional_accounts (id, tenant_id) MATCH FULL DEFERRABLE);
         REVOKE DELETE ON docs FROM app;
         GRANT DELETE ON regional_accounts TO app;"
            .to_owned(),
        // A definer function the role may execute.
        format!(
            "{NOTES} CREATE FUNCTION purge(a INT) RETURNS VOID LANGUAGE sql SECURITY DEFINER
               AS $$ DELETE FROM notes WHERE account_id = a $$;"
        ),
        // A definer function clearing the rows through a helper it calls as its owner.
        format!(
            "{NOTES} CREATE FUNCTION purge_notes(a INT) RETURNS VOID LANGUAGE sql
               AS $$ DELETE FROM notes WHERE account_id = a $$;
             CREATE FUNCTION close_account(a INT) RETURNS VOID LANGUAGE sql SECURITY DEFINER
               AS $$ SELECT purge_notes(a); DELETE FROM accounts WHERE id = a $$;"
        ),
        format!(
            "{NOTES} CREATE FUNCTION purge(a INT) RETURNS VOID LANGUAGE sql SECURITY DEFINER
               BEGIN ATOMIC DELETE FROM notes WHERE account_id = a; END;"
        ),
        format!(
            "{NOTES} CREATE FUNCTION purge(a INT) RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               AS $$ WITH gone AS (DELETE FROM public.notes WHERE account_id = a RETURNING id) SELECT count(*) FROM gone $$;"
        ),
        // A definer function detaching the rows.
        "CREATE TABLE notes (account_id INT REFERENCES accounts (id));
         REVOKE DELETE, UPDATE ON notes FROM app;
         CREATE FUNCTION detach(a INT) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
           AS $$ BEGIN UPDATE notes SET account_id = NULL WHERE account_id = a; END $$;"
            .to_owned(),
        // Dynamic SQL in a definer function may delete anything.
        format!(
            "{NOTES} CREATE FUNCTION run(command TEXT) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
               AS $$ BEGIN EXECUTE command; END $$;"
        ),
        // A BEFORE DELETE trigger clearing the rows as its owner.
        format!(
            "{NOTES} CREATE FUNCTION purge() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
               AS $$ BEGIN DELETE FROM notes WHERE account_id = OLD.id; RETURN OLD; END $$;
             REVOKE EXECUTE ON FUNCTION purge() FROM PUBLIC;
             CREATE TRIGGER accounts_purge BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION purge();"
        ),
    ] {
        assert_eq!(reported(&sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_role_without_delete_on_the_parent_passes() {
    let mut constrainer: GenericConstrainer<ParserDB> = UndeletableReference::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("app"));
    let sql = format!("CREATE ROLE app; CREATE TABLE accounts (id INT PRIMARY KEY); {NOTES}");
    assert_eq!(
        findings(&constrainer, "undeletable_reference", &sql),
        Vec::new()
    );
}
