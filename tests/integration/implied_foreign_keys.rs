//! Foreign keys implied by a wider key of the same table, observed through
//! the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

const ACCOUNTS: &str = "CREATE TABLE regions (id INT PRIMARY KEY);
    CREATE TABLE accounts (id INT PRIMARY KEY, tenant_id INT NOT NULL, region_id INT NOT NULL,
      UNIQUE (id, tenant_id), UNIQUE (id, tenant_id, region_id), UNIQUE (tenant_id));
    CREATE TABLE archived_accounts (id INT PRIMARY KEY, tenant_id INT NOT NULL,
      UNIQUE (id, tenant_id));";

fn reported(notes: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = DuplicateForeignKey::default().into();
    findings(
        &constrainer,
        "duplicate_foreign_key",
        &format!("{ACCOUNTS} {notes}"),
    )
    .into_iter()
    .map(|(_, _, message)| message)
    .collect()
}

#[test]
fn the_narrower_key_is_reported_once_naming_the_wider_one() {
    assert_eq!(
        reported(
            "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
               FOREIGN KEY (account_id) REFERENCES accounts (id),
               FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id));"
        ),
        ["Table 'notes' has the foreign key FOREIGN KEY (account_id) REFERENCES accounts (id), \
          which the wider FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) \
          already enforces."]
    );
}

#[test]
fn a_wider_key_checking_every_row_with_the_same_actions_implies_the_narrower() {
    for notes in [
        // MATCH FULL checks a row whose extra column is NULL.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT,
           FOREIGN KEY (account_id) REFERENCES accounts (id),
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) MATCH FULL);",
        // Column order in either key does not hide the pairs.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id),
           FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id));",
        // A composite narrower key inside a wider one.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           region_id INT NOT NULL,
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id),
           FOREIGN KEY (account_id, tenant_id, region_id)
             REFERENCES accounts (id, tenant_id, region_id));",
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) ON DELETE CASCADE);",
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE RESTRICT ON UPDATE RESTRICT,
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id)
             ON DELETE RESTRICT ON UPDATE RESTRICT);",
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id) DEFERRABLE INITIALLY DEFERRED,
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id)
             DEFERRABLE INITIALLY DEFERRED);",
        // A wider key checked at every statement covers a narrower deferred one.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id) DEFERRABLE INITIALLY DEFERRED,
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id));",
    ] {
        assert_eq!(reported(notes).len(), 1, "{notes}");
    }
}

#[test]
fn a_narrower_key_the_wider_one_does_not_imply_is_kept() {
    for notes in [
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id),
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) NOT ENFORCED);",
        // MATCH SIMPLE skips the wider check when tenant_id is NULL.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT,
           FOREIGN KEY (account_id) REFERENCES accounts (id),
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id));",
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id),
           FOREIGN KEY (account_id, tenant_id) REFERENCES archived_accounts (id, tenant_id));",
        // The same host column paired with another referenced column.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (tenant_id) REFERENCES accounts (tenant_id),
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (tenant_id, id));",
        // The narrower NO ACTION check fails before the wider cascade runs.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id),
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) ON DELETE CASCADE);",
        // Updating both parent columns fails the narrower cascade's check.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id) ON UPDATE CASCADE,
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) ON UPDATE CASCADE);",
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE SET NULL,
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) MATCH FULL
             ON DELETE SET NULL);",
        // A delete and reinsert in one transaction fails the immediate narrower key.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id),
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id)
             DEFERRABLE INITIALLY DEFERRED);",
        // Rows written before the wider key was added were never checked by it.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
           FOREIGN KEY (account_id) REFERENCES accounts (id));
         ALTER TABLE notes ADD CONSTRAINT notes_account_tenant
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) NOT VALID;",
        // A partly NULL narrower MATCH FULL key escapes a MATCH SIMPLE wider one.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT,
           region_id INT NOT NULL,
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) MATCH FULL,
           FOREIGN KEY (account_id, tenant_id, region_id)
             REFERENCES accounts (id, tenant_id, region_id));",
    ] {
        assert_eq!(reported(notes), Vec::<String>::new(), "{notes}");
    }
}
