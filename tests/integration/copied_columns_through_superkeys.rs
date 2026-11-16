//! Columns copied from a parent through a key wider than its primary key,
//! observed through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

const ACCOUNTS: &str = "CREATE TABLE tenants (id INT PRIMARY KEY);
    CREATE TABLE accounts (id INT PRIMARY KEY, label TEXT NOT NULL CHECK (label IN ('a', 'b')),
      tenant_id INT NOT NULL REFERENCES tenants (id), email TEXT UNIQUE,
      UNIQUE (id, label), UNIQUE (id, tenant_id));";

fn reported(notes: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = CopiedColumnThroughSuperkey::default().into();
    findings(
        &constrainer,
        "copied_column_through_superkey",
        &format!("{ACCOUNTS} {notes}"),
    )
    .into_iter()
    .map(|(_, _, message)| message)
    .collect()
}

#[test]
fn a_cascaded_copy_the_host_keys_on_nowhere_is_reported() {
    for notes in [
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, label TEXT NOT NULL,
           FOREIGN KEY (account_id, label) REFERENCES accounts (id, label) ON UPDATE CASCADE);",
        // Column order in the key does not hide the copy.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, label TEXT NOT NULL,
           FOREIGN KEY (label, account_id) REFERENCES accounts (label, id) ON UPDATE CASCADE);",
        // A check repeating the parent's own check on the column adds nothing.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL,
           label TEXT NOT NULL CHECK (label IN ('a', 'b')),
           FOREIGN KEY (account_id, label) REFERENCES accounts (id, label) ON UPDATE CASCADE);",
        // An index the copy does not lead serves no lookup on it.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, label TEXT NOT NULL,
           FOREIGN KEY (account_id, label) REFERENCES accounts (id, label) ON UPDATE CASCADE);
         CREATE INDEX notes_account_label ON notes (account_id, label);",
    ] {
        let messages = reported(notes);
        assert_eq!(messages.len(), 1, "{notes}");
        assert!(messages[0].contains("'label'"), "{}", messages[0]);
    }
}

#[test]
fn a_copy_the_host_also_keys_on_passes() {
    for notes in [
        // Another foreign key: the tenant-consistency shape.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL,
           tenant_id INT NOT NULL REFERENCES tenants (id),
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) ON UPDATE CASCADE);",
        // The host's primary key.
        "CREATE TABLE notes (account_id INT NOT NULL, tenant_id INT NOT NULL, n INT,
           PRIMARY KEY (tenant_id, n),
           FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id) ON UPDATE CASCADE);",
        // A unique key of the host.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, label TEXT NOT NULL,
           UNIQUE (label, id),
           FOREIGN KEY (account_id, label) REFERENCES accounts (id, label) ON UPDATE CASCADE);",
        // An index leading with the column.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, label TEXT NOT NULL,
           FOREIGN KEY (account_id, label) REFERENCES accounts (id, label) ON UPDATE CASCADE);
         CREATE INDEX notes_label ON notes (label);",
        // A check stricter than the parent's limits which parents may be referenced.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL,
           label TEXT NOT NULL CHECK (label = 'a'),
           FOREIGN KEY (account_id, label) REFERENCES accounts (id, label) ON UPDATE CASCADE);",
        // A check relating the copy to another column of the host.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, label TEXT NOT NULL,
           body TEXT NOT NULL, CHECK (body <> label),
           FOREIGN KEY (account_id, label) REFERENCES accounts (id, label) ON UPDATE CASCADE);",
    ] {
        assert_eq!(reported(notes), Vec::<String>::new(), "{notes}");
    }
}

#[test]
fn a_reference_without_a_cascaded_superkey_passes() {
    for notes in [
        // Without ON UPDATE CASCADE the copy cannot follow the parent.
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, label TEXT NOT NULL,
           FOREIGN KEY (account_id, label) REFERENCES accounts (id, label));",
        "CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL REFERENCES accounts (id) ON UPDATE CASCADE);",
        // A unique key not containing the primary key is no superkey.
        "CREATE TABLE notes (id INT PRIMARY KEY, email TEXT REFERENCES accounts (email) ON UPDATE CASCADE);",
    ] {
        assert_eq!(reported(notes), Vec::<String>::new(), "{notes}");
    }
}
