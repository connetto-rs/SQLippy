//! One-to-many relationships kept in a table keyed by the child, observed
//! through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

fn reported(sql: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = OneToManyEdgeTable::default().into();
    findings(&constrainer, "one_to_many_edge_table", sql)
        .into_iter()
        .map(|(_, _, message)| message)
        .collect()
}

const PARTICIPANTS: &str = "CREATE TABLE parents (id BIGINT PRIMARY KEY);
     CREATE TABLE children (id BIGINT PRIMARY KEY);";

const TENANT_TEAMS: &str = "CREATE TABLE organizations (id UUID PRIMARY KEY);
     CREATE TABLE teams (
         id UUID PRIMARY KEY,
         organization_id UUID NOT NULL REFERENCES organizations (id),
         UNIQUE (organization_id, id)
     );";

#[test]
fn an_edge_table_keyed_by_the_child_is_reported() {
    for edge in [
        "CREATE TABLE child_parents (
             child_id BIGINT PRIMARY KEY REFERENCES children (id),
             parent_id BIGINT NOT NULL REFERENCES parents (id)
         );",
        // A unique key identifies the child as well as a primary key does.
        "CREATE TABLE child_parents (
             child_id BIGINT NOT NULL UNIQUE REFERENCES children (id),
             parent_id BIGINT REFERENCES parents (id)
         );",
    ] {
        let messages = reported(&format!("{PARTICIPANTS} {edge}"));
        assert_eq!(messages.len(), 1, "{edge}");
    }
}

#[test]
fn the_finding_names_the_child_table_and_the_parent_columns() {
    let messages = reported(&format!(
        "{PARTICIPANTS} CREATE TABLE child_parents (
             child_id BIGINT PRIMARY KEY REFERENCES children (id),
             parent_id BIGINT NOT NULL REFERENCES parents (id)
         );"
    ));
    assert_eq!(messages.len(), 1);
    assert!(
        messages[0].contains("'child_parents'")
            && messages[0].contains("'children'")
            && messages[0].contains("'parents'")
            && messages[0].contains("(parent_id)"),
        "{}",
        messages[0]
    );
}

#[test]
fn tenant_columns_shared_by_both_keys_still_count_as_one_edge() {
    for edge in [
        "CREATE TABLE team_parents (
             id UUID PRIMARY KEY,
             organization_id UUID NOT NULL,
             parent_id UUID NOT NULL CHECK (parent_id <> id),
             FOREIGN KEY (organization_id, id) REFERENCES teams (organization_id, id),
             FOREIGN KEY (organization_id, parent_id) REFERENCES teams (organization_id, id)
         );",
        // The tenant's own foreign key lies inside the child's and adds no parent.
        "CREATE TABLE team_parents (
             id UUID,
             organization_id UUID NOT NULL REFERENCES organizations (id),
             parent_id UUID NOT NULL,
             PRIMARY KEY (organization_id, id),
             FOREIGN KEY (organization_id, id) REFERENCES teams (organization_id, id),
             FOREIGN KEY (organization_id, parent_id) REFERENCES teams (organization_id, id)
         );",
    ] {
        let messages = reported(&format!("{TENANT_TEAMS} {edge}"));
        assert_eq!(messages.len(), 1, "{edge}");
        assert!(messages[0].contains("(parent_id)"), "{}", messages[0]);
    }
}

#[test]
fn a_discriminator_open_to_several_values_does_not_mark_a_subtype() {
    let messages = reported(
        "CREATE TABLE resources (
             id UUID PRIMARY KEY,
             kind TEXT NOT NULL,
             UNIQUE (id, kind)
         );
         CREATE TABLE resource_parents (
             id UUID PRIMARY KEY,
             kind TEXT NOT NULL CHECK (kind IN ('folder', 'project')),
             parent_id UUID NOT NULL,
             parent_kind TEXT NOT NULL CHECK (parent_kind IN ('organization', 'folder')),
             FOREIGN KEY (id, kind) REFERENCES resources (id, kind),
             FOREIGN KEY (parent_id, parent_kind) REFERENCES resources (id, kind)
         );",
    );
    assert_eq!(messages.len(), 1);
}

#[test]
fn a_reference_the_child_key_already_identifies_is_no_parent() {
    for subtype in [
        "CREATE TABLE subtypes (
             id INT PRIMARY KEY REFERENCES models (id),
             organization_id INT NOT NULL,
             archived BOOLEAN NOT NULL,
             FOREIGN KEY (organization_id, id, archived)
                 REFERENCES resources (organization_id, id, archived)
         );",
        // A column copied from the row the child key identifies is no parent
        // of its own, whatever else it references.
        "CREATE TABLE subtypes (
             id INT PRIMARY KEY REFERENCES models (id),
             organization_id INT NOT NULL REFERENCES organizations (id),
             FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id)
         );",
    ] {
        let sql = format!(
            "CREATE TABLE organizations (id INT PRIMARY KEY);
             CREATE TABLE resources (
                 id INT PRIMARY KEY,
                 organization_id INT NOT NULL REFERENCES organizations (id),
                 archived BOOLEAN NOT NULL,
                 UNIQUE (organization_id, id),
                 UNIQUE (organization_id, id, archived)
             );
             CREATE TABLE models (id INT PRIMARY KEY REFERENCES resources (id));
             {subtype}"
        );
        assert_eq!(reported(&sql), Vec::<String>::new(), "{subtype}");
    }
}

#[test]
fn tables_that_are_not_one_to_many_edges_pass() {
    for edge in [
        // Both participants in the key: a many-to-many relationship.
        "CREATE TABLE child_parents (
             child_id BIGINT REFERENCES children (id),
             parent_id BIGINT REFERENCES parents (id),
             PRIMARY KEY (child_id, parent_id)
         );",
        // The parent already sits on the child.
        "CREATE TABLE child_parents (
             id BIGINT PRIMARY KEY,
             parent_id BIGINT NOT NULL REFERENCES parents (id)
         );",
        // An extension with no second participant.
        "CREATE TABLE child_parents (child_id BIGINT PRIMARY KEY REFERENCES children (id));",
        // Payload cannot be told apart from a subtype's own attributes.
        "CREATE TABLE child_parents (
             child_id BIGINT PRIMARY KEY REFERENCES children (id),
             parent_id BIGINT NOT NULL REFERENCES parents (id),
             since DATE NOT NULL
         );",
        // A third participant.
        "CREATE TABLE child_parents (
             child_id BIGINT PRIMARY KEY REFERENCES children (id),
             parent_id BIGINT NOT NULL REFERENCES parents (id),
             approved_by_id BIGINT NOT NULL REFERENCES parents (id)
         );",
        // A key that is no child's identity.
        "CREATE TABLE child_parents (
             child_id BIGINT REFERENCES children (id),
             parent_id BIGINT NOT NULL REFERENCES parents (id)
         );",
    ] {
        assert_eq!(
            reported(&format!("{PARTICIPANTS} {edge}")),
            Vec::<String>::new(),
            "{edge}"
        );
    }
}

#[test]
fn a_constant_discriminator_marks_a_subtype() {
    for subtype in [
        "CREATE TABLE teams (
             id UUID PRIMARY KEY,
             kind TEXT NOT NULL DEFAULT 'team' CHECK (kind = 'team'),
             organization_id UUID NOT NULL REFERENCES organizations (id),
             FOREIGN KEY (id, kind) REFERENCES grantees (id, kind)
         );",
        // A key holding the discriminator does not hide it.
        "CREATE TABLE teams (
             id UUID PRIMARY KEY,
             kind TEXT NOT NULL CHECK (kind = 'team'),
             organization_id UUID NOT NULL REFERENCES organizations (id),
             UNIQUE (id, kind),
             FOREIGN KEY (id, kind) REFERENCES grantees (id, kind)
         );",
        "CREATE TABLE teams (
             id UUID PRIMARY KEY,
             kind TEXT GENERATED ALWAYS AS ('team') STORED,
             organization_id UUID NOT NULL REFERENCES organizations (id),
             FOREIGN KEY (id, kind) REFERENCES grantees (id, kind)
         );",
    ] {
        let sql = format!(
            "CREATE TABLE organizations (id UUID PRIMARY KEY);
             CREATE TABLE grantees (id UUID PRIMARY KEY, kind TEXT NOT NULL, UNIQUE (id, kind));
             {subtype}"
        );
        assert_eq!(reported(&sql), Vec::<String>::new(), "{subtype}");
    }
}
