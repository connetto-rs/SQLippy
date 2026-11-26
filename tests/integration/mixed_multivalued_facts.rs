//! All-key tables that may mix independent multivalued facts, observed
//! through the public constrainer API.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

const EMPLOYEES: &str = "CREATE TABLE employees (id INT PRIMARY KEY);";

const ORGANIZATIONS: &str = "CREATE TABLE organizations (id INT PRIMARY KEY);
    CREATE TABLE teams (organization_id INT REFERENCES organizations (id), id INT,
        PRIMARY KEY (organization_id, id));
    CREATE TABLE users (organization_id INT REFERENCES organizations (id), id INT,
        PRIMARY KEY (organization_id, id));";

fn reported_under(deployment: Deployment, sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = MixedMultivaluedFacts::default().into();
    constrainer.set_deployment(deployment);
    findings(&constrainer, "mixed_multivalued_facts", sql)
        .into_iter()
        .map(|(_, _, message)| message)
        .collect()
}

fn reported(sql: &str) -> Vec<String> {
    reported_under(Deployment::default(), sql)
}

#[test]
fn independent_facts_of_a_referenced_entity_are_reported_with_their_split() {
    let messages = reported(&format!(
        "{EMPLOYEES} CREATE TABLE employee_projects_dependents (
            employee_id INT REFERENCES employees (id), project_name TEXT, dependent_name TEXT,
            PRIMARY KEY (employee_id, project_name, dependent_name));"
    ));
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(
        messages[0].contains(
            "(project_name) and (dependent_name) may be independent facts of (employee_id)"
        ),
        "{}",
        messages[0]
    );
}

#[test]
fn every_all_key_table_of_three_participants_is_reported() {
    for sql in [
        // The entity is the column both foreign keys share.
        format!(
            "{EMPLOYEES}
             CREATE TABLE employee_projects (employee_id INT REFERENCES employees (id),
                 project_name TEXT, PRIMARY KEY (employee_id, project_name));
             CREATE TABLE employee_dependents (employee_id INT REFERENCES employees (id),
                 dependent_name TEXT, PRIMARY KEY (employee_id, dependent_name));
             CREATE TABLE assignments (employee_id INT, project_name TEXT, dependent_name TEXT,
                 PRIMARY KEY (employee_id, project_name, dependent_name),
                 FOREIGN KEY (employee_id, project_name) REFERENCES employee_projects (employee_id, project_name),
                 FOREIGN KEY (employee_id, dependent_name) REFERENCES employee_dependents (employee_id, dependent_name));"
        ),
        // A genuine three-way fact has the same shape and needs an allowance.
        "CREATE TABLE suppliers (id INT PRIMARY KEY);
         CREATE TABLE parts (id INT PRIMARY KEY);
         CREATE TABLE projects (id INT PRIMARY KEY);
         CREATE TABLE supplies (supplier_id INT REFERENCES suppliers (id),
             part_id INT REFERENCES parts (id), project_id INT REFERENCES projects (id),
             PRIMARY KEY (supplier_id, part_id, project_id));"
            .to_owned(),
        "CREATE TABLE facts (a INT, b INT, c INT, PRIMARY KEY (a, b, c));".to_owned(),
        "CREATE TABLE facts (a INT NOT NULL, b INT NOT NULL, c INT NOT NULL, UNIQUE (a, b, c));"
            .to_owned(),
        // Without a foreign key of its own, the shared column is the entity.
        format!(
            "{ORGANIZATIONS}
             CREATE TABLE team_members (organization_id INT, team_id INT, user_id INT,
                 PRIMARY KEY (organization_id, team_id, user_id),
                 FOREIGN KEY (organization_id, team_id) REFERENCES teams (organization_id, id),
                 FOREIGN KEY (organization_id, user_id) REFERENCES users (organization_id, id));"
        ),
        // One composite foreign key over the entity is not a scope.
        format!(
            "{EMPLOYEES}
             CREATE TABLE employee_projects (employee_id INT REFERENCES employees (id),
                 project_name TEXT, PRIMARY KEY (employee_id, project_name));
             CREATE TABLE assignments (employee_id INT REFERENCES employees (id),
                 project_name TEXT, dependent_name TEXT,
                 PRIMARY KEY (employee_id, project_name, dependent_name),
                 FOREIGN KEY (employee_id, project_name) REFERENCES employee_projects (employee_id, project_name));"
        ),
        // A repeated foreign key holds its columns once, so it scopes nothing.
        format!(
            "{ORGANIZATIONS}
             CREATE TABLE team_labels (organization_id INT REFERENCES organizations (id),
                 team_id INT, label TEXT, PRIMARY KEY (organization_id, team_id, label),
                 FOREIGN KEY (organization_id, team_id) REFERENCES teams (organization_id, id),
                 FOREIGN KEY (organization_id, team_id) REFERENCES teams (organization_id, id));"
        ),
    ] {
        assert_eq!(reported(&sql).len(), 1, "{sql}");
    }
}

#[test]
fn a_table_without_a_shared_entity_names_every_participant() {
    let messages = reported("CREATE TABLE facts (a INT, b INT, c INT, PRIMARY KEY (a, b, c));");
    assert_eq!(messages.len(), 1);
    assert!(
        messages[0].contains("key across (a), (b) and (c)"),
        "{}",
        messages[0]
    );
}

#[test]
fn tables_of_fewer_participants_or_with_payload_pass() {
    for sql in [
        format!(
            "{EMPLOYEES}
             CREATE TABLE employee_projects (employee_id INT REFERENCES employees (id),
                 project_name TEXT, PRIMARY KEY (employee_id, project_name));
             CREATE TABLE employee_dependents (employee_id INT REFERENCES employees (id),
                 dependent_name TEXT, PRIMARY KEY (employee_id, dependent_name));"
        ),
        // The tenant references its organization, so it scopes both identities.
        format!(
            "{ORGANIZATIONS}
             CREATE TABLE team_members (organization_id INT REFERENCES organizations (id),
                 team_id INT, user_id INT, PRIMARY KEY (organization_id, team_id, user_id),
                 FOREIGN KEY (organization_id, team_id) REFERENCES teams (organization_id, id),
                 FOREIGN KEY (organization_id, user_id) REFERENCES users (organization_id, id));"
        ),
        // A non-key column is a fact about the whole key.
        format!(
            "{ORGANIZATIONS}
             CREATE TABLE team_members (organization_id INT, team_id INT, user_id INT,
                 team_role TEXT NOT NULL, PRIMARY KEY (organization_id, team_id, user_id),
                 FOREIGN KEY (organization_id, team_id) REFERENCES teams (organization_id, id),
                 FOREIGN KEY (organization_id, user_id) REFERENCES users (organization_id, id));"
        ),
        // A composite foreign key is one participant.
        format!(
            "{ORGANIZATIONS}
             CREATE TABLE user_roles (organization_id INT, user_id INT, role TEXT,
                 PRIMARY KEY (organization_id, user_id, role),
                 FOREIGN KEY (organization_id, user_id) REFERENCES users (organization_id, id));"
        ),
        "CREATE TABLE parents (a INT, b INT, c INT, label TEXT, PRIMARY KEY (a, b, c));
         CREATE TABLE children (a INT, b INT, c INT, PRIMARY KEY (a, b, c),
             FOREIGN KEY (a, b, c) REFERENCES parents (a, b, c));"
            .to_owned(),
        // A narrower key makes the remaining column payload.
        "CREATE TABLE facts (a INT, b INT, c INT, PRIMARY KEY (a, b, c), UNIQUE (a, b));"
            .to_owned(),
        "CREATE TABLE facts (a INT, b INT, c INT, PRIMARY KEY (a, b, c));
         CREATE UNIQUE INDEX facts_a ON facts (a);"
            .to_owned(),
        "CREATE TABLE facts (a INT, b INT, PRIMARY KEY (a, b));".to_owned(),
        "CREATE TABLE facts (a INT, b INT, c INT);".to_owned(),
        // Structurally identical to the scoped team_members, so it passes too.
        format!(
            "{EMPLOYEES}
             CREATE TABLE employee_projects (employee_id INT REFERENCES employees (id),
                 project_name TEXT, PRIMARY KEY (employee_id, project_name));
             CREATE TABLE employee_dependents (employee_id INT REFERENCES employees (id),
                 dependent_name TEXT, PRIMARY KEY (employee_id, dependent_name));
             CREATE TABLE assignments (employee_id INT REFERENCES employees (id),
                 project_name TEXT, dependent_name TEXT,
                 PRIMARY KEY (employee_id, project_name, dependent_name),
                 FOREIGN KEY (employee_id, project_name) REFERENCES employee_projects (employee_id, project_name),
                 FOREIGN KEY (employee_id, dependent_name) REFERENCES employee_dependents (employee_id, dependent_name));"
        ),
    ] {
        assert_eq!(reported(&sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn a_declared_tenant_key_scopes_the_identities_it_prefixes() {
    let deployment = || {
        Deployment::default()
            .with_tenant_key("public", "team_members", ["organization_id"])
            .with_tenant_key("public", "team_labels", ["organization_id"])
    };
    for sql in [
        format!(
            "{ORGANIZATIONS}
             CREATE TABLE team_members (organization_id INT, team_id INT, user_id INT,
                 PRIMARY KEY (organization_id, team_id, user_id),
                 FOREIGN KEY (organization_id, team_id) REFERENCES teams (organization_id, id),
                 FOREIGN KEY (organization_id, user_id) REFERENCES users (organization_id, id));"
        ),
        // The foreign key to the tenant itself holds no participant.
        format!(
            "{ORGANIZATIONS}
             CREATE TABLE team_labels (organization_id INT REFERENCES organizations (id),
                 team_name TEXT, label TEXT, PRIMARY KEY (organization_id, team_name, label));"
        ),
    ] {
        assert_eq!(reported(&sql).len(), 1, "{sql}");
        assert_eq!(
            reported_under(deployment(), &sql),
            Vec::<String>::new(),
            "{sql}"
        );
    }
}
