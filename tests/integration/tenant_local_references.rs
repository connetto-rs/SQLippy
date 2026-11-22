//! Foreign keys between tenant tables that do not pair their tenant keys,
//! observed through the public constrainer API.

use crate::rule_findings::inactive_declarations;
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const PROJECTS: &str = "CREATE TABLE projects (id INT PRIMARY KEY, organization_id INT NOT NULL,
      UNIQUE (organization_id, id));";

fn deployment() -> Deployment {
    Deployment::default()
        .with_tenant_key("public", "organizations", "id")
        .with_tenant_key("public", "projects", "organization_id")
        .with_tenant_key("public", "documents", "organization_id")
        .with_tenant_key("public", "apps", "organization_id")
        .with_tenant_key("public", "app_installations", "organization_id")
        .with_tenant_key("public", "resources", "organization_id")
        .with_tenant_key("public", "parents", "organization_id")
        .with_tenant_key("public", "children", "organization_id")
        .with_tenant_key("billing", "Invoices", "Org")
}

fn constrainer() -> GenericConstrainer<ParserDB> {
    let mut constrainer: GenericConstrainer<ParserDB> = TenantLocalReference::default().into();
    constrainer.set_deployment(deployment());
    constrainer
}

/// Object and resolution of every finding of the rule on `sql`.
fn reported(constrainer: &GenericConstrainer<ParserDB>, sql: &str) -> Vec<(String, String)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.object().to_owned(),
                violation.resolution().to_owned(),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn objects(sql: &str) -> Vec<String> {
    reported(&constrainer(), sql)
        .into_iter()
        .map(|(object, _)| object)
        .collect()
}

#[test]
fn a_key_on_the_identifier_alone_is_reported() {
    assert_eq!(
        objects(&format!(
            "{PROJECTS} CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
               project_id INT NOT NULL REFERENCES projects (id));"
        )),
        ["documents.documents_project_id_fkey"]
    );
}

#[test]
fn a_key_pairing_the_tenant_keys_in_any_position_is_clean() {
    for documents in [
        "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
           project_id INT NOT NULL,
           FOREIGN KEY (organization_id, project_id) REFERENCES projects (organization_id, id));",
        "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
           project_id INT NOT NULL,
           FOREIGN KEY (project_id, organization_id) REFERENCES projects (id, organization_id));",
        // An optional reference is checked whenever it is present.
        "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL, project_id INT,
           FOREIGN KEY (organization_id, project_id) REFERENCES projects (organization_id, id));",
        // A wider key pairing the tenant keys checks every row the narrower one checks.
        "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
           project_id INT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
           FOREIGN KEY (organization_id, project_id) REFERENCES projects (organization_id, id));",
    ] {
        assert_eq!(
            objects(&format!("{PROJECTS} {documents}")),
            Vec::<String>::new(),
            "{documents}"
        );
    }
}

#[test]
fn a_tenant_key_paired_with_another_column_is_reported() {
    for documents in [
        "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
           project_id INT NOT NULL,
           FOREIGN KEY (project_id, organization_id) REFERENCES projects (organization_id, id));",
        "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
           other_organization_id INT NOT NULL, project_id INT NOT NULL,
           FOREIGN KEY (other_organization_id, project_id) REFERENCES projects (organization_id, id));",
        // A wider key that a NULL tenant key lets a row escape does not cover the narrower one.
        "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT,
           project_id INT NOT NULL REFERENCES projects (id),
           FOREIGN KEY (organization_id, project_id) REFERENCES projects (organization_id, id));",
    ] {
        assert_eq!(
            objects(&format!("{PROJECTS} {documents}")).len(),
            1,
            "{documents}"
        );
    }
}

#[test]
fn the_resolution_names_the_composite_key_and_whether_it_exists() {
    let documents = "CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
        project_id INT NOT NULL REFERENCES projects (id));";
    let [(_, keyed)] = reported(&constrainer(), &format!("{PROJECTS} {documents}"))
        .try_into()
        .expect("one finding");
    assert!(
        keyed.starts_with(
            "Make the key reference projects (organization_id, id) from (organization_id, project_id) of 'documents'"
        ),
        "{keyed}"
    );
    for projects in [
        "CREATE TABLE projects (id INT PRIMARY KEY, organization_id INT NOT NULL);",
        "CREATE TABLE projects (id INT PRIMARY KEY, organization_id INT NOT NULL,
           UNIQUE (organization_id, id) DEFERRABLE);",
        "CREATE TABLE projects (id INT PRIMARY KEY, organization_id INT NOT NULL,
           UNIQUE (organization_id, id) DEFERRABLE INITIALLY DEFERRED);",
    ] {
        let [(_, unkeyed)] = reported(&constrainer(), &format!("{projects} {documents}"))
            .try_into()
            .expect("one finding");
        assert!(
            unkeyed.starts_with(
                "Add UNIQUE (organization_id, id) to 'projects', which a composite reference requires"
            ),
            "{unkeyed}"
        );
    }
    let [(_, swapped)] = reported(
        &constrainer(),
        &format!(
            "{PROJECTS} CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
               project_id INT NOT NULL,
               FOREIGN KEY (project_id, organization_id) REFERENCES projects (organization_id, id));"
        ),
    )
    .try_into()
    .expect("one finding");
    assert!(
        swapped.starts_with(
            "Make the key reference projects (organization_id, id) from (organization_id, project_id) of 'documents'"
        ),
        "{swapped}"
    );
}

#[test]
fn tables_without_a_declared_tenant_key_are_never_endpoints() {
    assert_eq!(
        objects(&format!(
            "{PROJECTS} CREATE TABLE users (id INT PRIMARY KEY);
             CREATE TABLE documents (id INT PRIMARY KEY, organization_id INT NOT NULL,
               author_id INT NOT NULL REFERENCES users (id));
             CREATE TABLE notes (id INT PRIMARY KEY, organization_id INT NOT NULL,
               project_id INT NOT NULL REFERENCES projects (id));"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn tenant_keys_of_any_name_are_paired_by_stored_names() {
    let sql = |key: &str| {
        format!(
            r#"{PROJECTS} CREATE SCHEMA billing;
               CREATE TABLE billing."Invoices" (id INT PRIMARY KEY, "Org" INT NOT NULL,
                 project_id INT NOT NULL, FOREIGN KEY {key});"#
        )
    };
    assert_eq!(
        objects(&sql(
            r#"("Org", project_id) REFERENCES projects (organization_id, id)"#
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        objects(&sql("(project_id) REFERENCES projects (id)")),
        ["Invoices.Invoices_project_id_fkey"]
    );
}

#[test]
fn a_key_into_the_tenant_table_itself_pairs_the_tenant_with_its_identifier() {
    let sql = |column: &str| {
        format!(
            "CREATE TABLE organizations (id INT PRIMARY KEY);
             CREATE TABLE projects (id INT PRIMARY KEY, organization_id INT NOT NULL,
               publisher_id INT NOT NULL, FOREIGN KEY ({column}) REFERENCES organizations (id));"
        )
    };
    assert_eq!(objects(&sql("organization_id")), Vec::<String>::new());
    assert_eq!(objects(&sql("publisher_id")).len(), 1);
}

const RESOURCES: &str = "CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL,
      UNIQUE (organization_id, id));";

const PARENTS: &str = "CREATE TABLE parents (id INT PRIMARY KEY, organization_id INT NOT NULL,
      kind INT NOT NULL, UNIQUE (id, kind),
      FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id));";

#[test]
fn a_key_between_rows_pinned_to_one_row_of_a_shared_root_is_clean() {
    for children in [
        "CREATE TABLE children (id INT PRIMARY KEY REFERENCES parents (id),
           organization_id INT NOT NULL,
           FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id));",
        "CREATE TABLE children (id INT PRIMARY KEY, organization_id INT NOT NULL, kind INT NOT NULL,
           FOREIGN KEY (id, kind) REFERENCES parents (id, kind),
           FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id));",
        "CREATE TABLE children (id INT PRIMARY KEY, organization_id INT NOT NULL,
           parent_id INT NOT NULL REFERENCES parents (id),
           FOREIGN KEY (organization_id, parent_id) REFERENCES resources (organization_id, id));",
        // MATCH FULL checks a row whose tenant key is NULL and whose identifier is not.
        "CREATE TABLE children (id INT PRIMARY KEY REFERENCES parents (id), organization_id INT,
           FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id) MATCH FULL);",
    ] {
        assert_eq!(
            objects(&format!("{RESOURCES} {PARENTS} {children}")),
            Vec::<String>::new(),
            "{children}"
        );
    }
}

#[test]
fn a_shared_root_that_does_not_pin_both_rows_to_one_tenant_is_reported() {
    let extension = "CREATE TABLE children (id INT PRIMARY KEY REFERENCES parents (id),
        organization_id INT NOT NULL,
        FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id));";
    for sql in [
        format!(
            "{RESOURCES} {PARENTS} CREATE TABLE children (id INT PRIMARY KEY REFERENCES parents (id),
               organization_id INT NOT NULL);"
        ),
        // Without a key on the identifier alone, one identifier names a row of each tenant.
        format!(
            "CREATE TABLE resources (id INT, organization_id INT NOT NULL,
               PRIMARY KEY (organization_id, id)); {PARENTS} {extension}"
        ),
        format!(
            "CREATE TABLE resources (id INT PRIMARY KEY DEFERRABLE, organization_id INT NOT NULL,
               UNIQUE (organization_id, id)); {PARENTS} {extension}"
        ),
        format!(
            "CREATE TABLE resources (id INT UNIQUE DEFERRABLE INITIALLY DEFERRED,
               organization_id INT NOT NULL, PRIMARY KEY (organization_id, id));
             {PARENTS} {extension}"
        ),
        // MATCH SIMPLE skips a row whose tenant key is NULL.
        format!(
            "{RESOURCES} {PARENTS} CREATE TABLE children (id INT PRIMARY KEY REFERENCES parents (id),
               organization_id INT,
               FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id));"
        ),
        // A column other than the tenant key is bound to the tenant of the root.
        format!(
            "{RESOURCES} {PARENTS} CREATE TABLE children (id INT PRIMARY KEY REFERENCES parents (id),
               organization_id INT NOT NULL, owner_id INT NOT NULL,
               FOREIGN KEY (owner_id, id) REFERENCES resources (organization_id, id));"
        ),
        // Each table is pinned to a row of another root.
        format!(
            "{RESOURCES} CREATE TABLE ownables (id INT PRIMARY KEY, organization_id INT NOT NULL,
               UNIQUE (organization_id, id));
             CREATE TABLE parents (id INT PRIMARY KEY, organization_id INT NOT NULL,
               FOREIGN KEY (organization_id, id) REFERENCES ownables (organization_id, id));
             {extension}"
        ),
    ] {
        assert!(
            objects(&sql).contains(&"children.children_id_fkey".to_owned()),
            "{sql}"
        );
    }
}

#[test]
fn an_allowance_excuses_only_its_own_key() {
    let sql = "CREATE TABLE apps (id INT PRIMARY KEY, organization_id INT NOT NULL,
          UNIQUE (organization_id, id));
        CREATE TABLE app_installations (id INT PRIMARY KEY, organization_id INT NOT NULL,
          app_id INT NOT NULL REFERENCES apps (id),
          parent_id INT REFERENCES app_installations (id),
          UNIQUE (organization_id, id));
        CREATE TABLE projects (id INT PRIMARY KEY, organization_id INT NOT NULL,
          app_id INT NOT NULL REFERENCES apps (id));";
    let mut constrainer = constrainer();
    constrainer.allow_foreign_key(
        "tenant_local_reference",
        TargetName::new("app_installations", false),
        "app_installations_app_id_fkey",
    );
    let mut remaining: Vec<String> = reported(&constrainer, sql)
        .into_iter()
        .map(|(object, _)| object)
        .collect();
    remaining.sort();
    assert_eq!(
        remaining,
        [
            "app_installations.app_installations_parent_id_fkey",
            "projects.projects_app_id_fkey",
        ]
    );
}

#[test]
fn the_rule_is_inactive_without_tenant_keys() {
    let constrainer: GenericConstrainer<ParserDB> = TenantLocalReference::default().into();
    assert_eq!(
        inactive_declarations(&constrainer),
        [("tenant_local_reference", Declaration::TenantKeys)]
    );
}
