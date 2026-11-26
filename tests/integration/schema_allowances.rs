//! Allowances naming a table, a foreign key, a unique index, a view or a
//! materialized view, observed through the public constrainer API.

use sqlippy::prelude::*;

use crate::common::parse;

const SCHEMA: &str = "
    CREATE ROLE app NOLOGIN;
    CREATE TABLE grantees (id UUID PRIMARY KEY, kind TEXT NOT NULL);
    ALTER TABLE grantees ENABLE ROW LEVEL SECURITY;
    CREATE TABLE memberships (
      organization_id UUID NOT NULL,
      user_id UUID NOT NULL,
      state TEXT NOT NULL,
      PRIMARY KEY (organization_id, user_id),
      UNIQUE (organization_id, user_id, state)
    );
    CREATE TABLE team_members (
      team_id UUID NOT NULL,
      organization_id UUID NOT NULL,
      user_id UUID NOT NULL,
      membership_state TEXT NOT NULL,
      PRIMARY KEY (team_id, user_id),
      FOREIGN KEY (organization_id, user_id, membership_state)
        REFERENCES memberships (organization_id, user_id, state) ON UPDATE CASCADE ON DELETE CASCADE,
      CONSTRAINT team_members_team_fkey FOREIGN KEY (team_id) REFERENCES grantees (id) ON DELETE CASCADE
    );
    ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
    CREATE POLICY team_members_update ON team_members FOR UPDATE TO app USING (TRUE) WITH CHECK (TRUE);
    CREATE POLICY team_members_delete ON team_members FOR DELETE TO app USING (TRUE);";

const MEMBERSHIP_KEY: &str = "team_members_organization_id_user_id_membership_state_fkey";

fn table(name: &str) -> TargetName<'_> {
    TargetName::new(name, false)
}

fn constrainer() -> GenericConstrainer<ParserDB> {
    let mut constrainer: GenericConstrainer<ParserDB> =
        RowLevelSecurityWithoutPolicies::default().into();
    constrainer.register_foreign_key_rule(Box::new(CascadeIntoRowLevelSecurityTable::default()));
    constrainer
}

/// Rule and object of every violation, and the description of every unused
/// allowance, failing on anything else.
fn outcome(
    constrainer: &GenericConstrainer<ParserDB>,
    sql: &str,
) -> (Vec<(&'static str, String)>, Vec<String>) {
    let (mut violations, mut unused) = (Vec::new(), Vec::new());
    for error in constrainer.diagnostics(&parse(sql)) {
        match error {
            Error::Violation(violation) => {
                violations.push((violation.rule().name, violation.object().to_owned()));
            }
            Error::UnusedAllowance(allowance) => unused.push(allowance.to_string()),
            other => panic!("unexpected failure: {other}"),
        }
    }
    (violations, unused)
}

#[test]
fn every_foreign_key_finding_names_the_constraint_an_allowance_takes() {
    assert_eq!(
        outcome(&constrainer(), SCHEMA),
        (
            vec![
                (
                    "cascade_into_row_level_security_table",
                    format!("team_members.{MEMBERSHIP_KEY}")
                ),
                (
                    "cascade_into_row_level_security_table",
                    "team_members.team_members_team_fkey".to_owned()
                ),
                ("row_level_security_without_policies", "grantees".to_owned()),
            ],
            vec![]
        )
    );
}

#[test]
fn a_table_allowance_excuses_its_rule_on_that_table_alone() {
    let mut constrainer = constrainer();
    constrainer.allow_table("row_level_security_without_policies", table("grantees"));
    constrainer.allow_table(
        "cascade_into_row_level_security_table",
        table("team_members"),
    );
    let (violations, unused) = outcome(&constrainer, SCHEMA);
    assert_eq!(
        violations.iter().map(|(rule, _)| *rule).collect::<Vec<_>>(),
        [
            "cascade_into_row_level_security_table",
            "cascade_into_row_level_security_table"
        ]
    );
    assert_eq!(
        unused,
        [
            "the allowance for cascade_into_row_level_security_table on table 'team_members' excuses no violation"
        ]
    );
}

#[test]
fn a_foreign_key_allowance_excuses_its_rule_on_that_key_alone() {
    let mut constrainer = constrainer();
    constrainer.allow_foreign_key(
        "cascade_into_row_level_security_table",
        table("team_members"),
        MEMBERSHIP_KEY,
    );
    assert_eq!(
        outcome(&constrainer, SCHEMA),
        (
            vec![
                (
                    "cascade_into_row_level_security_table",
                    "team_members.team_members_team_fkey".to_owned()
                ),
                ("row_level_security_without_policies", "grantees".to_owned()),
            ],
            vec![]
        )
    );
}

#[test]
fn a_foreign_key_allowance_that_excuses_nothing_is_reported_unused() {
    for (rule, host, key) in [
        (
            "cascade_into_row_level_security_table",
            "memberships",
            MEMBERSHIP_KEY,
        ),
        (
            "cascade_into_row_level_security_table",
            "team_members",
            "team_members_user_fkey",
        ),
        (
            "row_level_security_without_policies",
            "team_members",
            MEMBERSHIP_KEY,
        ),
    ] {
        let mut constrainer = constrainer();
        constrainer.allow_foreign_key(rule, table(host), key);
        let (violations, unused) = outcome(&constrainer, SCHEMA);
        assert_eq!(violations.len(), 3, "{rule} {host} {key}");
        assert_eq!(
            unused,
            [format!(
                "the allowance for {rule} on foreign key '{key}' of table '{host}' excuses no violation"
            )]
        );
    }
}

#[test]
fn an_allowance_left_after_the_finding_is_fixed_fails_validation() {
    let mut constrainer = constrainer();
    constrainer.allow_table("row_level_security_without_policies", table("grantees"));
    constrainer.allow_foreign_key(
        "cascade_into_row_level_security_table",
        table("team_members"),
        MEMBERSHIP_KEY,
    );
    constrainer.allow_foreign_key(
        "cascade_into_row_level_security_table",
        table("team_members"),
        "team_members_team_fkey",
    );
    assert!(constrainer.validate_schema(&parse(SCHEMA)).is_ok());
    let fixed = SCHEMA
        .replace("ON UPDATE CASCADE ON DELETE CASCADE", "")
        .replace(
            "CREATE TABLE memberships",
            "CREATE POLICY grantees_read ON grantees FOR SELECT TO app USING (TRUE);
             CREATE TABLE memberships",
        );
    let (violations, unused) = outcome(&constrainer, &fixed);
    assert!(violations.is_empty(), "{violations:?}");
    assert_eq!(
        unused,
        [
            "the allowance for row_level_security_without_policies on table 'grantees' excuses no violation".to_owned(),
            format!(
                "the allowance for cascade_into_row_level_security_table on foreign key '{MEMBERSHIP_KEY}' of table 'team_members' excuses no violation"
            ),
        ]
    );
}

const TENANT_SCHEMA: &str = "
    CREATE TABLE users (id INT PRIMARY KEY, email TEXT, handle TEXT, tenant_id INT NOT NULL,
      UNIQUE (handle));
    CREATE UNIQUE INDEX users_email ON users (email);
    ALTER TABLE users ENABLE ROW LEVEL SECURITY;
    CREATE POLICY users_rls ON users USING (tenant_id = current_setting('app.tenant', true)::int);";

fn tenant_constrainer() -> GenericConstrainer<ParserDB> {
    let mut constrainer: GenericConstrainer<ParserDB> =
        UnscopedUniqueConstraintOnRowLevelSecurityTable::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_credential("current_setting('app.tenant', true)")
            .expect("credential parses"),
    );
    constrainer
}

#[test]
fn an_index_allowance_excuses_its_rule_on_that_index_alone() {
    assert_eq!(
        outcome(&tenant_constrainer(), TENANT_SCHEMA).0,
        [
            (
                "unscoped_unique_constraint_on_row_level_security_table",
                "users.users_handle_key".to_owned()
            ),
            (
                "unscoped_unique_constraint_on_row_level_security_table",
                "users.users_email".to_owned()
            ),
        ]
    );
    for (allowed, kept) in [
        ("users_handle_key", "users.users_email"),
        ("users_email", "users.users_handle_key"),
    ] {
        let mut constrainer = tenant_constrainer();
        constrainer.allow_index(
            "unscoped_unique_constraint_on_row_level_security_table",
            table("users"),
            allowed,
        );
        assert_eq!(
            outcome(&constrainer, TENANT_SCHEMA),
            (
                vec![(
                    "unscoped_unique_constraint_on_row_level_security_table",
                    kept.to_owned()
                )],
                vec![]
            ),
            "{allowed}"
        );
    }
}

#[test]
fn an_index_allowance_for_an_index_the_rule_skips_is_reported_unused() {
    let mut constrainer = tenant_constrainer();
    constrainer.allow_index(
        "unscoped_unique_constraint_on_row_level_security_table",
        table("users"),
        "users_pkey",
    );
    assert_eq!(
        outcome(&constrainer, TENANT_SCHEMA).1,
        [
            "the allowance for unscoped_unique_constraint_on_row_level_security_table on index 'users_pkey' of table 'users' excuses no violation"
        ]
    );
}

const VIEW_SCHEMA: &str = "
    CREATE TABLE entries (id INT, body TEXT);
    CREATE VIEW visible AS SELECT * FROM entries;
    CREATE VIEW drafts AS SELECT * FROM entries;
    CREATE MATERIALIZED VIEW digest AS SELECT * FROM entries;";

fn wildcard_constrainer() -> GenericConstrainer<ParserDB> {
    WildcardView::default().into()
}

fn wildcard_findings(objects: &[&str]) -> Vec<(&'static str, String)> {
    objects
        .iter()
        .map(|object| ("wildcard_view", (*object).to_owned()))
        .collect()
}

#[test]
fn a_view_allowance_excuses_its_rule_on_that_view_alone() {
    let mut constrainer = wildcard_constrainer();
    constrainer.allow_view("wildcard_view", TargetName::new("visible", false));
    assert_eq!(
        outcome(&constrainer, VIEW_SCHEMA),
        (wildcard_findings(&["drafts", "digest"]), vec![])
    );
}

#[test]
fn a_materialized_view_allowance_excuses_its_rule_on_that_view_alone() {
    let mut constrainer = wildcard_constrainer();
    constrainer.allow_materialized_view("wildcard_view", TargetName::new("digest", false));
    assert_eq!(
        outcome(&constrainer, VIEW_SCHEMA),
        (wildcard_findings(&["drafts", "visible"]), vec![])
    );
}

#[test]
fn an_allowance_naming_a_view_as_another_kind_of_relation_is_reported_unused() {
    let mut constrainer = wildcard_constrainer();
    constrainer.allow_table("wildcard_view", TargetName::new("visible", false));
    constrainer.allow_view("wildcard_view", TargetName::new("digest", false));
    constrainer.allow_materialized_view("wildcard_view", TargetName::new("drafts", false));
    assert_eq!(
        outcome(&constrainer, VIEW_SCHEMA),
        (
            wildcard_findings(&["drafts", "visible", "digest"]),
            vec![
                "the allowance for wildcard_view on table 'visible' excuses no violation".to_owned(),
                "the allowance for wildcard_view on view 'digest' excuses no violation".to_owned(),
                "the allowance for wildcard_view on materialized view 'drafts' excuses no violation"
                    .to_owned(),
            ]
        )
    );
}

#[test]
fn a_schema_qualified_view_allowance_excuses_the_view_in_that_schema_alone() {
    let mut constrainer = wildcard_constrainer();
    constrainer.allow_view(
        "wildcard_view",
        TargetName::new("visible", false).with_schema("reporting", false),
    );
    let schema = format!(
        "{VIEW_SCHEMA}
        CREATE SCHEMA reporting;
        CREATE VIEW reporting.visible AS SELECT * FROM entries;"
    );
    assert_eq!(
        outcome(&constrainer, &schema),
        (wildcard_findings(&["drafts", "visible", "digest"]), vec![])
    );
}
