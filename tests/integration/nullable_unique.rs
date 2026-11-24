//! Unique constraints over nullable columns, observed through the public
//! constrainer API. On PostgreSQL 17.11 and 18.6, `UNIQUE` stored two rows
//! holding `NULL` and `UNIQUE NULLS NOT DISTINCT` refused the second.

use sqlippy::prelude::*;
use sqlparser::dialect::{PostgreSqlDialect, SQLiteDialect};

/// Level and message of every finding of the rule.
fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    sql: &str,
) -> Vec<(Level, String)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == "nullable_unique_column" => {
                Some((violation.level(), violation.message().to_owned()))
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn unique_constraints_over_nullable_columns_are_reported() {
    let found = findings(
        &GenericConstrainer::from(NullableUniqueColumn::default()),
        "CREATE TABLE t (id INT PRIMARY KEY, email TEXT UNIQUE, a INT NOT NULL, b INT, c TEXT,
           d TEXT UNIQUE NULLS NOT DISTINCT, e TEXT NOT NULL UNIQUE,
           CONSTRAINT pair UNIQUE (a, b));
         CREATE UNIQUE INDEX t_c ON t (c);
         CREATE UNIQUE INDEX t_c_all ON t (c) NULLS NOT DISTINCT;
         CREATE INDEX t_c_plain ON t (c);",
    );
    let messages: Vec<&str> = found.iter().map(|(_, message)| message.as_str()).collect();
    assert_eq!(
        messages,
        [
            "Unique constraint unique ('email') on 't' covers nullable 'email' and treats NULLs as distinct, so rows with a NULL there can repeat the rest.",
            "Unique constraint 'pair' on 't' covers nullable 'b' and treats NULLs as distinct, so rows with a NULL there can repeat the rest.",
            "Unique constraint 't_c' on 't' covers nullable 'c' and treats NULLs as distinct, so rows with a NULL there can repeat the rest.",
        ]
    );
    assert!(found.iter().all(|(level, _)| *level == Level::Warn));
}

#[test]
fn a_unique_optional_reference_is_not_reported() {
    let found = findings(
        &GenericConstrainer::from(NullableUniqueColumn::default()),
        "CREATE TABLE tenants (id UUID PRIMARY KEY);
         CREATE TABLE invitations (id UUID PRIMARY KEY,
           tenant_id UUID NOT NULL REFERENCES tenants (id), UNIQUE (tenant_id, id));
         CREATE TABLE members (tenant_id UUID NOT NULL REFERENCES tenants (id),
           user_id UUID NOT NULL, invitation_id UUID UNIQUE,
           PRIMARY KEY (tenant_id, user_id), UNIQUE (tenant_id, invitation_id),
           FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id));
         CREATE TABLE plain_members (user_id UUID PRIMARY KEY,
           invitation_id UUID UNIQUE REFERENCES invitations (id));
         CREATE TABLE notes (invitation_id UUID REFERENCES invitations (id), note TEXT,
           UNIQUE (invitation_id, note));
         CREATE TABLE loose (tenant_id UUID, invitation_id UUID UNIQUE,
           FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id));",
    );
    let messages: Vec<&str> = found.iter().map(|(_, message)| message.as_str()).collect();
    assert_eq!(
        messages,
        [
            "Unique constraint unique ('invitation_id') on 'loose' covers nullable 'invitation_id' and treats NULLs as distinct, so rows with a NULL there can repeat the rest.",
            "Unique constraint unique ('note') on 'notes' covers nullable 'note' and treats NULLs as distinct, so rows with a NULL there can repeat the rest.",
        ]
    );
}

#[test]
fn the_rule_is_pedantic() {
    let sql = "CREATE TABLE t (email TEXT UNIQUE);";
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    assert_eq!(findings(&constrainer, sql), Vec::<(Level, String)>::new());
    constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
    assert_eq!(findings(&constrainer, sql).len(), 1);
}

const REPLICA: &str = "CREATE TABLE invitations (organization_id BLOB NOT NULL, id BLOB NOT NULL,
    PRIMARY KEY (organization_id, id));
  CREATE TABLE memberships (organization_id BLOB NOT NULL, user_id BLOB NOT NULL,
    invitation_id BLOB UNIQUE, PRIMARY KEY (organization_id, user_id));
  CREATE TABLE loose (organization_id BLOB, invitation_id BLOB UNIQUE);";

/// The deployment declaring that another party checks
/// `table (organization_id, invitation_id)` against
/// `invitations (organization_id, id)`.
fn checked_elsewhere(table: &str) -> Deployment {
    Deployment::default().with_external_foreign_key(
        "main",
        table,
        ["organization_id", "invitation_id"],
        "main",
        "invitations",
        ["organization_id", "id"],
    )
}

/// Every diagnostic of the rule on the SQLite `schema` under `deployment`.
fn replica_diagnostics(deployment: Deployment, schema: &str) -> Vec<Error<ParserDB>> {
    let database = ParserDB::parse::<SQLiteDialect>(schema).expect("schema parses");
    let mut constrainer = GenericConstrainer::from(NullableUniqueColumn::default());
    constrainer.set_deployment(deployment);
    constrainer.diagnostics(&database)
}

/// The tables the rule reports on the SQLite `REPLICA` under `deployment`,
/// sorted.
fn reported_tables(deployment: Deployment) -> Vec<String> {
    let mut tables: Vec<String> = replica_diagnostics(deployment, REPLICA)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => match violation.location() {
                Location::Table(table) => table.table_name().to_owned(),
                other => panic!("unexpected location: {other:?}"),
            },
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    tables.sort_unstable();
    tables
}

#[test]
fn an_external_optional_reference_is_not_reported() {
    assert_eq!(
        reported_tables(Deployment::default()),
        ["loose", "memberships"]
    );
    assert_eq!(reported_tables(checked_elsewhere("memberships")), ["loose"]);
}

#[test]
fn an_external_key_with_two_nullable_columns_excuses_neither() {
    assert_eq!(
        reported_tables(checked_elsewhere("loose")),
        ["loose", "memberships"]
    );
}

#[test]
fn an_external_key_naming_what_the_schema_lacks_is_an_error() {
    let cases = [
        (
            checked_elsewhere("members"),
            "names table 'main.members', which the schema lacks",
        ),
        (
            Deployment::default().with_external_foreign_key(
                "main",
                "memberships",
                ["organization_id", "invite_id"],
                "main",
                "invitations",
                ["organization_id", "id"],
            ),
            "names column 'invite_id', which 'main.memberships' lacks",
        ),
        (
            Deployment::default().with_external_foreign_key(
                "main",
                "memberships",
                ["organization_id", "invitation_id"],
                "main",
                "invitations",
                ["organization_id", "invitation_id"],
            ),
            "names column 'invitation_id', which 'main.invitations' lacks",
        ),
        (
            Deployment::default().with_external_foreign_key(
                "main",
                "memberships",
                ["organization_id", "invitation_id"],
                "main",
                "invitations",
                ["id"],
            ),
            "has 2 columns referencing 1",
        ),
    ];
    for (deployment, problem) in cases {
        let diagnostics = replica_diagnostics(deployment, REPLICA);
        let [Error::UnresolvedForeignKey(unresolved), ..] = diagnostics.as_slice() else {
            panic!("expected an unresolved foreign key first, got {diagnostics:#?}");
        };
        assert!(
            unresolved.to_string().ends_with(problem),
            "{unresolved} does not end with {problem}"
        );
    }
}
