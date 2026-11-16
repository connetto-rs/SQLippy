//! Unique constraints over nullable columns, observed through the public
//! constrainer API. On PostgreSQL 17.11 and 18.6, `UNIQUE` stored two rows
//! holding `NULL` and `UNIQUE NULLS NOT DISTINCT` refused the second.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

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
