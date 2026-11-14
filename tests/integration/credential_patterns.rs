//! Policy clauses using a credential as a match pattern.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
CREATE TABLE docs (owner_email TEXT);
CREATE TABLE members (email TEXT, doc_owner TEXT);
";

const EMAIL: &str = "current_setting('app.email', true)";

fn messages(clause: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "{SCHEMA} CREATE POLICY own ON docs {clause};"
    ))
    .expect("schema parses");
    let mut constrainer: GenericConstrainer<ParserDB> = CredentialPatternPolicy::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_credential(EMAIL)
            .expect("credential parses"),
    );
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn a_credential_pattern_names_the_match() {
    for (clause, matched) in [
        (
            format!("USING (owner_email LIKE {EMAIL})"),
            format!("owner_email LIKE {EMAIL}"),
        ),
        (
            format!("USING (owner_email ILIKE {EMAIL})"),
            format!("owner_email ILIKE {EMAIL}"),
        ),
        (
            format!("USING (owner_email SIMILAR TO {EMAIL})"),
            format!("owner_email SIMILAR TO {EMAIL}"),
        ),
        (
            format!("USING (owner_email ~ {EMAIL})"),
            format!("owner_email ~ {EMAIL}"),
        ),
        (
            format!("USING (owner_email ~* {EMAIL})"),
            format!("owner_email ~* {EMAIL}"),
        ),
        (
            format!("USING (owner_email LIKE ({EMAIL})::TEXT)"),
            format!("owner_email LIKE ({EMAIL})::TEXT"),
        ),
        (
            format!("FOR INSERT WITH CHECK (owner_email LIKE {EMAIL})"),
            format!("owner_email LIKE {EMAIL}"),
        ),
        (
            format!(
                "USING (EXISTS (SELECT 1 FROM members WHERE doc_owner = owner_email AND email LIKE {EMAIL}))"
            ),
            format!("email LIKE {EMAIL}"),
        ),
    ] {
        assert_eq!(
            messages(&clause),
            [format!(
                "Policy 'own' on 'docs' matches against the credential as a pattern in `{matched}`, so wildcards in the credential match rows meant for other callers."
            )],
            "{clause}"
        );
    }
}

#[test]
fn every_clause_of_a_policy_is_one_finding() {
    let found = messages(&format!(
        "FOR UPDATE USING (owner_email LIKE {EMAIL}) WITH CHECK (owner_email ~ {EMAIL})"
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains(&format!(
            "`owner_email LIKE {EMAIL}`, `owner_email ~ {EMAIL}`"
        )),
        "{found:?}"
    );
}

#[test]
fn other_uses_of_the_credential_are_not_reported() {
    for clause in [
        format!("USING (owner_email = {EMAIL})"),
        format!("USING ({EMAIL} LIKE owner_email)"),
        format!("USING (owner_email NOT LIKE {EMAIL})"),
        format!("USING (owner_email NOT ILIKE {EMAIL})"),
        format!("USING (owner_email !~ {EMAIL})"),
        format!("USING (owner_email !~* {EMAIL})"),
        format!("USING (owner_email LIKE replace({EMAIL}, '%', '\\%'))"),
        "USING (owner_email LIKE '%@example.com')".to_owned(),
    ] {
        assert_eq!(messages(&clause), Vec::<String>::new(), "{clause}");
    }
}
