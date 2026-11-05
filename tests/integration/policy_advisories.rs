//! Array-membership grants, deny-list-only grants and unindexed policy
//! filters, observed through the public constrainer API.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Level and site of every finding of `rule`.
fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    rule: &str,
    sql: &str,
) -> Vec<(Level, String, String)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == rule => {
                let Location::Policies(sites) = violation.location() else {
                    panic!("{rule} reports policies");
                };
                Some((
                    violation.level(),
                    violation.object().to_owned(),
                    sites
                        .iter()
                        .map(PolicySite::expression)
                        .collect::<Vec<_>>()
                        .join(" | "),
                ))
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn sites(constrainer: &GenericConstrainer<ParserDB>, rule: &str, sql: &str) -> Vec<String> {
    findings(constrainer, rule, sql)
        .into_iter()
        .map(|(_, _, site)| site)
        .collect()
}

const DOCS: &str = "CREATE ROLE readers; CREATE ROLE editors_role;
    CREATE TABLE docs (id INT PRIMARY KEY, team INT, owner TEXT, tags TEXT, editors TEXT[]);
    CREATE TABLE members (team INT, member TEXT, since INT);
    CREATE TABLE blocks (doc_id INT, member TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

fn arrays(policy: &str) -> Vec<String> {
    sites(
        &ArrayMembershipPolicy::default().into(),
        "ArrayMembershipPolicy",
        &format!("{DOCS} {policy}"),
    )
}

#[test]
fn membership_of_the_caller_in_an_array_column_is_reported() {
    for (policy, site) in [
        (
            "CREATE POLICY p ON docs USING (current_setting('app.user_id', true) = ANY (editors));",
            "current_setting('app.user_id', true) = ANY(editors)",
        ),
        (
            "CREATE POLICY p ON docs FOR UPDATE USING (true) WITH CHECK (editors @> ARRAY[current_user]);",
            "editors @> ARRAY[current_user]",
        ),
        (
            "CREATE POLICY p ON docs USING (ARRAY[session_user] <@ docs.editors);",
            "ARRAY[session_user] <@ docs.editors",
        ),
    ] {
        assert_eq!(arrays(policy), [site], "{policy}");
    }
}

#[test]
fn array_tests_of_constants_rows_scalars_and_subqueries_pass() {
    for policy in [
        "CREATE POLICY p ON docs USING ('admin' = ANY (editors));",
        "CREATE POLICY p ON docs USING (owner = ANY (editors));",
        "CREATE POLICY p ON docs USING (current_user = ANY (ARRAY[owner, tags]));",
        "CREATE POLICY p ON docs USING (owner = current_user);",
        "CREATE POLICY p ON docs USING (current_user = ANY (ARRAY[tags]) AND editors @> editors);",
        "CREATE POLICY p ON docs USING (EXISTS (
           SELECT 1 FROM members m WHERE current_user = ANY (ARRAY[m.member]) AND current_user = ANY (editors)));",
    ] {
        assert_eq!(arrays(policy), Vec::<String>::new(), "{policy}");
    }
}

#[test]
fn a_declared_credential_counts_as_the_caller() {
    let constrainer: GenericConstrainer<ParserDB> = ArrayMembershipPolicy::default().into();
    let sql = format!("{DOCS} CREATE POLICY p ON docs USING (auth.uid() = ANY (editors));");
    assert_eq!(
        findings(&constrainer, "ArrayMembershipPolicy", &sql),
        Vec::<(Level, String, String)>::new()
    );
    let mut constrainer = constrainer;
    constrainer.set_deployment(
        Deployment::default()
            .with_credential("auth.uid()")
            .expect("credential parses"),
    );
    assert_eq!(
        findings(&constrainer, "ArrayMembershipPolicy", &sql)
            .into_iter()
            .map(|(_, _, site)| site)
            .collect::<Vec<_>>(),
        ["auth.uid() = ANY(editors)"]
    );
}

const DENY: &str =
    "NOT EXISTS (SELECT 1 FROM blocks b WHERE b.doc_id = docs.id AND b.member = current_user)";

fn deny_lists(policies: &str) -> Vec<String> {
    sites(
        &DenyListPolicy::default().into(),
        "DenyListPolicy",
        &format!("{DOCS} {policies}"),
    )
}

#[test]
fn a_deny_list_narrowing_only_an_always_true_grant_is_reported() {
    let cases = [
        format!(
            "CREATE POLICY everyone ON docs FOR SELECT USING (true);
             CREATE POLICY blocked ON docs AS RESTRICTIVE FOR SELECT USING ({DENY});"
        ),
        format!(
            "CREATE POLICY everyone ON docs USING (true);
             CREATE POLICY blocked ON docs AS RESTRICTIVE USING ({DENY});"
        ),
        "CREATE POLICY everyone ON docs TO readers USING (true);
         CREATE POLICY own ON docs TO editors_role USING (owner = current_user);
         CREATE POLICY blocked ON docs AS RESTRICTIVE TO readers USING (
           NOT (docs.id IN (SELECT doc_id FROM blocks WHERE member = current_user)));"
            .to_owned(),
        "CREATE POLICY everyone ON docs FOR SELECT USING (true);
         CREATE POLICY blocked ON docs AS RESTRICTIVE FOR SELECT USING (
           (docs.id NOT IN (SELECT doc_id FROM blocks WHERE member = current_user)));"
            .to_owned(),
    ];
    for policies in cases {
        assert_eq!(deny_lists(&policies).len(), 1, "{policies}");
    }
}

#[test]
fn deny_lists_over_real_grants_and_other_restrictions_pass() {
    let cases = [
        format!(
            "CREATE POLICY everyone ON docs FOR SELECT USING (true);
             CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);
             CREATE POLICY blocked ON docs AS RESTRICTIVE FOR SELECT USING ({DENY});"
        ),
        format!(
            "CREATE POLICY own ON docs FOR SELECT USING (owner = current_user);
             CREATE POLICY blocked ON docs AS RESTRICTIVE FOR SELECT USING ({DENY});"
        ),
        format!(
            "CREATE POLICY everyone ON docs FOR UPDATE USING (true) WITH CHECK (owner = current_user);
             CREATE POLICY blocked ON docs AS RESTRICTIVE FOR UPDATE USING ({DENY});"
        ),
        format!(
            "CREATE POLICY everyone ON docs FOR INSERT WITH CHECK (true);
             CREATE POLICY blocked ON docs AS RESTRICTIVE FOR SELECT USING ({DENY});"
        ),
        format!(
            "CREATE POLICY everyone ON docs TO readers USING (true);
             CREATE POLICY blocked ON docs AS RESTRICTIVE TO editors_role USING ({DENY});"
        ),
        "CREATE POLICY everyone ON docs USING (true);
         CREATE POLICY mine ON docs AS RESTRICTIVE USING (owner = current_user);
         CREATE POLICY listed ON docs AS RESTRICTIVE USING (
           EXISTS (SELECT 1 FROM members WHERE member = current_user));"
            .to_owned(),
    ];
    for policies in cases {
        assert_eq!(deny_lists(&policies), Vec::<String>::new(), "{policies}");
    }
}

fn filters(sql: &str) -> Vec<String> {
    sites(
        &UnindexedPolicyFilter::default().into(),
        "UnindexedPolicyFilter",
        &format!("{DOCS} {sql}"),
    )
}

#[test]
fn unindexed_columns_filtered_by_the_caller_are_reported() {
    for (sql, site) in [
        (
            "CREATE POLICY p ON docs USING (owner = current_setting('app.user_id', true));",
            "owner = current_setting('app.user_id', true)",
        ),
        (
            "CREATE POLICY p ON docs USING (current_user >= docs.owner AND owner = current_user);",
            "current_user >= docs.owner",
        ),
        (
            "CREATE POLICY p ON docs USING (owner IN (current_user, session_user));",
            "owner IN (current_user, session_user)",
        ),
        (
            "CREATE POLICY p ON docs USING (owner = ANY (string_to_array(current_setting('app.users'), ',')));",
            "owner = ANY(string_to_array(current_setting('app.users'), ','))",
        ),
        (
            "CREATE INDEX members_team ON members (team);
             CREATE POLICY p ON docs USING (team IN (SELECT team FROM members WHERE member = current_user));",
            "team IN (SELECT team FROM members WHERE member = current_user) | member = current_user",
        ),
        (
            "CREATE INDEX docs_team ON docs (team);
             CREATE POLICY p ON docs USING (EXISTS (
               SELECT 1 FROM members m WHERE m.team = docs.team AND m.member IN (current_user)));",
            "m.member IN (current_user)",
        ),
    ] {
        assert_eq!(
            filters(sql).join(" | "),
            site,
            "{sql}"
        );
    }
}

#[test]
fn indexed_or_row_dependent_or_constant_filters_pass() {
    for sql in [
        "CREATE INDEX docs_owner ON docs (owner, team);
         CREATE POLICY p ON docs USING (owner = current_user);",
        "CREATE TABLE notes (owner TEXT UNIQUE); ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON notes USING (owner = current_user);",
        "CREATE TABLE notes (owner TEXT PRIMARY KEY); ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON notes USING (owner = current_user);",
        "CREATE POLICY p ON docs USING (id = current_setting('app.doc')::INT);",
        "CREATE POLICY p ON docs USING (owner = 'admin' OR owner = tags OR owner <> current_user);",
        "CREATE POLICY p ON docs USING (owner NOT IN (current_user) AND current_user = current_user);",
        "CREATE POLICY p ON docs FOR INSERT WITH CHECK (owner = current_user);",
        "CREATE POLICY p ON docs USING (owner IN (SELECT member FROM members WHERE members.team = docs.team));",
        "CREATE INDEX members_member ON members (member);
         CREATE POLICY p ON docs USING (EXISTS (
           SELECT 1 FROM members m WHERE m.member = current_user AND m.since = m.team
             AND m.since IN (SELECT team FROM members WHERE member = current_user)));",
    ] {
        assert_eq!(filters(sql), Vec::<String>::new(), "{sql}");
    }
}

#[test]
fn partial_and_expression_indexes_do_not_count() {
    for index in [
        "CREATE INDEX docs_owner ON docs (owner) WHERE team > 0;",
        "CREATE INDEX docs_owner ON docs (lower(owner));",
        "CREATE INDEX docs_owner ON docs (team, owner);",
    ] {
        assert_eq!(
            filters(&format!(
                "{index} CREATE POLICY p ON docs USING (owner = current_user);"
            )),
            ["owner = current_user"],
            "{index}"
        );
    }
}

#[test]
fn the_default_constrainer_applies_each_group_level() {
    let sql = format!(
        "{DOCS}
         CREATE POLICY everyone ON docs FOR SELECT USING (true);
         CREATE POLICY blocked ON docs AS RESTRICTIVE FOR SELECT USING ({DENY});
         CREATE POLICY edit ON docs FOR UPDATE USING (current_user = ANY (editors) AND owner = current_user);"
    );
    let constrainer = DefaultConstrainer::<ParserDB>::default();
    let levels = |rule| {
        findings(&constrainer, rule, &sql)
            .into_iter()
            .map(|(level, object, _)| (level, object))
            .collect::<Vec<_>>()
    };
    assert_eq!(levels("ArrayMembershipPolicy"), []);
    assert_eq!(
        levels("DenyListPolicy"),
        [(Level::Warn, "docs.blocked".to_owned())]
    );
    assert_eq!(
        levels("UnindexedPolicyFilter"),
        [
            (Level::Warn, "docs.blocked".to_owned()),
            (Level::Warn, "docs.edit".to_owned())
        ]
    );
    let mut pedantic = DefaultConstrainer::<ParserDB>::default();
    pedantic.set_group_level(LintGroup::Pedantic, Level::Warn);
    assert_eq!(
        findings(&pedantic, "ArrayMembershipPolicy", &sql)
            .into_iter()
            .map(|(level, object, _)| (level, object))
            .collect::<Vec<_>>(),
        [(Level::Warn, "docs.edit".to_owned())]
    );
}
