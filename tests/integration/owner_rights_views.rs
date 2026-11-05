//! Views over row-level-security tables that run with their owner's rights,
//! observed through the public constrainer API.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Each view the rule reports, with whether the finding says rows leak.
fn reported(sql: &str) -> Vec<(String, bool)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE ROLE bob;
         CREATE ROLE vo;
         CREATE ROLE tbl_owner;
         CREATE ROLE vb BYPASSRLS;
         CREATE TABLE docs (id INT, owner TEXT);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE TABLE open_notes (id INT);
         {sql}"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = OwnerRightsView::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.object().to_owned(),
                violation.message().contains("every caller sees every row"),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

const SETTING: &str = "CREATE POLICY p ON docs USING (owner = current_setting('app.uid', true));";

/// Measured on PostgreSQL 16.8 with bob reading the view over bob's row and
/// alice's: 1 row is correct, 2 leak alice's, 0 hide bob's.
#[test]
fn an_owner_rights_view_is_reported_where_its_owner_bypasses_or_misses_the_policies() {
    let cases = [
        (
            format!("{SETTING} CREATE VIEW v AS SELECT * FROM docs; ALTER VIEW v OWNER TO vo;"),
            vec![],
        ),
        (
            "CREATE POLICY p ON docs USING (owner = current_user);
             CREATE VIEW v AS SELECT * FROM docs; ALTER VIEW v OWNER TO vo;"
                .to_owned(),
            vec![],
        ),
        (
            "CREATE POLICY p ON docs TO bob USING (owner = current_setting('app.uid', true));
             CREATE POLICY writes ON docs FOR INSERT TO vo WITH CHECK (true);
             CREATE VIEW v AS SELECT * FROM docs; ALTER VIEW v OWNER TO vo;"
                .to_owned(),
            vec![("v".to_owned(), false)],
        ),
        (
            format!(
                "ALTER TABLE docs OWNER TO tbl_owner; {SETTING}
                 CREATE VIEW v AS SELECT * FROM docs; ALTER VIEW v OWNER TO tbl_owner;"
            ),
            vec![("v".to_owned(), true)],
        ),
        (
            format!(
                "ALTER TABLE docs OWNER TO tbl_owner; ALTER TABLE docs FORCE ROW LEVEL SECURITY; {SETTING}
                 CREATE VIEW v AS SELECT * FROM docs; ALTER VIEW v OWNER TO tbl_owner;"
            ),
            vec![],
        ),
        (
            format!("{SETTING} CREATE VIEW v AS SELECT * FROM docs;"),
            vec![("v".to_owned(), true)],
        ),
        (
            format!("{SETTING} CREATE VIEW v WITH (security_invoker) AS SELECT * FROM docs;"),
            vec![],
        ),
    ];
    for (sql, expected) in cases {
        assert_eq!(reported(&sql), expected, "{sql}");
    }
}

#[test]
fn an_owner_that_bypasses_by_attribute_or_cannot_be_checked_leaks() {
    for owner in ["vb", "ghost"] {
        assert_eq!(
            reported(&format!(
                "{SETTING} CREATE VIEW v AS SELECT * FROM docs; ALTER VIEW v OWNER TO {owner};"
            )),
            [("v".to_owned(), true)],
            "{owner}"
        );
    }
}

#[test]
fn reads_through_invoker_views_count_and_owner_views_answer_for_themselves() {
    assert_eq!(
        reported(&format!(
            "{SETTING}
             CREATE VIEW inner_invoker WITH (security_invoker) AS SELECT * FROM docs;
             CREATE VIEW through_invoker AS SELECT * FROM inner_invoker;
             CREATE VIEW inner_owner AS SELECT * FROM docs; ALTER VIEW inner_owner OWNER TO vo;
             CREATE VIEW through_owner AS SELECT * FROM inner_owner;
             CREATE VIEW notes AS SELECT * FROM open_notes;
             CREATE MATERIALIZED VIEW snapshot AS SELECT * FROM docs;"
        )),
        [("through_invoker".to_owned(), true)]
    );
}
