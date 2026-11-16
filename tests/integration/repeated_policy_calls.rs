//! Duplicate row-dependent policy calls.
use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Returns the rule's findings through the public constrainer.
fn findings(clause: &str, behavior: &str) -> usize {
    let schema = format!(
        "CREATE ROLE authenticated; CREATE TABLE docs(owner_id INT); ALTER TABLE docs ENABLE ROW LEVEL SECURITY; CREATE FUNCTION can_read(owner_id INT) RETURNS BOOLEAN LANGUAGE plpgsql {behavior} AS $$ BEGIN RETURN owner_id > 0; END $$; CREATE FUNCTION changing() RETURNS INT LANGUAGE plpgsql VOLATILE AS $$ BEGIN RETURN 1; END $$; CREATE POLICY own ON docs TO authenticated {clause};"
    );
    let database = ParserDB::parse::<PostgreSqlDialect>(&schema).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = RepeatedPolicyCall::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter(|error| match error {
            Error::Violation(_) => true,
            Error::Inactive(_) => false,
            other => panic!("{other}"),
        })
        .count()
}

#[test]
fn stable_and_immutable_duplicates_are_reported() {
    for behavior in ["STABLE", "IMMUTABLE"] {
        assert_eq!(
            findings("USING(can_read(owner_id) AND can_read(owner_id))", behavior),
            1
        );
    }
}
#[test]
fn different_boolean_branches_are_reported() {
    assert_eq!(
        findings(
            "USING((owner_id > 0 AND can_read(owner_id)) OR (owner_id < 0 AND can_read(owner_id)))",
            "STABLE"
        ),
        1
    );
}
#[test]
fn single_and_distinct_arguments_pass() {
    for clause in [
        "USING(can_read(owner_id))",
        "USING(can_read(owner_id) AND can_read(owner_id + 1))",
    ] {
        assert_eq!(findings(clause, "STABLE"), 0);
    }
}
#[test]
fn volatile_calls_and_arguments_pass() {
    assert_eq!(
        findings(
            "USING(can_read(owner_id) AND can_read(owner_id))",
            "VOLATILE"
        ),
        0
    );
    assert_eq!(
        findings(
            "USING(can_read(owner_id + changing()) AND can_read(owner_id + changing()))",
            "STABLE"
        ),
        0
    );
    assert_eq!(
        findings(
            "USING(can_read(owner_id + random()::int) AND can_read(owner_id + random()::int))",
            "STABLE"
        ),
        0
    );
}
#[test]
fn row_independent_builtin_and_sublink_calls_pass() {
    for clause in [
        "USING(can_read(1) AND can_read(1))",
        "USING(abs(owner_id) > 0 AND abs(owner_id) < 10)",
        "USING(EXISTS(SELECT 1 WHERE can_read(owner_id) AND can_read(owner_id)))",
        "USING(can_read(owner_id) AND (SELECT can_read(owner_id)))",
    ] {
        assert_eq!(findings(clause, "STABLE"), 0);
    }
}
#[test]
fn separate_clauses_do_not_share_counts() {
    assert_eq!(
        findings(
            "USING(can_read(owner_id)) WITH CHECK(can_read(owner_id))",
            "STABLE"
        ),
        0
    );
}

#[test]
fn qualified_stable_helper_ignores_unrelated_volatile_overload() {
    let database = ParserDB::parse::<PostgreSqlDialect>("CREATE SCHEMA auth; CREATE FUNCTION auth.can_read(owner_id INT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$ BEGIN RETURN owner_id > 0; END $$; CREATE FUNCTION can_read(owner_id INT) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$ BEGIN RETURN owner_id > 0; END $$; CREATE TABLE docs(owner_id INT); CREATE POLICY own ON docs USING(auth.can_read(owner_id) AND auth.can_read(owner_id));").unwrap();
    let constrainer: GenericConstrainer<ParserDB> = RepeatedPolicyCall::default().into();
    assert_eq!(constrainer.diagnostics(&database).len(), 1);
}

#[test]
fn nested_repetition_is_reported_once() {
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE docs(owner_id INT);
         CREATE FUNCTION norm(value INT) RETURNS INT LANGUAGE sql STABLE AS $$ SELECT value $$;
         CREATE FUNCTION can_read(value INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$ SELECT value > 0 $$;
         CREATE POLICY own ON docs USING(can_read(norm(owner_id)) AND can_read(norm(owner_id)));"
    ).unwrap();
    let constrainer: GenericConstrainer<ParserDB> = RepeatedPolicyCall::default().into();
    assert_eq!(constrainer.diagnostics(&database).len(), 1);
}

#[test]
fn subquery_arguments_do_not_supply_outer_row_dependencies() {
    for (clause, expected) in [
        (
            "USING(can_read((SELECT owner_id FROM docs)) AND can_read((SELECT owner_id FROM docs)))",
            0,
        ),
        (
            "USING(can_read(owner_id + (SELECT 1)) AND can_read(owner_id + (SELECT 1)))",
            1,
        ),
    ] {
        assert_eq!(findings(clause, "STABLE"), expected, "{clause}");
    }
}
