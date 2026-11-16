//! Enum thresholds protecting authority attributes.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
CREATE ROLE authenticated;
CREATE TYPE role AS ENUM ('reader', 'writer', 'admin');
CREATE TABLE docs (id UUID PRIMARY KEY, writers_can_share BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE doc_grants (doc_id UUID REFERENCES docs, user_id UUID, role role);
CREATE FUNCTION docs_with(min_role role) RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT g.doc_id FROM doc_grants g WHERE g.user_id = current_setting('app.user_id', true)::uuid AND g.role >= min_role
$$;
CREATE FUNCTION sharable_docs() RETURNS SETOF UUID LANGUAGE sql STABLE AS $$
 SELECT d.id FROM docs d WHERE d.writers_can_share AND d.id IN (SELECT docs_with('writer'))
$$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT TO authenticated USING (id IN (SELECT docs_with('reader')));
CREATE POLICY grants_share ON doc_grants FOR INSERT TO authenticated WITH CHECK (doc_id IN (SELECT sharable_docs()));
GRANT SELECT, UPDATE ON docs TO authenticated;
GRANT INSERT ON doc_grants TO authenticated;
";

/// Counts threshold findings through the public constrainer.
fn findings(schema: &str) -> usize {
    let database = ParserDB::parse::<PostgreSqlDialect>(schema).expect("schema parses");
    let mut constrainer: GenericConstrainer<ParserDB> =
        AuthorityAttributeWritableBelowThreshold::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(
                    violation.rule().name,
                    "authority_attribute_writable_below_threshold"
                );
                1
            }
            other => panic!("unexpected diagnostic {other}"),
        })
        .sum()
}

/// Adds a write policy at the requested threshold.
fn schema(threshold: &str) -> String {
    format!(
        "{SCHEMA} CREATE POLICY docs_update ON docs FOR UPDATE TO authenticated USING (id IN (SELECT docs_with('{threshold}'))) WITH CHECK (id IN (SELECT docs_with('{threshold}')));"
    )
}

#[test]
fn write_at_or_below_arm_is_reported() {
    for threshold in ["reader", "writer"] {
        assert_eq!(findings(&schema(threshold)), 1, "{threshold}");
    }
}

#[test]
fn write_above_arm_passes() {
    assert_eq!(findings(&schema("admin")), 0);
}

#[test]
fn strict_threshold_uses_next_enum_label() {
    let strict = schema("writer").replace("g.role >= min_role", "g.role > min_role");
    assert_eq!(findings(&strict), 1);
    assert_eq!(findings(&strict.replace("docs_update ON docs FOR UPDATE TO authenticated USING (id IN (SELECT docs_with('writer'))) WITH CHECK (id IN (SELECT docs_with('writer')))", "docs_update ON docs FOR UPDATE TO authenticated USING (id IN (SELECT docs_with('admin'))) WITH CHECK (id IN (SELECT docs_with('admin')))")), 0);
}

#[test]
fn all_policy_and_any_set_are_covered() {
    assert_eq!(
        findings(&schema("writer").replace("FOR UPDATE", "FOR ALL")),
        1
    );
    assert_eq!(
        findings(&schema("writer").replace(
            "d.id IN (SELECT docs_with('writer'))",
            "d.id = ANY (ARRAY(SELECT docs_with('writer')))"
        )),
        1
    );
}

#[test]
fn withheld_attribute_passes() {
    assert_eq!(
        findings(&format!(
            "{} REVOKE UPDATE ON docs FROM authenticated; GRANT UPDATE (id) ON docs TO authenticated;",
            schema("writer")
        )),
        0
    );
}

#[test]
fn text_threshold_is_excluded() {
    let text = schema("writer")
        .replace(
            "CREATE TYPE role AS ENUM ('reader', 'writer', 'admin');",
            "",
        )
        .replace("role role", "role TEXT")
        .replace("min_role role", "min_role TEXT");
    assert_eq!(findings(&text), 0);
}

#[test]
fn restrictive_policy_and_unreached_arm_are_excluded() {
    assert_eq!(
        findings(
            &schema("writer").replace("docs_update ON docs", "docs_update ON docs AS RESTRICTIVE")
        ),
        0
    );
    assert_eq!(
        findings(&schema("writer").replace("doc_id IN (SELECT sharable_docs())", "true")),
        0
    );
}

#[test]
fn strict_write_threshold_advances_past_the_arm() {
    let helper = "CREATE FUNCTION docs_above(min_role role) RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER AS $$
        SELECT g.doc_id FROM doc_grants g WHERE g.user_id = current_setting('app.user_id', true)::uuid AND g.role > min_role
        $$;";
    for (threshold, expected) in [("reader", 1), ("writer", 0), ("admin", 0)] {
        let sql = format!(
            "{SCHEMA}{helper} CREATE POLICY docs_update ON docs FOR UPDATE TO authenticated USING (id IN (SELECT docs_above('{threshold}')));"
        );
        assert_eq!(findings(&sql), expected, "{threshold}");
    }
}

#[test]
fn direct_policy_arm_is_covered() {
    let sql = schema("writer").replace("doc_id IN (SELECT sharable_docs())", "doc_id IN (SELECT d.id FROM docs d WHERE d.writers_can_share AND d.id IN (SELECT docs_with('writer')))");
    assert_eq!(findings(&sql), 1);
}

#[test]
fn reversed_threshold_comparisons_are_reported() {
    for (comparison, reversed) in [
        ("g.role >= min_role", "min_role <= g.role"),
        ("g.role >= min_role", "min_role < g.role"),
    ] {
        assert_eq!(findings(&schema("writer").replace(comparison, reversed)), 1);
    }
}

#[test]
fn parameter_names_use_postgresql_identifier_folding() {
    for reference in ["\"min_role\"", "DOCS_WITH.\"min_role\""] {
        let sql = schema("writer")
            .replace("docs_with(min_role role)", "docs_with(Min_Role role)")
            .replace("g.role >= min_role", &format!("g.role >= {reference}"));
        assert_eq!(findings(&sql), 1, "{reference}");
    }
}

#[test]
fn threshold_requires_a_credential_filtered_enum_parameter() {
    for comparison in [
        "g.role >= 'writer'",
        "g.doc_id >= min_role",
        "'writer' >= min_role",
        "g.role >= min_role OR true",
        "g.role >= min_role AND true",
    ] {
        let expected = usize::from(comparison == "g.role >= min_role AND true");
        assert_eq!(
            findings(&schema("writer").replace("g.role >= min_role", comparison)),
            expected,
            "{comparison}"
        );
    }
    assert_eq!(
        findings(&schema("writer").replace(
            "g.user_id = current_setting('app.user_id', true)::uuid",
            "g.user_id IS NOT NULL"
        )),
        0
    );
    assert_eq!(
        findings(&schema("writer").replace("min_role role", "min_role TEXT")),
        0
    );
}

#[test]
fn membership_requires_a_literal_bound_from_a_scalar_helper_projection() {
    for query in [
        "SELECT docs_with('writer') UNION SELECT docs_with('writer')",
        "SELECT docs_with('writer') FROM docs",
        "SELECT docs_with('writer') WHERE true",
        "SELECT docs_with('writer') AS allowed",
        "SELECT docs_with('writer'), 1",
        "SELECT docs_with(min_role => 'writer')",
        "SELECT docs_with(SELECT 'writer')",
        "SELECT docs_with(NULL)",
        "SELECT docs_with(current_setting('app.role'))",
        "SELECT docs_with('missing')",
    ] {
        let sql = schema("writer").replace(
            "d.id IN (SELECT docs_with('writer'))",
            &format!("d.id IN ({query})"),
        );
        assert_eq!(findings(&sql), 0, "{query}");
    }
    assert_eq!(
        findings(&schema("writer").replace(
            "d.id IN (SELECT docs_with('writer'))",
            "d.id IN (SELECT docs_with(('writer')::role))"
        )),
        1
    );
}

#[test]
fn authority_arm_requires_stored_columns_and_matching_write_key() {
    for predicate in [
        "d.writers_can_share AND (d.id || '') IN (SELECT docs_with('writer'))",
        "true AND d.id IN (SELECT docs_with('writer'))",
    ] {
        assert_eq!(
            findings(&schema("writer").replace(
                "d.writers_can_share AND d.id IN (SELECT docs_with('writer'))",
                predicate
            )),
            0,
            "{predicate}"
        );
    }
    for predicate in [
        "true",
        "(id || '') IN (SELECT docs_with('writer'))",
        "other_id IN (SELECT docs_with('writer'))",
    ] {
        let sql = format!("{SCHEMA} CREATE POLICY docs_update ON docs FOR UPDATE TO authenticated USING ({predicate});").replace("id UUID PRIMARY KEY", "id UUID PRIMARY KEY, other_id UUID");
        assert_eq!(findings(&sql), 0, "{predicate}");
    }
}

#[test]
fn scalar_helper_authority_arms_are_reported() {
    let sql = schema("writer")
        .replace("RETURNS SETOF UUID LANGUAGE sql STABLE AS $$\n SELECT d.id FROM docs d WHERE d.writers_can_share AND d.id IN (SELECT docs_with('writer'))\n$$", "RETURNS BOOLEAN LANGUAGE sql RETURN EXISTS (SELECT d.id FROM docs d WHERE d.writers_can_share AND d.id IN (SELECT docs_with('writer')))")
        .replace("doc_id IN (SELECT sharable_docs())", "sharable_docs()");
    assert_eq!(findings(&sql), 1);
}

#[test]
fn boolean_parameters_do_not_hide_stored_authority_attributes() {
    let sql = schema("writer")
        .replace(
            "sharable_docs()",
            "sharable_docs(enabled BOOLEAN DEFAULT true)",
        )
        .replace(
            "SELECT sharable_docs(enabled BOOLEAN DEFAULT true)",
            "SELECT sharable_docs(true)",
        )
        .replace(
            "WHERE d.writers_can_share",
            "WHERE enabled AND d.writers_can_share",
        );
    assert_eq!(findings(&sql), 1);
}

#[test]
fn repeated_authority_arms_report_each_attribute_once() {
    let arm = "SELECT d.id FROM docs d WHERE d.writers_can_share AND d.id IN (SELECT docs_with('writer'))";
    assert_eq!(
        findings(&schema("writer").replace(arm, &format!("{arm} UNION {arm}"))),
        1
    );
}

#[test]
fn cast_and_parenthesized_threshold_parameters_are_resolved() {
    assert_eq!(
        findings(&schema("writer").replace("g.role >= min_role", "g.role >= (min_role)::role")),
        1
    );
}

#[test]
fn builtin_name_projection_does_not_supply_an_enum_threshold() {
    let sql = schema("writer")
        .replace("UUID", "TEXT")
        .replace("::uuid", "::text")
        .replace(
            "d.id IN (SELECT docs_with('writer'))",
            "d.id IN (SELECT CURRENT_USER)",
        );
    assert_eq!(findings(&sql), 0);
}

#[test]
fn nonboolean_columns_do_not_hide_authority_flags() {
    let sql = schema("writer").replace(
        "WHERE d.writers_can_share",
        "WHERE d.id <> '00000000-0000-0000-0000-000000000000' AND d.writers_can_share",
    );
    assert_eq!(findings(&sql), 1);
}

#[test]
fn nonstored_relations_do_not_hide_authority_predicates() {
    for relation in [
        "(SELECT true AS enabled) flags",
        "LATERAL (SELECT true AS enabled) flags",
        "(VALUES (true)) AS flags(enabled)",
    ] {
        for relations in [
            format!("docs d CROSS JOIN {relation}"),
            format!("{relation} CROSS JOIN docs d"),
        ] {
            let sql = schema("writer").replace(
                "FROM docs d WHERE d.writers_can_share",
                &format!("FROM {relations} WHERE flags.enabled AND d.writers_can_share"),
            );
            assert_eq!(findings(&sql), 1, "{relations}");
        }
    }
}
