//! Closed domains, relation identity, lifecycle state and repeated constants:
//! the rules reporting text and booleans that stand in for a type, a
//! relation or a moment, and a recursion bound written at several walks.

use crate::common::parse;
use sqlippy::prelude::*;

/// The object of every finding `rule` raises on `sql`, under `deployment`.
fn objects(
    rule: impl Into<GenericConstrainer<ParserDB>>,
    deployment: Deployment,
    sql: &str,
) -> Vec<String> {
    let mut constrainer = rule.into();
    constrainer.set_deployment(deployment);
    constrainer
        .diagnostics(&parse(sql))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.object().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

/// The message of every finding `rule` raises on `sql`.
fn messages(rule: impl Into<GenericConstrainer<ParserDB>>, sql: &str) -> Vec<String> {
    rule.into()
        .diagnostics(&parse(sql))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

/// The message and resolution of every finding `rule` raises on `sql`, joined
/// by a line break.
fn explained(rule: impl Into<GenericConstrainer<ParserDB>>, sql: &str) -> Vec<String> {
    rule.into()
        .diagnostics(&parse(sql))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                format!("{}\n{}", violation.message(), violation.resolution())
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn lifecycle_booleans_are_reported_bare_or_after_a_flag_prefix() {
    let sql = "CREATE TABLE t (
                   id INT PRIMARY KEY,
                   is_deleted BOOLEAN,
                   archived BOOLEAN,
                   active BOOLEAN,
                   email_verified BOOLEAN,
                   is_soft_deleted BOOLEAN,
                   cancelled INT
               );";
    assert_eq!(
        objects(
            BooleanStateWithoutTime::default(),
            Deployment::default(),
            sql
        ),
        ["t.is_deleted", "t.archived"]
    );
}

#[test]
fn a_lifecycle_boolean_beside_its_moment_is_not_reported() {
    let sql = "CREATE TABLE t (id INT PRIMARY KEY, revoked BOOLEAN, revoked_at TIMESTAMPTZ, is_locked BOOLEAN, unlocked_at TIMESTAMPTZ);";
    assert_eq!(
        objects(
            BooleanStateWithoutTime::default(),
            Deployment::default(),
            sql
        ),
        ["t.is_locked"]
    );
}

#[test]
fn lifecycle_terms_come_from_the_selected_vocabularies() {
    let sql = "CREATE TABLE t (id INT PRIMARY KEY, revocato BOOLEAN, revoked BOOLEAN);";
    let italian = Vocabulary::default()
        .with_flag_prefix("e")
        .with_lifecycle_term("revocato");
    assert_eq!(
        objects(
            BooleanStateWithoutTime::default(),
            Deployment::default().with_vocabulary(italian),
            sql
        ),
        ["t.revocato"]
    );
}

#[test]
fn every_spelling_of_a_literal_list_closes_a_text_column() {
    let sql = "CREATE TABLE t (
                   id INT PRIMARY KEY,
                   listed TEXT CHECK (listed IN ('a', 'b')),
                   arrayed VARCHAR(8) CHECK ((arrayed)::text = ANY ((ARRAY['a'::character varying, 'b'::character varying])::text[])),
                   alternated TEXT CHECK (alternated = 'a' OR 'b' = alternated),
                   tabled TEXT,
                   single TEXT CHECK (single IN ('a', 'a')),
                   excluded TEXT CHECK (excluded NOT IN ('a', 'b')),
                   opened TEXT CHECK (opened IN ('a', 'b') OR length(opened) > 3),
                   numbered INT CHECK (numbered IN (1, 2)),
                   CHECK (tabled IN ('x', 'y') AND tabled <> '')
               );";
    assert_eq!(
        objects(ClosedSetAsText::default(), Deployment::default(), sql),
        ["t.listed", "t.arrayed", "t.alternated", "t.tabled"]
    );
}

#[test]
fn a_column_fixed_by_its_default_and_check_is_reported_only_when_not_null() {
    let sql = "CREATE TABLE t (
                   id INT PRIMARY KEY,
                   kind TEXT NOT NULL DEFAULT 'entry'::text CHECK ('entry' = kind),
                   nullable_kind TEXT DEFAULT 'entry' CHECK (nullable_kind = 'entry'),
                   other_kind TEXT NOT NULL DEFAULT 'entry' CHECK (other_kind = 'note'),
                   version INT NOT NULL DEFAULT 2,
                   CHECK (version = 2 AND id > 0)
               );";
    assert_eq!(
        objects(
            ConstantColumnNotGenerated::default(),
            Deployment::default(),
            sql
        ),
        ["t.kind", "t.version"]
    );
}

const RELATIONS: &str = "CREATE TABLE documents (id INT PRIMARY KEY);
     CREATE VIEW visible_documents AS SELECT id FROM documents;
     CREATE TABLE grants (id INT PRIMARY KEY, relation_name TEXT NOT NULL, kind TEXT NOT NULL, relation REGCLASS);";

#[test]
fn text_compared_with_a_relation_name_is_reported_at_its_site() {
    let sql = format!(
        "{RELATIONS}
         CREATE VIEW qualified AS SELECT id FROM grants WHERE relation_name = 'public.documents';
         CREATE VIEW listed AS SELECT id FROM grants WHERE relation_name IN ('visible_documents', 'other');
         CREATE VIEW categories AS SELECT id FROM grants WHERE kind = 'entry';
         CREATE VIEW identities AS SELECT id FROM grants WHERE relation = 'public.documents'::regclass;
         CREATE VIEW cast_names AS SELECT id FROM grants WHERE relation_name::regclass = 'documents'::regclass;
         CREATE VIEW other_schema AS SELECT id FROM grants WHERE relation_name = 'audit.documents';"
    );
    assert_eq!(
        objects(CatalogNameAsText::default(), Deployment::default(), &sql),
        ["listed", "qualified"]
    );
}

#[test]
fn branching_on_the_trigger_table_is_reported_and_storing_it_is_not() {
    let sql = format!(
        "{RELATIONS}
         CREATE FUNCTION matching() RETURNS TRIGGER LANGUAGE plpgsql AS $$
         BEGIN
           PERFORM 1 FROM grants WHERE relation_name = TG_TABLE_NAME;
           RETURN NEW;
         END $$;
         CREATE FUNCTION recording() RETURNS TRIGGER LANGUAGE plpgsql AS $$
         BEGIN
           INSERT INTO grants (id, relation_name, kind) VALUES (1, TG_TABLE_NAME, 'audit');
           RETURN NEW;
         END $$;"
    );
    assert_eq!(
        objects(CatalogNameAsText::default(), Deployment::default(), &sql),
        ["matching()"]
    );
}

const INVITATIONS: &str = "CREATE TABLE invitations (id INT PRIMARY KEY, email TEXT NOT NULL);
     CREATE TABLE lowered (id INT PRIMARY KEY, owner_email TEXT NOT NULL CHECK (owner_email = lower(owner_email)));
     CREATE TABLE folded (id INT PRIMARY KEY, email CITEXT NOT NULL);";

#[test]
fn email_comparisons_pass_only_when_both_sides_fold_the_same_case() {
    let sql = format!(
        "{INVITATIONS}
         CREATE VIEW exact AS SELECT id FROM invitations WHERE email = current_setting('app.verified_email', true);
         CREATE VIEW one_side AS SELECT id FROM invitations WHERE email = lower(current_setting('app.verified_email', true));
         CREATE VIEW both_sides AS SELECT id FROM invitations WHERE lower(email) = lower(NULLIF(current_setting('app.verified_email', true), ''));
         CREATE VIEW mixed_cases AS SELECT id FROM invitations WHERE upper(email) = lower(current_setting('app.verified_email', true));
         CREATE VIEW held AS SELECT id FROM lowered WHERE owner_email = lower(current_setting('app.verified_email', true));
         CREATE VIEW held_unfolded AS SELECT id FROM lowered WHERE owner_email = current_setting('app.verified_email', true);
         CREATE VIEW refolded AS SELECT id FROM lowered WHERE upper(owner_email) = lower(current_setting('app.verified_email', true));
         CREATE VIEW outer_fold AS SELECT id FROM invitations WHERE lower(upper(email)) = lower(current_setting('app.verified_email', true));
         CREATE VIEW insensitive AS SELECT id FROM folded WHERE email = current_setting('app.verified_email', true);
         CREATE VIEW cast_insensitive AS SELECT id FROM invitations WHERE email::citext = current_setting('app.verified_email', true);
         CREATE VIEW json_claim AS SELECT id FROM invitations WHERE email = current_setting('request.jwt.claims', true)::jsonb ->> 'email';
         CREATE VIEW other_setting AS SELECT id FROM invitations WHERE email = current_setting('app.user_id', true);"
    );
    assert_eq!(
        objects(CaseSensitiveEmail::default(), Deployment::default(), &sql),
        [
            "exact",
            "held_unfolded",
            "json_claim",
            "mixed_cases",
            "one_side",
            "refolded"
        ]
    );
}

#[test]
fn an_accessor_function_carries_its_setting_and_its_folding() {
    let sql = format!(
        "{INVITATIONS}
         CREATE SCHEMA authz;
         CREATE FUNCTION authz.verified_email() RETURNS TEXT LANGUAGE sql STABLE
           AS $$ SELECT lower(NULLIF(current_setting('app.verified_email', true), '')) $$;
         CREATE FUNCTION authz.raw_email() RETURNS TEXT LANGUAGE sql STABLE
           AS $$ SELECT current_setting('app.verified_email', true) $$;
         CREATE VIEW through_folded AS SELECT id FROM lowered WHERE owner_email = authz.verified_email();
         CREATE VIEW through_raw AS SELECT id FROM lowered WHERE owner_email = authz.raw_email();
         CREATE VIEW unchecked AS SELECT id FROM invitations WHERE email = authz.verified_email();"
    );
    let found = messages(CaseSensitiveEmail::default(), &sql);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[0].starts_with("View 'through_raw'"), "{found:?}");
    assert!(
        found[0].contains("setting 'app.verified_email' through 'authz.raw_email()'"),
        "{found:?}"
    );
    assert!(found[1].starts_with("View 'unchecked'"), "{found:?}");
}

/// A function walking at most `bound` steps, with the bound written by
/// `condition` in its recursive term and `outer` in the query reading it.
fn walk(name: &str, condition: &str, outer: &str) -> String {
    format!(
        "CREATE FUNCTION {name}() RETURNS INT LANGUAGE sql IMMUTABLE AS $$
           WITH RECURSIVE walk(depth) AS (SELECT 0 UNION ALL SELECT w.depth + 1 FROM walk w WHERE {condition})
           SELECT max(depth) FROM walk {outer} $$;"
    )
}

#[test]
fn a_bound_repeated_across_sites_is_reported_at_each() {
    let sql = [
        walk("first", "w.depth < 32", ""),
        walk("second", "32 > depth", ""),
        walk("checked", "w.depth < 64", "WHERE depth >= 20"),
        walk("outer_only", "w.depth < 128", "WHERE walk.depth <= 20"),
        walk("alone", "w.depth < 7 AND w.depth <= 7", ""),
        walk("structural", "w.depth < 1", ""),
    ]
    .concat();
    assert_eq!(
        objects(
            RepeatedRecursionBound::default(),
            Deployment::default(),
            &sql
        ),
        ["checked()", "first()", "outer_only()", "second()"]
    );
}

#[test]
fn bounds_in_return_bodies_are_read() {
    let walk = "RETURN (WITH RECURSIVE walk(depth) AS (SELECT 0 UNION ALL SELECT depth + 1 FROM walk WHERE depth < 32) SELECT max(depth) FROM walk)";
    let sql = format!(
        "CREATE FUNCTION first() RETURNS INT LANGUAGE sql IMMUTABLE {walk};
         CREATE FUNCTION second() RETURNS INT LANGUAGE sql IMMUTABLE {walk};"
    );
    assert_eq!(
        objects(
            RepeatedRecursionBound::default(),
            Deployment::default(),
            &sql
        ),
        ["first()", "second()"]
    );
}

#[test]
fn a_bound_shared_by_a_view_and_a_policy_names_both() {
    let sql = "CREATE TABLE nodes (id INT PRIMARY KEY, parent_id INT);
               CREATE VIEW depths AS WITH RECURSIVE walk(id, depth) AS (
                 SELECT id, 0 FROM nodes UNION ALL
                 SELECT n.id, w.depth + 1 FROM nodes n JOIN walk w ON n.parent_id = w.id WHERE w.depth < 16)
               SELECT id FROM walk;
               ALTER TABLE nodes ENABLE ROW LEVEL SECURITY;
               CREATE POLICY shallow ON nodes USING (id IN (WITH RECURSIVE walk(id, depth) AS (
                 SELECT id, 0 FROM nodes UNION ALL
                 SELECT n.id, w.depth + 1 FROM nodes n JOIN walk w ON n.parent_id = w.id WHERE w.depth < 16)
               SELECT id FROM walk));";
    let found = messages(RepeatedRecursionBound::default(), sql);
    assert_eq!(
        found,
        [
            "View 'depths' bounds a recursive walk at 16, as the USING clause of policy 'shallow' on 'nodes' also does, so the copies drift apart when one changes.",
            "The USING clause of policy 'shallow' on 'nodes' bounds a recursive walk at 16, as view 'depths' also does, so the copies drift apart when one changes.",
        ]
    );
}

const ACCESS: &str = "CREATE TYPE access_level AS ENUM ('read', 'write', 'admin');";

/// The explained findings on a function comparing two `access_level`
/// parameters with `body`, declared `STRICT` when `strict` holds.
fn sufficient(body: &str, strict: bool) -> Vec<String> {
    let strictness = if strict { "STRICT" } else { "" };
    explained(
        OrderedSetAsDisjunction::default(),
        &format!(
            "{ACCESS} CREATE FUNCTION sufficient(actual access_level, required access_level)
               RETURNS boolean LANGUAGE sql IMMUTABLE {strictness} AS $$ SELECT {body} $$;"
        ),
    )
}

#[test]
fn equalities_answering_as_the_declared_order_are_reported() {
    let found = sufficient(
        "actual = required OR (actual = 'write' AND required = 'read') OR (actual = 'admin' AND required IN ('read', 'write'))",
        false,
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains(
            "which answers as `actual >= required` over the order 'read' < 'write' < 'admin'"
        ),
        "{found:?}"
    );
    let found = sufficient(
        "required = actual OR (required = 'read' AND actual <> 'read') OR (required = 'write' AND actual = 'admin')",
        false,
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("`required <= actual`"), "{found:?}");
}

#[test]
fn equalities_answering_otherwise_than_an_order_are_not_reported() {
    for body in [
        "actual >= required",
        "actual = required OR actual = required",
        "actual = required OR (actual = 'admin' AND required = 'read')",
        "actual <> required OR actual = 'admin'",
        "(actual = 'write' AND required = 'read') OR (actual = 'admin' AND required = 'write')",
    ] {
        assert_eq!(sufficient(body, false), Vec::<String>::new(), "{body}");
    }
}

#[test]
fn a_null_the_disjunction_answers_otherwise_is_named_unless_strict() {
    let body = "actual = required OR actual = 'admin' OR required = 'read'";
    let found = sufficient(body, false);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("when 'actual' or 'required' is NULL"),
        "{found:?}"
    );
    let found = sufficient(body, true);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(!found[0].contains("is NULL"), "{found:?}");
}

#[test]
fn a_filter_reads_a_null_answer_as_false() {
    let body =
        "(required = 'read' AND actual <> 'read') OR (required = 'write' AND actual = 'admin')";
    let found = sufficient(body, false);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("`required < actual`"), "{found:?}");
    assert!(
        found[0].contains("when 'required' or 'actual' is NULL"),
        "{found:?}"
    );
    let found = explained(
        OrderedSetAsDisjunction::default(),
        &format!(
            "{ACCESS} CREATE TABLE pairs (id INT PRIMARY KEY, required access_level, actual access_level);
             CREATE VIEW raised AS SELECT id FROM pairs WHERE {body};"
        ),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(!found[0].contains("is NULL"), "{found:?}");
}

#[test]
fn a_column_an_outer_join_pads_counts_as_nullable() {
    let view = |join: &str| {
        explained(
            OrderedSetAsDisjunction::default(),
            &format!(
                "{ACCESS} CREATE TABLE members (id INT PRIMARY KEY, level access_level NOT NULL);
                 CREATE TABLE documents (id INT PRIMARY KEY, required access_level NOT NULL);
                 CREATE VIEW access AS SELECT m.level = 'admin' OR m.level = d.required
                   OR (m.level = 'write' AND d.required = 'read') AS allowed
                   FROM members m {join} documents d ON d.id = m.id;"
            ),
        )
    };
    let found = view("LEFT JOIN");
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("when 'd.required' is NULL"), "{found:?}");
    let found = view("JOIN");
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(!found[0].contains("is NULL"), "{found:?}");
}

#[test]
fn an_order_inside_a_wider_disjunction_is_reported() {
    let found = explained(
        OrderedSetAsDisjunction::default(),
        &format!(
            "{ACCESS} CREATE TYPE role_kind AS ENUM ('member', 'owner');
             CREATE FUNCTION permitted(kind role_kind, actual access_level, required access_level)
               RETURNS boolean LANGUAGE sql IMMUTABLE STRICT
               AS $$ SELECT kind = 'owner' OR (actual = required OR (actual = 'write' AND required = 'read')
                     OR (actual = 'admin' AND required IN ('read', 'write'))) $$;"
        ),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("`actual >= required`"), "{found:?}");
}

const GRANTS: &str = "CREATE TABLE grants (id INT PRIMARY KEY, level TEXT NOT NULL CHECK (level IN ('admin', 'read', 'write')));
     CREATE TABLE documents (id INT PRIMARY KEY, required_level TEXT CHECK (required_level IN ('admin', 'read', 'write')));";

#[test]
fn a_checked_text_set_is_reported_with_the_order_its_cases_fit() {
    let sql = format!(
        "{GRANTS}
         CREATE FUNCTION granted(required TEXT) RETURNS SETOF INT LANGUAGE sql STABLE AS $$
           SELECT id FROM grants WHERE level = required
             OR (level = 'admin' AND required IN ('read', 'write'))
             OR (level = 'write' AND required = 'read') $$;
         CREATE VIEW readable AS SELECT d.id FROM documents d JOIN grants g
           ON g.level = d.required_level
             OR (g.level = 'admin' AND d.required_level IN ('read', 'write'))
             OR (g.level = 'write' AND d.required_level = 'read');"
    );
    let found = explained(OrderedSetAsDisjunction::default(), &sql);
    assert_eq!(found.len(), 2, "{found:?}");
    for (message, comparison) in found
        .iter()
        .zip(["g.level >= d.required_level", "level >= required"])
    {
        assert!(
            message.contains(&format!(
                "which answers as `{comparison}` over the order 'read' < 'write' < 'admin'"
            )),
            "{message}"
        );
        assert!(!message.contains("is NULL"), "{message}");
    }
}

#[test]
fn text_parameters_without_a_set_are_not_reported() {
    let sql = "CREATE FUNCTION sufficient(actual TEXT, required TEXT) RETURNS boolean LANGUAGE sql IMMUTABLE
                 AS $$ SELECT actual = required OR (actual = 'write' AND required = 'read') $$;";
    assert_eq!(
        objects(
            OrderedSetAsDisjunction::default(),
            Deployment::default(),
            sql
        ),
        Vec::<String>::new()
    );
}
