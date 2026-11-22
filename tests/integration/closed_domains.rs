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
fn a_lifecycle_boolean_a_foreign_key_copies_is_judged_as_its_source() {
    let sql = "CREATE TABLE resources (
                   id INT PRIMARY KEY,
                   archived_at TIMESTAMPTZ,
                   archived BOOLEAN GENERATED ALWAYS AS (archived_at IS NOT NULL) STORED NOT NULL,
                   UNIQUE (id, archived)
               );
               CREATE TABLE flags (id INT PRIMARY KEY, archived BOOLEAN NOT NULL, UNIQUE (id, archived));
               CREATE TABLE notes (
                   id INT PRIMARY KEY,
                   resource_id INT NOT NULL,
                   archived BOOLEAN NOT NULL DEFAULT FALSE,
                   UNIQUE (id, archived),
                   FOREIGN KEY (resource_id, archived) REFERENCES resources (id, archived) ON UPDATE CASCADE
               );
               CREATE TABLE replies (
                   id INT PRIMARY KEY,
                   note_id INT NOT NULL,
                   archived BOOLEAN NOT NULL,
                   FOREIGN KEY (note_id, archived) REFERENCES notes (id, archived)
               );
               CREATE TABLE loose (
                   id INT PRIMARY KEY,
                   resource_id INT,
                   archived BOOLEAN NOT NULL,
                   FOREIGN KEY (resource_id, archived) REFERENCES resources (id, archived) ON UPDATE CASCADE
               );
               CREATE TABLE flagged (
                   id INT PRIMARY KEY,
                   flag_id INT NOT NULL,
                   archived BOOLEAN NOT NULL,
                   FOREIGN KEY (flag_id, archived) REFERENCES flags (id, archived) ON UPDATE CASCADE
               );";
    assert_eq!(
        objects(
            BooleanStateWithoutTime::default(),
            Deployment::default(),
            sql
        ),
        ["flagged.archived", "flags.archived", "loose.archived"]
    );
}

#[test]
fn a_lifecycle_boolean_copying_a_column_named_for_no_event_is_not_reported() {
    let sql = "CREATE TABLE resources (
                   id INT PRIMARY KEY,
                   hidden BOOLEAN NOT NULL,
                   UNIQUE (id, hidden)
               );
               CREATE TABLE notes (
                   id INT PRIMARY KEY,
                   resource_id INT NOT NULL,
                   archived BOOLEAN NOT NULL,
                   FOREIGN KEY (resource_id, archived) REFERENCES resources (id, hidden)
               );";
    assert_eq!(
        objects(
            BooleanStateWithoutTime::default(),
            Deployment::default(),
            sql
        ),
        Vec::<String>::new()
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
                   typed TEXT CHECK (typed IN (TEXT 'a', TEXT 'b')),
                   parenthesized TEXT CHECK ((parenthesized = 'a') OR (parenthesized = 'b')),
                   array_literal TEXT CHECK (array_literal = ANY ('{a,b}'::text[])),
                   mixed TEXT CHECK (mixed = 'a' OR id = 2),
                   CHECK (tabled IN ('x', 'y') AND tabled <> '')
               );";
    assert_eq!(
        objects(ClosedSetAsText::default(), Deployment::default(), sql),
        [
            "t.listed",
            "t.arrayed",
            "t.alternated",
            "t.tabled",
            "t.typed",
            "t.parenthesized"
        ]
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
                   CHECK (id > 0 AND version = 2)
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

#[test]
fn a_fixed_column_a_foreign_key_writes_into_is_not_reported() {
    let sql = "CREATE TABLE resources (
                   id INT PRIMARY KEY,
                   kind TEXT NOT NULL DEFAULT 'project' CHECK (kind = 'project'),
                   UNIQUE (id, kind)
               );
               CREATE TABLE cascaded (
                   resource_id INT NOT NULL,
                   kind TEXT NOT NULL DEFAULT 'project' CHECK (kind = 'project'),
                   FOREIGN KEY (resource_id, kind) REFERENCES resources (id, kind) ON UPDATE CASCADE
               );
               CREATE TABLE nulled (
                   resource_id INT,
                   kind TEXT NOT NULL DEFAULT 'project' CHECK (kind = 'project'),
                   FOREIGN KEY (resource_id, kind) REFERENCES resources (id, kind) ON UPDATE SET NULL
               );
               CREATE TABLE defaulted (
                   resource_id INT,
                   kind TEXT NOT NULL DEFAULT 'project' CHECK (kind = 'project'),
                   FOREIGN KEY (resource_id, kind) REFERENCES resources (id, kind) ON UPDATE SET DEFAULT
               );
               CREATE TABLE deleted_null (
                   resource_id INT,
                   kind TEXT NOT NULL DEFAULT 'project' CHECK (kind = 'project'),
                   FOREIGN KEY (resource_id, kind) REFERENCES resources (id, kind) ON DELETE SET NULL
               );
               CREATE TABLE deleted_default (
                   resource_id INT,
                   kind TEXT NOT NULL DEFAULT 'project' CHECK (kind = 'project'),
                   FOREIGN KEY (resource_id, kind) REFERENCES resources (id, kind) ON DELETE SET DEFAULT
               );
               CREATE TABLE deleted_cascade (
                   resource_id INT NOT NULL,
                   kind TEXT NOT NULL DEFAULT 'project' CHECK (kind = 'project'),
                   FOREIGN KEY (resource_id, kind) REFERENCES resources (id, kind) ON DELETE CASCADE ON UPDATE RESTRICT
               );
               CREATE TABLE beside (
                   resource_id INT NOT NULL REFERENCES resources (id) ON UPDATE CASCADE,
                   kind TEXT NOT NULL DEFAULT 'project' CHECK (kind = 'project')
               );";
    assert_eq!(
        objects(
            ConstantColumnNotGenerated::default(),
            Deployment::default(),
            sql
        ),
        ["beside.kind", "deleted_cascade.kind", "resources.kind"]
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

#[test]
fn relation_names_are_read_at_every_site_and_in_every_comparison() {
    let sql = format!(
        "{RELATIONS}
         CREATE MATERIALIZED VIEW snapshot AS SELECT id FROM documents;
         CREATE VIEW arrayed AS SELECT id FROM grants WHERE relation_name = ANY (ARRAY['documents', 'other']);
         CREATE VIEW branched AS SELECT CASE relation_name WHEN 'visible_documents' THEN 1 ELSE 0 END AS visible FROM grants;
         CREATE VIEW snapshots AS SELECT id FROM grants WHERE relation_name = 'snapshot';
         CREATE MATERIALIZED VIEW stored_grants AS SELECT id FROM grants WHERE relation_name <> 'documents';
         ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
         CREATE POLICY own_documents ON grants USING (relation_name = 'public.documents');
         CREATE TABLE audits (id INT PRIMARY KEY, relation_name TEXT CHECK (relation_name <> 'documents'));
         CREATE FUNCTION atomic_grants() RETURNS SETOF INT LANGUAGE sql STABLE
           BEGIN ATOMIC SELECT id FROM grants WHERE relation_name = 'documents'; END;"
    );
    let found = messages(CatalogNameAsText::default(), &sql);
    assert_eq!(found.len(), 7, "{found:?}");
    for expected in [
        "View 'arrayed' uses `relation_name = ANY(ARRAY['documents', 'other'])`, comparing text column 'grants.relation_name' with the name of table 'documents'",
        "View 'branched' uses `CASE relation_name WHEN 'visible_documents' THEN 1 ELSE 0 END`, comparing text column 'grants.relation_name' with the name of view 'visible_documents'",
        "View 'snapshots' uses `relation_name = 'snapshot'`, comparing text column 'grants.relation_name' with the name of materialized view 'snapshot'",
        "Materialized view 'stored_grants' uses `relation_name <> 'documents'`",
        "Policy 'own_documents' on 'grants' uses `relation_name = 'public.documents'`, comparing text column 'grants.relation_name' with the name of table 'documents' in its USING clause",
        "Check `relation_name <> 'documents'` on 'audits' uses `relation_name <> 'documents'`",
        "Function 'atomic_grants()' uses `relation_name = 'documents'`",
    ] {
        assert!(
            found.iter().any(|message| message.starts_with(expected)),
            "{expected}\n{found:#?}"
        );
    }
}

#[test]
fn an_ambiguous_column_is_a_lookup_failure() {
    let ambiguous = |table: &str, condition: &str| {
        format!(
            "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
             CREATE POLICY ambiguous ON {table} USING (EXISTS (SELECT 1 FROM {table} a, {table} b WHERE {condition}));"
        )
    };
    let cases: [(GenericConstrainer<ParserDB>, String); 3] = [
        (
            CatalogNameAsText::default().into(),
            format!(
                "{RELATIONS} {}",
                ambiguous("grants", "relation_name = 'documents'")
            ),
        ),
        (
            CaseSensitiveEmail::default().into(),
            format!(
                "{INVITATIONS} {}",
                ambiguous(
                    "invitations",
                    "email = current_setting('app.verified_email', true)"
                )
            ),
        ),
        (
            OrderedSetAsDisjunction::default().into(),
            format!(
                "{GRANTS} {}",
                ambiguous("grants", "level = 'read' OR level = 'write'")
            ),
        ),
    ];
    for (constrainer, sql) in cases {
        assert!(
            matches!(
                constrainer.validate_schema(&parse(&sql)),
                Err(Error::Lookup(_))
            ),
            "{sql}"
        );
    }
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

#[test]
fn email_terms_come_from_the_selected_vocabularies() {
    let sql = "CREATE TABLE inscriptions (id INT PRIMARY KEY, courriel TEXT NOT NULL);
               CREATE VIEW exacte AS SELECT id FROM inscriptions WHERE courriel = current_setting('app.courriel', true);";
    let french = Vocabulary::default().with_email_term("courriel");
    assert_eq!(
        objects(
            CaseSensitiveEmail::default(),
            Deployment::default().with_vocabulary(french),
            sql
        ),
        ["exacte"]
    );
    assert_eq!(
        objects(CaseSensitiveEmail::default(), Deployment::default(), sql),
        Vec::<String>::new()
    );
}

#[test]
fn only_an_email_column_compared_with_an_address_read_through_known_shapes_is_reported() {
    let setting = "current_setting('app.verified_email', true)";
    let sql = format!(
        "{INVITATIONS}
         CREATE TABLE contacts (id INT PRIMARY KEY, email TEXT NOT NULL, confirmed_email TEXT,
           CHECK (length(email) > 3), CHECK (confirmed_email = email));
         CREATE SCHEMA authz;
         CREATE FUNCTION authz.returned_email() RETURNS TEXT LANGUAGE sql STABLE RETURN {setting};
         CREATE FUNCTION authz.plpgsql_email() RETURNS TEXT LANGUAGE plpgsql STABLE AS $$ BEGIN RETURN {setting}; END $$;
         CREATE FUNCTION authz.second_email() RETURNS TEXT LANGUAGE sql STABLE AS $$ SELECT 1; SELECT {setting} $$;
         CREATE FUNCTION authz.valued_email() RETURNS TEXT LANGUAGE sql STABLE AS $$ VALUES ({setting}) $$;
         CREATE FUNCTION authz.stored_email() RETURNS TEXT LANGUAGE sql STABLE AS $$ SELECT {setting} FROM invitations LIMIT 1 $$;
         CREATE VIEW stored AS SELECT id FROM invitations WHERE email = authz.stored_email();
         CREATE FUNCTION authz.paired_email() RETURNS TEXT LANGUAGE sql STABLE AS $$ SELECT {setting}, 1 $$;
         CREATE FUNCTION authz.looped_email() RETURNS TEXT LANGUAGE sql STABLE AS $$ SELECT authz.looped_email() $$;
         CREATE FUNCTION lower(address TEXT, locale TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$ SELECT lower(address) $$;
         CREATE FUNCTION authz.picked(address TEXT) RETURNS TEXT LANGUAGE sql STABLE AS $$ SELECT address $$;
         CREATE FUNCTION authz.picked(address INT) RETURNS TEXT LANGUAGE sql STABLE AS $$ SELECT address::text $$;
         CREATE VIEW returned AS SELECT id FROM invitations WHERE email = authz.returned_email();
         CREATE VIEW through_plpgsql AS SELECT id FROM invitations WHERE email = authz.plpgsql_email();
         CREATE VIEW second_statement AS SELECT id FROM invitations WHERE email = authz.second_email();
         CREATE VIEW valued AS SELECT id FROM invitations WHERE email = authz.valued_email();
         CREATE VIEW paired AS SELECT id FROM invitations WHERE email = authz.paired_email();
         CREATE VIEW looped AS SELECT id FROM invitations WHERE email = authz.looped_email();
         CREATE VIEW json_path AS SELECT id FROM invitations WHERE email = {setting}::jsonb #>> '{{user,email}}';
         CREATE VIEW two_argument_fold AS SELECT id FROM invitations WHERE email = lower({setting}, 'C');
         CREATE VIEW overloaded AS SELECT id FROM invitations WHERE email = authz.picked({setting});
         CREATE VIEW parenthesized AS SELECT id FROM invitations WHERE (email) = {setting};
         CREATE VIEW trimmed AS SELECT id FROM invitations WHERE btrim(email) = {setting};
         CREATE VIEW derived AS SELECT s.id FROM (SELECT id, email FROM invitations) s WHERE s.email = {setting};
         CREATE VIEW identifier AS SELECT id FROM invitations WHERE id::text = {setting};
         CREATE VIEW constant AS SELECT id FROM invitations WHERE 'admin@example.com' = {setting};
         CREATE VIEW role_named AS SELECT id FROM invitations WHERE email = CURRENT_USER;
         CREATE FUNCTION authz.is_caller(email TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$ SELECT email = {setting} $$;
         CREATE VIEW unheld AS SELECT id FROM contacts WHERE email = lower({setting});"
    );
    assert_eq!(
        objects(CaseSensitiveEmail::default(), Deployment::default(), &sql),
        [
            "derived",
            "json_path",
            "parenthesized",
            "returned",
            "unheld"
        ]
    );
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

#[test]
fn bounds_are_read_through_signs_and_casts_at_every_site() {
    let sql = "CREATE TABLE nodes (id INT PRIMARY KEY, parent_id INT);
               CREATE SCHEMA audit;
               CREATE TABLE audit.marks (id INT PRIMARY KEY);
               CREATE MATERIALIZED VIEW depths AS WITH RECURSIVE
                 roots(id) AS (SELECT id FROM nodes WHERE parent_id IS NULL),
                 walk(id, depth) AS (SELECT id, 0 FROM roots UNION ALL
                   SELECT n.id, w.depth + 1 FROM nodes n JOIN walk w ON n.parent_id = w.id
                   WHERE w.depth < +(24)::int AND w.depth > -8 AND n.id > 2 AND w.depth < '99')
               SELECT w.id FROM audit.marks m JOIN (SELECT 1 AS one) s ON true JOIN walk w ON w.id = m.id
               UNION ALL SELECT 0;
               CREATE FUNCTION deepest() RETURNS INT LANGUAGE sql STABLE BEGIN ATOMIC
                 WITH RECURSIVE walk(id, depth) AS (SELECT id, 0 FROM nodes WHERE parent_id IS NULL UNION ALL
                   SELECT n.id, w.depth + 1 FROM nodes n JOIN walk w ON n.parent_id = w.id WHERE w.depth < 24 AND w.depth > -(8))
                 SELECT max(depth) FROM walk; END;";
    let found = messages(RepeatedRecursionBound::default(), sql);
    assert_eq!(
        found,
        [
            "Materialized view 'depths' bounds a recursive walk at -8, as function 'deepest()' also does, so the copies drift apart when one changes.",
            "Materialized view 'depths' bounds a recursive walk at 24, as function 'deepest()' also does, so the copies drift apart when one changes.",
            "Function 'deepest()' bounds a recursive walk at -8, as materialized view 'depths' also does, so the copies drift apart when one changes.",
            "Function 'deepest()' bounds a recursive walk at 24, as materialized view 'depths' also does, so the copies drift apart when one changes.",
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

#[test]
fn equalities_fitting_no_order_of_a_text_set_are_not_reported() {
    for body in [
        "(level = required AND level = 'admin') OR (level = 'write' AND required = 'read')",
        "level = required OR (level = 'read' AND required = 'write') OR (level = 'write' AND required = 'read')",
        "level = required OR (level = 'admin' AND required = 'read') OR (level = 'read' AND required = 'write') OR (level = 'write' AND required = 'admin')",
        "level = required OR level = 'superuser'",
        "level = 'admin' OR level = 'write'",
        "level = required OR level IN (required, 'admin')",
        "level = required OR 'read' IN ('read', 'write')",
    ] {
        let sql = format!(
            "{GRANTS} CREATE FUNCTION granted(required TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
               AS $$ SELECT id FROM grants WHERE {body} $$;"
        );
        assert_eq!(
            objects(
                OrderedSetAsDisjunction::default(),
                Deployment::default(),
                &sql
            ),
            Vec::<String>::new(),
            "{body}"
        );
    }
}

#[test]
fn negated_and_reversed_equalities_and_every_filter_are_read() {
    let order = "g.level = d.required_level OR (g.level = 'admin' AND d.required_level IN ('read', 'write')) OR (g.level = 'write' AND d.required_level = 'read')";
    let sql = format!(
        "{GRANTS}
         CREATE FUNCTION negated(required TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
           AS $$ SELECT id FROM grants WHERE level = required OR (NOT (level = 'read') AND required = 'read') OR ('admin' = level AND required = 'write') $$;
         CREATE FUNCTION excluded(required TEXT) RETURNS SETOF INT LANGUAGE sql STABLE
           AS $$ SELECT id FROM grants WHERE level = required OR (level NOT IN ('read') AND required = 'read') OR (level = 'admin' AND required = 'write') $$;
         CREATE FUNCTION raise(required TEXT) RETURNS VOID LANGUAGE sql
           AS $$ UPDATE grants SET level = 'admin' WHERE level = required OR (level = 'admin' AND required IN ('read', 'write')) OR (level = 'write' AND required = 'read') $$;
         CREATE VIEW nested_join AS SELECT d.id FROM (documents d JOIN grants g ON g.id = d.id) WHERE {order};
         CREATE VIEW crossed AS SELECT d.id FROM documents d CROSS JOIN grants g WHERE {order};
         CREATE VIEW derived AS SELECT s.x = 'read' OR s.x = 'write' AS listed FROM (SELECT NULL AS x) s;"
    );
    let found = explained(OrderedSetAsDisjunction::default(), &sql);
    assert_eq!(found.len(), 5, "{found:#?}");
    for (comparison, count) in [("level >= required", 3), ("g.level >= d.required_level", 2)] {
        assert_eq!(
            found
                .iter()
                .filter(|message| message.contains(&format!("which answers as `{comparison}`")))
                .count(),
            count,
            "{comparison}\n{found:#?}"
        );
    }
    assert!(
        found.iter().all(|message| !message.contains("is NULL")),
        "{found:#?}"
    );
}
