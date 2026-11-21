//! `SECURITY DEFINER` function rules observed through the public constrainer
//! API. The search path shapes were measured on PostgreSQL 17 and 18 with a
//! caller holding a temporary `docs` table over a three-row `public.docs`.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Rule, level and function of every finding, failing on any error other than
/// a rule the deployment leaves inactive.
fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    sql: &str,
) -> Vec<(String, Level, String)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let mut found: Vec<_> = constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) => Some((
                violation.rule().name.to_owned(),
                violation.level(),
                violation.object().to_owned(),
            )),
            Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    found.sort();
    found
}

/// Functions the rule reports.
fn reported(rule: impl Into<GenericConstrainer<ParserDB>>, sql: &str) -> Vec<String> {
    findings(&rule.into(), sql)
        .into_iter()
        .map(|(_, _, function)| function)
        .collect()
}

const DOCS: &str = "CREATE TABLE docs (id INT);";

#[test]
fn a_definer_body_resolved_at_call_time_without_its_own_path_is_denied() {
    assert_eq!(
        reported(
            DefinerWithoutSearchPath::default(),
            &format!(
                "{DOCS}
                 CREATE FUNCTION string_body() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION plpgsql_body() RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER
                   AS $$ BEGIN RETURN (SELECT count(*) FROM docs); END $$;
                 CREATE FUNCTION reset_later(n INT) RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = '' AS 'SELECT count(*) FROM public.docs';
                 ALTER FUNCTION reset_later(INT) RESET search_path;"
            ),
        ),
        ["plpgsql_body()", "reset_later(INT)", "string_body()"]
    );
}

#[test]
fn bound_bodies_pinned_paths_and_invoker_functions_pass() {
    assert_eq!(
        reported(
            DefinerWithoutSearchPath::default(),
            &format!(
                "{DOCS}
                 CREATE FUNCTION returned() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   RETURN (SELECT count(*) FROM docs);
                 CREATE FUNCTION atomic() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   BEGIN ATOMIC SELECT count(*) FROM docs; END;
                 CREATE FUNCTION emptied() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = '' AS 'SELECT count(*) FROM public.docs';
                 CREATE FUNCTION captured() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path FROM CURRENT AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION pinned_later() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   AS 'SELECT count(*) FROM public.docs';
                 ALTER FUNCTION pinned_later() SET search_path = '';
                 CREATE FUNCTION invoker() RETURNS BIGINT LANGUAGE sql
                   AS 'SELECT count(*) FROM docs';"
            ),
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_definer_path_leaving_the_temporary_schema_implicit_or_early_is_reported() {
    assert_eq!(
        reported(
            DefinerTemporarySchemaNotLast::default(),
            &format!(
                "{DOCS}
                 CREATE FUNCTION implicit() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = public AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION early() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = pg_temp, public AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION last() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = public, pg_temp AS 'SELECT count(*) FROM docs';
                 CREATE FUNCTION emptied() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   SET search_path = '' AS 'SELECT count(*) FROM public.docs';
                 CREATE FUNCTION unpinned() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                   AS 'SELECT count(*) FROM docs';"
            ),
        ),
        ["early()", "emptied()", "implicit()"]
    );
}

#[test]
fn an_empty_definer_path_is_fixed_by_naming_pg_temp_after_pg_catalog() {
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE FUNCTION role_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
           SET search_path = '' AS 'SELECT count(*) FROM pg_roles';",
    )
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = DefinerTemporarySchemaNotLast::default().into();
    let diagnostics = constrainer.diagnostics(&database);
    let [Error::Violation(violation)] = diagnostics.as_slice() else {
        panic!("expected one violation");
    };
    assert_eq!(
        violation.message(),
        "`SECURITY DEFINER` function 'role_count()' sets `search_path = ''` and leaves `pg_temp` out, so it is searched first."
    );
    assert_eq!(
        violation.resolution(),
        "ALTER FUNCTION role_count() SET search_path = pg_catalog, pg_temp;"
    );
}

const PROTECTED: &str = "
    CREATE ROLE anon;
    CREATE TABLE docs (id INT, owner TEXT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    CREATE TABLE open_notes (id INT);";

fn exposed(deployment: Deployment, sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> =
        ExposedDefinerOverProtectedTable::default().into();
    constrainer.set_deployment(deployment);
    findings(&constrainer, &format!("{PROTECTED}{sql}"))
        .into_iter()
        .map(|(_, _, function)| function)
        .collect()
}

#[test]
fn a_definer_over_a_protected_table_that_public_can_execute_is_reported() {
    assert_eq!(
        exposed(
            Deployment::default(),
            "CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               SET search_path = pg_catalog, pg_temp AS 'SELECT count(*) FROM public.docs';
             CREATE FUNCTION wipe_docs() RETURNS VOID LANGUAGE sql SECURITY DEFINER
               SET search_path = pg_catalog, pg_temp AS 'DELETE FROM public.docs';
             CREATE FUNCTION note_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               SET search_path = pg_catalog, pg_temp AS 'SELECT count(*) FROM public.open_notes';
             CREATE FUNCTION invoker_count() RETURNS BIGINT LANGUAGE sql
               SET search_path = pg_catalog, pg_temp AS 'SELECT count(*) FROM public.docs';",
        ),
        ["doc_count()", "wipe_docs()"]
    );
}

#[test]
fn revoking_from_public_clears_it_unless_an_anonymous_role_still_executes() {
    let revoked = "CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
                     SET search_path = pg_catalog, pg_temp AS 'SELECT count(*) FROM public.docs';
                   REVOKE EXECUTE ON FUNCTION doc_count() FROM PUBLIC;";
    assert_eq!(
        exposed(Deployment::default(), revoked),
        Vec::<String>::new()
    );
    let anon = || Deployment::default().with_anonymous_role("anon");
    assert_eq!(exposed(anon(), revoked), Vec::<String>::new());
    assert_eq!(
        exposed(
            anon(),
            &format!("{revoked} GRANT EXECUTE ON FUNCTION doc_count() TO anon;")
        ),
        ["doc_count()"]
    );
    assert_eq!(
        exposed(
            anon(),
            &format!("ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO anon; {revoked}")
        ),
        ["doc_count()"]
    );
}

#[test]
fn a_definer_over_a_protected_table_that_an_app_role_can_execute_is_reported() {
    let helpers = "
        CREATE ROLE app NOLOGIN;
        CREATE ROLE readers NOLOGIN;
        CREATE ROLE auditor NOLOGIN;
        GRANT readers TO app;
        GRANT SELECT ON docs TO app;
        CREATE FUNCTION doc_ids() RETURNS SETOF INT LANGUAGE sql SECURITY DEFINER
          SET search_path = pg_catalog, pg_temp AS 'SELECT id FROM public.docs';
        CREATE FUNCTION doc_owned(doc INT) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER
          SET search_path = pg_catalog, pg_temp
          AS 'SELECT EXISTS (SELECT FROM public.docs WHERE id = doc AND owner IS NOT NULL)';
        CREATE FUNCTION audit_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
          SET search_path = pg_catalog, pg_temp AS 'SELECT count(*) FROM public.docs';
        CREATE FUNCTION visible_doc_ids() RETURNS SETOF INT LANGUAGE sql SECURITY INVOKER
          SET search_path = pg_catalog, pg_temp AS 'SELECT id FROM public.docs';
        CREATE FUNCTION note_ids() RETURNS SETOF INT LANGUAGE sql SECURITY DEFINER
          SET search_path = pg_catalog, pg_temp AS 'SELECT id FROM public.open_notes';
        CREATE POLICY owned_docs ON docs FOR SELECT TO app USING (doc_owned(id));
        REVOKE ALL ON FUNCTION doc_ids() FROM PUBLIC;
        REVOKE ALL ON FUNCTION doc_owned(INT) FROM PUBLIC;
        REVOKE ALL ON FUNCTION audit_count() FROM PUBLIC;
        REVOKE ALL ON FUNCTION visible_doc_ids() FROM PUBLIC;
        REVOKE ALL ON FUNCTION note_ids() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION doc_ids() TO app;
        GRANT EXECUTE ON FUNCTION visible_doc_ids() TO app;
        GRANT EXECUTE ON FUNCTION note_ids() TO app;
        GRANT EXECUTE ON FUNCTION doc_owned(INT) TO readers;
        GRANT EXECUTE ON FUNCTION audit_count() TO auditor;";
    assert_eq!(
        exposed(Deployment::default(), helpers),
        Vec::<String>::new()
    );
    assert_eq!(
        exposed(Deployment::default().with_app_role("app"), helpers),
        ["doc_ids()", "doc_owned(INT)"]
    );

    let mut constrainer: GenericConstrainer<ParserDB> =
        ExposedDefinerOverProtectedTable::default().into();
    constrainer.set_deployment(Deployment::default().with_app_role("app"));
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!("{PROTECTED}{helpers}"))
        .expect("schema parses");
    let violations: Vec<(String, String)> = constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.object() == "doc_ids()" => Some((
                violation.message().to_owned(),
                violation.resolution().to_owned(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        violations,
        [(
            "`SECURITY DEFINER` function 'doc_ids()' reads or writes 'docs', which has row-level security, as its owner, and 'app' can execute it.".to_owned(),
            "REVOKE EXECUTE ON FUNCTION doc_ids() FROM app; and grant it only to the roles that need it, or have its body limit each caller to the rows that caller may see.".to_owned(),
        )]
    );
}

#[test]
fn a_plpgsql_definer_is_reported_only_when_its_body_touches_a_protected_table() {
    assert_eq!(
        exposed(
            Deployment::default(),
            "CREATE FUNCTION set_state(p_id INT) RETURNS INT LANGUAGE plpgsql SECURITY DEFINER
               SET search_path TO pg_catalog, pg_temp AS $$ BEGIN UPDATE public.docs SET owner = 'x' WHERE id = p_id; RETURN p_id; END; $$;
             CREATE FUNCTION count_notes() RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER
               SET search_path TO pg_catalog, pg_temp AS $$ BEGIN RETURN (SELECT count(*) FROM public.open_notes); END; $$;",
        ),
        ["set_state(INT)"]
    );
}

#[test]
fn a_definer_body_whose_tables_cannot_be_read_is_reported() {
    assert_eq!(
        exposed(
            Deployment::default(),
            "CREATE FUNCTION wipe(t TEXT) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
               SET search_path TO pg_catalog, pg_temp AS $$ BEGIN EXECUTE 'DELETE FROM public.' || quote_ident(t); END; $$;
             CREATE FUNCTION native() RETURNS INT LANGUAGE c SECURITY DEFINER
               AS 'library', 'symbol';",
        ),
        ["native()", "wipe(TEXT)"]
    );
}

const MEMBERSHIPS: &str = "
    CREATE ROLE app NOLOGIN;
    CREATE TABLE memberships (user_id TEXT NOT NULL, organization_id INT NOT NULL);
    CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL);
    ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
    ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
    GRANT SELECT ON memberships, resources TO app;
    ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
    ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
    CREATE FUNCTION member_organizations() RETURNS SETOF INT
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        SELECT membership.organization_id FROM public.memberships membership
        WHERE membership.user_id = current_setting('app.user_id', true) $$;
    CREATE POLICY own_memberships ON memberships FOR SELECT TO app
      USING (user_id = current_setting('app.user_id', true));
    CREATE POLICY member_resources ON resources FOR SELECT TO app
      USING (organization_id IN (SELECT public.member_organizations()));";

fn exposed_to_app(sql: &str) -> Vec<String> {
    exposed(
        Deployment::default().with_app_role("app"),
        &format!("{MEMBERSHIPS}{sql}"),
    )
}

#[test]
fn a_definer_returning_only_rows_the_callers_policies_show_is_not_reported() {
    assert_eq!(
        exposed_to_app(
            "CREATE FUNCTION member_resource_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 JOIN public.memberships membership
                   ON membership.organization_id = resource.organization_id
                   AND membership.user_id = current_setting('app.user_id', true)
                 WHERE resource.organization_id IN (SELECT public.member_organizations()) $$;
             CREATE FUNCTION resource_exists(resource_id INT) RETURNS BOOLEAN
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT EXISTS (SELECT 1 FROM public.resources resource WHERE resource.id = resource_id) $$;
             CREATE FUNCTION all_resources() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource $$;
             CREATE FUNCTION member_or_all_resources() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 WHERE resource.organization_id IN (SELECT public.member_organizations())
                 UNION
                 SELECT resource.id FROM public.resources resource WHERE resource.id > 0 $$;",
        ),
        [
            "all_resources()",
            "member_or_all_resources()",
            "resource_exists(INT)"
        ]
    );
}

#[test]
fn a_policys_scalar_subquery_reads_as_the_value_it_projects() {
    assert_eq!(
        exposed(
            Deployment::default().with_app_role("app"),
            "CREATE ROLE app NOLOGIN;
             CREATE TABLE seats (user_id TEXT NOT NULL, organization_id INT NOT NULL);
             ALTER TABLE seats ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON seats TO app;
             CREATE POLICY own_seats ON seats FOR SELECT TO app
               USING (user_id = (SELECT current_setting('app.user_id', true))
                 AND ((SELECT current_setting('app.organization_id', true)) IS NULL
                   OR organization_id = (SELECT current_setting('app.organization_id', true))::INT));
             CREATE FUNCTION seated_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT seat.organization_id FROM public.seats seat
                 WHERE seat.user_id = current_setting('app.user_id', true)
                   AND (current_setting('app.organization_id', true) IS NULL
                     OR seat.organization_id = current_setting('app.organization_id', true)::INT) $$;
             CREATE FUNCTION any_seated_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT seat.organization_id FROM public.seats seat
                 WHERE seat.user_id = current_setting('app.user_id', true) $$;
             REVOKE EXECUTE ON FUNCTION seated_organizations() FROM PUBLIC;
             REVOKE EXECUTE ON FUNCTION any_seated_organizations() FROM PUBLIC;
             GRANT EXECUTE ON FUNCTION seated_organizations() TO app;
             GRANT EXECUTE ON FUNCTION any_seated_organizations() TO app;",
        ),
        ["any_seated_organizations()"]
    );
}

#[test]
fn a_set_declared_within_the_policys_set_confines_a_read() {
    let helper = "
        CREATE FUNCTION admin_organizations() RETURNS SETOF INT
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT membership.organization_id FROM public.memberships membership
            WHERE membership.user_id = current_setting('app.user_id', true)
              AND membership.organization_id > 100 $$;
        CREATE FUNCTION administered_resource_ids() RETURNS SETOF INT
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT resource.id FROM public.resources resource
            WHERE resource.organization_id IN (SELECT public.admin_organizations()) $$;";
    let schema = format!("{PROTECTED}{MEMBERSHIPS}{helper}");
    let reported = |deployment: Deployment| -> Vec<String> {
        let mut constrainer: GenericConstrainer<ParserDB> =
            ExposedDefinerOverProtectedTable::default().into();
        constrainer.set_deployment(deployment.with_app_role("app"));
        findings(&constrainer, &schema)
            .into_iter()
            .map(|(_, _, function)| function)
            .collect()
    };
    assert_eq!(
        reported(Deployment::default()),
        ["administered_resource_ids()"]
    );
    assert_eq!(
        reported(
            Deployment::default()
                .with_set_within(
                    "public.admin_organizations()",
                    "public.member_organizations()"
                )
                .expect("both sets parse")
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_definer_returning_rows_a_restrictive_policy_hides_is_reported_until_it_repeats_it() {
    assert_eq!(
        exposed_to_app(
            "CREATE TABLE blocks (user_id TEXT NOT NULL, organization_id INT NOT NULL);
             ALTER TABLE blocks ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON blocks TO app;
             CREATE FUNCTION blocking_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT block.organization_id FROM public.blocks block
                 WHERE block.user_id = current_setting('app.user_id', true) $$;
             CREATE POLICY unblocked_memberships ON memberships AS RESTRICTIVE FOR ALL TO app
               USING (NOT (organization_id = ANY (ARRAY(SELECT public.blocking_organizations()))));
             CREATE FUNCTION unblocked_member_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT membership.organization_id FROM public.memberships membership
                 WHERE membership.user_id = current_setting('app.user_id', true)
                   AND NOT (membership.organization_id = ANY (ARRAY(SELECT public.blocking_organizations()))) $$;",
        ),
        ["blocking_organizations()", "member_organizations()"]
    );
}

#[test]
fn a_called_function_counts_unless_each_caller_may_execute_it_directly() {
    assert_eq!(
        exposed_to_app(
            "CREATE TABLE grants (user_id TEXT NOT NULL, resource_id INT NOT NULL);
             ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
             CREATE FUNCTION granted_resource_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT permission.resource_id FROM public.grants permission
                 WHERE permission.user_id = current_setting('app.user_id', true) $$;
             CREATE FUNCTION granted_resources() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 WHERE resource.id IN (SELECT public.granted_resource_ids()) $$;
             CREATE FUNCTION resource_total() RETURNS BIGINT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT count(*) FROM public.resources $$;
             REVOKE EXECUTE ON FUNCTION resource_total() FROM app;
             CREATE FUNCTION open_resource_total() RETURNS BIGINT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT count(*) FROM public.resources $$;
             CREATE FUNCTION resources_with_total() RETURNS TABLE (id INT, total BIGINT)
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id, public.resource_total() FROM public.resources resource
                 WHERE resource.organization_id IN (SELECT public.member_organizations()) $$;
             CREATE FUNCTION resources_with_open_total() RETURNS TABLE (id INT, total BIGINT)
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id, public.open_resource_total() FROM public.resources resource
                 WHERE resource.organization_id IN (SELECT public.member_organizations()) $$;",
        ),
        [
            "granted_resource_ids()",
            "granted_resources()",
            "open_resource_total()",
            "resources_with_total()"
        ]
    );
}

#[test]
fn a_filter_term_reading_otherwise_as_the_owner_confines_nothing() {
    assert_eq!(
        exposed_to_app(
            "CREATE TABLE organization_roles (role_name TEXT, organization_id INT);
             CREATE FUNCTION role_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
                 SELECT granted.organization_id FROM public.organization_roles granted
                 WHERE granted.role_name = current_user $$;
             CREATE TABLE notes (id INT, author TEXT, organization_id INT);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON notes TO app;
             CREATE POLICY own_notes ON notes FOR SELECT TO app USING (author = current_user);
             CREATE POLICY organization_notes ON notes FOR SELECT TO app
               USING (organization_id IN (SELECT public.role_organizations()));
             CREATE FUNCTION own_note_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note WHERE note.author = current_user $$;
             CREATE FUNCTION organization_note_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note
                 WHERE note.organization_id IN (SELECT public.role_organizations()) $$;",
        ),
        ["organization_note_ids()", "own_note_ids()"]
    );
}

#[test]
fn a_filter_term_reading_the_role_or_path_as_the_owner_confines_nothing() {
    assert_eq!(
        exposed_to_app(
            "CREATE TABLE notes (id INT, author TEXT, schema_name TEXT);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON notes TO app;
             CREATE POLICY own_notes ON notes FOR SELECT TO app USING (author = user);
             CREATE POLICY schema_notes ON notes FOR SELECT TO app
               USING (schema_name = current_schema());
             CREATE FUNCTION own_note_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note WHERE note.author = user $$;
             CREATE FUNCTION schema_note_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note WHERE note.schema_name = current_schema() $$;",
        ),
        ["own_note_ids()", "schema_note_ids()"]
    );
}

#[test]
fn a_table_alias_renaming_its_columns_confines_nothing() {
    assert_eq!(
        exposed_to_app(
            "CREATE TABLE notes (author TEXT, reviewer TEXT, id INT);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON notes TO app;
             CREATE POLICY own_notes ON notes FOR SELECT TO app
               USING (author = current_setting('app.user_id', true));
             CREATE FUNCTION reviewed_note_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes AS note(reviewer, author)
                 WHERE note.author = current_setting('app.user_id', true) $$;",
        ),
        ["reviewed_note_ids()"]
    );
}

#[test]
fn a_quoted_column_confines_by_its_exact_name() {
    assert_eq!(
        exposed_to_app(
            r#"CREATE TABLE posts (id INT, "userId" TEXT);
               CREATE TABLE entries (id INT, owner TEXT, "Owner" TEXT);
               ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
               ALTER TABLE entries ENABLE ROW LEVEL SECURITY;
               GRANT SELECT ON posts, entries TO app;
               CREATE POLICY own_posts ON posts FOR SELECT TO app
                 USING ("userId" = current_setting('app.user_id', true));
               CREATE POLICY own_entries ON entries FOR SELECT TO app
                 USING (owner = current_setting('app.user_id', true));
               CREATE FUNCTION own_post_ids() RETURNS SETOF INT
                 LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                   SELECT post.id FROM public.posts post
                   WHERE post."userId" = current_setting('app.user_id', true) $$;
               CREATE FUNCTION capitalized_owner_entry_ids() RETURNS SETOF INT
                 LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                   SELECT entry.id FROM public.entries entry
                   WHERE entry."Owner" = current_setting('app.user_id', true) $$;"#,
        ),
        ["capitalized_owner_entry_ids()"]
    );
}

#[test]
fn a_definer_setting_a_parameter_besides_its_path_is_reported() {
    assert_eq!(
        exposed_to_app(
            "CREATE FUNCTION administrator_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER
               SET search_path = pg_catalog, pg_temp SET app.user_id = 'administrator' AS $$
                 SELECT membership.organization_id FROM public.memberships membership
                 WHERE membership.user_id = current_setting('app.user_id', true) $$;",
        ),
        ["administrator_organizations()"]
    );
}

#[test]
fn an_outer_join_condition_confines_only_the_side_it_extends_with_nulls() {
    assert_eq!(
        exposed_to_app(
            "CREATE FUNCTION left_extended() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.memberships membership
                 LEFT JOIN public.resources resource
                   ON resource.organization_id IN (SELECT public.member_organizations())
                 WHERE membership.user_id = current_setting('app.user_id', true) $$;
             CREATE FUNCTION left_preserved() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 LEFT JOIN public.memberships membership
                   ON resource.organization_id IN (SELECT public.member_organizations())
                   AND membership.user_id = current_setting('app.user_id', true) $$;
             CREATE FUNCTION right_extended() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 RIGHT JOIN public.memberships membership
                   ON resource.organization_id IN (SELECT public.member_organizations())
                 WHERE membership.user_id = current_setting('app.user_id', true) $$;
             CREATE FUNCTION right_preserved() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.memberships membership
                 RIGHT JOIN public.resources resource
                   ON resource.organization_id IN (SELECT public.member_organizations())
                   AND membership.user_id = current_setting('app.user_id', true) $$;",
        ),
        ["left_preserved()", "right_preserved()"]
    );
}

#[test]
fn a_definer_projecting_a_column_its_callers_cannot_select_is_reported() {
    assert_eq!(
        exposed_to_app(
            "REVOKE SELECT ON resources FROM app;
             GRANT SELECT (id) ON resources TO app;
             CREATE FUNCTION member_resource_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.organization_id FROM public.resources resource
                 WHERE resource.organization_id IN (SELECT public.member_organizations()) $$;",
        ),
        ["member_resource_organizations()"]
    );
}

#[test]
fn the_default_constrainer_runs_the_function_rules_at_their_group_levels() {
    let found = findings(
        &DefaultConstrainer::<ParserDB>::default(),
        &format!(
            "{PROTECTED}
             CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               SET search_path = public AS 'SELECT count(*) FROM docs';
             CREATE FUNCTION unpinned() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
               AS 'SELECT 1';"
        ),
    );
    let function_rules: Vec<_> = found
        .into_iter()
        .filter(|(rule, _, _)| {
            rule.starts_with("definer_") || rule == "exposed_definer_over_protected_table"
        })
        .collect();
    assert_eq!(
        function_rules,
        [
            (
                "definer_schema_without_default_revoke".to_owned(),
                Level::Warn,
                "doc_count()".to_owned()
            ),
            (
                "definer_temporary_schema_not_last".to_owned(),
                Level::Deny,
                "doc_count()".to_owned()
            ),
            (
                "definer_without_search_path".to_owned(),
                Level::Deny,
                "unpinned()".to_owned()
            ),
            (
                "exposed_definer_over_protected_table".to_owned(),
                Level::Warn,
                "doc_count()".to_owned()
            ),
        ]
    );
}
