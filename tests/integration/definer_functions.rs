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
fn a_definer_is_named_by_the_arguments_a_revoke_takes() {
    let owner = "CREATE FUNCTION doc_owner(doc INT, OUT owner TEXT) RETURNS TEXT LANGUAGE sql
                   SECURITY DEFINER SET search_path = pg_catalog, pg_temp
                   AS 'SELECT owner FROM public.docs WHERE id = doc';";
    assert_eq!(exposed(Deployment::default(), owner), ["doc_owner(INT)"]);
    assert_eq!(
        exposed(
            Deployment::default(),
            &format!("{owner} REVOKE EXECUTE ON FUNCTION doc_owner(INT) FROM PUBLIC;")
        ),
        Vec::<String>::new()
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
fn a_value_list_confines_when_each_value_meets_a_policy_arm() {
    assert_eq!(
        exposed(
            Deployment::default().with_app_role("app"),
            "CREATE ROLE app NOLOGIN;
             CREATE TABLE seats (user_id TEXT NOT NULL, organization_id INT NOT NULL);
             ALTER TABLE seats ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON seats TO app;
             ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
             ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
             CREATE POLICY own_seats ON seats FOR SELECT TO app
               USING (user_id = (SELECT current_setting('app.user_id', true))
                 OR user_id = (SELECT current_setting('app.acting_id', true)));
             CREATE FUNCTION held_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT seat.organization_id FROM public.seats seat
                 WHERE seat.user_id IN (current_setting('app.acting_id', true),
                   current_setting('app.user_id', true)) $$;
             CREATE FUNCTION named_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT seat.organization_id FROM public.seats seat
                 WHERE seat.user_id IN (current_setting('app.user_id', true), 'root') $$;
             CREATE FUNCTION other_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT seat.organization_id FROM public.seats seat
                 WHERE seat.user_id NOT IN (current_setting('app.acting_id', true),
                   current_setting('app.user_id', true)) $$;",
        ),
        ["named_organizations()", "other_organizations()"]
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
fn a_condition_comparing_two_columns_confines_as_written() {
    assert_eq!(
        exposed_to_app(
            "CREATE TABLE notes (author TEXT, reviewer TEXT, id INT);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON notes TO app;
             CREATE POLICY self_reviewed ON notes FOR SELECT TO app USING (reviewer = author);
             CREATE FUNCTION self_reviewed_note_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note WHERE note.reviewer = note.author $$;
             CREATE FUNCTION reviewed_note_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note WHERE note.reviewer IS NOT NULL $$;",
        ),
        ["reviewed_note_ids()"]
    );
}

#[test]
fn a_read_through_a_view_a_lock_a_parenthesized_join_a_write_or_table_is_reported() {
    let confined = "resource.organization_id IN (SELECT public.member_organizations())";
    assert_eq!(
        exposed_to_app(&format!(
            "CREATE VIEW resource_view AS SELECT * FROM resources;
             CREATE FUNCTION through_view() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource WHERE {confined}
                 UNION SELECT seen.id FROM public.resource_view seen $$;
             CREATE FUNCTION locked() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource WHERE {confined} FOR SHARE $$;
             CREATE FUNCTION parenthesized() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id
                 FROM (public.resources resource JOIN public.memberships membership
                   ON membership.organization_id = resource.organization_id)
                 WHERE {confined} AND membership.user_id = current_setting('app.user_id', true) $$;
             CREATE FUNCTION whole_table() RETURNS SETOF resources
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 TABLE public.resources $$;
             CREATE FUNCTION leaving() RETURNS SETOF INT
               LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH gone AS (DELETE FROM public.memberships membership
                   WHERE membership.user_id = current_setting('app.user_id', true)
                   RETURNING membership.organization_id)
                 SELECT gone.organization_id FROM gone $$;"
        )),
        [
            "leaving()",
            "locked()",
            "parenthesized()",
            "through_view()",
            "whole_table()"
        ]
    );
}

#[test]
fn rows_from_values_a_with_item_or_an_open_parenthesized_join_confine_nothing_away() {
    let confined = "resource.organization_id IN (SELECT public.member_organizations())";
    assert_eq!(
        exposed_to_app(&format!(
            "CREATE TABLE tags (id INT);
             CREATE FUNCTION with_values() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource WHERE {confined}
                 UNION VALUES (0) $$;
             CREATE FUNCTION through_with_item() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH mine AS (SELECT resource.id FROM public.resources resource WHERE {confined})
                 SELECT mine.id FROM mine $$;
             CREATE FUNCTION beside_open_join() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource,
                   (public.tags tag JOIN public.tags other ON other.id = tag.id)
                 WHERE {confined} AND tag.id = resource.id $$;"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn a_called_invoker_is_proved_once_and_a_cycle_or_opaque_body_proves_nothing() {
    assert_eq!(
        exposed_to_app(
            "CREATE FUNCTION own_organizations() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT membership.organization_id FROM public.memberships membership
                 WHERE membership.user_id = current_setting('app.user_id', true) $$;
             CREATE FUNCTION own_first() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT public.own_organizations() $$;
             CREATE FUNCTION own_second() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT public.own_organizations() $$;
             CREATE FUNCTION both_owned() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT public.own_first() UNION SELECT public.own_second()
                 UNION SELECT membership.organization_id FROM public.memberships membership
                 WHERE membership.user_id = current_setting('app.user_id', true) $$;
             CREATE FUNCTION ping() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT public.pong() $$;
             CREATE FUNCTION pong() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT public.ping() UNION SELECT resource.id FROM public.resources resource $$;
             CREATE FUNCTION cyclic() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT public.ping() UNION SELECT membership.organization_id
                 FROM public.memberships membership
                 WHERE membership.user_id = current_setting('app.user_id', true) $$;
             CREATE FUNCTION native_ids() RETURNS SETOF INT
               LANGUAGE c STABLE AS 'native', 'native_ids';
             CREATE FUNCTION beside_native() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT public.native_ids() UNION SELECT membership.organization_id
                 FROM public.memberships membership
                 WHERE membership.user_id = current_setting('app.user_id', true) $$;",
        ),
        ["beside_native()", "cyclic()"]
    );
}

#[test]
fn an_exempt_caller_needs_no_filter_and_an_unsettled_policy_role_proves_nothing() {
    assert_eq!(
        exposed_to_app(
            "CREATE TABLE drafts (id INT);
             ALTER TABLE drafts ENABLE ROW LEVEL SECURITY;
             ALTER TABLE drafts OWNER TO app;
             CREATE FUNCTION draft_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT draft.id FROM public.drafts draft $$;
             CREATE TABLE notes (id INT, author TEXT);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON notes TO app;
             CREATE POLICY own_notes ON notes FOR SELECT TO CURRENT_USER
               USING (author = current_setting('app.user_id', true));
             CREATE FUNCTION own_note_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note
                 WHERE note.author = current_setting('app.user_id', true) $$;",
        ),
        ["own_note_ids()"]
    );
}

#[test]
fn a_filter_term_reading_a_relation_counts_only_through_a_definer_call() {
    assert_eq!(
        exposed_to_app(
            "CREATE TABLE flags (id INT);
             CREATE FUNCTION open_flags() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT 1 $$;
             CREATE FUNCTION caller_flags() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT 1 $$;
             CREATE TABLE notes (id INT, kind TEXT);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON notes TO app;
             CREATE POLICY flagged ON notes FOR SELECT TO app
               USING (kind = 'flag' AND EXISTS (SELECT 1 FROM public.open_flags()));
             CREATE POLICY caller_flagged ON notes FOR SELECT TO app
               USING (kind = 'caller' AND EXISTS (SELECT 1 FROM public.caller_flags()));
             CREATE POLICY table_flagged ON notes FOR SELECT TO app
               USING (kind = 'table' AND EXISTS (SELECT 1 FROM public.flags));
             CREATE FUNCTION flagged_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note
                 WHERE note.kind = 'flag' AND EXISTS (SELECT 1 FROM public.open_flags()) $$;
             CREATE FUNCTION caller_flagged_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note
                 WHERE note.kind = 'caller' AND EXISTS (SELECT 1 FROM public.caller_flags()) $$;
             CREATE FUNCTION table_flagged_ids() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT note.id FROM public.notes note
                 WHERE note.kind = 'table' AND EXISTS (SELECT 1 FROM public.flags) $$;",
        ),
        ["caller_flagged_ids()", "table_flagged_ids()"]
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

const PROJECTS: &str = "
    CREATE TABLE projects (id INT, organization_id INT);
    CREATE TABLE ledgers (id INT, organization_id NUMERIC);
    ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
    ALTER TABLE ledgers ENABLE ROW LEVEL SECURITY;
    GRANT SELECT ON projects, ledgers TO app;
    CREATE POLICY member_projects ON projects FOR SELECT TO app
      USING (organization_id IN (SELECT public.member_organizations()));
    CREATE POLICY member_ledgers ON ledgers FOR SELECT TO app
      USING (organization_id IN (SELECT public.member_organizations()));";

#[test]
fn a_join_equality_carries_a_condition_to_the_rows_it_joins() {
    let confined = "resource.organization_id IN (SELECT public.member_organizations())";
    assert_eq!(
        exposed_to_app(&format!(
            "{PROJECTS}
             CREATE FUNCTION joined() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project ON project.organization_id = resource.organization_id
                 WHERE {confined} $$;
             CREATE FUNCTION left_joined() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 LEFT JOIN public.projects project ON project.organization_id = resource.organization_id
                 WHERE {confined} $$;
             CREATE FUNCTION numeric_joined() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT ledger.id FROM public.resources resource
                 JOIN public.ledgers ledger ON ledger.organization_id = resource.organization_id
                 WHERE {confined} $$;
             CREATE FUNCTION equated_under_or() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project
                   ON project.organization_id = resource.organization_id OR project.id = resource.id
                 WHERE {confined} $$;"
        )),
        ["equated_under_or()", "numeric_joined()"]
    );
}

#[test]
fn a_where_dropping_null_extended_rows_confines_the_preserved_side_of_an_outer_join() {
    let equated = "project.organization_id = resource.organization_id";
    let confined = "resource.organization_id IN (SELECT public.member_organizations())";
    assert_eq!(
        exposed_to_app(&format!(
            "{PROJECTS}
             CREATE FUNCTION left_rejected() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project
                 LEFT JOIN public.resources resource ON {equated}
                 WHERE {confined} $$;
             CREATE FUNCTION right_rejected() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 RIGHT JOIN public.projects project ON {equated}
                 WHERE {confined} $$;
             CREATE FUNCTION using_rejected() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project
                 LEFT JOIN public.resources resource USING (organization_id)
                 WHERE {confined} $$;
             CREATE FUNCTION rejected_by_comparison() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project
                 LEFT JOIN public.resources resource ON {equated} AND {confined}
                 WHERE resource.id > 0 $$;
             CREATE FUNCTION anti_joined() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project
                 LEFT JOIN public.resources resource ON {equated} AND {confined}
                 WHERE resource.id IS NULL $$;
             CREATE FUNCTION left_preserved_tested() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project
                 LEFT JOIN public.resources resource ON {equated} AND {confined}
                 WHERE project.id > 0 $$;
             CREATE FUNCTION right_preserved_tested() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 RIGHT JOIN public.projects project ON {equated} AND {confined}
                 WHERE project.id > 0 $$;
             CREATE FUNCTION not_in_kept() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project
                 LEFT JOIN public.resources resource ON {equated} AND {confined}
                 WHERE resource.organization_id NOT IN (SELECT public.member_organizations()) $$;"
        )),
        [
            "anti_joined()",
            "left_preserved_tested()",
            "not_in_kept()",
            "right_preserved_tested()"
        ]
    );
}

#[test]
fn a_with_item_or_subquery_carries_its_filter_to_the_rows_equated_to_its_columns() {
    let chosen = "SELECT resource.organization_id FROM public.resources resource
                  WHERE resource.organization_id IN (SELECT public.member_organizations())";
    let equated = "project.organization_id = chosen.organization_id";
    assert_eq!(
        exposed_to_app(&format!(
            "{PROJECTS}
             CREATE TABLE sites (id INT, organization_id INT);
             CREATE FUNCTION item_equality() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS ({chosen})
                 SELECT project.id FROM chosen JOIN public.projects project ON {equated} $$;
             CREATE FUNCTION derived_equality() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM ({chosen}) chosen
                 JOIN public.projects project ON {equated} $$;
             CREATE FUNCTION renamed_in_where() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM ({chosen}) chosen (organization), public.projects project
                 WHERE project.organization_id = chosen.organization $$;
             CREATE FUNCTION unfiltered_item() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS (SELECT site.organization_id FROM public.sites site)
                 SELECT project.id FROM chosen JOIN public.projects project ON {equated} $$;
             CREATE FUNCTION item_read_twice() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS (SELECT site.organization_id FROM public.sites site)
                 SELECT project.id FROM chosen picked JOIN chosen other ON true
                 JOIN public.projects project ON project.organization_id = picked.organization_id
                 WHERE other.organization_id IN (SELECT public.member_organizations()) $$;
             CREATE FUNCTION united_item() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS ({chosen} UNION SELECT site.organization_id FROM public.sites site)
                 SELECT project.id FROM chosen JOIN public.projects project ON {equated} $$;
             CREATE FUNCTION expanded_before() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM (
                   SELECT site.*, resource.organization_id AS member_organization
                   FROM public.sites site, public.resources resource
                   WHERE resource.organization_id IN (SELECT public.member_organizations())) chosen
                 JOIN public.projects project ON {equated} $$;"
        )),
        [
            "expanded_before()",
            "item_read_twice()",
            "unfiltered_item()",
            "united_item()"
        ]
    );
}

#[test]
fn a_using_join_holds_its_merged_column_equal_to_each_side() {
    let confined = "resource.organization_id IN (SELECT public.member_organizations())";
    let merged = "organization_id IN (SELECT public.member_organizations())";
    assert_eq!(
        exposed_to_app(&format!(
            "{PROJECTS}
             CREATE TABLE teams (id INT, owner_organization INT);
             CREATE TABLE crews (id INT, organization_ids INT[]);
             CREATE TABLE rosters (id INT, organization_ids INT[]);
             ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
             ALTER TABLE rosters ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON teams, rosters TO app;
             CREATE POLICY member_teams ON teams FOR SELECT TO app
               USING (owner_organization IN (SELECT public.member_organizations()));
             CREATE POLICY staffed_rosters ON rosters FOR SELECT TO app
               USING (cardinality(organization_ids) > 0);
             CREATE FUNCTION side_condition() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.crews crew
                 JOIN public.resources resource ON resource.id = crew.id
                 JOIN public.projects project USING (organization_id) WHERE {confined} $$;
             CREATE FUNCTION merged_condition() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.crews crew ON crew.id = resource.id
                 FULL JOIN public.projects project USING (organization_id) WHERE {merged} $$;
             CREATE FUNCTION merged_and_equated() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT team.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id)
                 JOIN public.teams team ON team.owner_organization = organization_id
                 WHERE {merged} $$;
             CREATE FUNCTION chained() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT other.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id)
                 JOIN public.projects other USING (organization_id) WHERE {merged} $$;
             CREATE FUNCTION numeric_chain() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id)
                 JOIN public.ledgers ledger USING (organization_id) WHERE {merged} $$;
             CREATE FUNCTION item_side() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS (SELECT 1 AS organization_id)
                 SELECT project.id FROM chosen
                 JOIN public.projects project USING (organization_id) WHERE {merged} $$;
             CREATE FUNCTION derived_side() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project
                 JOIN (SELECT 1 AS organization_id) chosen USING (organization_id) WHERE {merged} $$;
             CREATE FUNCTION outer_merge_held() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id)
                 WHERE {merged} AND EXISTS (
                   SELECT 1 FROM public.projects other
                   JOIN public.resources nearby USING (organization_id)) $$;
             CREATE FUNCTION numeric_side() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT ledger.id FROM public.resources resource
                 JOIN public.ledgers ledger USING (organization_id) WHERE {merged} $$;
             CREATE FUNCTION array_side() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT roster.id FROM public.crews crew
                 JOIN public.rosters roster ON roster.organization_ids = crew.organization_ids
                 WHERE cardinality(crew.organization_ids) > 0 $$;"
        )),
        [
            "array_side()",
            "derived_side()",
            "item_side()",
            "numeric_chain()",
            "numeric_side()",
            "outer_merge_held()"
        ]
    );
}

#[test]
fn a_using_join_carries_its_sides_through_chains_aliases_and_items() {
    let confined = "resource.organization_id IN (SELECT public.member_organizations())";
    let chosen =
        format!("SELECT resource.organization_id FROM public.resources resource WHERE {confined}");
    assert_eq!(
        exposed_to_app(&format!(
            "{PROJECTS}
             CREATE TABLE sites (id INT, organization_id INT);
             CREATE FUNCTION chain_side() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT other.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id)
                 JOIN public.projects other USING (organization_id) WHERE {confined} $$;
             CREATE FUNCTION chain_after_left() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT other.id FROM public.resources resource
                 LEFT JOIN public.projects project USING (organization_id)
                 JOIN public.projects other USING (organization_id) WHERE {confined} $$;
             CREATE FUNCTION aliased_side() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id) AS joined WHERE {confined} $$;
             CREATE FUNCTION aliased_merge() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id) AS joined
                 WHERE joined.organization_id IN (SELECT public.member_organizations()) $$;
             CREATE FUNCTION item_using() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS ({chosen})
                 SELECT project.id FROM chosen JOIN public.projects project USING (organization_id) $$;
             CREATE FUNCTION derived_using() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project
                 JOIN ({chosen}) chosen USING (organization_id) $$;
             CREATE FUNCTION unfiltered_item_using() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS (SELECT site.organization_id FROM public.sites site)
                 SELECT project.id FROM chosen JOIN public.projects project USING (organization_id) $$;
             CREATE FUNCTION chain_left_joined() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT other.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id)
                 LEFT JOIN public.projects other USING (organization_id) WHERE {confined} $$;
             CREATE FUNCTION aliased_other_name() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project USING (id) AS joined WHERE {confined} $$;
             CREATE FUNCTION chain_after_right() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT other.id FROM public.resources resource
                 RIGHT JOIN public.projects project USING (organization_id)
                 JOIN public.projects other USING (organization_id) WHERE {confined} $$;
             CREATE FUNCTION chain_after_full() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT other.id FROM public.resources resource
                 FULL JOIN public.projects project USING (organization_id)
                 JOIN public.projects other USING (organization_id) WHERE {confined} $$;
             CREATE FUNCTION item_bare_name() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS (SELECT organization_id FROM public.resources
                   WHERE organization_id IN (SELECT public.member_organizations()))
                 SELECT project.id FROM chosen JOIN public.projects project USING (organization_id) $$;
             CREATE FUNCTION item_after_constant() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS (SELECT 0, resource.organization_id
                   FROM public.resources resource WHERE {confined})
                 SELECT project.id FROM chosen JOIN public.projects project USING (organization_id) $$;
             CREATE FUNCTION item_renamed() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen (organization_id) AS (SELECT resource.organization_id AS chosen_id
                   FROM public.resources resource WHERE {confined})
                 SELECT project.id FROM chosen JOIN public.projects project USING (organization_id) $$;
             CREATE FUNCTION derived_renamed() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project
                 JOIN (SELECT resource.organization_id AS chosen_id FROM public.resources resource
                   WHERE {confined}) chosen (organization_id) USING (organization_id) $$;
             CREATE FUNCTION item_renamed_away() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen (organization_id, chosen_id) AS (
                   SELECT resource.id, resource.organization_id
                   FROM public.resources resource WHERE {confined})
                 SELECT project.id FROM chosen JOIN public.projects project USING (organization_id) $$;
             CREATE FUNCTION item_star() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH chosen AS (SELECT * FROM public.resources resource WHERE {confined})
                 SELECT project.id FROM chosen JOIN public.projects project USING (organization_id) $$;"
        )),
        [
            "aliased_other_name()",
            "chain_after_full()",
            "item_renamed_away()",
            "item_star()",
            "unfiltered_item_using()"
        ]
    );
}

#[test]
fn a_subquery_filters_the_merged_column_of_the_join_it_reaches() {
    let member = "IN (SELECT public.member_organizations())";
    assert_eq!(
        exposed_to_app(&format!(
            "{PROJECTS}
             CREATE TABLE sites (id INT, organization_id INT);
             CREATE FUNCTION outer_merge() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id)
                 WHERE EXISTS (SELECT 1 WHERE organization_id {member}) $$;
             CREATE FUNCTION aliased_outer_merge() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id) AS joined
                 WHERE EXISTS (SELECT 1 WHERE joined.organization_id {member}) $$;
             CREATE FUNCTION inner_merge() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.resources resource
                 JOIN public.projects project USING (organization_id)
                 WHERE EXISTS (SELECT 1 FROM public.sites site
                   JOIN public.sites other USING (organization_id) WHERE organization_id {member}) $$;"
        )),
        ["inner_merge()"]
    );
}

#[test]
fn a_correlated_subquery_holds_the_other_conditions_of_its_where() {
    let confined = "resource.organization_id IN (SELECT public.member_organizations())";
    assert_eq!(
        exposed_to_app(&format!(
            "{PROJECTS}
             CREATE FUNCTION without_projects() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 WHERE {confined} AND NOT EXISTS (
                   SELECT 1 FROM public.projects project
                   WHERE project.organization_id = resource.organization_id AND project.id = resource.id) $$;
             CREATE FUNCTION through_nested_subqueries() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 WHERE {confined} AND resource.id IN (
                   SELECT project.id FROM public.projects project
                   WHERE project.organization_id = resource.organization_id
                     AND EXISTS (SELECT 1 FROM public.projects other
                       WHERE other.organization_id = project.organization_id)) $$;
             CREATE FUNCTION same_name_inside() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT item.id FROM public.resources item
                 WHERE item.organization_id IN (SELECT public.member_organizations())
                   AND EXISTS (SELECT 1 FROM public.projects item WHERE item.id > 0) $$;
             CREATE FUNCTION in_the_same_condition() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 WHERE {confined} AND resource.id IN (SELECT project.id FROM public.projects project
                   WHERE project.organization_id = resource.organization_id OR project.id > 0) $$;"
        )),
        ["in_the_same_condition()", "same_name_inside()"]
    );
}

#[test]
fn a_semi_join_carries_its_filter_to_the_outer_column_it_equates() {
    let equated = "resource.organization_id = project.organization_id";
    let confined = "resource.organization_id IN (SELECT public.member_organizations())";
    assert_eq!(
        exposed_to_app(&format!(
            "{PROJECTS}
             CREATE FUNCTION exists_correlated() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project WHERE EXISTS (
                   SELECT * FROM public.resources resource WHERE {equated} AND {confined}) $$;
             CREATE FUNCTION in_subquery() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project WHERE project.organization_id IN (
                   SELECT resource.organization_id FROM public.resources resource
                   WHERE {confined}) $$;
             CREATE FUNCTION not_exists() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project WHERE NOT EXISTS (
                   SELECT 1 FROM public.resources resource WHERE {equated} AND {confined}) $$;
             CREATE FUNCTION not_in() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project WHERE project.organization_id NOT IN (
                   SELECT resource.organization_id FROM public.resources resource
                   WHERE {confined}) $$;
             CREATE FUNCTION counted() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project WHERE EXISTS (
                   SELECT count(*) FROM public.resources resource WHERE {equated} AND {confined}) $$;
             CREATE FUNCTION having_none() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project WHERE EXISTS (
                   SELECT 1 FROM public.resources resource WHERE {equated} AND {confined}
                   HAVING count(*) = 0) $$;
             CREATE FUNCTION united() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project WHERE EXISTS (
                   SELECT 1 FROM public.resources resource WHERE {equated} AND {confined}
                   UNION ALL SELECT 1) $$;
             CREATE FUNCTION in_other_column() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT project.id FROM public.projects project WHERE project.id IN (
                   SELECT resource.organization_id FROM public.resources resource
                   WHERE {confined}) $$;"
        )),
        [
            "counted()",
            "having_none()",
            "in_other_column()",
            "not_exists()",
            "not_in()",
            "united()"
        ]
    );
}

/// Teams of organizations whose members hold memberships, `keys` declaring
/// the keys of `teams` and `deferral` closing the key of `team_members` onto
/// it, with a team administrator helper that excludes blocked organizations.
fn teams(keys: &str, deferral: &str) -> String {
    format!(
        "CREATE ROLE app NOLOGIN;
         CREATE ROLE auditor NOLOGIN;
         CREATE SCHEMA authz;
         CREATE TABLE memberships (organization_id UUID NOT NULL, user_id UUID NOT NULL,
           active BOOLEAN NOT NULL, PRIMARY KEY (organization_id, user_id));
         CREATE TABLE teams (id UUID NOT NULL, organization_id UUID NOT NULL, {keys});
         CREATE TABLE team_members (team_id UUID NOT NULL, organization_id UUID NOT NULL,
           user_id UUID NOT NULL, admin BOOLEAN NOT NULL, PRIMARY KEY (team_id, user_id),
           FOREIGN KEY (organization_id, team_id) REFERENCES teams (organization_id, id){deferral},
           FOREIGN KEY (organization_id, user_id) REFERENCES memberships (organization_id, user_id));
         ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
         ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
         ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
         GRANT SELECT ON memberships, teams, team_members TO app;
         ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
         ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
         CREATE FUNCTION authz.caller_id() RETURNS UUID
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
           AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;
         CREATE FUNCTION authz.blocked() RETURNS SETOF UUID
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
           AS $$ SELECT NULLIF(current_setting('app.blocked', true), '')::uuid $$;
         CREATE FUNCTION authz.member_organizations() RETURNS SETOF UUID
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             SELECT membership.organization_id FROM public.memberships membership
             WHERE membership.user_id = authz.caller_id() AND membership.active
               AND NOT (membership.organization_id = ANY (ARRAY(SELECT authz.blocked()))) $$;
         CREATE FUNCTION authz.administered_teams() RETURNS SETOF UUID
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             SELECT member.team_id FROM public.team_members member
             JOIN public.memberships membership
               ON membership.organization_id = member.organization_id AND membership.user_id = member.user_id
             WHERE member.user_id = authz.caller_id() AND member.admin AND membership.active
               AND NOT (member.organization_id = ANY (ARRAY(SELECT authz.blocked()))) $$;
         CREATE POLICY memberships_select ON memberships FOR SELECT TO app
           USING (user_id = (SELECT authz.caller_id()));
         CREATE POLICY teams_select ON teams FOR SELECT TO app
           USING (organization_id = ANY (ARRAY(SELECT authz.member_organizations())));
         CREATE POLICY team_members_select ON team_members FOR SELECT TO app
           USING (organization_id = ANY (ARRAY(SELECT authz.member_organizations())));
         CREATE POLICY teams_blocked ON teams AS RESTRICTIVE FOR ALL TO app
           USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocked()))));
         CREATE POLICY team_members_blocked ON team_members AS RESTRICTIVE FOR ALL TO app
           USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocked()))));"
    )
}

const TEAM_KEYS: &str = "PRIMARY KEY (id), UNIQUE (organization_id, id)";

/// Functions reported over [`teams`] and `sql`, the organizations of the
/// teams `helper` returns declared within the caller's.
fn exposed_over_teams(schema: &str, helper: &str, sql: &str) -> Vec<String> {
    exposed(
        Deployment::default()
            .with_app_role("app")
            .with_set_within(helper, "authz.member_organizations()")
            .expect("both sets parse"),
        &format!("{schema}{sql}"),
    )
}

#[test]
fn a_helper_filter_reaches_the_row_its_returned_key_references() {
    let administered = "
        CREATE FUNCTION authz.team_admin_organizations() RETURNS SETOF UUID
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT team.organization_id FROM public.teams team
            WHERE team.id IN (SELECT authz.administered_teams()) $$;";
    let helper = "authz.team_admin_organizations()";
    assert_eq!(
        exposed_over_teams(&teams(TEAM_KEYS, ""), helper, administered),
        Vec::<String>::new()
    );
    let numeric_team_ids = teams(TEAM_KEYS, "")
        .replace("teams (id UUID", "teams (id NUMERIC")
        .replace("team_id UUID", "team_id NUMERIC")
        .replace(
            "administered_teams() RETURNS SETOF UUID",
            "administered_teams() RETURNS SETOF NUMERIC",
        );
    assert_eq!(
        exposed_over_teams(&numeric_team_ids, helper, administered),
        Vec::<String>::new()
    );
    for schema in [
        teams(TEAM_KEYS, " DEFERRABLE INITIALLY DEFERRED"),
        teams("UNIQUE (organization_id, id)", ""),
        teams(
            "PRIMARY KEY (id) DEFERRABLE, UNIQUE (organization_id, id)",
            "",
        ),
        teams(
            "PRIMARY KEY (id), code UUID NOT NULL, UNIQUE (organization_id, code)",
            "",
        )
        .replace(
            "REFERENCES teams (organization_id, id)",
            "REFERENCES teams (organization_id, code)",
        ),
    ] {
        assert_eq!(
            exposed_over_teams(&schema, helper, administered),
            ["team_admin_organizations()"]
        );
    }
    assert_eq!(
        exposed_over_teams(
            &teams(TEAM_KEYS, ""),
            "authz.volatile_admin_organizations()",
            "CREATE FUNCTION authz.volatile_administered_teams() RETURNS SETOF UUID
               LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT member.team_id FROM public.team_members member
                 WHERE member.user_id = authz.caller_id()
                   AND member.organization_id IN (SELECT authz.member_organizations())
                   AND NOT (member.organization_id = ANY (ARRAY(SELECT authz.blocked()))) $$;
             CREATE FUNCTION authz.volatile_admin_organizations() RETURNS SETOF UUID
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT team.organization_id FROM public.teams team
                 WHERE team.id IN (SELECT authz.volatile_administered_teams()) $$;"
        ),
        ["volatile_admin_organizations()"]
    );
}

#[test]
fn every_arm_of_a_helper_carries_its_filter_or_none_does() {
    let excluded = "member.organization_id IN (SELECT authz.member_organizations())
        AND NOT (member.organization_id = ANY (ARRAY(SELECT authz.blocked())))";
    let reported = |teams_body: &str| {
        exposed_over_teams(
            &teams(TEAM_KEYS, ""),
            "authz.listed_organizations()",
            &format!(
                "SET check_function_bodies = false;
                 CREATE FUNCTION authz.listed_teams() RETURNS SETOF UUID
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT team_id FROM public.team_members WHERE admin $$;
                 CREATE OR REPLACE FUNCTION authz.listed_teams() RETURNS SETOF UUID
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     {teams_body} $$;
                 CREATE FUNCTION authz.listed_organizations() RETURNS SETOF UUID
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT team.organization_id FROM public.teams team
                     WHERE team.id IN (SELECT authz.listed_teams()) $$;"
            ),
        )
    };
    let admin = format!(
        "SELECT member.team_id FROM public.team_members member WHERE member.admin AND {excluded}"
    );
    let own = format!(
        "SELECT member.team_id FROM public.team_members member
         WHERE member.user_id = authz.caller_id() AND {excluded}"
    );
    assert_eq!(
        reported(&format!("{admin} UNION {own}")),
        Vec::<String>::new()
    );
    for body in [
        format!("{admin} UNION VALUES ('00000000-0000-0000-0000-000000000000'::uuid)"),
        format!("{admin} UNION SELECT listed FROM authz.listed_teams() listed"),
        format!("{admin} UNION SELECT missing.team_id FROM public.missing_members missing"),
    ] {
        assert_eq!(reported(&body), ["listed_organizations()"], "{body}");
    }
    for body in [
        format!("{admin} UNION SELECT member.team_id FROM public.team_members member"),
        format!("{admin} UNION SELECT nobody.team_id FROM public.team_members member"),
    ] {
        assert_eq!(
            reported(&body),
            ["listed_organizations()", "listed_teams()"],
            "{body}"
        );
    }
}

#[test]
fn a_joined_row_meeting_a_helpers_whole_filter_proves_the_helpers_set() {
    let variants = "
        CREATE FUNCTION authz.inactive_teams() RETURNS SETOF UUID
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT member.team_id FROM public.team_members member
            JOIN public.memberships membership
              ON membership.organization_id = member.organization_id AND membership.user_id = member.user_id
            WHERE member.user_id = authz.caller_id() AND member.admin
              AND NOT (member.organization_id = ANY (ARRAY(SELECT authz.blocked()))) $$;
        CREATE FUNCTION authz.left_joined_teams() RETURNS SETOF UUID
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT member.team_id FROM public.team_members member
            LEFT JOIN public.memberships membership
              ON membership.organization_id = member.organization_id AND membership.user_id = member.user_id
              AND membership.active
            WHERE member.user_id = authz.caller_id() AND member.admin
              AND NOT (member.organization_id = ANY (ARRAY(SELECT authz.blocked()))) $$;";
    let unrelated = "authz.team_admin_organizations()";
    assert_eq!(
        exposed_over_teams(&teams(TEAM_KEYS, ""), unrelated, variants),
        ["inactive_teams()", "left_joined_teams()"]
    );
    assert_eq!(
        exposed_over_teams(
            &format!(
                "{}ALTER FUNCTION authz.member_organizations() OWNER TO auditor;",
                teams(TEAM_KEYS, "")
            ),
            unrelated,
            variants
        ),
        [
            "administered_teams()",
            "inactive_teams()",
            "left_joined_teams()"
        ]
    );
    for partial in [
        "FROM ONLY public.memberships membership",
        "FROM public.memberships membership TABLESAMPLE SYSTEM (10)",
    ] {
        assert_eq!(
            exposed_over_teams(
                &teams(TEAM_KEYS, "").replace("FROM public.memberships membership", partial),
                unrelated,
                variants
            ),
            [
                "administered_teams()",
                "inactive_teams()",
                "left_joined_teams()"
            ],
            "{partial}"
        );
    }
}

/// Grantees of three kinds, each user and organization pinned to its kind
/// by a key closed with `deferral`, with a helper yielding the caller, the
/// grantee standing for everyone and the caller's organizations.
fn grantees(deferral: &str) -> String {
    format!(
        "CREATE ROLE app NOLOGIN;
         CREATE SCHEMA authz;
         CREATE TYPE authz.grantee_kind AS ENUM ('user', 'organization', 'everyone');
         CREATE TABLE grantees (id UUID PRIMARY KEY, kind authz.grantee_kind NOT NULL, UNIQUE (id, kind));
         CREATE TABLE users (id UUID PRIMARY KEY,
           kind authz.grantee_kind GENERATED ALWAYS AS ('user'::authz.grantee_kind) STORED NOT NULL,
           FOREIGN KEY (id, kind) REFERENCES grantees (id, kind){deferral});
         CREATE TABLE organizations (id UUID PRIMARY KEY,
           kind authz.grantee_kind GENERATED ALWAYS AS ('organization'::authz.grantee_kind) STORED NOT NULL,
           FOREIGN KEY (id, kind) REFERENCES grantees (id, kind){deferral});
         CREATE TABLE memberships (organization_id UUID NOT NULL REFERENCES organizations (id),
           user_id UUID NOT NULL REFERENCES users (id), active BOOLEAN NOT NULL,
           PRIMARY KEY (organization_id, user_id));
         CREATE TABLE grants (resource_id UUID NOT NULL, organization_id UUID NOT NULL,
           grantee_id UUID NOT NULL REFERENCES grantees (id));
         ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
         GRANT SELECT ON memberships TO app;
         ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
         ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
         CREATE FUNCTION authz.caller_id() RETURNS UUID
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
           AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;
         CREATE FUNCTION authz.member_organizations() RETURNS SETOF UUID
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             SELECT membership.organization_id FROM public.memberships membership
             WHERE membership.user_id = authz.caller_id() AND membership.active $$;
         CREATE FUNCTION authz.caller_grantees() RETURNS SETOF UUID
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             WITH RECURSIVE reached (id) AS (
               SELECT grantee.id FROM public.grantees grantee
               WHERE grantee.id = authz.caller_id() AND grantee.kind = 'user'
               UNION
               SELECT grantee.id FROM public.grantees grantee WHERE grantee.kind = 'everyone'
               UNION
               SELECT organization FROM authz.member_organizations() organization
             )
             SELECT id FROM reached $$;
         CREATE POLICY memberships_select ON memberships FOR SELECT TO app
           USING (user_id = (SELECT authz.caller_id()));"
    )
}

#[test]
fn a_helper_arm_whose_kind_the_keys_rule_out_drops_from_its_set() {
    let functions = "
        CREATE FUNCTION authz.listed_grantees() RETURNS SETOF UUID
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT id FROM public.grantees WHERE id = authz.caller_id()
            UNION SELECT id FROM public.grantees WHERE kind = 'user' $$;
        CREATE FUNCTION authz.granted_resources() RETURNS SETOF UUID
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT permission.resource_id FROM public.grants permission
            WHERE permission.grantee_id IN (SELECT authz.caller_grantees())
              AND NOT EXISTS (
                SELECT 1 FROM public.memberships membership
                WHERE membership.organization_id = permission.organization_id
                  AND membership.user_id = permission.grantee_id AND NOT membership.active) $$;
        CREATE FUNCTION authz.granted_to_listed() RETURNS SETOF UUID
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT permission.resource_id FROM public.grants permission
            WHERE permission.grantee_id IN (SELECT authz.listed_grantees())
              AND NOT EXISTS (
                SELECT 1 FROM public.memberships membership
                WHERE membership.organization_id = permission.organization_id
                  AND membership.user_id = permission.grantee_id AND NOT membership.active) $$;";
    let app = || Deployment::default().with_app_role("app");
    assert_eq!(
        exposed(app(), &format!("{}{functions}", grantees(""))),
        ["granted_to_listed()"]
    );
    assert_eq!(
        exposed(
            app(),
            &format!("{}{functions}", grantees(" DEFERRABLE INITIALLY DEFERRED"))
        ),
        ["granted_resources()", "granted_to_listed()"]
    );
    let text_kinds = |user: &str| {
        grantees("")
            .replace("kind authz.grantee_kind", "kind TEXT")
            .replace("('user'::authz.grantee_kind)", user)
            .replace(
                "('organization'::authz.grantee_kind)",
                "('organization'::TEXT)",
            )
    };
    assert_eq!(
        exposed(
            app(),
            &format!("{}{functions}", text_kinds("('user'::TEXT)"))
        ),
        ["granted_to_listed()"]
    );
    let everyone = "grantee.kind = 'everyone'";
    for (kinds, reported) in [
        ("grantee.kind = ('everyone')", &["granted_to_listed()"][..]),
        (
            "grantee.kind IN ('everyone', 'organization')",
            &["granted_to_listed()"],
        ),
        (
            "grantee.kind IN ('everyone', 'user')",
            &["granted_resources()", "granted_to_listed()"],
        ),
    ] {
        assert_eq!(
            exposed(
                app(),
                &format!("{}{functions}", grantees("").replace(everyone, kinds))
            ),
            reported,
            "{kinds}"
        );
    }
    assert_eq!(
        exposed(
            app(),
            &format!(
                "{}ALTER TABLE grantees ADD FOREIGN KEY (id) REFERENCES grantees (id);{functions}",
                grantees("")
            )
        ),
        ["granted_to_listed()"]
    );
    for schema in [
        text_kinds("('useridx'::VARCHAR(4))"),
        format!(
            "{}CREATE TABLE guest_grantees () INHERITS (grantees);",
            grantees("")
        ),
    ] {
        assert_eq!(
            exposed(app(), &format!("{schema}{functions}")),
            ["granted_resources()", "granted_to_listed()"],
            "{schema}"
        );
    }
}

#[test]
fn a_validated_check_pins_a_not_null_kind_as_a_generated_one_does() {
    let functions = "
        CREATE FUNCTION authz.granted_resources() RETURNS SETOF UUID
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT permission.resource_id FROM public.grants permission
            WHERE permission.grantee_id IN (SELECT authz.caller_grantees())
              AND NOT EXISTS (
                SELECT 1 FROM public.memberships membership
                WHERE membership.organization_id = permission.organization_id
                  AND membership.user_id = permission.grantee_id AND NOT membership.active) $$;";
    let checked = |user: &str| {
        format!(
            "{}{functions}",
            grantees("")
                .replace(
                    "GENERATED ALWAYS AS ('organization'::authz.grantee_kind) STORED NOT NULL",
                    "NOT NULL DEFAULT 'organization' CHECK (kind = 'organization')",
                )
                .replace(
                    "GENERATED ALWAYS AS ('user'::authz.grantee_kind) STORED NOT NULL",
                    user,
                )
        )
    };
    let app = || Deployment::default().with_app_role("app");
    let added = format!(
        "{}ALTER TABLE users ADD CONSTRAINT user_kind CHECK (kind = 'user') NOT VALID;",
        checked("NOT NULL")
    );
    assert_eq!(exposed(app(), &added), ["granted_resources()"]);
    assert_eq!(
        exposed(
            app(),
            &format!("{added}ALTER TABLE users VALIDATE CONSTRAINT user_kind;")
        ),
        Vec::<String>::new()
    );
    for (user, reported) in [
        ("NOT NULL DEFAULT 'user' CHECK (kind = 'user')", &[][..]),
        ("NOT NULL CHECK ('user' = kind)", &[]),
        ("NOT NULL CHECK (kind IN ('user'))", &[]),
        (
            "NOT NULL, CHECK ((kind = 'user'::authz.grantee_kind) AND id IS NOT NULL)",
            &[],
        ),
        (
            "DEFAULT 'user' CHECK (kind = 'user')",
            &["granted_resources()"],
        ),
        (
            "NOT NULL CHECK (kind = 'user' OR id IS NULL)",
            &["granted_resources()"],
        ),
        (
            "NOT NULL CHECK (kind IN ('user', 'organization'))",
            &["granted_resources()"],
        ),
        (
            "NOT NULL, CHECK (kind = 'user') NOT ENFORCED",
            &["granted_resources()"],
        ),
        ("NOT NULL", &["granted_resources()"]),
    ] {
        assert_eq!(exposed(app(), &checked(user)), reported, "{user}");
    }
}

#[test]
fn a_strict_helper_a_policy_calls_with_null_admits_no_witnessed_row() {
    let reported = |strict: &str, default: &str, argument: &str| {
        exposed(
            Deployment::default().with_app_role("app"),
            &format!(
                "{ORGANIZATIONS}
                 CREATE FUNCTION authz.founded_with(min_role authz.role{default}) RETURNS SETOF INT
                   LANGUAGE sql STABLE {strict} SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     {FOUNDED} $$;
                 CREATE FUNCTION authz.founded_list() RETURNS SETOF INT
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     {FOUNDED} $$;
                 CREATE POLICY organizations_select ON public.organizations FOR SELECT TO app
                   USING (id = ANY (ARRAY(SELECT authz.founded_with({argument}))));"
            ),
        )
    };
    for (strict, default, argument) in [("STRICT", "", "NULL"), ("STRICT", " DEFAULT NULL", "")] {
        assert_eq!(
            reported(strict, default, argument),
            ["founded_list()", "founded_with(authz.role)"],
            "{default} {argument}"
        );
    }
    assert_eq!(reported("STRICT", "", "'reader'"), Vec::<String>::new());
    assert_eq!(reported("", "", "NULL"), Vec::<String>::new());
}

const ROLE_SETS: &str = "
    CREATE ROLE app NOLOGIN;
    CREATE SCHEMA authz;
    CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
    CREATE TABLE resources (id INT PRIMARY KEY, role_floor authz.role);
    ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
    GRANT SELECT ON resources TO app;
    ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
    ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
    CREATE FUNCTION authz.resources_with(min_role authz.role) RETURNS SETOF INT
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
      AS $$ SELECT 1 WHERE min_role IN ('reader', 'writer', 'admin') $$;
    CREATE POLICY readable_resources ON resources FOR SELECT TO app
      USING (id = ANY (ARRAY(SELECT authz.resources_with('reader'))));";

/// Functions reported over [`ROLE_SETS`] and `sql` under `deployment`.
fn exposed_over_role_sets(deployment: Deployment, sql: &str) -> Vec<String> {
    exposed(
        deployment.with_app_role("app"),
        &format!("{ROLE_SETS}{sql}"),
    )
}

/// `deployment` declaring each set `within` lists within the next one.
fn nested(deployment: Deployment, within: &[&str]) -> Deployment {
    within.windows(2).fold(deployment, |deployment, pair| {
        deployment
            .with_set_within(pair[0], pair[1])
            .expect("both sets parse")
    })
}

fn role_ladder() -> Deployment {
    nested(
        Deployment::default(),
        &[
            "authz.resources_with('admin')",
            "authz.resources_with('writer')",
            "authz.resources_with('reader')",
        ],
    )
}

#[test]
fn an_enum_parameter_confines_when_every_label_is_within_the_policys_set() {
    let functions = "
        CREATE FUNCTION named_reach(min_role authz.role) RETURNS SETOF INT
          LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT resource.id FROM public.resources resource
            WHERE resource.id IN (SELECT authz.resources_with(min_role)) $$;
        CREATE FUNCTION qualified_reach(min_role authz.role) RETURNS SETOF INT
          LANGUAGE sql STABLE RETURNS NULL ON NULL INPUT SECURITY DEFINER
          SET search_path = pg_catalog, pg_temp AS $$
            SELECT resource.id FROM public.resources resource
            WHERE resource.id = ANY (ARRAY(SELECT authz.resources_with(qualified_reach.min_role))) $$;
        CREATE FUNCTION positional_reach(authz.role) RETURNS SETOF INT
          LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT resource.id FROM public.resources resource
            WHERE resource.id IN (SELECT authz.resources_with($1)) $$;";
    assert_eq!(
        exposed_over_role_sets(Deployment::default(), functions),
        [
            "named_reach(authz.role)",
            "positional_reach(authz.role)",
            "qualified_reach(authz.role)"
        ]
    );
    assert_eq!(
        exposed_over_role_sets(role_ladder(), functions),
        Vec::<String>::new()
    );
}

#[test]
fn a_null_parameter_confines_only_through_a_strict_function() {
    let lenient = "
        CREATE FUNCTION lenient_reach(min_role authz.role) RETURNS SETOF INT
          LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT resource.id FROM public.resources resource
            WHERE resource.id IN (SELECT authz.resources_with(min_role)) $$;";
    assert_eq!(
        exposed_over_role_sets(role_ladder(), lenient),
        ["lenient_reach(authz.role)"]
    );
    let strict_helper = format!(
        "{}{lenient}",
        "CREATE FUNCTION authz.strict_resources_with(min_role authz.role) RETURNS SETOF INT
           LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp
           AS $$ SELECT 1 $$;"
    )
    .replace(
        "SELECT authz.resources_with(min_role)) $$",
        "SELECT authz.strict_resources_with(min_role)) $$",
    );
    assert_eq!(
        exposed_over_role_sets(role_ladder(), &strict_helper),
        ["lenient_reach(authz.role)"]
    );
    assert_eq!(
        exposed_over_role_sets(
            nested(
                role_ladder(),
                &[
                    "authz.strict_resources_with('admin')",
                    "authz.strict_resources_with('writer')",
                    "authz.strict_resources_with('reader')",
                    "authz.resources_with('reader')",
                ],
            ),
            &strict_helper,
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_parameter_confines_nothing_unless_it_is_an_enum_no_column_shadows() {
    assert_eq!(
        exposed_over_role_sets(
            role_ladder(),
            "CREATE FUNCTION shadowed_reach(role_floor authz.role) RETURNS SETOF INT
               LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 WHERE resource.id IN (SELECT authz.resources_with(role_floor)) $$;
             CREATE FUNCTION text_reach(min_role TEXT) RETURNS SETOF INT
               LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 WHERE resource.id IN (SELECT authz.resources_with(min_role::authz.role)) $$;"
        ),
        ["shadowed_reach(authz.role)", "text_reach(TEXT)"]
    );
}

const OWNED: &str = "
    CREATE ROLE app NOLOGIN;
    CREATE SCHEMA authz;
    CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
    CREATE TABLE public.resources (
      id INT PRIMARY KEY, parent_id INT, organization_id INT NOT NULL, owner_id INT NOT NULL,
      granted_role authz.role NOT NULL
    );
    ALTER TABLE public.resources ENABLE ROW LEVEL SECURITY;
    GRANT SELECT ON public.resources TO app;
    ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
    ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
    CREATE FUNCTION authz.caller_id() RETURNS INT
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;";

#[test]
fn a_helper_drawing_the_tested_row_by_its_key_carries_every_condition_of_it() {
    assert_eq!(
        exposed(
            Deployment::default().with_app_role("app"),
            &format!(
                "{OWNED}
                 CREATE POLICY owned_resources ON public.resources FOR SELECT TO app
                   USING (owner_id = authz.caller_id());
                 CREATE FUNCTION authz.owned_ids() RETURNS SETOF INT
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT resource.id FROM public.resources resource
                     WHERE resource.owner_id = authz.caller_id() $$;
                 CREATE FUNCTION authz.owned_parent_ids() RETURNS SETOF INT
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT resource.parent_id FROM public.resources resource
                     WHERE resource.owner_id = authz.caller_id() $$;
                 CREATE FUNCTION authz.through_owned() RETURNS SETOF INT
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT resource.id FROM public.resources resource
                     WHERE resource.id IN (SELECT authz.owned_ids()) $$;
                 CREATE FUNCTION authz.parents_through_owned() RETURNS SETOF INT
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT resource.id FROM public.resources resource
                     WHERE resource.parent_id IN (SELECT authz.owned_ids()) $$;
                 CREATE FUNCTION authz.through_owned_parents() RETURNS SETOF INT
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT resource.id FROM public.resources resource
                     WHERE resource.parent_id IN (SELECT authz.owned_parent_ids()) $$;"
            ),
        ),
        ["parents_through_owned()", "through_owned_parents()"]
    );
}

#[test]
fn a_policy_helper_parameter_takes_the_literal_the_policy_passes() {
    let reported = |policy_role: &str, filter: &str| {
        exposed(
            nested(
                Deployment::default(),
                &[
                    "authz.granted_ids('admin')",
                    "authz.granted_ids('writer')",
                    "authz.granted_ids('reader')",
                ],
            )
            .with_app_role("app"),
            &format!(
                "{OWNED}
                 CREATE FUNCTION authz.granted_ids(min_role authz.role) RETURNS SETOF INT
                   LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT resource.id FROM public.resources resource
                     WHERE resource.owner_id = authz.caller_id() AND resource.granted_role >= min_role $$;
                 CREATE POLICY granted_resources ON public.resources FOR SELECT TO app
                   USING (id IN (SELECT authz.granted_ids({policy_role})));
                 CREATE FUNCTION authz.readable_ids() RETURNS SETOF INT
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT resource.id FROM public.resources resource
                     WHERE {filter} $$;"
            ),
        )
    };
    let granted = "resource.owner_id = authz.caller_id() AND resource.granted_role >= 'reader'";
    assert_eq!(reported("'reader'", granted), Vec::<String>::new());
    assert_eq!(
        reported("'reader'", "resource.owner_id = authz.caller_id()"),
        ["readable_ids()"]
    );
    assert_eq!(
        reported("'admin'", granted),
        ["granted_ids(authz.role)", "readable_ids()"]
    );
}

#[test]
fn a_helper_parameter_takes_the_argument_its_caller_passes() {
    let organization_ladder = nested(
        Deployment::default(),
        &[
            "authz.organizations_with('admin')",
            "authz.organizations_with('writer')",
            "authz.organizations_with('reader')",
        ],
    );
    let schema = format!(
        "{OWNED}
         CREATE TABLE public.memberships (user_id INT NOT NULL, organization_id INT NOT NULL, role authz.role NOT NULL);
         CREATE FUNCTION authz.organizations_with(min_role authz.role) RETURNS SETOF INT
           LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             SELECT membership.organization_id FROM public.memberships membership
             WHERE membership.user_id = authz.caller_id() AND membership.role >= min_role $$;
         CREATE FUNCTION authz.resources_with(min_role authz.role) RETURNS SETOF INT
           LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             SELECT resource.id FROM public.resources resource
             WHERE resource.organization_id IN (SELECT authz.organizations_with(min_role)) $$;
         CREATE POLICY member_resources ON public.resources FOR SELECT TO app
           USING (organization_id IN (SELECT authz.organizations_with('reader')));
         CREATE FUNCTION authz.organizations_reaching(min_role authz.role) RETURNS SETOF INT
           LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             SELECT resource.organization_id FROM public.resources resource
             WHERE resource.id IN (SELECT authz.resources_with(min_role)) $$;
         CREATE FUNCTION authz.writable_ids() RETURNS SETOF INT
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             SELECT resource.id FROM public.resources resource
             WHERE resource.id IN (SELECT authz.resources_with('writer')) $$;"
    );
    assert_eq!(
        exposed(organization_ladder.with_app_role("app"), &schema),
        Vec::<String>::new()
    );
    assert_eq!(
        exposed(Deployment::default().with_app_role("app"), &schema),
        Vec::<String>::new()
    );
    let unordered = schema.replace("membership.role >= min_role", "membership.role = min_role");
    assert_eq!(
        exposed(Deployment::default().with_app_role("app"), &unordered),
        [
            "organizations_reaching(authz.role)",
            "resources_with(authz.role)",
            "writable_ids()"
        ]
    );
}

const CAPPED_KINDS: &str = "
    CREATE ROLE app NOLOGIN;
    CREATE SCHEMA authz;
    CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
    CREATE TYPE authz.resource_kind AS ENUM ('organization', 'team');
    CREATE TABLE memberships (organization_id INT NOT NULL, team_id INT NOT NULL);
    CREATE TABLE reader_caps (resource_id INT, kind authz.resource_kind);
    ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
    GRANT SELECT ON memberships TO app;
    ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
    ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
    CREATE FUNCTION authz.capped_kinds(min_role authz.role)
      RETURNS TABLE (resource_id INT, kind authz.resource_kind)
      LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp
      AS $$ SELECT 1, 'organization'::authz.resource_kind WHERE min_role IN ('reader', 'writer', 'admin') $$;";

const READER_CAP: &str = "SELECT * FROM authz.capped_kinds('reader')";

/// Functions reported over [`CAPPED_KINDS`], a policy admitting the
/// memberships of the organizations `policy` yields, and a definer named
/// `name` whose read of `memberships` keeps the rows `filter` admits.
fn capped(deployment: Deployment, policy: &str, name: &str, filter: &str) -> Vec<String> {
    exposed(
        deployment.with_app_role("app"),
        &format!(
            "{CAPPED_KINDS}
             CREATE POLICY capped_memberships ON memberships FOR SELECT TO app
               USING ((organization_id, 'organization'::authz.resource_kind) IN ({policy}));
             CREATE FUNCTION {name} RETURNS SETOF INT
               LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT membership.organization_id FROM public.memberships membership
                 WHERE {filter} $$;"
        ),
    )
}

fn capped_ladder() -> Deployment {
    nested(
        Deployment::default(),
        &[
            "authz.capped_kinds('admin')",
            "authz.capped_kinds('writer')",
            "authz.capped_kinds('reader')",
        ],
    )
}

#[test]
fn a_row_value_in_a_call_declared_within_the_policys_call_confines_a_read() {
    let admin = "(membership.organization_id, 'organization'::authz.resource_kind)
        IN (SELECT * FROM authz.capped_kinds('admin'))";
    assert_eq!(
        capped(Deployment::default(), READER_CAP, "admin_capped()", admin),
        ["admin_capped()"]
    );
    assert_eq!(
        capped(capped_ladder(), READER_CAP, "admin_capped()", admin),
        Vec::<String>::new()
    );
    for (name, filter) in [
        (
            "role_capped(min_role authz.role)",
            "IN (SELECT * FROM authz.capped_kinds(min_role))",
        ),
        (
            "lateral_capped()",
            "IN (SELECT * FROM LATERAL authz.capped_kinds('admin'))",
        ),
    ] {
        assert_eq!(
            capped(
                capped_ladder(),
                READER_CAP,
                name,
                &format!(
                    "(membership.organization_id, 'organization'::authz.resource_kind) {filter}"
                ),
            ),
            Vec::<String>::new()
        );
    }
}

#[test]
fn a_row_value_confines_only_when_it_lines_up_with_the_policys() {
    for (name, row) in [
        (
            "other_kind()",
            "(membership.organization_id, 'team'::authz.resource_kind)",
        ),
        (
            "other_column()",
            "(membership.team_id, 'organization'::authz.resource_kind)",
        ),
        (
            "computed_column()",
            "(membership.organization_id + 0, 'organization'::authz.resource_kind)",
        ),
    ] {
        assert_eq!(
            capped(
                capped_ladder(),
                READER_CAP,
                name,
                &format!("{row} IN (SELECT * FROM authz.capped_kinds('admin'))"),
            ),
            [name],
        );
    }
    for policy in [
        "SELECT * FROM authz.capped_kinds('reader') capped WHERE capped.resource_id > 1",
        "SELECT DISTINCT ON (capped.kind) * FROM authz.capped_kinds('reader') capped",
        "SELECT * FROM authz.capped_kinds('reader') NATURAL JOIN authz.capped_kinds('admin')",
    ] {
        assert_eq!(
            capped(
                capped_ladder(),
                policy,
                "under_narrowed_policy()",
                "(membership.organization_id, 'organization'::authz.resource_kind)
                   IN (SELECT * FROM authz.capped_kinds('admin'))",
            ),
            ["under_narrowed_policy()"]
        );
    }
    assert_eq!(
        capped(
            nested(
                capped_ladder(),
                &["authz.capped_kinds('reader')", "public.reader_caps()"]
            ),
            "SELECT * FROM public.reader_caps",
            "under_table_policy()",
            "(membership.organization_id, 'organization'::authz.resource_kind)
               IN (SELECT * FROM authz.capped_kinds('admin'))",
        ),
        ["under_table_policy()"]
    );
}

const ORGANIZATIONS: &str = "
    CREATE ROLE app NOLOGIN;
    CREATE SCHEMA authz;
    CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
    CREATE TABLE public.organizations (id INT PRIMARY KEY, parent_id INT, created_by_id INT, founded_at TIMESTAMP);
    ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
    GRANT SELECT ON public.organizations TO app;
    ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
    ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
    CREATE FUNCTION authz.caller_id() RETURNS INT
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
    CREATE FUNCTION authz.acting_installation_id() RETURNS INT
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT NULL::INT $$;";

const FOUNDED: &str = "SELECT organization.id FROM public.organizations organization
    WHERE organization.created_by_id = authz.caller_id()
      AND organization.founded_at IS NULL
      AND authz.acting_installation_id() IS NULL";

/// Functions the rule reports for `app` once `helper` is defined, with the
/// policy admitting the organizations `authz.founded_organizations()`
/// returns outside an installation and the `extra` statements after it.
fn founded(helper: &str, extra: &str, deployment: Deployment) -> Vec<String> {
    exposed(
        deployment.with_app_role("app"),
        &format!(
            "{ORGANIZATIONS}
             {helper}
             CREATE POLICY organizations_select ON public.organizations FOR SELECT TO app
               USING (id = ANY (ARRAY(SELECT authz.founded_organizations()))
                 AND (SELECT authz.acting_installation_id()) IS NULL);
             {extra}"
        ),
    )
}

/// The definition of `authz.founded_organizations()` running `body`.
fn founded_organizations(body: &str) -> String {
    format!(
        "CREATE FUNCTION authz.founded_organizations() RETURNS SETOF INT
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ {body} $$;"
    )
}

#[test]
fn a_definer_returning_the_keys_its_policy_admits_through_it_is_not_reported() {
    assert_eq!(
        founded(&founded_organizations(FOUNDED), "", Deployment::default()),
        Vec::<String>::new()
    );
    assert_eq!(
        founded(
            &founded_organizations(&FOUNDED.replace(
                "SELECT organization.id FROM public.organizations organization",
                "SELECT other.id FROM public.organizations organization
                 JOIN public.organizations other ON other.id = organization.id",
            )),
            "",
            Deployment::default()
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        founded(
            &founded_organizations(
                "SELECT organization.id FROM public.organizations organization
                 WHERE organization.created_by_id = authz.caller_id()"
            ),
            "",
            Deployment::default()
        ),
        ["founded_organizations()"]
    );
}

#[test]
fn a_key_changed_or_dropped_on_its_way_to_the_result_proves_nothing() {
    for body in [
        FOUNDED.replace("SELECT organization.id", "SELECT organization.id + 0"),
        FOUNDED.replace("SELECT organization.id", "SELECT max(organization.id)"),
        format!("{FOUNDED} LIMIT 1"),
        format!("{FOUNDED} OFFSET 1"),
        format!("{FOUNDED} EXCEPT SELECT 0"),
        format!("WITH found (id) AS ({FOUNDED}) SELECT id FROM found WHERE id > 0"),
        format!("WITH found (id) AS ({FOUNDED}) SELECT id FROM found LIMIT 1"),
        format!("WITH found (id) AS ({FOUNDED}) SELECT DISTINCT ON (id) id FROM found"),
        format!(
            "WITH found (id) AS ({FOUNDED})
             SELECT id FROM found WHERE (SELECT count(*) FROM found) > 1"
        ),
        FOUNDED.replace(
            "SELECT organization.id FROM public.organizations organization",
            "SELECT other.id FROM public.organizations organization
             JOIN public.organizations other ON other.parent_id = organization.id",
        ),
    ] {
        assert_eq!(
            founded(&founded_organizations(&body), "", Deployment::default()),
            ["founded_organizations()"],
            "{body}"
        );
    }
    assert_eq!(
        founded(
            &founded_organizations(FOUNDED).replace("STABLE", "VOLATILE"),
            "",
            Deployment::default()
        ),
        ["founded_organizations()"]
    );
}

#[test]
fn every_union_arm_and_recursive_step_carries_the_key() {
    let reached = |step_filter: &str, outer_filter: &str| {
        founded(
            &founded_organizations(&format!(
                "WITH RECURSIVE reached (id) AS (
                   {FOUNDED}
                   UNION
                   SELECT organization.id FROM public.organizations organization
                   JOIN reached ON organization.parent_id = reached.id
                   WHERE {step_filter}
                 )
                 SELECT reached.id FROM reached {outer_filter}"
            )),
            "",
            Deployment::default(),
        )
    };
    assert_eq!(
        reached("authz.acting_installation_id() IS NULL", ""),
        Vec::<String>::new()
    );
    assert_eq!(
        reached("organization.founded_at IS NULL", ""),
        ["founded_organizations()"]
    );
    assert_eq!(
        reached(
            "authz.acting_installation_id() IS NULL",
            "WHERE reached.id > 0"
        ),
        ["founded_organizations()"]
    );
}

#[test]
fn a_set_declared_within_the_policys_set_carries_the_key() {
    let helpers = format!(
        "{}
         CREATE FUNCTION authz.parentless_founded_organizations() RETURNS SETOF INT
           LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             {FOUNDED} AND organization.parent_id IS NULL $$;",
        founded_organizations(FOUNDED)
    );
    assert_eq!(
        founded(&helpers, "", Deployment::default()),
        Vec::<String>::new()
    );
    assert_eq!(
        founded(&helpers, AUDITOR_OWNS_FOUNDED, Deployment::default()),
        ["parentless_founded_organizations()"]
    );
    assert_eq!(
        founded(
            &helpers,
            AUDITOR_OWNS_FOUNDED,
            Deployment::default()
                .with_set_within(
                    "authz.parentless_founded_organizations()",
                    "authz.founded_organizations()"
                )
                .expect("both sets parse")
        ),
        Vec::<String>::new()
    );
}

const AUDITOR_OWNS_FOUNDED: &str = "CREATE ROLE auditor NOLOGIN;
    ALTER FUNCTION authz.founded_organizations() OWNER TO auditor;";

#[test]
fn a_restrictive_policy_still_needs_the_filter_to_imply_it() {
    let restrictive = |using: &str| {
        founded(
            &founded_organizations(FOUNDED),
            &format!(
                "CREATE POLICY organizations_restricted ON public.organizations AS RESTRICTIVE
                   FOR SELECT TO app USING ({using});"
            ),
            Deployment::default(),
        )
    };
    assert_eq!(restrictive("founded_at IS NULL"), Vec::<String>::new());
    assert_eq!(
        restrictive("parent_id IS NULL"),
        ["founded_organizations()"]
    );
}

#[test]
fn a_parameter_is_carried_over_every_value_a_strict_definer_takes() {
    let schema = |strict: &str| {
        exposed(
            Deployment::default()
                .with_app_role("app")
                .with_set_within(
                    "authz.organizations_with('admin')",
                    "authz.organizations_with('writer')",
                )
                .and_then(|deployment| {
                    deployment.with_set_within(
                        "authz.organizations_with('writer')",
                        "authz.organizations_with('reader')",
                    )
                })
                .expect("both sets parse"),
            &format!(
                "{ORGANIZATIONS}
                 CREATE FUNCTION authz.organizations_with(min_role authz.role) RETURNS SETOF INT
                   LANGUAGE sql STABLE {strict} SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     {FOUNDED} AND min_role IS NOT NULL $$;
                 CREATE POLICY organizations_select ON public.organizations FOR SELECT TO app
                   USING (id = ANY (ARRAY(SELECT authz.organizations_with('reader')))
                     AND (SELECT authz.acting_installation_id()) IS NULL);"
            ),
        )
    };
    assert_eq!(schema("STRICT"), Vec::<String>::new());
    assert_eq!(schema(""), ["organizations_with(authz.role)"]);
}

#[test]
fn a_key_named_through_a_with_item_in_any_spelling_is_carried() {
    for body in [
        format!("WITH found (id) AS ({FOUNDED}) SELECT id FROM found"),
        format!(
            "WITH found AS ({}) SELECT key FROM found",
            FOUNDED.replace("SELECT organization.id", "SELECT organization.id AS key")
        ),
        "WITH found AS (
           SELECT id FROM public.organizations
           WHERE created_by_id = authz.caller_id()
             AND founded_at IS NULL
             AND authz.acting_installation_id() IS NULL
         )
         SELECT id FROM found"
            .to_owned(),
        format!("WITH found AS (({FOUNDED}) UNION {FOUNDED}) SELECT id FROM found"),
        format!(
            "WITH RECURSIVE reached (id) AS ({FOUNDED} UNION SELECT reached.id FROM reached)
             SELECT id FROM reached"
        ),
    ] {
        assert_eq!(
            founded(&founded_organizations(&body), "", Deployment::default()),
            Vec::<String>::new(),
            "{body}"
        );
    }
}

#[test]
fn a_with_item_column_holding_another_value_carries_no_key() {
    for body in [
        format!(
            "WITH found (id, parent_id) AS ({}) SELECT id FROM found",
            FOUNDED.replace(
                "SELECT organization.id",
                "SELECT organization.parent_id, organization.id"
            )
        ),
        format!(
            "WITH found AS ({}) SELECT coalesce FROM found",
            FOUNDED.replace(
                "SELECT organization.id",
                "SELECT COALESCE(organization.parent_id, organization.id)"
            )
        ),
    ] {
        assert_eq!(
            founded(&founded_organizations(&body), "", Deployment::default()),
            ["founded_organizations()"],
            "{body}"
        );
    }
}

#[test]
fn a_definer_returning_every_key_its_policy_admits_through_it_is_not_reported() {
    assert_eq!(
        exposed(
            Deployment::default().with_app_role("app"),
            &format!(
                "{ORGANIZATIONS}
                 CREATE FUNCTION authz.every_organization() RETURNS SETOF INT
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
                     SELECT id FROM organizations $$;
                 CREATE POLICY organizations_select ON public.organizations FOR SELECT TO app
                   USING (id = ANY (ARRAY(SELECT authz.every_organization())));"
            ),
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_quoted_definer_name_carries_the_key_as_written() {
    assert_eq!(
        exposed(
            Deployment::default().with_app_role("app"),
            &format!(
                "{ORGANIZATIONS}
                 CREATE SCHEMA \"Authz\";
                 {}
                 CREATE POLICY organizations_select ON public.organizations FOR SELECT TO app
                   USING (id = ANY (ARRAY(SELECT \"Authz\".\"Founded organizations\"()))
                     AND (SELECT authz.acting_installation_id()) IS NULL);",
                founded_organizations(FOUNDED).replace(
                    "authz.founded_organizations()",
                    "\"Authz\".\"Founded organizations\"()"
                )
            ),
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_definer_with_an_input_output_parameter_or_returning_its_input_carries_no_key() {
    let reported = |extra: &str, projected: &str| {
        founded(
            &founded_organizations(FOUNDED),
            &format!(
                "{AUDITOR_OWNS_FOUNDED}
                 CREATE FUNCTION {extra} RETURNS SETOF INT
                   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     {} $$;",
                FOUNDED.replace("organization.id FROM", &format!("{projected} FROM"))
            ),
            Deployment::default(),
        )
    };
    assert_eq!(
        reported("authz.founded_from(INOUT wanted INT)", "organization.id"),
        ["founded_from(INT)"]
    );
    assert_eq!(
        reported("authz.echoed(wanted INT)", "wanted"),
        ["echoed(INT)"]
    );
}

#[test]
fn a_parameter_compared_directly_confines_only_in_a_strict_function() {
    assert_eq!(
        exposed(
            Deployment::default().with_app_role("app"),
            "CREATE ROLE app NOLOGIN;
             CREATE TYPE clearance AS ENUM ('public');
             CREATE TABLE notices (id INT, level clearance);
             ALTER TABLE notices ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON notices TO app;
             ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
             ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
             CREATE POLICY public_notices ON notices FOR SELECT TO app USING (level = 'public');
             CREATE FUNCTION strict_notices(wanted clearance) RETURNS SETOF INT
               LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT notice.id FROM public.notices notice WHERE notice.level = wanted $$;
             CREATE FUNCTION lenient_notices(wanted clearance) RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT notice.id FROM public.notices notice WHERE notice.level = wanted $$;",
        ),
        ["lenient_notices(clearance)"]
    );
}

const ROLE: &str = "CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');";

/// Functions reported when `role` declares `authz.role`, `body` is the body
/// of `authz.resources_with(min_role)`, the policy on `resources` tests
/// `policy_set`, and `writable()` reads the resources
/// `authz.resources_with('writer')` returns.
fn exposed_through_ladder(
    deployment: Deployment,
    role: &str,
    body: &str,
    policy_set: &str,
) -> Vec<String> {
    exposed(
        deployment.with_app_role("app"),
        &format!(
            "CREATE ROLE app NOLOGIN;
             CREATE SCHEMA authz;
             {role}
             CREATE TABLE grants (resource_id INT, role authz.role);
             CREATE TABLE edges (id INT, parent_id INT);
             CREATE TABLE resources (id INT PRIMARY KEY);
             ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON resources TO app;
             ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
             ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
             CREATE FUNCTION authz.granted(min_role authz.role) RETURNS SETOF INT
               LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT permission.resource_id FROM public.grants permission
                 WHERE permission.role >= min_role $$;
             CREATE FUNCTION authz.granted_below(min_role authz.role) RETURNS SETOF INT
               LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT permission.resource_id FROM public.grants permission
                 WHERE permission.role <= min_role $$;
             CREATE FUNCTION authz.other_resources() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT edge.id FROM public.edges edge $$;
             CREATE FUNCTION authz.resources_with(min_role authz.role) RETURNS SETOF INT
               LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 {body} $$;
             CREATE POLICY readable_resources ON resources FOR SELECT TO app
               USING (id = ANY (ARRAY(SELECT {policy_set})));
             CREATE FUNCTION writable() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 WHERE resource.id IN (SELECT authz.resources_with('writer')) $$;"
        ),
    )
}

/// [`exposed_through_ladder`] over [`ROLE`] and a policy testing
/// `authz.resources_with('reader')`.
fn exposed_through_reader_ladder(body: &str) -> Vec<String> {
    exposed_through_ladder(
        Deployment::default(),
        ROLE,
        body,
        "authz.resources_with('reader')",
    )
}

#[test]
fn a_helper_testing_its_role_column_at_or_above_the_parameter_nests_its_sets() {
    let reported = |condition: &str| {
        exposed_through_reader_ladder(&format!(
            "SELECT permission.resource_id FROM public.grants permission WHERE {condition}"
        ))
    };
    for nested in [
        "permission.role >= min_role",
        "min_role <= permission.role",
        "permission.role > $1",
        "permission.resource_id > 0 AND (permission.role >= min_role OR permission.role = 'admin')",
    ] {
        assert_eq!(reported(nested), Vec::<String>::new(), "{nested}");
    }
    for unordered in [
        "permission.role <= min_role",
        "NOT (permission.role >= min_role)",
        "permission.role::text >= min_role::text",
        "permission.role >= min_role OR min_role = 'admin'",
    ] {
        assert_eq!(reported(unordered), ["writable()"], "{unordered}");
    }
}

#[test]
fn a_helper_passing_its_parameter_to_a_nested_helper_nests_its_sets() {
    for body in [
        "SELECT granted.id FROM authz.granted(min_role) granted (id)",
        "SELECT edge.id FROM public.edges edge
         WHERE edge.parent_id IS NULL OR edge.parent_id IN (SELECT authz.granted(min_role))",
        "WITH RECURSIVE reached (id) AS (
           SELECT granted.id FROM authz.granted(min_role) granted (id)
           UNION SELECT edge.id FROM reached JOIN public.edges edge ON edge.parent_id = reached.id)
         SELECT id FROM reached",
        "SELECT edge.id FROM public.edges edge
         WHERE EXISTS (SELECT 1 FROM authz.granted($1) granted (id) WHERE granted.id = edge.parent_id)",
    ] {
        assert_eq!(
            exposed_through_reader_ladder(body),
            Vec::<String>::new(),
            "{body}"
        );
    }
    for body in [
        "SELECT authz.granted_below(min_role)",
        "SELECT edge.id FROM public.edges edge EXCEPT SELECT authz.granted(min_role)",
        "SELECT edge.id FROM public.edges edge
         WHERE edge.parent_id NOT IN (SELECT authz.granted(min_role))",
        "SELECT edge.id FROM public.edges edge
         LEFT JOIN authz.granted(min_role) granted (id) ON granted.id = edge.parent_id
         WHERE granted.id IS NULL",
        "SELECT count(*)::INT FROM authz.granted(min_role)",
        "SELECT granted.id FROM authz.granted(min_role) granted (id) LIMIT 1",
    ] {
        assert_eq!(
            exposed_through_reader_ladder(body),
            ["writable()"],
            "{body}"
        );
    }
}

#[test]
fn the_ladder_follows_the_label_order_after_every_added_value() {
    let body = "SELECT authz.granted(min_role)";
    let reported = |role: &str| {
        exposed_through_ladder(
            Deployment::default(),
            role,
            body,
            "authz.resources_with('reader')",
        )
    };
    assert_eq!(
        reported(
            "CREATE TYPE authz.role AS ENUM ('writer', 'admin');
             ALTER TYPE authz.role ADD VALUE 'reader' BEFORE 'writer';"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        reported(
            "CREATE TYPE authz.role AS ENUM ('writer', 'admin');
             ALTER TYPE authz.role ADD VALUE 'reader' AFTER 'admin';"
        ),
        ["writable()"]
    );
}

#[test]
fn an_inferred_ladder_composes_with_declared_sets() {
    let body = "SELECT authz.granted(min_role)";
    let declared = Deployment::default()
        .with_set_within("authz.resources_with('reader')", "authz.other_resources()")
        .expect("both sets parse");
    assert_eq!(
        exposed_through_ladder(declared, ROLE, body, "authz.other_resources()"),
        Vec::<String>::new()
    );
    assert_eq!(
        exposed_through_ladder(Deployment::default(), ROLE, body, "authz.other_resources()"),
        ["writable()"]
    );
}

/// Functions reported when `authz.readable()` returns the resources
/// `filter` admits among those a private recursive helper, declared
/// `volatility`, reaches over `edges`, and `policy` is the read policy of
/// `resources`.
fn exposed_behind_private_helper(volatility: &str, filter: &str, policy: &str) -> Vec<String> {
    exposed(
        Deployment::default().with_app_role("app"),
        &format!(
            "CREATE ROLE app NOLOGIN;
             CREATE SCHEMA authz;
             CREATE TABLE resources (id INT PRIMARY KEY, hidden BOOLEAN NOT NULL);
             CREATE TABLE edges (id INT, parent_id INT);
             ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
             ALTER TABLE edges ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON resources, edges TO app;
             ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
             ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
             CREATE FUNCTION authz.reached() RETURNS SETOF INT
               LANGUAGE sql {volatility} SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 WITH RECURSIVE reached (id) AS (
                   SELECT 1 UNION SELECT edge.id FROM reached JOIN public.edges edge ON edge.parent_id = reached.id)
                 SELECT id FROM reached $$;
             REVOKE EXECUTE ON FUNCTION authz.reached() FROM app;
             CREATE FUNCTION authz.readable() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource
                 WHERE {filter} resource.id IN (SELECT authz.reached()) $$;
             CREATE POLICY readable_resources ON resources FOR SELECT TO app USING ({policy});
             CREATE POLICY readable_edges ON edges FOR SELECT TO app
               USING (id IN (SELECT authz.readable()));"
        ),
    )
}

#[test]
fn a_private_helper_counts_when_the_policy_tests_every_value_its_caller_returns() {
    let tested = "id IN (SELECT authz.readable())";
    assert_eq!(
        exposed_behind_private_helper("STABLE", "", tested),
        Vec::<String>::new()
    );
    assert_eq!(
        exposed_behind_private_helper("VOLATILE", "", tested),
        ["readable()"]
    );
    assert_eq!(
        exposed_behind_private_helper("STABLE", "NOT resource.hidden AND", "NOT hidden"),
        ["readable()"]
    );
}

#[test]
fn a_row_drawn_through_a_helper_call_lies_in_the_set_of_that_helper() {
    let reported = |policy_role: &str, passed: &str| {
        exposed(
            Deployment::default().with_app_role("app"),
            &format!(
                "CREATE ROLE app NOLOGIN;
                 CREATE SCHEMA authz;
                 {ROLE}
                 CREATE TABLE grants (resource_id INT, role authz.role);
                 CREATE TABLE resources (id INT PRIMARY KEY, organization_id INT NOT NULL);
                 ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
                 GRANT SELECT ON resources TO app;
                 ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
                 ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
                 CREATE FUNCTION authz.residual(min_role authz.role) RETURNS SETOF INT
                   LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT resource.id FROM public.resources resource
                     WHERE resource.id IN (SELECT permission.resource_id FROM public.grants permission
                                           WHERE permission.role >= min_role) $$;
                 CREATE POLICY readable_resources ON resources FOR SELECT TO app
                   USING (id IN (SELECT authz.residual({policy_role})));
                 CREATE FUNCTION authz.resources_with(min_role authz.role) RETURNS SETOF INT
                   LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT residual.id FROM authz.residual({passed}) residual (id) $$;
                 CREATE FUNCTION authz.organizations_reaching(min_role authz.role) RETURNS SETOF INT
                   LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                     SELECT resource.organization_id FROM public.resources resource
                     WHERE resource.id IN (SELECT authz.resources_with(min_role)) $$;"
            ),
        )
    };
    assert_eq!(reported("'reader'", "min_role"), Vec::<String>::new());
    assert_eq!(reported("'reader'", "'writer'"), Vec::<String>::new());
    assert_eq!(
        reported("'admin'", "min_role"),
        ["organizations_reaching(authz.role)", "residual(authz.role)"]
    );
    assert_eq!(
        reported("'reader'", "min_role::text::authz.role"),
        ["organizations_reaching(authz.role)"]
    );
}

#[test]
fn a_helper_passed_one_label_spelled_two_ways_yields_one_set() {
    assert_eq!(
        exposed_through_ladder(
            Deployment::default(),
            ROLE,
            "SELECT authz.granted(min_role)",
            "authz.resources_with('writer'::authz.role)"
        ),
        Vec::<String>::new()
    );
}

/// [`ROLE`] and helpers over `public.grants` the ladder reads only in part.
const ROLE_AND_HELPERS: &str = "
    CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
    CREATE FUNCTION authz.volatile_granted(min_role authz.role) RETURNS SETOF INT
      LANGUAGE sql VOLATILE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        SELECT permission.resource_id FROM public.grants permission
        WHERE permission.role >= min_role $$;
    CREATE FUNCTION authz.procedural_granted(min_role authz.role) RETURNS SETOF INT
      LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
          RETURN QUERY SELECT permission.resource_id FROM public.grants permission
          WHERE permission.role >= min_role;
        END $$;
    CREATE FUNCTION authz.granted_in(tenant INT, min_role authz.role) RETURNS SETOF INT
      LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        SELECT permission.resource_id FROM public.grants permission
        WHERE permission.resource_id > tenant AND permission.role >= min_role $$;
    CREATE FUNCTION authz.granted_rows(min_role authz.role, OUT id INT) RETURNS SETOF INT
      LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        SELECT permission.resource_id FROM public.grants permission
        WHERE permission.role >= min_role $$;
    CREATE FUNCTION authz.granted_any(VARIADIC roles authz.role[]) RETURNS SETOF INT
      LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        SELECT permission.resource_id FROM public.grants permission
        WHERE permission.role = ANY (roles) $$;";

/// [`exposed_through_ladder`] over [`ROLE_AND_HELPERS`] and a policy
/// testing `authz.resources_with('reader')`.
fn exposed_through_helpers(body: &str) -> Vec<String> {
    exposed_through_ladder(
        Deployment::default(),
        ROLE_AND_HELPERS,
        body,
        "authz.resources_with('reader')",
    )
}

#[test]
fn a_helper_reading_its_parameter_through_nested_queries_nests_its_sets() {
    for body in [
        "SELECT edge.id FROM public.edges edge",
        "WITH other AS (SELECT edge.id FROM public.edges edge)
         SELECT granted.id FROM authz.granted(min_role) granted (id)
         WHERE granted.id IN (SELECT id FROM other)",
        "(SELECT authz.granted(min_role)) UNION (SELECT authz.granted(min_role))",
        "SELECT * FROM authz.granted(min_role)",
        "SELECT sub.id FROM (SELECT authz.granted(min_role) AS id) sub",
        "SELECT granted.id
         FROM (authz.granted(min_role) granted (id) JOIN public.edges edge ON edge.id = granted.id)",
        "SELECT authz.granted_in(1, min_role)",
        "SELECT authz.granted((min_role))",
        "SELECT granted.id FROM authz.granted_rows(min_role) granted",
        "SELECT edge.id FROM public.edges edge
         WHERE edge.parent_id = ANY (ARRAY(SELECT authz.granted(min_role)))",
        "SELECT permission.resource_id FROM public.grants permission
         WHERE permission.role >= (min_role)",
    ] {
        assert_eq!(exposed_through_helpers(body), Vec::<String>::new(), "{body}");
    }
}

#[test]
fn a_helper_whose_descent_the_ladder_cannot_read_is_reported() {
    for body in [
        "SELECT authz.volatile_granted(min_role)",
        "SELECT authz.procedural_granted(min_role)",
        "SELECT authz.resources_with(min_role)",
        "SELECT authz.granted_any(min_role)",
        "SELECT authz.missing(min_role)",
        "SELECT granted.id FROM authz.missing(min_role) granted (id)",
        "SELECT granted.id FROM authz.granted(min_role) WITH ORDINALITY granted (id, n)",
        "SELECT authz.other_resources() FROM authz.granted(min_role) granted (id)",
        "SELECT DISTINCT ON (granted.id) granted.id FROM authz.granted(min_role) granted (id)",
        "WITH below (id) AS (SELECT authz.granted_below(min_role)) SELECT id FROM below",
        "SELECT edge.id FROM public.edges edge UNION VALUES ((SELECT 1 WHERE min_role = 'admin'))",
        "SELECT edge.id FROM public.edges edge
         JOIN public.grants permission ON permission.role <= min_role",
        "SELECT edge.id FROM public.edges edge
         JOIN authz.granted_below(min_role) granted (id) ON granted.id = edge.id",
        "SELECT listed.id FROM unnest(ARRAY[min_role::text::INT]) listed (id)",
        "SELECT edge.id FROM public.edges edge WHERE edge.parent_id = ANY (ARRAY[min_role::text::INT])",
        "SELECT edge.id FROM public.edges edge WHERE edge.parent_id = ANY (array(min_role))",
        "SELECT listed.id FROM (SELECT permission.resource_id AS id, NULL AS role
         FROM public.grants permission) listed WHERE listed.role >= min_role",
        "SELECT permission.resource_id FROM public.grants permission, public.grants other
         WHERE role >= min_role",
    ] {
        assert_eq!(exposed_through_helpers(body), ["writable()"], "{body}");
    }
}

#[test]
fn a_policy_passing_its_label_other_than_as_one_literal_is_not_nested() {
    for policy_set in [
        "authz.resources_with(current_setting('app.role')::authz.role)",
        "authz.resources_with(min_role => 'reader')",
    ] {
        assert_eq!(
            exposed_through_ladder(
                Deployment::default(),
                ROLE,
                "SELECT authz.granted(min_role)",
                policy_set
            ),
            ["writable()"],
            "{policy_set}"
        );
    }
}

#[test]
fn a_declared_set_nests_through_a_ladder_over_every_other_argument_alike() {
    let reported = |within: &str, policy_set: &str| {
        let declared = Deployment::default()
            .with_set_within("authz.resources_with('writer')", within)
            .expect("both sets parse");
        exposed_through_ladder(
            declared,
            ROLE_AND_HELPERS,
            "SELECT authz.granted(min_role)",
            policy_set,
        )
    };
    assert_eq!(
        reported(
            "authz.granted_in(1, 'writer')",
            "authz.granted_in(1, 'reader')"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        reported(
            "authz.granted_in(1, 'writer')",
            "authz.granted_in(2, 'reader')"
        ),
        ["writable()"]
    );
    assert_eq!(
        reported("authz.missing()", "authz.other_resources()"),
        ["writable()"]
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

/// Functions reported when `authz.kinded()` returns the resources `filter`
/// admits and `policy` is the read policy of `resources`, both free to test
/// pairs against `authz.capped()`.
fn exposed_through_pairs(filter: &str, policy: &str) -> Vec<String> {
    exposed(
        Deployment::default().with_app_role("app"),
        &format!(
            "CREATE ROLE app NOLOGIN;
             CREATE SCHEMA authz;
             CREATE TABLE caps (resource_id INT, kind TEXT);
             CREATE TABLE resources (id INT PRIMARY KEY, kind TEXT NOT NULL);
             ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
             GRANT SELECT ON resources TO app;
             ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
             ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO app;
             CREATE FUNCTION authz.capped() RETURNS TABLE (resource_id INT, kind TEXT)
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT cap.resource_id, cap.kind FROM public.caps cap $$;
             CREATE POLICY readable_resources ON resources FOR SELECT TO app USING ({policy});
             CREATE FUNCTION authz.kinded() RETURNS SETOF INT
               LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
                 SELECT resource.id FROM public.resources resource WHERE {filter} $$;"
        ),
    )
}

#[test]
fn a_column_fixed_to_a_literal_stands_for_it_in_a_tested_pair() {
    let by_kind = "(id, kind) IN (SELECT * FROM authz.capped())";
    let by_literal = "(id, 'organization') IN (SELECT * FROM authz.capped())";
    let literal_pair = "(resource.id, 'organization') IN (SELECT * FROM authz.capped())";
    let column_pair = "(resource.id, resource.kind) IN (SELECT * FROM authz.capped())";
    for (filter, policy) in [
        (
            format!("resource.kind = 'organization' AND {literal_pair}"),
            by_kind,
        ),
        (
            format!("'organization' = resource.kind AND {literal_pair}"),
            by_kind,
        ),
        (
            format!("resource.kind = 'organization' AND {column_pair}"),
            by_literal,
        ),
    ] {
        assert_eq!(
            exposed_through_pairs(&filter, policy),
            Vec::<String>::new(),
            "{filter}"
        );
    }
    for (filter, policy) in [
        (literal_pair.to_owned(), by_kind),
        (
            format!("resource.kind = 'project' AND {literal_pair}"),
            by_kind,
        ),
        (
            format!("resource.kind <> 'organization' AND {literal_pair}"),
            by_kind,
        ),
        (
            format!("resource.kind = 'project' AND {column_pair}"),
            by_literal,
        ),
    ] {
        assert_eq!(
            exposed_through_pairs(&filter, policy),
            ["kinded()"],
            "{filter}"
        );
    }
}
