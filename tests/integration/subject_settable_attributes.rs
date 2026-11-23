//! Write policies on authority tables that let a row's subject set an
//! attribute column other policies test, observed through the public
//! constrainer API. Every flagged and passing shape below was measured on
//! PostgreSQL 17.11 and 18.6.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const CREDENTIAL: &str = "current_setting('app.user_id', true)";

const SCHEMA: &str = "
    CREATE ROLE app; CREATE ROLE editors; CREATE ROLE other;
    CREATE TABLE profiles (id TEXT PRIMARY KEY, display_name TEXT, is_admin BOOL,
      role TEXT, level INT);
    CREATE TABLE docs (id INT);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;";

/// Docs readable by admins, as profiles say.
const ADMIN_READ: &str = "CREATE POLICY docs_admin ON docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM profiles p WHERE p.id = CRED AND p.is_admin));";

/// Level and object of every finding of the rule.
fn findings<C: Constrainer<Database = ParserDB>>(constrainer: &C, sql: &str) -> Vec<String> {
    let sql = format!("{SCHEMA}{sql}").replace("CRED", CREDENTIAL);
    let database = ParserDB::parse::<PostgreSqlDialect>(&sql).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation)
                if violation.rule().name == "subject_settable_attribute" =>
            {
                Some(format!("{:?} {}", violation.level(), violation.object()))
            }
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn reported_for(deployment: Deployment, sql: &str) -> Vec<String> {
    let mut constrainer: GenericConstrainer<ParserDB> = SubjectSettableAttribute::default().into();
    constrainer.set_deployment(
        deployment
            .with_credential(CREDENTIAL)
            .expect("credential parses"),
    );
    findings(&constrainer, sql)
}

fn reported(sql: &str) -> Vec<String> {
    reported_for(Deployment::default().with_app_role("app"), sql)
}

/// The update policy measured open in the request's example.
const OPEN_UPDATE: &str = "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED);";

#[test]
fn a_write_admitting_the_subject_and_leaving_an_attribute_free_is_reported() {
    for write in [
        OPEN_UPDATE,
        "CREATE POLICY w ON profiles FOR INSERT WITH CHECK (id = CRED);",
        "CREATE POLICY w ON profiles FOR ALL USING (CRED = profiles.id);",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND is_admin = true);",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND is_admin IN (true, false));",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND is_admin = (true)::BOOLEAN);",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND lower(display_name) = 'x');",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND (is_admin = false OR display_name = 'x'));",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND role = 'member');",
        "CREATE POLICY w ON profiles FOR INSERT
           WITH CHECK ((id = CRED AND NOT is_admin) OR (id = CRED));",
        "CREATE POLICY w ON profiles FOR INSERT
           WITH CHECK (((display_name = 'x') OR (id = CRED AND NOT is_admin)) OR CRED = id);",
    ] {
        assert_eq!(
            reported(&format!("{ADMIN_READ} {write}")),
            ["Warn profiles.w"],
            "{write}"
        );
    }
}

#[test]
fn a_fixed_attribute_passes() {
    for write in [
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND NOT is_admin);",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND is_admin IS FALSE);",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND (is_admin) = false);",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND false = profiles.is_admin);",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (id = CRED AND is_admin IN (false));",
        "CREATE POLICY w ON profiles FOR DELETE USING (id = CRED);",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (display_name <> '');",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED)
           WITH CHECK (EXISTS (SELECT 1 FROM docs WHERE profiles.id = CRED));",
        "CREATE POLICY w ON profiles AS RESTRICTIVE FOR UPDATE USING (id = CRED);",
        "CREATE POLICY w ON profiles FOR INSERT
           WITH CHECK ((id = CRED AND NOT is_admin) OR (CRED = id AND is_admin IS FALSE));",
        "CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED);
         CREATE POLICY g ON profiles AS RESTRICTIVE FOR UPDATE WITH CHECK (NOT is_admin);",
    ] {
        assert_eq!(
            reported(&format!("{ADMIN_READ} {write}")),
            Vec::<String>::new(),
            "{write}"
        );
    }
}

#[test]
fn a_restrictive_guard_for_other_roles_or_commands_does_not_close_the_gap() {
    for guard in [
        "CREATE POLICY g ON profiles AS RESTRICTIVE FOR UPDATE TO other WITH CHECK (NOT is_admin);",
        "CREATE POLICY g ON profiles AS RESTRICTIVE FOR INSERT WITH CHECK (NOT is_admin);",
        "CREATE POLICY g ON profiles AS RESTRICTIVE FOR UPDATE WITH CHECK (id = CRED);",
    ] {
        assert_eq!(
            reported(&format!("{ADMIN_READ} {OPEN_UPDATE} {guard}")),
            ["Warn profiles.w"],
            "{guard}"
        );
    }
}

#[test]
fn each_or_arm_admitting_the_subject_is_judged_by_its_own_pins() {
    let schema = "
        CREATE TABLE orgs (id INT PRIMARY KEY, founder TEXT NOT NULL);
        CREATE TABLE members (org_id INT NOT NULL REFERENCES orgs (id), member TEXT NOT NULL,
          state TEXT NOT NULL, PRIMARY KEY (org_id, member));
        CREATE TABLE files (org_id INT);
        ALTER TABLE files ENABLE ROW LEVEL SECURITY;
        ALTER TABLE members ENABLE ROW LEVEL SECURITY;
        CREATE POLICY files_read ON files FOR SELECT TO app USING (org_id IN (
          SELECT org_id FROM members WHERE member = CRED AND state = 'active'));";
    let admin = "(org_id IN (SELECT org_id FROM members WHERE member = CRED AND state = 'admin'))";
    let founder = "(member = CRED AND state = 'active'
        AND org_id IN (SELECT id FROM orgs WHERE founder = CRED))";
    for (check, expected) in [
        (format!("{admin} OR {founder}"), Vec::<&str>::new()),
        (
            format!("{admin} OR member = CRED"),
            vec!["Warn members.join_org"],
        ),
    ] {
        assert_eq!(
            reported(&format!(
                "{schema} CREATE POLICY join_org ON members FOR INSERT TO app WITH CHECK ({check});"
            )),
            expected,
            "{check}"
        );
    }
}

#[test]
fn attributes_are_the_columns_an_authority_read_tests_against_literals() {
    for (read, write) in [
        (
            "p.role = 'admin'",
            "WITH CHECK (id = CRED AND role IN ('member', 'viewer'))",
        ),
        ("'admin' = p.role", "WITH CHECK (id = CRED AND role = 'x')"),
        (
            "p.role <> 'banned'",
            "WITH CHECK (id = CRED AND role = 'x')",
        ),
        (
            "p.role IN ('admin', 'owner')",
            "WITH CHECK (id = CRED AND role = 'x')",
        ),
        (
            "p.role = ANY (ARRAY['admin', 'owner'])",
            "WITH CHECK (id = CRED AND role = 'x')",
        ),
        ("p.level >= 3", "WITH CHECK (id = CRED AND level = 1)"),
        (
            "p.is_admin IS TRUE",
            "WITH CHECK (id = CRED AND NOT is_admin)",
        ),
        ("NOT p.is_admin", "WITH CHECK (id = CRED AND NOT is_admin)"),
        (
            "(p.is_admin OR p.role = 'owner')",
            "WITH CHECK (id = CRED AND NOT is_admin AND role = 'x')",
        ),
        (
            "p.role = 'admin'::TEXT",
            "WITH CHECK (id = CRED AND role = 'x')",
        ),
        (
            "p.role = TEXT 'admin'",
            "WITH CHECK (id = CRED AND role = TEXT 'x')",
        ),
    ] {
        let schema = format!(
            "CREATE POLICY docs_read ON docs FOR SELECT USING (
               EXISTS (SELECT 1 FROM profiles p WHERE p.id = CRED AND {read}));"
        );
        assert_eq!(
            reported(&format!("{schema} {OPEN_UPDATE}")),
            ["Warn profiles.w"],
            "{read}"
        );
        assert_eq!(
            reported(&format!(
                "{schema} CREATE POLICY w ON profiles FOR UPDATE USING (id = CRED) {write};"
            )),
            Vec::<String>::new(),
            "{read} fixed by {write}"
        );
    }
}

#[test]
fn columns_tested_against_no_literal_or_outside_an_authority_read_are_not_attributes() {
    for read in [
        "CREATE POLICY docs_read ON docs FOR SELECT USING (
           EXISTS (SELECT 1 FROM profiles p WHERE p.id = CRED AND p.role = p.display_name));",
        "CREATE POLICY docs_read ON docs FOR SELECT USING (
           EXISTS (SELECT 1 FROM profiles p WHERE p.is_admin));",
        "CREATE FUNCTION authz.admin_ids(wanted TEXT) RETURNS SETOF TEXT LANGUAGE sql STABLE
           AS $$ SELECT id FROM profiles WHERE id = current_setting('app.user_id', true)
           AND role = $1 $$;
         CREATE POLICY docs_read ON docs FOR SELECT USING (
           CRED IN (SELECT authz.admin_ids('admin')));",
    ] {
        assert_eq!(
            reported(&format!("CREATE SCHEMA authz; {read} {OPEN_UPDATE}")),
            Vec::<String>::new(),
            "{read}"
        );
    }
}

#[test]
fn an_attribute_tested_in_a_helper_body_is_read() {
    assert_eq!(
        reported(&format!(
            "CREATE SCHEMA authz;
             CREATE FUNCTION authz.admin_ids() RETURNS SETOF TEXT LANGUAGE sql STABLE
               AS $$ SELECT id FROM profiles WHERE id = current_setting('app.user_id', true)
               AND role = 'admin' $$;
             CREATE POLICY docs_read ON docs FOR SELECT USING (
               CRED IN (SELECT authz.admin_ids()));
             {OPEN_UPDATE}"
        )),
        ["Warn profiles.w"]
    );
}

#[test]
fn a_scalar_return_used_in_arithmetic_does_not_make_its_projection_an_attribute() {
    for (expression, expected) in [
        ("authz.subject_level() + 1 > 0", Vec::<String>::new()),
        (
            "authz.subject_level() > 0",
            vec!["Warn profiles.w".to_owned()],
        ),
    ] {
        assert_eq!(
            reported(&format!(
                "CREATE SCHEMA authz;
                 CREATE FUNCTION authz.subject_level() RETURNS INT LANGUAGE sql STABLE
                   RETURN (SELECT level FROM profiles WHERE id = CRED);
                 CREATE POLICY docs_read ON docs FOR SELECT USING ({expression});
                 {OPEN_UPDATE}"
            )),
            expected,
            "{expression}"
        );
    }
}

#[test]
fn an_attribute_tested_in_a_scalar_helper_body_is_read() {
    for (helper, call) in [
        (
            "CREATE FUNCTION authz.can_share(target TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
               SECURITY DEFINER SET search_path = public, pg_temp
               AS $$ SELECT EXISTS (SELECT 1 FROM public.profiles WHERE id = target
               AND id = current_setting('app.user_id', true) AND is_admin) $$;",
            "authz.can_share(id::TEXT)",
        ),
        (
            "CREATE FUNCTION authz.can_share(target TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
               SECURITY DEFINER SET search_path = public, pg_temp
               AS $$ SELECT is_admin FROM profiles WHERE id = target
               AND id = current_setting('app.user_id', true) $$;",
            "authz.can_share(id::TEXT)",
        ),
        (
            "CREATE FUNCTION authz.can_share(target TEXT) RETURNS INT LANGUAGE sql STABLE
               AS $$ SELECT 1 FROM profiles WHERE id = target
               AND current_setting('app.user_id', true) = id AND role = 'admin' $$;",
            "authz.can_share(id::TEXT) IS NOT NULL",
        ),
        (
            "CREATE FUNCTION authz.role_of() RETURNS TEXT LANGUAGE sql STABLE
               AS $$ SELECT role FROM profiles WHERE id = current_setting('app.user_id', true) $$;",
            "authz.role_of() = 'admin'",
        ),
        (
            "CREATE FUNCTION authz.can_share(target TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
               RETURN EXISTS (SELECT 1 FROM profiles WHERE id = target
               AND id = current_setting('app.user_id', true) AND is_admin);",
            "authz.can_share(id::TEXT)",
        ),
        (
            "CREATE FUNCTION authz.can_share(target TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
               BEGIN ATOMIC SELECT is_admin FROM profiles WHERE id = target
               AND id = current_setting('app.user_id', true); END;",
            "NOT authz.can_share(id::TEXT) IS FALSE",
        ),
    ] {
        assert_eq!(
            reported(&format!(
                "CREATE SCHEMA authz; {helper}
                 CREATE POLICY docs_read ON docs FOR SELECT USING ({call});
                 {OPEN_UPDATE}"
            )),
            ["Warn profiles.w"],
            "{helper}"
        );
    }
}

#[test]
fn a_value_a_scalar_helper_returns_without_a_test_is_no_attribute() {
    assert_eq!(
        reported(&format!(
            "CREATE SCHEMA authz;
             CREATE FUNCTION authz.role_of() RETURNS TEXT LANGUAGE sql STABLE
               AS $$ SELECT role FROM profiles WHERE id = current_setting('app.user_id', true) $$;
             CREATE POLICY docs_read ON docs FOR SELECT USING (authz.role_of() IS NOT NULL);
             {OPEN_UPDATE}"
        )),
        Vec::<String>::new()
    );
}

/// The membership whose `writers_can_share` a scalar definer helper tests,
/// with the subject's update granted the flag.
const SHARING: &str = "
    CREATE ROLE authz_writer;
    CREATE TABLE memberships (id INT PRIMARY KEY, actor_id UUID NOT NULL,
      writers_can_share BOOLEAN NOT NULL DEFAULT false);
    CREATE TABLE documents (id INT PRIMARY KEY, membership_id INT NOT NULL REFERENCES memberships (id));
    ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
    ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
    CREATE FUNCTION can_share(target_id INT) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
      SET search_path = public, pg_temp AS $$ SELECT EXISTS (SELECT 1 FROM public.memberships
      WHERE id = target_id AND actor_id = NULLIF(current_setting('app.user_id', true), '')::uuid
      AND writers_can_share) $$;
    CREATE POLICY sharing ON documents FOR SELECT TO app USING (can_share(membership_id));
    CREATE POLICY own_read ON memberships FOR SELECT TO app
      USING (actor_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
    CREATE POLICY own_write ON memberships FOR UPDATE TO app
      USING (actor_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
      WITH CHECK (actor_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
    REVOKE ALL ON memberships FROM app;
    GRANT SELECT ON memberships TO app;";

#[test]
fn a_flag_a_scalar_definer_helper_tests_is_withheld_only_by_revoking_it() {
    let mut constrainer: GenericConstrainer<ParserDB> = SubjectSettableAttribute::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_app_role("app")
            .with_credential("NULLIF(current_setting('app.user_id', true), '')")
            .expect("credential parses"),
    );
    assert_eq!(
        findings(
            &constrainer,
            &format!("{SHARING} GRANT UPDATE (writers_can_share) ON memberships TO app;")
        ),
        ["Warn memberships.own_write"]
    );
    assert_eq!(
        findings(
            &constrainer,
            &format!(
                "{SHARING} GRANT UPDATE (writers_can_share) ON memberships TO authz_writer;
                 CREATE POLICY trusted_write ON memberships FOR UPDATE TO authz_writer
                   USING (true) WITH CHECK (true);"
            )
        ),
        Vec::<String>::new()
    );
}

/// Takes table-wide `UPDATE` from `app` and grants it the display name.
const WITHHELD: &str = "REVOKE UPDATE ON profiles FROM app;
    GRANT UPDATE (display_name) ON profiles TO app;";

#[test]
fn a_privilege_the_schema_takes_from_the_writers_excuses_the_attribute() {
    for write in [
        OPEN_UPDATE,
        "CREATE POLICY w ON profiles FOR UPDATE TO app USING (id = CRED);",
    ] {
        assert_eq!(
            reported(&format!("{ADMIN_READ} {write} {WITHHELD}")),
            Vec::<String>::new(),
            "{write}"
        );
    }
    assert_eq!(
        reported(&format!(
            "{ADMIN_READ} CREATE POLICY w ON profiles FOR INSERT WITH CHECK (id = CRED);
             REVOKE ALL ON profiles FROM app;"
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        reported(&format!(
            "{ADMIN_READ} ALTER TABLE profiles OWNER TO editors; {OPEN_UPDATE}
             REVOKE UPDATE ON profiles FROM app GRANTED BY editors;"
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        reported_for(
            Deployment::default()
                .with_app_role("app")
                .with_anonymous_role("anon"),
            &format!(
                "{ADMIN_READ} {OPEN_UPDATE} {WITHHELD} CREATE ROLE anon;
                 REVOKE UPDATE ON profiles FROM anon;"
            )
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_privilege_left_reaching_a_writer_keeps_the_finding() {
    for grants in [
        "REVOKE UPDATE ON profiles FROM PUBLIC; GRANT UPDATE (display_name) ON profiles TO app;",
        "GRANT UPDATE ON profiles TO other WITH GRANT OPTION;
         REVOKE UPDATE ON profiles FROM app GRANTED BY other;",
        "REVOKE INSERT ON profiles FROM app;",
        "REVOKE UPDATE ON profiles FROM app; GRANT UPDATE ON profiles TO editors;
         GRANT editors TO app;",
        "REVOKE UPDATE ON profiles FROM app; GRANT UPDATE ON profiles TO PUBLIC;",
        "REVOKE UPDATE ON profiles FROM app; GRANT ALL ON profiles TO app;",
        "REVOKE UPDATE ON profiles FROM app;
         GRANT UPDATE (display_name, is_admin) ON profiles TO app;",
        "REVOKE UPDATE ON profiles FROM app; GRANT UPDATE (\"is_admin\") ON profiles TO PUBLIC;",
    ] {
        assert_eq!(
            reported(&format!("{ADMIN_READ} {OPEN_UPDATE} {grants}")),
            ["Warn profiles.w"],
            "{grants}"
        );
    }
    for write in [
        "CREATE POLICY w ON profiles FOR ALL USING (id = CRED);",
        "CREATE POLICY w ON profiles FOR UPDATE TO app, other USING (id = CRED);",
    ] {
        assert_eq!(
            reported(&format!("{ADMIN_READ} {write} {WITHHELD}")),
            ["Warn profiles.w"],
            "{write}"
        );
    }
    assert_eq!(
        reported_for(
            Deployment::default(),
            &format!("{ADMIN_READ} {OPEN_UPDATE} {WITHHELD}")
        ),
        ["Warn profiles.w"]
    );
    assert_eq!(
        reported_for(
            Deployment::default()
                .with_app_role("app")
                .with_anonymous_role("anon"),
            &format!("{ADMIN_READ} {OPEN_UPDATE} {WITHHELD} CREATE ROLE anon;")
        ),
        ["Warn profiles.w"]
    );
    assert_eq!(
        reported_for(
            Deployment::default()
                .with_app_role("app")
                .with_anonymous_role("anon"),
            &format!("{ADMIN_READ} {OPEN_UPDATE} {WITHHELD}")
        ),
        ["Warn profiles.w"]
    );
}

#[test]
fn the_finding_names_every_free_attribute_and_command_once() {
    let mut constrainer: GenericConstrainer<ParserDB> = SubjectSettableAttribute::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_credential(CREDENTIAL)
            .expect("credential parses"),
    );
    let sql = format!(
        "{SCHEMA} CREATE POLICY docs_read ON docs FOR SELECT USING (
           EXISTS (SELECT 1 FROM profiles p WHERE p.id = CRED AND (p.is_admin OR p.role = 'owner')));
         CREATE POLICY w ON profiles FOR ALL USING (id = CRED);"
    )
    .replace("CRED", CREDENTIAL);
    let database = ParserDB::parse::<PostgreSqlDialect>(&sql).expect("schema parses");
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| error.to_string())
        .collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(
        messages[0].contains("set 'is_admin', 'role', which policies test"),
        "{}",
        messages[0]
    );
    assert!(
        messages[0].contains("revoke table-wide INSERT and UPDATE on 'profiles'"),
        "{}",
        messages[0]
    );
}

#[test]
fn the_rule_needs_declared_credentials() {
    let constrainer: GenericConstrainer<ParserDB> = SubjectSettableAttribute::default().into();
    let sql = format!("{SCHEMA}{ADMIN_READ} {OPEN_UPDATE}").replace("CRED", CREDENTIAL);
    let database = ParserDB::parse::<PostgreSqlDialect>(&sql).expect("schema parses");
    assert!(constrainer.validate_schema(&database).is_ok());
    assert_eq!(
        constrainer
            .inactive_rules(Engine::PostgreSql)
            .iter()
            .map(|inactive| inactive.rule().name)
            .collect::<Vec<_>>(),
        ["subject_settable_attribute"]
    );
}

#[test]
fn scalar_helper_scope_values_are_not_authority_attributes() {
    for (body, predicate, result_type) in [
        (
            "RETURN (SELECT level FROM profiles WHERE id = current_setting('app.user_id', true))",
            "id = own_role()",
            "INT",
        ),
        (
            "AS $$ SELECT * FROM (SELECT role FROM profiles WHERE id = current_setting('app.user_id', true)) selected $$",
            "own_role() = 'admin'",
            "TEXT",
        ),
    ] {
        assert_eq!(
            reported(&format!(
                "CREATE FUNCTION own_role() RETURNS {result_type} LANGUAGE sql STABLE {body};
                 CREATE POLICY docs_read ON docs USING ({predicate});
                 {OPEN_UPDATE}"
            )),
            Vec::<String>::new(),
            "{body}"
        );
    }
}

#[test]
fn catalog_atomic_helper_preserves_authority_attributes() {
    use pg_diesel::PgDieselDatabase;

    let (_container, database) = crate::live_catalog::catalog(
        "public",
        &format!(
            "{SCHEMA}
         CREATE FUNCTION own_role() RETURNS TEXT LANGUAGE sql STABLE
         BEGIN ATOMIC SELECT role FROM profiles WHERE id = {CREDENTIAL}; END;
         CREATE POLICY docs_read ON docs USING (own_role() = 'admin');
         CREATE POLICY w ON profiles FOR UPDATE USING (id = {CREDENTIAL});
         GRANT SELECT, UPDATE ON profiles TO app;"
        ),
    );
    let mut constrainer: GenericConstrainer<PgDieselDatabase> =
        SubjectSettableAttribute::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_app_role("app")
            .with_credential("current_setting('app.user_id'::text, true)")
            .unwrap(),
    );
    let diagnostics = constrainer.diagnostics(&database);
    let [Error::Violation(violation)] = diagnostics.as_slice() else {
        panic!("{diagnostics:?}");
    };
    assert_eq!(violation.rule().name, "subject_settable_attribute");
    assert_eq!(violation.object().to_string(), "profiles.w");
}
