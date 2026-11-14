//! Session-only write policy clauses.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const SCHEMA: &str = "
CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
CREATE TABLE docs (owner uuid);
CREATE TABLE admins (uid uuid);
CREATE VIEW session_view AS SELECT current_user AS who;
CREATE FUNCTION session_gate() RETURNS boolean LANGUAGE sql STABLE
AS $$ SELECT current_setting('app.tenant', true) IS NOT NULL $$;
CREATE FUNCTION table_gate() RETURNS boolean LANGUAGE sql STABLE
AS $$ SELECT EXISTS (SELECT 1 FROM admins WHERE uid = auth.uid()) $$;
CREATE FUNCTION indirect_gate() RETURNS boolean LANGUAGE sql STABLE
AS $$ SELECT table_gate() $$;
CREATE FUNCTION view_gate() RETURNS boolean LANGUAGE sql STABLE
AS $$ SELECT EXISTS (SELECT 1 FROM session_view) $$;
CREATE FUNCTION pl_gate() RETURNS boolean LANGUAGE plpgsql STABLE
AS $$ BEGIN RETURN EXISTS (SELECT 1 FROM admins); END $$;
CREATE FUNCTION atomic_gate() RETURNS boolean LANGUAGE sql STABLE
BEGIN ATOMIC SELECT EXISTS (SELECT 1 FROM admins); END;
CREATE FUNCTION definer_gate() RETURNS boolean LANGUAGE sql SECURITY DEFINER
AS $$ SELECT EXISTS (SELECT 1 FROM admins) $$;
";

fn messages(policy: &str) -> Vec<String> {
    let database =
        ParserDB::parse::<PostgreSqlDialect>(&format!("{SCHEMA} {policy}")).expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = PolicyWithoutRowReference::default().into();
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
fn session_only_write_clauses_name_their_commands() {
    for (policy, commands) in [
        ("FOR UPDATE USING (auth.uid() IS NOT NULL)", "UPDATE"),
        (
            "FOR DELETE USING (current_setting('app.tenant', true) IS NOT NULL)",
            "DELETE",
        ),
        ("FOR INSERT WITH CHECK (auth.uid() IS NOT NULL)", "INSERT"),
        (
            "FOR ALL USING (auth.uid() IS NOT NULL)",
            "INSERT, UPDATE, DELETE",
        ),
        ("FOR UPDATE USING (session_gate())", "UPDATE"),
        ("FOR DELETE USING (current_user = 'app')", "DELETE"),
        (
            "FOR UPDATE USING (owner = auth.uid()) WITH CHECK (session_gate())",
            "UPDATE",
        ),
        (
            "FOR ALL USING (owner = auth.uid()) WITH CHECK (session_gate())",
            "INSERT, UPDATE",
        ),
        (
            "FOR ALL USING (session_gate()) WITH CHECK (owner = auth.uid())",
            "UPDATE, DELETE",
        ),
        ("FOR DELETE USING ((SELECT current_user) = 'app')", "DELETE"),
    ] {
        let found = messages(&format!("CREATE POLICY gate ON docs {policy};"));
        assert_eq!(found.len(), 1, "{policy}");
        assert!(
            found[0].contains(&format!("decides {commands} by the session alone")),
            "{policy}: {}",
            found[0]
        );
    }
}

#[test]
fn read_constant_and_relation_dependent_clauses_are_unreported() {
    for policy in [
        "FOR SELECT USING (auth.uid() IS NOT NULL)",
        "FOR UPDATE USING (owner = auth.uid())",
        "FOR UPDATE USING (true)",
        "FOR UPDATE USING (false)",
        "FOR UPDATE USING (1 = 1)",
        "FOR UPDATE USING (owner = auth.uid() OR true)",
        "FOR DELETE USING (EXISTS (SELECT 1 FROM admins WHERE uid = auth.uid()))",
        "FOR DELETE USING (table_gate())",
        "FOR DELETE USING (indirect_gate())",
        "FOR DELETE USING (EXISTS (SELECT 1 FROM session_view))",
        "FOR DELETE USING (view_gate())",
        "FOR INSERT WITH CHECK (owner = auth.uid())",
        "FOR ALL",
        "FOR DELETE USING (pl_gate())",
        "FOR DELETE USING (atomic_gate())",
        "FOR DELETE USING (definer_gate())",
        "AS RESTRICTIVE FOR DELETE USING (session_gate())",
        "AS RESTRICTIVE FOR ALL USING (auth.uid() IS NOT NULL)",
    ] {
        assert!(
            messages(&format!("CREATE POLICY gate ON docs {policy};")).is_empty(),
            "{policy}"
        );
    }
}
