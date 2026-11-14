//! Policies with the same definition under different names, observed through
//! the public constrainer API.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const DOCS: &str = "
    CREATE ROLE anon;
    CREATE ROLE authenticated;
    CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT, tenant INT, is_public BOOL);
    ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";

/// Objects of every violation the rule raises on `policies` declared on
/// `docs`.
fn findings(policies: &str) -> Vec<String> {
    findings_with(ParseOptions::default(), policies)
}

/// [`findings`] in a schema parsed with `options`.
fn findings_with(options: ParseOptions, policies: &str) -> Vec<String> {
    let constrainer: GenericConstrainer<ParserDB> = DuplicatePolicy::default().into();
    constrainer
        .diagnostics(
            &options
                .parse::<PostgreSqlDialect>(&format!("{DOCS} {policies}"))
                .expect("schema parses"),
        )
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().name, "duplicate_policy");
                violation.object().to_owned()
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

#[test]
fn a_restrictive_policy_repeated_under_another_name_is_reported() {
    assert_eq!(
        findings(
            "CREATE POLICY tenant_floor ON docs AS RESTRICTIVE USING (tenant = 1);
             CREATE POLICY tenant_guard ON docs AS RESTRICTIVE USING (tenant = 1);"
        ),
        ["docs.tenant_floor -> docs.tenant_guard"]
    );
}

#[test]
fn a_permissive_policy_repeated_under_another_name_is_reported() {
    assert_eq!(
        findings(
            "CREATE POLICY own ON docs FOR SELECT TO anon, authenticated USING ((owner = current_user));
             CREATE POLICY own_again ON docs FOR SELECT TO authenticated, anon USING (owner = current_user);"
        ),
        ["docs.own -> docs.own_again"]
    );
}

#[test]
fn policies_differing_in_any_part_of_their_definition_are_not_reported() {
    for second in [
        "CREATE POLICY b ON docs AS RESTRICTIVE FOR SELECT USING (owner = current_user);",
        "CREATE POLICY b ON docs FOR UPDATE USING (owner = current_user);",
        "CREATE POLICY b ON docs FOR SELECT TO anon USING (owner = current_user);",
        "CREATE POLICY b ON docs FOR SELECT USING (is_public);",
    ] {
        assert_eq!(
            findings(&format!(
                "CREATE POLICY a ON docs FOR SELECT USING (owner = current_user); {second}"
            )),
            Vec::<String>::new(),
            "{second}"
        );
    }
    assert_eq!(
        findings(
            "CREATE POLICY a ON docs FOR UPDATE USING (owner = current_user) WITH CHECK (is_public);
             CREATE POLICY b ON docs FOR UPDATE USING (owner = current_user);"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn three_copies_are_reported_against_the_first() {
    assert_eq!(
        findings(
            "CREATE POLICY a ON docs FOR SELECT USING (is_public);
             CREATE POLICY b ON docs FOR SELECT USING (is_public);
             CREATE POLICY c ON docs FOR SELECT USING (is_public);"
        ),
        ["docs.a -> docs.b", "docs.a -> docs.c"]
    );
}

#[test]
fn restrictive_copies_running_a_volatile_function_are_not_reported() {
    const COINFLIP: &str = "
        CREATE SCHEMA app;
        CREATE FUNCTION app.coinflip(a INT, b INT) RETURNS BOOL LANGUAGE sql VOLATILE
            AS 'SELECT random() < 0.5';
        CREATE OPERATOR app.<?> (LEFTARG = INT, RIGHTARG = INT, FUNCTION = app.coinflip);
        CREATE OPERATOR ~~ (LEFTARG = INT, RIGHTARG = INT, FUNCTION = app.coinflip);
        CREATE OPERATOR !~~ (LEFTARG = INT, RIGHTARG = INT, FUNCTION = app.coinflip);";
    for check in [
        "random() < 0.5",
        "undeclared_flag()",
        "tenant OPERATOR(app.<?>) 1",
        "tenant OPERATOR(app.<%>) 1",
        "tenant ~~ ANY (ARRAY[1])",
        "tenant ~~ ALL (ARRAY[1])",
        "tenant LIKE 1",
        "tenant NOT LIKE 1",
    ] {
        assert_eq!(
            findings(&format!(
                "{COINFLIP}
                 CREATE POLICY a ON docs AS RESTRICTIVE FOR INSERT WITH CHECK ({check});
                 CREATE POLICY b ON docs AS RESTRICTIVE FOR INSERT WITH CHECK ({check});"
            )),
            Vec::<String>::new(),
            "{check}"
        );
    }
    assert_eq!(
        findings(
            "CREATE POLICY a ON docs AS RESTRICTIVE FOR INSERT WITH CHECK (upper(owner) = 'A');
             CREATE POLICY b ON docs AS RESTRICTIVE FOR INSERT WITH CHECK (upper(owner) = 'A');
             CREATE POLICY c ON docs FOR INSERT WITH CHECK (random() < 0.5);
             CREATE POLICY d ON docs FOR INSERT WITH CHECK (random() < 0.5);"
        ),
        ["docs.a -> docs.b", "docs.c -> docs.d"]
    );
}

#[test]
fn restrictive_copies_casting_through_a_volatile_function_are_not_reported() {
    let app = |name| TargetName::new(name, false).with_schema("app", false);
    let int = || TargetName::new("int4", false).with_schema("pg_catalog", false);
    let options = || {
        ParseOptions::default().with_postgres_catalog(PostgresCatalog::default().with_cast(
            PostgresCatalogCast::through_function(
                int(),
                app("coin"),
                CastContext::Explicit,
                app("flip"),
                [int()],
            ),
        ))
    };
    let copies = |check: &str| {
        format!(
            "CREATE SCHEMA app;
             CREATE TYPE app.coin AS (v INT);
             CREATE FUNCTION app.flip(INT) RETURNS app.coin LANGUAGE sql VOLATILE
                 AS 'SELECT ROW((random() < 0.5)::INT)::app.coin';
             CREATE POLICY a ON docs AS RESTRICTIVE FOR INSERT WITH CHECK ({check});
             CREATE POLICY b ON docs AS RESTRICTIVE FOR INSERT WITH CHECK ({check});"
        )
    };
    for check in [
        "(tenant::app.coin).v = 1",
        "((ARRAY[tenant]::app.coin[])[1]).v = 1",
    ] {
        assert_eq!(
            findings_with(options(), &copies(check)),
            Vec::<String>::new(),
            "{check}"
        );
    }
    for check in ["tenant::BIGINT = 1", "(ARRAY[tenant]::BIGINT[])[1] = 1"] {
        assert_eq!(
            findings_with(options(), &copies(check)),
            ["docs.a -> docs.b"],
            "{check}"
        );
    }
}
