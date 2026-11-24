//! Policy-reachable recursive sets must constrain table-reading seeds.

use crate::rule_findings::findings;
use sqlippy::prelude::*;

const TABLES: &str = "CREATE ROLE authenticated;
CREATE TABLE memberships (id INT, parent_id INT, actor_id TEXT);
CREATE TABLE resources (id INT);
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;";

/// Builds a helper reached from a policy with the supplied recursive seed.
fn schema(seed: &str, parameters: &str, call: &str) -> String {
    format!(
        "{TABLES} CREATE FUNCTION visible_ids({parameters}) RETURNS SETOF INT LANGUAGE sql AS $$ WITH RECURSIVE reachable(id) AS ({seed} UNION SELECT memberships.id FROM memberships JOIN reachable ON memberships.parent_id = reachable.id) SELECT id FROM reachable $$; CREATE POLICY resources_read ON resources TO authenticated USING (id IN (SELECT visible_ids({call}))); "
    )
}

/// Counts the enabled rule's findings under the example deployment.
fn reported(schema: &str) -> usize {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    constrainer.set_deployment(Deployment::example());
    constrainer.set_rule_level("unseeded_policy_set", Level::Warn);
    findings(&constrainer, "unseeded_policy_set", schema).len()
}

#[test]
fn table_reading_unconstrained_seed_is_reported() {
    assert_eq!(reported(&schema("SELECT id FROM memberships", "", "")), 1);
}

#[test]
fn seed_constraints_and_tableless_seeds_pass() {
    for (seed, parameters, call) in [
        (
            "SELECT id FROM memberships WHERE actor_id = current_setting('app.user_id', true)",
            "",
            "",
        ),
        (
            "SELECT id FROM memberships WHERE actor_id = actor",
            "actor TEXT",
            "current_setting('app.user_id', true)",
        ),
        (
            "SELECT id FROM memberships WHERE actor_id = $1",
            "TEXT",
            "current_setting('app.user_id', true)",
        ),
        (
            "SELECT memberships.id FROM memberships JOIN resources ON resources.id = memberships.id AND memberships.actor_id = actor",
            "actor TEXT",
            "current_setting('app.user_id', true)",
        ),
        (
            "SELECT memberships.id FROM memberships JOIN resources ON resources.id = memberships.id WHERE memberships.actor_id = actor",
            "actor TEXT",
            "current_setting('app.user_id', true)",
        ),
        ("SELECT 1", "", ""),
    ] {
        assert_eq!(reported(&schema(seed, parameters, call)), 0, "{seed}");
    }
}

#[test]
fn projection_and_recursive_filters_do_not_constrain_the_seed() {
    for seed in [
        "SELECT id FROM memberships WHERE actor_id = 'fixed'",
        "SELECT CASE WHEN actor_id = current_setting('app.user_id', true) THEN id ELSE NULL END FROM memberships",
    ] {
        assert_eq!(reported(&schema(seed, "", "")), 1, "{seed}");
    }
}

#[test]
fn unreachable_functions_and_nonrecursive_sets_pass() {
    let unreachable = format!(
        "{TABLES} CREATE FUNCTION visible_ids() RETURNS SETOF INT LANGUAGE sql AS $$ WITH RECURSIVE reachable(id) AS (SELECT id FROM memberships UNION SELECT memberships.id FROM memberships JOIN reachable ON memberships.parent_id = reachable.id) SELECT id FROM reachable $$;"
    );
    assert_eq!(reported(&unreachable), 0);
    let nonrecursive = format!(
        "{TABLES} CREATE FUNCTION visible_ids() RETURNS SETOF INT LANGUAGE sql AS $$ WITH reachable AS (SELECT id FROM memberships) SELECT id FROM reachable $$; CREATE POLICY resources_read ON resources USING (id IN (SELECT visible_ids()));"
    );
    assert_eq!(reported(&nonrecursive), 0);
}

#[test]
fn helpers_reached_through_another_function_are_reported_once() {
    let direct = schema("SELECT id FROM memberships", "", "");
    let indirect = direct.replace("CREATE POLICY", "CREATE FUNCTION wrapped_ids() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT visible_ids() $$; CREATE POLICY").replace("USING (id IN (SELECT visible_ids()))", "USING (id IN (SELECT wrapped_ids()))");
    assert_eq!(reported(&indirect), 1);
}

#[test]
fn reviewed_global_sets_accept_a_function_allowance() {
    let database = ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(&schema(
        "SELECT id FROM memberships",
        "",
        "",
    ))
    .unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnseededPolicySet::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.allow_function("unseeded_policy_set", TargetName::new("visible_ids", false));
    assert!(constrainer.validate_schema(&database).is_ok());
}

#[test]
fn unrelated_function_allowances_are_unused() {
    let database = ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(&schema(
        "SELECT id FROM memberships",
        "",
        "",
    ))
    .unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnseededPolicySet::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.allow_function("unseeded_policy_set", TargetName::new("other", false));
    assert!(
        constrainer
            .diagnostics(&database)
            .iter()
            .any(|error| matches!(error, Error::UnusedAllowance(Allowance::Function(_))))
    );
}

#[test]
fn sql_atomic_and_plpgsql_bodies_are_checked() {
    let direct = schema("SELECT id FROM memberships", "", "");
    let atomic = direct
        .replace("LANGUAGE sql AS $$", "LANGUAGE sql BEGIN ATOMIC")
        .replace(
            "SELECT id FROM reachable $$;",
            "SELECT id FROM reachable; END;",
        );
    let procedural = direct
        .replace(
            "LANGUAGE sql AS $$",
            "LANGUAGE plpgsql AS $$ BEGIN RETURN QUERY",
        )
        .replace(
            "SELECT id FROM reachable $$;",
            "SELECT id FROM reachable; END $$;",
        );
    assert_eq!(reported(&atomic), 1);
    assert_eq!(reported(&procedural), 1);
}

#[test]
fn recursive_term_filter_does_not_constrain_the_seed() {
    let direct = schema("SELECT id FROM memberships", "", "");
    let filtered = direct.replace("memberships.parent_id = reachable.id)", "memberships.parent_id = reachable.id WHERE actor_id = current_setting('app.user_id', true))");
    assert_eq!(reported(&filtered), 1);
}

#[test]
fn function_allowances_respect_schema_and_cover_overloads() {
    let direct = schema("SELECT id FROM memberships", "", "");
    for target in [
        TargetName::new("visible_ids", false),
        TargetName::new("visible_ids", false).with_schema("public", false),
    ] {
        let database = ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(&format!("{direct} CREATE FUNCTION visible_ids(dummy INT) RETURNS SETOF INT LANGUAGE sql AS $$ SELECT visible_ids() $$;")).unwrap();
        let mut constrainer: GenericConstrainer<ParserDB> = UnseededPolicySet::default().into();
        constrainer.set_deployment(Deployment::example());
        constrainer.allow_function("unseeded_policy_set", target);
        assert!(constrainer.validate_schema(&database).is_ok());
    }
    let database = ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(&direct).unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnseededPolicySet::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.allow_function(
        "unseeded_policy_set",
        TargetName::new("visible_ids", false).with_schema("other", false),
    );
    assert_eq!(constrainer.diagnostics(&database).len(), 2);
}

#[test]
fn fixed_and_disabled_function_allowances_are_unused() {
    for (seed, level) in [
        ("SELECT 1", Level::Warn),
        ("SELECT id FROM memberships", Level::Allow),
    ] {
        let database =
            ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(&schema(seed, "", ""))
                .unwrap();
        let mut constrainer: GenericConstrainer<ParserDB> = UnseededPolicySet::default().into();
        constrainer.set_deployment(Deployment::example());
        constrainer.set_rule_level("unseeded_policy_set", level);
        constrainer.allow_function("unseeded_policy_set", TargetName::new("visible_ids", false));
        assert!(matches!(
            constrainer.validate_schema(&database),
            Err(Error::UnusedAllowance(Allowance::Function(_)))
        ));
    }
}

#[test]
fn return_expression_recursive_seed_is_checked() {
    let sql = schema("SELECT id FROM memberships", "", "")
        .replace(
            "RETURNS SETOF INT LANGUAGE sql AS $$",
            "RETURNS INT LANGUAGE sql RETURN (",
        )
        .replace("SELECT id FROM reachable $$;", "SELECT id FROM reachable);");
    assert_eq!(reported(&sql), 1);
}

#[test]
fn unconstrained_cross_join_and_derived_seeds_are_reported() {
    for seed in [
        "SELECT memberships.id FROM memberships CROSS JOIN resources",
        "SELECT memberships.id FROM memberships JOIN resources USING (id)",
        "SELECT id FROM (SELECT id FROM memberships) AS source",
    ] {
        assert_eq!(reported(&schema(seed, "", "")), 1, "{seed}");
    }
}

#[test]
fn unused_function_allowance_identifies_the_reviewed_exception() {
    let database =
        ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(&schema("SELECT 1", "", ""))
            .unwrap();
    let mut constrainer: GenericConstrainer<ParserDB> = UnseededPolicySet::default().into();
    constrainer.set_deployment(Deployment::example());
    constrainer.allow_function(
        "unseeded_policy_set",
        TargetName::new("visible_ids", false).with_schema("public", false),
    );
    let error = constrainer.validate_schema(&database).unwrap_err();
    let Error::UnusedAllowance(Allowance::Function(allowance)) = &error else {
        panic!("unexpected diagnostic {error}");
    };
    assert_eq!(allowance.rule(), "unseeded_policy_set");
    assert_eq!(allowance.function().schema(), Some("public"));
    assert_eq!(allowance.function().name(), "visible_ids");
    assert_eq!(
        error.to_string(),
        "Unused allowance: the allowance for unseeded_policy_set on function 'public.visible_ids' excuses no violation"
    );
}

/// Builds the schema for `seed` with `helpers` created before the recursive set.
fn with_helpers(helpers: &str, seed: &str) -> String {
    schema(seed, "", "").replacen(
        "CREATE FUNCTION visible_ids",
        &format!("{helpers} CREATE FUNCTION visible_ids"),
        1,
    )
}

#[test]
fn membership_in_a_caller_constrained_helper_constrains_the_seed() {
    let caller_ids = "CREATE FUNCTION caller_ids() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT id FROM memberships WHERE actor_id = current_setting('app.user_id', true) $$;";
    for seed in [
        "SELECT id FROM memberships WHERE id IN (SELECT caller_ids())",
        "SELECT id FROM memberships WHERE id IN (SELECT caller.id FROM caller_ids() caller(id))",
    ] {
        assert_eq!(reported(&with_helpers(caller_ids, seed)), 0, "{seed}");
    }
    let wrapped = format!(
        "{caller_ids} CREATE FUNCTION wrapped_ids() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT id FROM resources WHERE id IN (SELECT caller_ids()) $$;"
    );
    assert_eq!(
        reported(&with_helpers(
            &wrapped,
            "SELECT id FROM memberships WHERE id = ANY (ARRAY(SELECT wrapped_ids()))"
        )),
        0
    );
}

#[test]
fn helpers_without_a_caller_term_leave_the_seed_unconstrained() {
    for helpers in [
        "CREATE FUNCTION caller_ids() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT id FROM memberships WHERE actor_id = 'fixed' $$;",
        "CREATE FUNCTION caller_ids() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT actor_ids('fixed') $$; CREATE FUNCTION actor_ids(actor TEXT) RETURNS SETOF INT LANGUAGE sql AS $$ SELECT id FROM memberships WHERE actor_id = actor $$;",
        "CREATE FUNCTION caller_ids() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT other_ids() $$; CREATE FUNCTION other_ids() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT caller_ids() $$;",
    ] {
        assert_eq!(
            reported(&with_helpers(
                helpers,
                "SELECT id FROM memberships WHERE id IN (SELECT caller_ids())"
            )),
            1,
            "{helpers}"
        );
    }
}

#[test]
fn subqueries_reading_only_tables_do_not_constrain_the_seed() {
    assert_eq!(
        reported(&schema(
            "SELECT id FROM memberships WHERE id IN (SELECT id FROM resources)",
            "",
            ""
        )),
        1
    );
    assert_eq!(
        reported(&schema(
            "SELECT id FROM memberships WHERE actor_id = current_setting('app.user_id', true) AND id IN (SELECT id FROM resources)",
            "",
            ""
        )),
        0
    );
}

#[test]
fn helpers_the_seed_reaches_on_another_search_path_are_not_followed() {
    let helpers = "CREATE SCHEMA private; CREATE FUNCTION private.caller_ids() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT id FROM memberships $$; CREATE FUNCTION caller_ids() RETURNS SETOF INT LANGUAGE sql AS $$ SELECT id FROM memberships WHERE actor_id = current_setting('app.user_id', true) $$;";
    let seed = "SELECT id FROM memberships WHERE id IN (SELECT caller_ids())";
    assert_eq!(reported(&with_helpers(helpers, seed)), 0);
    let elsewhere = with_helpers(helpers, seed).replace(
        "RETURNS SETOF INT LANGUAGE sql AS $$ WITH RECURSIVE",
        "RETURNS SETOF INT LANGUAGE sql SET search_path = private, public AS $$ WITH RECURSIVE",
    );
    assert_eq!(reported(&elsewhere), 1);
}
