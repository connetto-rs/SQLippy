//! Policy read cycles and policy allowances observed through the public constrainer API.

use sql_rules::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

fn parse(sql: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses")
}

fn cycles(
    constrainer: &GenericConstrainer<ParserDB>,
    database: &ParserDB,
) -> Vec<(String, Level, Vec<String>)> {
    constrainer
        .diagnostics(database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                let Location::Policies(sites) = violation.location() else {
                    panic!("a policy finding is located on policies");
                };
                let sites = sites
                    .iter()
                    .map(|site| format!("{}.{}", site.table().table_name(), site.policy().name()))
                    .collect();
                (violation.rule().name.to_owned(), violation.level(), sites)
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn cycle_rules() -> GenericConstrainer<ParserDB> {
    let mut constrainer = GenericConstrainer::<ParserDB>::default();
    constrainer.register_schema_rule(Box::new(PolicyReadCycle::default()));
    constrainer.register_schema_rule(Box::new(LatentPolicyReadCycle::default()));
    constrainer.register_schema_rule(Box::new(FunctionMediatedPolicyCycle::default()));
    constrainer
}

const SELF_LOOP: &str = "
    CREATE TABLE memberships (owner_id INT, member_id TEXT, role TEXT);
    ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
    CREATE POLICY memberships_admin ON memberships FOR ALL USING (
      EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = memberships.owner_id
              AND m.member_id = current_setting('app.user_id', true) AND m.role = 'admin'));";

#[test]
fn a_policy_reading_its_own_table_is_a_denied_cycle() {
    let database = parse(SELF_LOOP);
    assert_eq!(
        cycles(&cycle_rules(), &database),
        [(
            "PolicyReadCycle".to_owned(),
            Level::Deny,
            vec!["memberships.memberships_admin".to_owned()]
        )]
    );
}

#[test]
fn a_two_table_cycle_is_reported_once_with_both_policies_in_order() {
    let database = parse(
        "CREATE TABLE members (owner INT);
         CREATE TABLE owners (id INT);
         ALTER TABLE members ENABLE ROW LEVEL SECURITY;
         ALTER TABLE owners ENABLE ROW LEVEL SECURITY;
         CREATE POLICY read_members ON members FOR SELECT USING (owner IN (SELECT id FROM owners));
         CREATE POLICY read_owners ON owners FOR SELECT USING (EXISTS (SELECT 1 FROM members m WHERE m.owner = owners.id));",
    );
    let found = cycles(&cycle_rules(), &database);
    assert_eq!(found.len(), 1);
    let (rule, level, sites) = &found[0];
    assert_eq!((rule.as_str(), *level), ("PolicyReadCycle", Level::Deny));
    let mut rotated = sites.clone();
    let start = rotated
        .iter()
        .position(|site| site == "members.read_members")
        .expect("members listed");
    rotated.rotate_left(start);
    assert_eq!(rotated, ["members.read_members", "owners.read_owners"]);
}

#[test]
fn a_write_self_read_is_valid_when_select_policies_hold_no_subquery() {
    let database = parse(
        "CREATE TABLE memberships (owner_id INT, member_id TEXT, role TEXT);
         ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
         CREATE POLICY memberships_read ON memberships FOR SELECT USING (member_id = current_setting('app.user_id', true));
         CREATE POLICY memberships_insert ON memberships FOR INSERT WITH CHECK (
           EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = memberships.owner_id
                   AND m.member_id = current_setting('app.user_id', true) AND m.role = 'admin'));",
    );
    assert_eq!(cycles(&cycle_rules(), &database), []);
}

#[test]
fn a_write_self_read_is_a_cycle_when_a_select_policy_holds_a_subquery() {
    let database = parse(
        "CREATE TABLE organization_admins (organization_id INT, admin_id TEXT);
         CREATE TABLE team_admins (team_id INT, organization_id INT, admin_id TEXT);
         ALTER TABLE team_admins ENABLE ROW LEVEL SECURITY;
         CREATE POLICY team_admins_read ON team_admins FOR SELECT USING (
           admin_id = current_setting('app.user_id', true)
           OR EXISTS (SELECT 1 FROM organization_admins a WHERE a.organization_id = team_admins.organization_id
                      AND a.admin_id = current_setting('app.user_id', true)));
         CREATE POLICY team_admins_insert ON team_admins FOR INSERT WITH CHECK (
           EXISTS (SELECT 1 FROM team_admins a WHERE a.team_id = team_admins.team_id
                   AND a.admin_id = current_setting('app.user_id', true)));",
    );
    assert_eq!(
        cycles(&cycle_rules(), &database),
        [(
            "PolicyReadCycle".to_owned(),
            Level::Deny,
            vec!["team_admins.team_admins_insert".to_owned()]
        )]
    );
}

#[test]
fn a_write_policy_closes_a_cycle_through_another_table() {
    let database = parse(
        "CREATE TABLE t (id INT, team INT);
         CREATE TABLE u (team INT, member TEXT);
         CREATE TABLE v (team INT);
         ALTER TABLE t ENABLE ROW LEVEL SECURITY;
         ALTER TABLE u ENABLE ROW LEVEL SECURITY;
         CREATE POLICY t_read ON t FOR SELECT USING (team IN (SELECT team FROM v));
         CREATE POLICY t_ins ON t FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM u WHERE u.team = t.team));
         CREATE POLICY u_read ON u FOR SELECT USING (EXISTS (SELECT 1 FROM t WHERE t.team = u.team));",
    );
    assert_eq!(
        cycles(&cycle_rules(), &database),
        [(
            "PolicyReadCycle".to_owned(),
            Level::Deny,
            vec!["t.t_ins".to_owned(), "u.u_read".to_owned()]
        )]
    );
}

const DISJOINT_ROLES: &str = "
    CREATE ROLE p1_admin;
    CREATE ROLE p1_reader;
    CREATE TABLE members (id INT, owner INT);
    CREATE TABLE owners (id INT);
    ALTER TABLE members ENABLE ROW LEVEL SECURITY;
    ALTER TABLE owners ENABLE ROW LEVEL SECURITY;
    CREATE POLICY m_admin ON members FOR SELECT TO p1_admin USING (owner IN (SELECT id FROM owners));
    CREATE POLICY o_reader ON owners FOR SELECT TO p1_reader USING (EXISTS (SELECT 1 FROM members m WHERE m.owner = owners.id));";

#[test]
fn a_cycle_over_roles_the_schema_keeps_apart_is_a_latent_warning() {
    let database = parse(DISJOINT_ROLES);
    let found = cycles(&cycle_rules(), &database);
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].0.as_str(), found[0].1),
        ("LatentPolicyReadCycle", Level::Warn)
    );
}

#[test]
fn a_role_holding_both_roles_makes_the_cycle_a_denied_error() {
    let database = parse(&format!(
        "{DISJOINT_ROLES} CREATE ROLE p1_both IN ROLE p1_admin, p1_reader;"
    ));
    let found = cycles(&cycle_rules(), &database);
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].0.as_str(), found[0].1),
        ("PolicyReadCycle", Level::Deny)
    );
}

#[test]
fn a_table_without_row_level_security_breaks_the_cycle() {
    let database = parse(
        "CREATE TABLE members (owner INT);
         CREATE TABLE owners (id INT);
         ALTER TABLE members ENABLE ROW LEVEL SECURITY;
         CREATE POLICY read_members ON members FOR SELECT USING (owner IN (SELECT id FROM owners));
         CREATE POLICY read_owners ON owners FOR SELECT USING (EXISTS (SELECT 1 FROM members m WHERE m.owner = owners.id));",
    );
    assert_eq!(cycles(&cycle_rules(), &database), []);
}

#[test]
fn a_read_through_a_view_whose_owner_may_bypass_the_table_closes_no_denied_cycle() {
    let database = parse(
        "CREATE TABLE a (id INT, team INT);
         CREATE TABLE b (id INT, team INT);
         ALTER TABLE a ENABLE ROW LEVEL SECURITY;
         ALTER TABLE b ENABLE ROW LEVEL SECURITY;
         CREATE VIEW bv AS SELECT team FROM b;
         CREATE POLICY pb ON b USING (EXISTS (SELECT 1 FROM a WHERE a.team = b.team));
         CREATE POLICY pa ON a USING (EXISTS (SELECT 1 FROM bv WHERE bv.team = a.team));",
    );
    assert_eq!(cycles(&cycle_rules(), &database), []);
}

/// Measured on PostgreSQL 17 and 18 querying `a` as `reader`, the last three
/// cases on PostgreSQL 16.8.
#[test]
fn a_read_through_a_view_expands_the_base_table_as_the_role_the_view_checks() {
    let schema = |views: &str, policies: &str| {
        parse(&format!(
            "CREATE ROLE reader;
             CREATE ROLE vo;
             CREATE ROLE vb BYPASSRLS;
             CREATE ROLE vt;
             CREATE TABLE a (id INT);
             CREATE TABLE b (id INT);
             ALTER TABLE a ENABLE ROW LEVEL SECURITY;
             ALTER TABLE b ENABLE ROW LEVEL SECURITY;
             {views}
             {policies}"
        ))
    };
    let cycle = "CREATE POLICY pa ON a USING (id IN (SELECT id FROM bv));
                 CREATE POLICY pb ON b USING (id IN (SELECT id FROM a));";
    let cases = [
        (
            "CREATE VIEW bv WITH (security_invoker) AS SELECT id FROM b;",
            cycle,
            &["PolicyReadCycle"][..],
        ),
        (
            "CREATE VIEW bv AS SELECT id FROM b; ALTER VIEW bv OWNER TO vo;",
            cycle,
            &["PolicyReadCycle"],
        ),
        (
            "CREATE VIEW bv AS SELECT id FROM b; ALTER VIEW bv OWNER TO vb;",
            cycle,
            &[],
        ),
        (
            "ALTER TABLE b OWNER TO vt; CREATE VIEW bv AS SELECT id FROM b; ALTER VIEW bv OWNER TO vt;",
            cycle,
            &[],
        ),
        (
            "ALTER TABLE b OWNER TO vt; ALTER TABLE b FORCE ROW LEVEL SECURITY;
             CREATE VIEW bv AS SELECT id FROM b; ALTER VIEW bv OWNER TO vt;",
            cycle,
            &["PolicyReadCycle"],
        ),
        (
            "CREATE VIEW bv AS SELECT id FROM b; ALTER VIEW bv OWNER TO vo;",
            "CREATE POLICY pa ON a USING (id IN (SELECT id FROM bv));
             CREATE POLICY pb ON b TO reader USING (id IN (SELECT id FROM a));
             CREATE POLICY pb_vo ON b TO vo USING (true);",
            &["LatentPolicyReadCycle"],
        ),
        (
            "CREATE VIEW bv AS SELECT id FROM b; ALTER VIEW bv OWNER TO vo;",
            "CREATE POLICY pa ON a TO reader USING (id IN (SELECT id FROM bv));
             CREATE POLICY pa_vo ON a TO vo USING (true);
             CREATE POLICY pb ON b TO vo USING (id IN (SELECT id FROM a));",
            &["LatentPolicyReadCycle"],
        ),
        (
            "CREATE VIEW inner_v WITH (security_invoker) AS SELECT id FROM b;
             CREATE VIEW bv AS SELECT id FROM inner_v; ALTER VIEW bv OWNER TO vb;",
            cycle,
            &["PolicyReadCycle"],
        ),
        (
            "CREATE VIEW inner_v AS SELECT id FROM b; ALTER VIEW inner_v OWNER TO vb;
             CREATE VIEW bv WITH (security_invoker) AS SELECT id FROM inner_v;",
            cycle,
            &[],
        ),
        (
            "CREATE MATERIALIZED VIEW bv AS SELECT id FROM b;",
            cycle,
            &[],
        ),
        (
            "ALTER TABLE b OWNER TO vt; CREATE VIEW bv AS SELECT id FROM b; ALTER VIEW bv OWNER TO VT;",
            cycle,
            &[],
        ),
        (
            "CREATE MATERIALIZED VIEW m AS SELECT id FROM b;
             CREATE VIEW bv WITH (security_invoker) AS SELECT id FROM m;",
            cycle,
            &[],
        ),
    ];
    for (views, policies, expected) in cases {
        let found: Vec<String> = cycles(&cycle_rules(), &schema(views, policies))
            .into_iter()
            .map(|(rule, _, _)| rule)
            .collect();
        assert_eq!(found, expected, "{views}\n{policies}");
    }
}

/// Measured on PostgreSQL 16.8 querying `a` as `reader`: each reported shape
/// failed with `stack depth limit exceeded`, each passing one returned rows.
#[test]
fn a_policy_call_reading_back_into_the_table_recurses_as_the_role_the_function_runs_as() {
    let schema = |functions: &str| {
        parse(&format!(
            "CREATE ROLE reader;
             CREATE ROLE fo;
             CREATE ROLE fb BYPASSRLS;
             CREATE TABLE a (id INT);
             CREATE TABLE b (id INT);
             ALTER TABLE a ENABLE ROW LEVEL SECURITY;
             ALTER TABLE b ENABLE ROW LEVEL SECURITY;
             {functions}
             CREATE POLICY pa ON a USING (f(id));
             CREATE POLICY pb ON b USING (id IN (SELECT id FROM a));"
        ))
    };
    let sql = "CREATE FUNCTION f(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE
                 AS 'SELECT EXISTS (SELECT 1 FROM public.b WHERE b.id = x)';";
    let plpgsql = |security: &str| {
        format!(
            "CREATE FUNCTION f(x INT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE {security}
               AS 'BEGIN RETURN EXISTS (SELECT 1 FROM public.b WHERE b.id = x); END';"
        )
    };
    let definer = plpgsql("SECURITY DEFINER");
    let cases = [
        (sql.to_owned(), &["FunctionMediatedPolicyCycle"][..]),
        (plpgsql(""), &["FunctionMediatedPolicyCycle"]),
        (definer.clone(), &[]),
        (
            format!("{definer} ALTER FUNCTION f(INT) OWNER TO fo;"),
            &["FunctionMediatedPolicyCycle"],
        ),
        (format!("{definer} ALTER FUNCTION f(INT) OWNER TO fb;"), &[]),
        (
            format!("ALTER TABLE b OWNER TO fo; {definer} ALTER FUNCTION f(INT) OWNER TO fo;"),
            &[],
        ),
        (
            "CREATE VIEW bv WITH (security_invoker) AS SELECT id FROM b;
             CREATE FUNCTION f(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE
               AS 'SELECT EXISTS (SELECT 1 FROM public.bv WHERE bv.id = x)';"
                .to_owned(),
            &["FunctionMediatedPolicyCycle"],
        ),
        (
            "CREATE MATERIALIZED VIEW m AS SELECT id FROM b;
             CREATE FUNCTION f(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE
               AS 'SELECT EXISTS (SELECT 1 FROM public.m WHERE m.id = x)';"
                .to_owned(),
            &[],
        ),
        (
            "CREATE FUNCTION g(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE
               AS 'SELECT EXISTS (SELECT 1 FROM public.b WHERE b.id = x)';
             CREATE FUNCTION f(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE AS 'SELECT public.g(x)';"
                .to_owned(),
            &["FunctionMediatedPolicyCycle"],
        ),
        (
            "CREATE FUNCTION f(x INT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS 'BEGIN
               IF x > 100 THEN RETURN public.f(x - 1); END IF;
               RETURN EXISTS (SELECT 1 FROM public.b WHERE b.id = x); END';"
                .to_owned(),
            &["FunctionMediatedPolicyCycle"],
        ),
    ];
    for (functions, expected) in cases {
        let found: Vec<String> = cycles(&cycle_rules(), &schema(&functions))
            .into_iter()
            .map(|(rule, _, _)| rule)
            .collect();
        assert_eq!(found, expected, "{functions}");
    }
}

#[test]
fn a_call_cycle_over_roles_the_schema_keeps_apart_is_reported_as_latent() {
    let database = parse(
        "CREATE ROLE admin;
         CREATE ROLE reader;
         CREATE TABLE a (id INT);
         CREATE TABLE b (id INT);
         ALTER TABLE a ENABLE ROW LEVEL SECURITY;
         ALTER TABLE b ENABLE ROW LEVEL SECURITY;
         CREATE FUNCTION f(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE
           AS 'SELECT EXISTS (SELECT 1 FROM public.b WHERE b.id = x)';
         CREATE POLICY pa ON a FOR SELECT TO admin USING (f(id));
         CREATE POLICY pb ON b FOR SELECT TO reader USING (id IN (SELECT id FROM a));",
    );
    let mut constrainer = GenericConstrainer::<ParserDB>::default();
    constrainer.register_schema_rule(Box::new(FunctionMediatedPolicyCycle::default()));
    let violations: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => violation.message().to_owned(),
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    assert_eq!(violations.len(), 1);
    assert!(
        violations[0].contains("which no role in the schema holds together yet"),
        "{}",
        violations[0]
    );
}

#[test]
fn a_common_table_expression_shadowing_the_table_is_not_a_read() {
    for read in [
        "WITH memberships AS (SELECT 1 AS owner_id) SELECT owner_id FROM memberships",
        "WITH memberships AS (SELECT 1 AS owner_id) SELECT owner_id FROM (SELECT owner_id FROM memberships) AS inner_rows",
    ] {
        let database = parse(&format!(
            "CREATE TABLE memberships (owner_id INT, member_id TEXT);
             ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
             CREATE POLICY own ON memberships FOR SELECT USING (owner_id IN ({read}));"
        ));
        assert_eq!(cycles(&cycle_rules(), &database), [], "{read}");
    }
}

#[test]
fn an_allowance_naming_a_listed_policy_suppresses_the_cycle() {
    let database = parse(SELF_LOOP);
    let mut constrainer = cycle_rules();
    constrainer.allow_policy(
        "PolicyReadCycle",
        TargetName::new("memberships", false),
        "memberships_admin",
    );
    assert!(constrainer.validate_schema(&database).is_ok());
    assert!(constrainer.diagnostics(&database).is_empty());
}

#[test]
fn an_allowance_for_another_rule_or_policy_suppresses_nothing_and_is_unused() {
    let database = parse(SELF_LOOP);
    let mut constrainer = cycle_rules();
    constrainer.allow_policy(
        "LatentPolicyReadCycle",
        TargetName::new("memberships", false),
        "memberships_admin",
    );
    constrainer.allow_policy(
        "PolicyReadCycle",
        TargetName::new("memberships", false),
        "other_policy",
    );
    let diagnostics = constrainer.diagnostics(&database);
    let violations = diagnostics
        .iter()
        .filter(|error| matches!(error, Error::Violation(_)))
        .count();
    let unused = diagnostics
        .iter()
        .filter(|error| matches!(error, Error::UnusedAllowance(_)))
        .count();
    assert_eq!((violations, unused), (1, 2));
}

#[test]
fn an_allowance_left_after_the_policy_is_fixed_fails_validation() {
    let database = parse(
        "CREATE TABLE memberships (owner_id INT, member_id TEXT);
         ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
         CREATE POLICY memberships_admin ON memberships FOR ALL USING (member_id = current_setting('app.user_id', true));",
    );
    let mut constrainer = cycle_rules();
    constrainer.allow_policy(
        "PolicyReadCycle",
        TargetName::new("memberships", false),
        "memberships_admin",
    );
    let Err(Error::UnusedAllowance(allowance)) = constrainer.validate_schema(&database) else {
        panic!("an allowance excusing nothing must fail validation");
    };
    assert_eq!(
        (allowance.rule(), allowance.policy()),
        ("PolicyReadCycle", "memberships_admin")
    );
}

#[test]
fn an_allowance_for_a_rule_at_allow_is_unused() {
    let database = parse(SELF_LOOP);
    let mut constrainer = cycle_rules();
    constrainer.set_rule_level("PolicyReadCycle", Level::Allow);
    constrainer.allow_policy(
        "PolicyReadCycle",
        TargetName::new("memberships", false),
        "memberships_admin",
    );
    assert!(matches!(
        constrainer.validate_schema(&database),
        Err(Error::UnusedAllowance(_))
    ));
}

#[test]
fn the_default_constrainer_denies_policy_read_cycles() {
    let database = parse(SELF_LOOP);
    let raised = DefaultConstrainer::<ParserDB>::default().diagnostics(&database);
    assert!(raised.iter().any(|error| matches!(
        error,
        Error::Violation(violation) if violation.rule().name == "PolicyReadCycle" && violation.level() == Level::Deny
    )));
}

#[test]
fn a_cycle_reached_by_several_roles_is_reported_once() {
    let database = parse(&format!(
        "CREATE ROLE app; CREATE ROLE auditor; {SELF_LOOP}"
    ));
    let found = cycles(&cycle_rules(), &database);
    assert_eq!(found.len(), 1);
}

#[test]
fn a_policy_for_a_session_principal_still_recurses() {
    for principal in ["CURRENT_USER", "CURRENT_ROLE", "SESSION_USER"] {
        let database = parse(&format!(
            "CREATE TABLE memberships (owner_id INT, member_id TEXT);
             ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
             CREATE POLICY admins ON memberships FOR SELECT TO {principal} USING (
               owner_id IN (SELECT owner_id FROM memberships m WHERE m.member_id = current_user));"
        ));
        assert_eq!(
            cycles(&cycle_rules(), &database),
            [(
                "PolicyReadCycle".to_owned(),
                Level::Deny,
                vec!["memberships.admins".to_owned()]
            )],
            "{principal}"
        );
    }
}

#[test]
fn a_role_reaching_both_roles_through_shared_ancestry_makes_the_cycle_denied() {
    let database = parse(&format!(
        "{DISJOINT_ROLES} CREATE ROLE staff IN ROLE p1_admin, p1_reader;
         CREATE ROLE lead IN ROLE staff, p1_admin;"
    ));
    let found = cycles(&cycle_rules(), &database);
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].0.as_str(), found[0].1),
        ("PolicyReadCycle", Level::Deny)
    );
}

#[test]
fn a_latent_cycle_lists_each_role_set_once() {
    let database = parse(
        "CREATE ROLE admin;
         CREATE ROLE reader;
         CREATE TABLE a (id INT);
         CREATE TABLE b (id INT);
         CREATE TABLE c (id INT);
         ALTER TABLE a ENABLE ROW LEVEL SECURITY;
         ALTER TABLE b ENABLE ROW LEVEL SECURITY;
         ALTER TABLE c ENABLE ROW LEVEL SECURITY;
         CREATE POLICY a_admin ON a FOR SELECT TO admin USING (id IN (SELECT id FROM b));
         CREATE POLICY b_admin ON b FOR SELECT TO admin USING (id IN (SELECT id FROM c));
         CREATE POLICY c_reader ON c FOR SELECT TO reader USING (id IN (SELECT id FROM a));",
    );
    let diagnostics = cycle_rules().diagnostics(&database);
    let [Error::Violation(violation)] = diagnostics.as_slice() else {
        panic!("expected one latent cycle, got {}", diagnostics.len());
    };
    assert!(violation.message().contains("holding admin and reader,"));
}

#[test]
fn a_read_the_schema_cannot_resolve_is_a_lookup_failure() {
    let database = parse(
        "CREATE TABLE docs (id INT);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON docs FOR SELECT USING (id IN (SELECT id FROM a.b.c.members));",
    );
    assert!(matches!(
        cycle_rules().validate_schema(&database),
        Err(Error::Lookup(_))
    ));
}

#[test]
fn a_role_that_does_not_inherit_its_memberships_leaves_the_cycle_latent() {
    let database = parse(&format!(
        "{DISJOINT_ROLES} CREATE ROLE p1_both NOINHERIT IN ROLE p1_admin, p1_reader;"
    ));
    let found = cycles(&cycle_rules(), &database);
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].0.as_str(), found[0].1),
        ("LatentPolicyReadCycle", Level::Warn)
    );
}

#[test]
fn a_latent_cycle_may_pass_through_a_policy_for_everyone() {
    let database = parse(
        "CREATE ROLE admin;
         CREATE ROLE reader;
         CREATE TABLE a (id INT);
         CREATE TABLE b (id INT);
         CREATE TABLE c (id INT);
         ALTER TABLE a ENABLE ROW LEVEL SECURITY;
         ALTER TABLE b ENABLE ROW LEVEL SECURITY;
         ALTER TABLE c ENABLE ROW LEVEL SECURITY;
         CREATE POLICY a_admin ON a FOR SELECT TO admin USING (id IN (SELECT id FROM b));
         CREATE POLICY b_all ON b FOR SELECT USING (id IN (SELECT id FROM c));
         CREATE POLICY c_reader ON c FOR SELECT TO reader USING (id IN (SELECT id FROM a));",
    );
    let found = cycles(&cycle_rules(), &database);
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].0.as_str(), found[0].2.len()),
        ("LatentPolicyReadCycle", 3)
    );
}

#[test]
fn a_cycle_names_the_clause_and_subquery_of_each_policy() {
    let database = parse(
        "CREATE TABLE t (id INT, team INT);
         CREATE TABLE u (team INT, member TEXT);
         CREATE TABLE v (team INT);
         ALTER TABLE t ENABLE ROW LEVEL SECURITY;
         ALTER TABLE u ENABLE ROW LEVEL SECURITY;
         CREATE POLICY t_read ON t FOR SELECT USING (team IN (SELECT team FROM v));
         CREATE POLICY t_ins ON t FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM u WHERE u.team = t.team));
         CREATE POLICY u_read ON u FOR SELECT USING (EXISTS (SELECT 1 FROM t WHERE t.team = u.team));",
    );
    let diagnostics = cycle_rules().diagnostics(&database);
    let [Error::Violation(violation)] = diagnostics.as_slice() else {
        panic!("expected one cycle, got {}", diagnostics.len());
    };
    let Location::Policies(sites) = violation.location() else {
        panic!("a policy finding is located on policies");
    };
    let described: Vec<_> = sites
        .iter()
        .map(|site| (site.clause(), site.expression()))
        .collect();
    assert_eq!(
        described,
        [
            (
                PolicyClause::WithCheck,
                "SELECT 1 FROM u WHERE u.team = t.team"
            ),
            (PolicyClause::Using, "SELECT 1 FROM t WHERE t.team = u.team"),
        ]
    );
    assert!(
        violation
            .to_string()
            .contains("at t.t_ins WITH CHECK: SELECT 1 FROM u")
    );
}

#[test]
fn an_unused_allowance_names_its_table() {
    let database = parse("CREATE TABLE memberships (owner_id INT);");
    let mut constrainer = cycle_rules();
    constrainer.allow_policy(
        "PolicyReadCycle",
        TargetName::new("memberships", false),
        "admins",
    );
    let Err(Error::UnusedAllowance(allowance)) = constrainer.validate_schema(&database) else {
        panic!("the allowance excuses nothing");
    };
    assert_eq!(allowance.table().name(), "memberships");
    assert!(allowance.to_string().contains("admins"));
}

#[test]
fn a_rendered_cycle_names_each_policy_clause_and_subquery() {
    let database = parse(SELF_LOOP);
    let Err(error) = cycle_rules().validate_schema(&database) else {
        panic!("the self-loop must be reported");
    };
    assert!(error.to_string().contains(
        "at memberships.memberships_admin USING: SELECT 1 FROM memberships m WHERE m.owner_id = memberships.owner_id"
    ));
}

#[test]
fn a_clause_reading_a_table_twice_lists_its_policy_once() {
    let database = parse(
        "CREATE TABLE members (id INT, owner INT);
         CREATE TABLE owners (id INT);
         ALTER TABLE members ENABLE ROW LEVEL SECURITY;
         ALTER TABLE owners ENABLE ROW LEVEL SECURITY;
         CREATE POLICY read_members ON members FOR SELECT USING (
           owner IN (SELECT id FROM owners) OR id IN (SELECT id FROM owners));
         CREATE POLICY read_owners ON owners FOR SELECT USING (id IN (SELECT owner FROM members));",
    );
    let found = cycles(&cycle_rules(), &database);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].2.len(), 2);
}
