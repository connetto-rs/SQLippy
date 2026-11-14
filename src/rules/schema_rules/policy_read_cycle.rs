//! Submodule providing the `PolicyReadCycle`, `LatentPolicyReadCycle` and
//! `FunctionMediatedPolicyCycle` rules, which find row-level security
//! policies whose expansion recurses.

use std::collections::BTreeSet;

use sql_traits::{
    errors::LookupError,
    traits::{DatabaseLike, PolicyLike, RoleLike, TableLike},
};
use sqlparser::ast::CreatePolicyCommand;

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        policy_read_support::{Checker, Holder, Read, sublink_reads},
        policy_support::{Command, held_roles, policy_roles, walked_clauses},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

const RESOLUTION: &str = "Read the looked-up table through a `STABLE SECURITY DEFINER` function owned by a role with `BYPASSRLS` and call it as `(SELECT fn())`, or remove the subquery from one policy on the cycle.";
const CALL_RESOLUTION: &str = "Have the called function run as a role that bypasses the read table's policies, a `SECURITY DEFINER` owned by a role with `BYPASSRLS` or by the table's owner without `FORCE`, or drop the read from one policy on the cycle.";
const SOURCE: Option<&str> = Some(
    "https://supabase.com/docs/guides/database/postgres/row-level-security#avoid-recursive-policies",
);

/// What the expansion of one policy depends on.
struct PolicyFacts<'db, DB: DatabaseLike> {
    table: &'db DB::Table,
    policy: &'db DB::Policy,
    command: CreatePolicyCommand,
    /// Normalized role names, or `None` for `PUBLIC`.
    roles: Option<Vec<String>>,
    has_sublinks: bool,
    has_check: bool,
    using: Vec<Read<'db, DB>>,
    check: Vec<Read<'db, DB>>,
}

impl Holder {
    fn reaches<DB: DatabaseLike>(&self, facts: &PolicyFacts<'_, DB>) -> bool {
        match (self, &facts.roles) {
            (Self::Everyone, _) | (_, None) => true,
            (Self::Roles(held), Some(roles)) => roles.iter().any(|role| held.contains(role)),
        }
    }
}

/// One expanded policy clause and the table its sublink reads.
#[derive(Clone, Copy)]
struct Step {
    policy: usize,
    /// Whether the clause is `WITH CHECK` rather than `USING`.
    check: bool,
    read: usize,
}

/// A recursion path, its querying roles and the relation that closes it.
struct Finding<'db, DB: DatabaseLike> {
    steps: Vec<Step>,
    holders: Vec<String>,
    closing: &'db DB::Table,
}

struct Analysis<'db, DB: DatabaseLike> {
    database: &'db DB,
    facts: Vec<PolicyFacts<'db, DB>>,
    secured: Vec<&'db DB::Table>,
}

impl<'db, DB: DatabaseLike> Analysis<'db, DB> {
    fn new(database: &'db DB) -> Result<Self, LookupError> {
        let mut facts = Vec::new();
        for policy in database.policies() {
            let [(_, using), (_, check)] = walked_clauses(database, policy)?;
            let (using_sublink, using_reads) = sublink_reads(database, policy, using)?;
            let (check_sublink, check_reads) = sublink_reads(database, policy, check)?;
            facts.push(PolicyFacts {
                table: policy.table(database)?,
                policy,
                command: policy.command(),
                roles: policy_roles(database, policy),
                has_sublinks: using_sublink || check_sublink,
                has_check: check.is_some(),
                using: using_reads,
                check: check_reads,
            });
        }
        let mut secured = Vec::new();
        for table in database.tables() {
            if table.has_row_level_security(database)? {
                secured.push(table);
            }
        }
        Ok(Self {
            database,
            facts,
            secured,
        })
    }

    /// Querying roles worth trying, each labelled for the message.
    fn holders(&self) -> Vec<(String, Holder)> {
        let mut holders = vec![("every role".to_owned(), Holder::Roles(BTreeSet::new()))];
        let mut declared = BTreeSet::new();
        for role in self.database.roles() {
            let name = role.stored_name().into_owned();
            let held = held_roles(self.database, role);
            declared.insert(name.clone());
            holders.push((format!("role '{name}'"), Holder::Roles(held)));
        }
        let undeclared: BTreeSet<&String> = self
            .facts
            .iter()
            .filter_map(|facts| facts.roles.as_ref())
            .flatten()
            .filter(|role| !declared.contains(*role))
            .collect();
        for role in undeclared {
            holders.push((
                format!("role '{role}'"),
                Holder::Roles(BTreeSet::from([role.clone()])),
            ));
        }
        holders
    }

    fn secured(&self, table: &DB::Table) -> bool {
        self.secured.contains(&table)
    }

    /// Clauses PostgreSQL adds for `command`, from policies `holder` reaches.
    fn steps(&self, table: &DB::Table, command: Command, holder: &Holder) -> (bool, Vec<Step>) {
        let mut has_sublinks = false;
        let mut steps = Vec::new();
        for (index, facts) in self.facts.iter().enumerate() {
            if facts.table != table || !command.covered_by(facts.command) || !holder.reaches(facts)
            {
                continue;
            }
            has_sublinks |= facts.has_sublinks;
            let mut add = |check, reads: &[Read<'db, DB>]| {
                steps.extend((0..reads.len()).map(|read| Step {
                    policy: index,
                    check,
                    read,
                }));
            };
            match command {
                Command::Insert if facts.has_check => add(true, &facts.check),
                Command::Select | Command::Delete | Command::Insert => {
                    add(false, &facts.using);
                }
                Command::Update => {
                    add(false, &facts.using);
                    add(true, &facts.check);
                }
            }
        }
        (has_sublinks, steps)
    }

    fn read(&self, step: Step) -> &Read<'db, DB> {
        let facts = &self.facts[step.policy];
        if step.check {
            &facts.check[step.read]
        } else {
            &facts.using[step.read]
        }
    }

    /// Expands `steps`, taken as `current` for a query `caller` runs.
    fn expand(
        &self,
        caller: &Holder,
        current: &Holder,
        active: &mut Vec<&'db DB::Table>,
        path: &mut Vec<Step>,
        steps: Vec<Step>,
        found: &mut Vec<(Vec<Step>, &'db DB::Table)>,
    ) {
        for step in steps {
            let read = self.read(step);
            if !self.secured(read.table) {
                continue;
            }
            let Some(checker) = &read.checker else {
                continue;
            };
            let holder = match checker {
                Checker::Current => current,
                Checker::Owner(owner) if *caller != Holder::Everyone => owner,
                Checker::Caller | Checker::Owner(_) => caller,
            };
            let (has_sublinks, next) = self.steps(read.table, Command::Select, holder);
            if !has_sublinks {
                continue;
            }
            path.push(step);
            if let Some(start) = active.iter().position(|relation| *relation == read.table) {
                found.push((path[start..].to_vec(), read.table));
            } else {
                active.push(read.table);
                self.expand(caller, holder, active, path, next, found);
                active.pop();
            }
            path.pop();
        }
    }

    /// Recursion paths `holder` reaches, keyed by their set of policies.
    fn paths(&self, holder: &Holder) -> Vec<(Vec<Step>, &'db DB::Table)> {
        let mut found = Vec::new();
        for &table in &self.secured {
            for command in Command::ALL {
                let (has_sublinks, steps) = self.steps(table, command, holder);
                if has_sublinks {
                    self.expand(
                        holder,
                        holder,
                        &mut vec![table],
                        &mut Vec::new(),
                        steps,
                        &mut found,
                    );
                }
            }
        }
        found
    }

    fn key(&self, steps: &[Step]) -> BTreeSet<&'db DB::Policy> {
        steps
            .iter()
            .map(|step| self.facts[step.policy].policy)
            .collect()
    }

    /// Paths some querying role reaches, then paths only every policy reaches.
    fn findings(&self) -> (Vec<Finding<'db, DB>>, Vec<Finding<'db, DB>>) {
        let mut reached: Vec<Finding<'db, DB>> = Vec::new();
        for (label, holder) in self.holders() {
            for (steps, closing) in self.paths(&holder) {
                let key = self.key(&steps);
                match reached
                    .iter_mut()
                    .find(|finding| self.key(&finding.steps) == key)
                {
                    Some(finding) => {
                        if !finding.holders.contains(&label) {
                            finding.holders.push(label.clone());
                        }
                    }
                    None => reached.push(Finding {
                        steps,
                        holders: vec![label.clone()],
                        closing,
                    }),
                }
            }
        }
        let mut latent: Vec<Finding<'db, DB>> = Vec::new();
        for (steps, closing) in self.paths(&Holder::Everyone) {
            let key = self.key(&steps);
            if reached
                .iter()
                .chain(&latent)
                .all(|finding| self.key(&finding.steps) != key)
            {
                let mut holders: Vec<String> = Vec::new();
                for step in &steps {
                    let label = match &self.facts[step.policy].roles {
                        None => "PUBLIC".to_owned(),
                        Some(roles) => roles.join(", "),
                    };
                    if !holders.contains(&label) {
                        holders.push(label);
                    }
                }
                latent.push(Finding {
                    steps,
                    holders,
                    closing,
                });
            }
        }
        (reached, latent)
    }

    fn sites(&self, steps: &[Step]) -> Vec<PolicySite<DB>> {
        steps
            .iter()
            .map(|&step| {
                let facts = &self.facts[step.policy];
                PolicySite {
                    table: Box::new(facts.table.clone()),
                    policy: Box::new(facts.policy.clone()),
                    clause: if step.check {
                        PolicyClause::WithCheck
                    } else {
                        PolicyClause::Using
                    },
                    expression: self.read(step).via.clone(),
                }
            })
            .collect()
    }

    fn tables(&self, finding: &Finding<'db, DB>) -> String {
        finding
            .steps
            .iter()
            .map(|step| self.facts[step.policy].table.table_name())
            .chain(std::iter::once(finding.closing.table_name()))
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    /// Whether a step of the path reads its table inside a called function.
    fn through_call(&self, finding: &Finding<'db, DB>) -> bool {
        finding.steps.iter().any(|&step| self.read(step).call)
    }

    /// The holders reaching a finding, worded for its message.
    fn reached_by(finding: &Finding<'db, DB>) -> String {
        if finding.holders.iter().any(|holder| holder == "every role") {
            "every role".to_owned()
        } else {
            finding.holders.join(", ")
        }
    }
}

/// Struct defining a rule that reports policies whose expansion recurses for a
/// role the schema shows can reach every policy on the path.
///
/// PostgreSQL expands a relation's applicable policies and the sublinks they
/// hold, applying each read relation's `SELECT` policies in turn. Meeting a
/// relation it is already expanding, whose applicable policies hold a sublink,
/// fails the statement with `infinite recursion detected in policy`.
///
/// A sublink reading a view reads the view's base tables. A view with
/// `security_invoker` applies the querying role's policies to them. Any other
/// view applies its owner's, and none when the owner bypasses row-level
/// security, owns the table without `FORCE`, or is not named in the schema.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = PolicyReadCycle::default().into();
///
/// let recursive = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE memberships (owner_id INT, member_id TEXT);
///      ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
///      CREATE POLICY admins ON memberships FOR ALL USING (
///        owner_id IN (SELECT owner_id FROM memberships m WHERE m.member_id = current_user));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&recursive).is_err());
///
/// let direct = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE memberships (owner_id INT, member_id TEXT);
///      ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
///      CREATE POLICY own ON memberships FOR ALL USING (member_id = current_user);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&direct).is_ok());
/// ```
pub struct PolicyReadCycle<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PolicyReadCycle<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PolicyReadCycle<DB>> for GenericConstrainer<DB> {
    fn from(rule: PolicyReadCycle<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for PolicyReadCycle<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(PolicyReadCycle),
            group: LintGroup::Correctness,
            rationale: "PostgreSQL fails a statement with `infinite recursion detected in policy` when expanding a relation's policies reaches a sublink on a relation it is already expanding.",
            source: SOURCE,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE memberships (owner_id INT, member_id TEXT);\n\
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON memberships USING (owner_id IN (SELECT owner_id FROM memberships m WHERE m.member_id = current_setting('app.user_id', true)));",
                good: "CREATE TABLE memberships (owner_id INT, member_id TEXT);\n\
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON memberships USING (member_id = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for PolicyReadCycle<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let analysis = Analysis::new(database)?;
        for finding in analysis
            .findings()
            .0
            .into_iter()
            .filter(|finding| !analysis.through_call(finding))
        {
            let holders = Analysis::reached_by(&finding);
            reporter.policies(
                analysis.sites(&finding.steps),
                format!(
                    "Expanding the policies {} recurses for {holders}, so PostgreSQL fails the statement with infinite recursion detected in policy for relation \"{}\".",
                    analysis.tables(&finding),
                    finding.closing.table_name()
                ),
                RESOLUTION.to_owned(),
            )?;
        }
        Ok(())
    }
}

/// Struct defining a rule that reports policy read cycles whose policies name
/// roles the schema keeps apart.
///
/// No role declared in the schema reaches every policy on the cycle, so
/// PostgreSQL expands it without error today. A membership the schema does not
/// show, such as `GRANT role TO role`, can join the roles and turn the cycle
/// into the recursion error [`PolicyReadCycle`] reports.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = LatentPolicyReadCycle::default().into();
/// let database = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE ROLE admin;
///      CREATE ROLE reader;
///      CREATE TABLE members (owner INT);
///      CREATE TABLE owners (id INT);
///      ALTER TABLE members ENABLE ROW LEVEL SECURITY;
///      ALTER TABLE owners ENABLE ROW LEVEL SECURITY;
///      CREATE POLICY m ON members FOR SELECT TO admin USING (owner IN (SELECT id FROM owners));
///      CREATE POLICY o ON owners FOR SELECT TO reader USING (id IN (SELECT owner FROM members));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&database).is_err());
/// ```
pub struct LatentPolicyReadCycle<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for LatentPolicyReadCycle<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<LatentPolicyReadCycle<DB>> for GenericConstrainer<DB> {
    fn from(rule: LatentPolicyReadCycle<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for LatentPolicyReadCycle<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(LatentPolicyReadCycle),
            group: LintGroup::Suspicious,
            rationale: "A role granted every role these policies name, through a membership the schema cannot show, fails each statement with `infinite recursion detected in policy`.",
            source: SOURCE,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE admin;\n\
CREATE ROLE reader;\n\
CREATE TABLE members (owner TEXT);\n\
CREATE TABLE owners (id TEXT);\n\
ALTER TABLE members ENABLE ROW LEVEL SECURITY;\n\
ALTER TABLE owners ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY m ON members FOR SELECT TO admin USING (owner IN (SELECT id FROM owners));\n\
CREATE POLICY o ON owners FOR SELECT TO reader USING (id IN (SELECT owner FROM members));",
                good: "CREATE ROLE admin;\n\
CREATE ROLE reader;\n\
CREATE TABLE members (owner TEXT);\n\
CREATE TABLE owners (id TEXT);\n\
ALTER TABLE members ENABLE ROW LEVEL SECURITY;\n\
ALTER TABLE owners ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY m ON members FOR SELECT TO admin USING (owner IN (SELECT id FROM owners));\n\
CREATE POLICY o ON owners FOR SELECT TO reader USING (id = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for LatentPolicyReadCycle<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let analysis = Analysis::new(database)?;
        for finding in analysis
            .findings()
            .1
            .into_iter()
            .filter(|finding| !analysis.through_call(finding))
        {
            reporter.policies(
                analysis.sites(&finding.steps),
                format!(
                    "Expanding the policies {} recurses for a role holding {}, which no role in the schema holds together yet.",
                    analysis.tables(&finding),
                    finding.holders.join(" and ")
                ),
                RESOLUTION.to_owned(),
            )?;
        }
        Ok(())
    }
}

/// Struct defining a rule that reports policy cycles closed through a function
/// a policy calls.
///
/// The rewriter cannot see into a function body, so PostgreSQL does not raise
/// `infinite recursion detected in policy` for these. The function reads its
/// table when it runs, that table's policies lead back to the calling policy,
/// and the statement fails with `stack depth limit exceeded`. An invoker
/// function reads as the role expanding the policy, a `SECURITY DEFINER` as its
/// owner, and nothing when the owner bypasses row-level security, owns the
/// table without `FORCE`, or is not named in the schema.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = FunctionMediatedPolicyCycle::default().into();
/// let schema = "CREATE TABLE a (id INT); CREATE TABLE b (id INT);
///     ALTER TABLE a ENABLE ROW LEVEL SECURITY; ALTER TABLE b ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY pb ON b USING (id IN (SELECT id FROM a));";
///
/// let invoker = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE FUNCTION in_b(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE
///        AS 'SELECT EXISTS (SELECT 1 FROM public.b WHERE b.id = x)';
///      CREATE POLICY pa ON a USING (in_b(id));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&invoker).is_err());
///
/// let bypassing = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "CREATE ROLE helper BYPASSRLS; {schema}
///      CREATE FUNCTION in_b(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
///        AS 'SELECT EXISTS (SELECT 1 FROM public.b WHERE b.id = x)';
///      ALTER FUNCTION in_b(INT) OWNER TO helper;
///      CREATE POLICY pa ON a USING (in_b(id));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&bypassing).is_ok());
/// ```
pub struct FunctionMediatedPolicyCycle<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for FunctionMediatedPolicyCycle<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<FunctionMediatedPolicyCycle<DB>> for GenericConstrainer<DB> {
    fn from(rule: FunctionMediatedPolicyCycle<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for FunctionMediatedPolicyCycle<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(FunctionMediatedPolicyCycle),
            group: LintGroup::Suspicious,
            rationale: "A function a policy calls reads a table whose policies lead back to the calling policy, so PostgreSQL recurses until it fails the statement with `stack depth limit exceeded`.",
            source: Some(
                "https://supabase.com/docs/guides/database/postgres/row-level-security#use-security-definer-functions",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE ROLE helper BYPASSRLS;\n\
CREATE TABLE a (id INT);\n\
CREATE TABLE b (id INT);\n\
ALTER TABLE a ENABLE ROW LEVEL SECURITY;\n\
ALTER TABLE b ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY pb ON b USING (id IN (SELECT id FROM a));\n\
CREATE FUNCTION in_b(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY INVOKER SET search_path = '' AS $$ SELECT EXISTS (SELECT 1 FROM public.b WHERE b.id = x) $$;\n\
ALTER FUNCTION in_b(INT) OWNER TO helper;\n\
CREATE POLICY pa ON a USING (in_b(id));",
                good: "CREATE ROLE helper BYPASSRLS;\n\
CREATE TABLE a (id INT);\n\
CREATE TABLE b (id INT);\n\
ALTER TABLE a ENABLE ROW LEVEL SECURITY;\n\
ALTER TABLE b ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY pb ON b USING (id IN (SELECT id FROM a));\n\
CREATE FUNCTION in_b(x INT) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$ SELECT EXISTS (SELECT 1 FROM public.b WHERE b.id = x) $$;\n\
ALTER FUNCTION in_b(INT) OWNER TO helper;\n\
CREATE POLICY pa ON a USING (in_b(id));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for FunctionMediatedPolicyCycle<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let analysis = Analysis::new(database)?;
        let (reached, latent) = analysis.findings();
        let reached = reached.into_iter().map(|finding| (finding, true));
        let latent = latent.into_iter().map(|finding| (finding, false));
        for (finding, is_reached) in reached.chain(latent) {
            if !analysis.through_call(&finding) {
                continue;
            }
            let holders = if is_reached {
                Analysis::reached_by(&finding)
            } else {
                format!(
                    "a role holding {}, which no role in the schema holds together yet",
                    finding.holders.join(" and ")
                )
            };
            reporter.policies(
                analysis.sites(&finding.steps),
                format!(
                    "Expanding the policies {} calls back into \"{}\" for {holders}, so PostgreSQL fails the statement with stack depth limit exceeded.",
                    analysis.tables(&finding),
                    finding.closing.table_name()
                ),
                CALL_RESOLUTION.to_owned(),
            )?;
        }
        Ok(())
    }
}
