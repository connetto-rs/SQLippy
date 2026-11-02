//! Submodule providing the `PolicyReadCycle` and `LatentPolicyReadCycle`
//! rules, which find row-level security policies whose expansion recurses.

use std::{collections::BTreeSet, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    traits::{DataStatementLike, DatabaseLike, PolicyLike, RoleLike, TableLike},
};
use sqlparser::ast::{CreatePolicyCommand, Expr, Query, Visit, Visitor};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::policy_support::{Command, held_roles, policy_roles},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

const RESOLUTION: &str = "Read the looked-up table through a `STABLE SECURITY DEFINER` function owned by a role with `BYPASSRLS` and call it as `(SELECT fn())`, or remove the subquery from one policy on the cycle.";
const SOURCE: Option<&str> = Some(
    "https://supabase.com/docs/guides/database/postgres/row-level-security#avoid-recursive-policies",
);

/// A base table read by a sublink of a policy clause.
struct Read<'db, DB: DatabaseLike> {
    table: &'db DB::Table,
    subquery: String,
}

/// Collects the base tables read by the outermost query of every sublink of an
/// expression, so nested queries are resolved within their enclosing `WITH`.
struct SublinkReads<'db, DB: DatabaseLike> {
    database: &'db DB,
    depth: usize,
    found: bool,
    reads: Vec<Read<'db, DB>>,
}

impl<DB: DatabaseLike> Visitor for SublinkReads<'_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        self.found = true;
        let tables = match DataStatementLike::<DB>::referenced_tables(query, self.database) {
            Ok(tables) => tables,
            Err(error) => return ControlFlow::Break(error),
        };
        for table in tables {
            if !self.reads.iter().any(|read| read.table == table) {
                self.reads.push(Read {
                    table,
                    subquery: query.to_string(),
                });
            }
        }
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }
}

/// Returns whether the expression holds a sublink and the tables they read.
fn sublink_reads<'db, DB: DatabaseLike>(
    database: &'db DB,
    expression: Option<&Expr>,
) -> Result<(bool, Vec<Read<'db, DB>>), LookupError> {
    let Some(expression) = expression else {
        return Ok((false, Vec::new()));
    };
    let mut collector = SublinkReads {
        database,
        depth: 0,
        found: false,
        reads: Vec::new(),
    };
    if let ControlFlow::Break(error) = expression.visit(&mut collector) {
        return Err(error);
    }
    Ok((collector.found, collector.reads))
}

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

/// The roles a querying role holds the privileges of.
enum Holder {
    /// Every policy applies, whatever its roles.
    Everyone,
    /// The named roles, empty for a role the schema does not declare.
    Roles(BTreeSet<String>),
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
            let using = policy.using_expression(database);
            let check = policy.check_expression(database);
            let (using_sublink, using_reads) = sublink_reads(database, using)?;
            let (check_sublink, check_reads) = sublink_reads(database, check)?;
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

    fn expand(
        &self,
        holder: &Holder,
        active: &mut Vec<&'db DB::Table>,
        path: &mut Vec<Step>,
        steps: Vec<Step>,
        found: &mut Vec<(Vec<Step>, &'db DB::Table)>,
    ) {
        for step in steps {
            let table = self.read(step).table;
            if !self.secured(table) {
                continue;
            }
            let (has_sublinks, next) = self.steps(table, Command::Select, holder);
            if !has_sublinks {
                continue;
            }
            path.push(step);
            if let Some(start) = active.iter().position(|relation| *relation == table) {
                found.push((path[start..].to_vec(), table));
            } else {
                active.push(table);
                self.expand(holder, active, path, next, found);
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
                    self.expand(holder, &mut vec![table], &mut Vec::new(), steps, &mut found);
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
                    expression: self.read(step).subquery.clone(),
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
}

/// Struct defining a rule that reports policies whose expansion recurses for a
/// role the schema shows can reach every policy on the path.
///
/// PostgreSQL expands a relation's applicable policies and the sublinks they
/// hold, applying each read relation's `SELECT` policies in turn. Meeting a
/// relation it is already expanding, whose applicable policies hold a sublink,
/// fails the statement with `infinite recursion detected in policy`.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
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
            name: "PolicyReadCycle",
            group: LintGroup::Correctness,
            rationale: "PostgreSQL fails a statement with `infinite recursion detected in policy` when expanding a relation's policies reaches a sublink on a relation it is already expanding.",
            source: SOURCE,
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
        for finding in analysis.findings().0 {
            let holders = if finding.holders.iter().any(|holder| holder == "every role") {
                "every role".to_owned()
            } else {
                finding.holders.join(", ")
            };
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
/// use sql_rules::prelude::*;
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
            name: "LatentPolicyReadCycle",
            group: LintGroup::Suspicious,
            rationale: "A role granted every role these policies name, through a membership the schema cannot show, fails each statement with `infinite recursion detected in policy`.",
            source: SOURCE,
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
        for finding in analysis.findings().1 {
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
