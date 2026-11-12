//! Submodule providing the `PolicyReadCycle`, `LatentPolicyReadCycle` and
//! `FunctionMediatedPolicyCycle` rules, which find row-level security
//! policies whose expansion recurses.

use std::{collections::BTreeSet, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    traits::{
        DataStatementLike, DatabaseLike, FunctionLike, PolicyLike, Relation, RoleLike, TableLike,
        ViewLike,
    },
};
use sqlparser::ast::{CreatePolicyCommand, Expr, FunctionSecurity, Query, Visit, Visitor};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        function_rules::unreadable_body,
        policy_support::{Command, held_by_name, held_roles, policy_roles, walked_clauses},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

const RESOLUTION: &str = "Read the looked-up table through a `STABLE SECURITY DEFINER` function owned by a role with `BYPASSRLS` and call it as `(SELECT fn())`, or remove the subquery from one policy on the cycle.";
const CALL_RESOLUTION: &str = "Have the called function run as a role that bypasses the read table's policies, a `SECURITY DEFINER` owned by a role with `BYPASSRLS` or by the table's owner without `FORCE`, or drop the read from one policy on the cycle.";
const SOURCE: Option<&str> = Some(
    "https://supabase.com/docs/guides/database/postgres/row-level-security#avoid-recursive-policies",
);

/// The role whose policies apply to a read.
#[derive(Clone, PartialEq)]
enum Checker {
    /// The role the expansion runs as when the clause reads the table.
    Current,
    /// The querying role, through views that run with their reader's rights.
    Caller,
    /// The owner of a view or function that runs with its owner's rights.
    Owner(Holder),
}

/// The rights a view or function reads its relations with.
enum Rights<'db> {
    /// The reader's, for a view with `security_invoker` or an invoker function.
    Reader,
    /// Those of the named owner, which sql-traits reports as PostgreSQL stores it.
    Owner(&'db str),
    /// Those of an owner that bypasses row-level security or that the schema does not name.
    Bypassing,
}

impl<'db> Rights<'db> {
    /// The rights of an owner, or of the reader when the object takes them.
    fn of<DB: DatabaseLike>(database: &'db DB, reader: bool, owner: Option<&'db str>) -> Self {
        // An owner the schema does not name is whoever ran it, which may bypass every policy.
        match owner {
            _ if reader => Self::Reader,
            Some(owner) => match database.role(owner) {
                Some(role) if role.can_bypass_rls() || role.is_superuser() => Self::Bypassing,
                _ => Self::Owner(owner),
            },
            None => Self::Bypassing,
        }
    }
}

/// The roles checked where a read happens, for its direct table reads and for
/// the views it reads with their reader's rights.
#[derive(Clone)]
struct Context {
    tables: Checker,
    readers: Checker,
}

/// A base table read by a sublink of a policy clause or by a function it calls.
struct Read<'db, DB: DatabaseLike> {
    table: &'db DB::Table,
    checker: Checker,
    /// The sublink or call the clause reads the table through.
    via: String,
    /// Whether the read happens inside a called function.
    call: bool,
}

/// Collects the base tables read by the outermost query of every sublink of an
/// expression, so nested queries are resolved within their enclosing `WITH`,
/// and the tables read by every function the expression calls.
struct SublinkReads<'db, DB: DatabaseLike> {
    database: &'db DB,
    policy: &'db DB::Policy,
    depth: usize,
    found: bool,
    reads: Vec<Read<'db, DB>>,
}

impl<'db, DB: DatabaseLike> SublinkReads<'db, DB> {
    fn push(&mut self, table: &'db DB::Table, checker: Checker, via: &str, call: bool) {
        self.found |= call;
        if !self
            .reads
            .iter()
            .any(|read| read.table == table && read.checker == checker && read.call == call)
        {
            self.reads.push(Read {
                table,
                checker,
                via: via.to_owned(),
                call,
            });
        }
    }

    /// Adds a table read with `rights`, unless an owner bypasses its policies.
    fn table(
        &mut self,
        table: &'db DB::Table,
        rights: &Rights<'db>,
        context: &Context,
        via: &str,
        call: bool,
    ) -> Result<(), LookupError> {
        match *rights {
            Rights::Reader => self.push(table, context.readers.clone(), via, call),
            Rights::Owner(owner) => {
                let owns = table.owner(self.database)? == Some(owner);
                if !owns || table.has_forced_row_level_security(self.database)? {
                    let held = held_by_name(self.database, owner);
                    self.push(table, Checker::Owner(Holder::Roles(held)), via, call);
                }
            }
            Rights::Bypassing => {}
        }
        Ok(())
    }

    /// Adds the base tables a view reads, each with the role checked on it.
    ///
    /// A view nested in it decides its own rights, so it is followed even when
    /// this view's owner reads its tables past their policies.
    fn view(
        &mut self,
        view: &'db DB::View,
        context: &Context,
        via: &str,
        call: bool,
    ) -> Result<(), LookupError> {
        let database = self.database;
        let rights = Rights::of(database, view.is_security_invoker(), view.owner(database)?);
        for relation in DataStatementLike::<DB>::referenced_relations(view.definition(), database)?
        {
            match relation {
                Relation::View(inner) => self.view(inner, context, via, call)?,
                Relation::Table(table) => self.table(table, &rights, context, via, call)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Adds the tables a called function reads, through views and the
    /// functions it calls, each with the role its rights check.
    fn function(
        &mut self,
        function: &'db DB::Function,
        context: &Context,
        via: &str,
        visited: &mut Vec<&'db DB::Function>,
    ) -> Result<(), LookupError> {
        if visited.contains(&function) {
            return Ok(());
        }
        visited.push(function);
        let database = self.database;
        let invoker = function.security_mode() != FunctionSecurity::Definer;
        let (inner, owner) = match Rights::of(database, invoker, function.owner(database)?) {
            Rights::Reader => (context.clone(), None),
            Rights::Owner(owner) => {
                let checker = Checker::Owner(Holder::Roles(held_by_name(database, owner)));
                let inner = Context {
                    tables: checker.clone(),
                    readers: checker,
                };
                (inner, Some(owner))
            }
            Rights::Bypassing => return Ok(()),
        };
        let relations = match function.referenced_relations(database) {
            Err(error) if unreadable_body(&error) => Vec::new(),
            relations => relations?,
        };
        for relation in relations {
            match (relation, owner) {
                (Relation::View(view), _) => self.view(view, &inner, via, true)?,
                (Relation::Table(table), None) => {
                    self.push(table, inner.tables.clone(), via, true);
                }
                (Relation::Table(table), Some(owner)) => {
                    self.table(table, &Rights::Owner(owner), &inner, via, true)?;
                }
                _ => {}
            }
        }
        let called = match function.referenced_functions(database) {
            Err(error) if unreadable_body(&error) => Vec::new(),
            called => called?,
        };
        for called in called {
            self.function(called, &inner, via, visited)?;
        }
        Ok(())
    }

    /// Adds the tables the outermost query of a sublink reads, through views.
    fn query(&mut self, query: &Query) -> Result<(), LookupError> {
        let context = Context {
            tables: Checker::Current,
            readers: Checker::Caller,
        };
        let via = query.to_string();
        for relation in DataStatementLike::<DB>::referenced_relations(query, self.database)? {
            match relation {
                Relation::Table(table) => self.push(table, Checker::Current, &via, false),
                Relation::View(view) => self.view(view, &context, &via, false)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Adds the tables read by every function a call in the clause may reach.
    fn call(&mut self, expression: &Expr) -> Result<(), LookupError> {
        let Expr::Function(call) = expression else {
            return Ok(());
        };
        let context = Context {
            tables: Checker::Current,
            readers: Checker::Caller,
        };
        let via = expression.to_string();
        for function in self.policy.functions_reached_by(call, self.database)? {
            self.function(function, &context, &via, &mut Vec::new())?;
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for SublinkReads<'_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        self.found = true;
        self.query(query)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        self.call(expression)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Returns whether the expression holds a sublink or a call that reads a
/// table, and the tables they read.
fn sublink_reads<'db, DB: DatabaseLike>(
    database: &'db DB,
    policy: &'db DB::Policy,
    expression: Option<&Expr>,
) -> Result<(bool, Vec<Read<'db, DB>>), LookupError> {
    let Some(expression) = expression else {
        return Ok((false, Vec::new()));
    };
    let mut collector = SublinkReads {
        database,
        policy,
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
#[derive(Clone, PartialEq)]
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
            let holder = match &read.checker {
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
