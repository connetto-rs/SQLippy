//! Submodule defining a generic constrainer for SQL rules.

use std::ops::ControlFlow;

use sql_traits::{
    structs::{IdentifierCase, TargetName},
    traits::{DatabaseLike, TableLike},
};
use sqlparser::{ast::Statement, dialect::PostgreSqlDialect, parser::Parser};

use crate::{
    deployment::Deployment,
    error::{Allowance, Error, InactiveRule, Interruption, PolicyAllowance, StatementAllowance},
    lint::{Level, LintGroup, RegisteredRule, Rule, RuleKind, RuleMetadata},
    traits::{
        ColumnRule, Constrainer, ForeignKeyRule, FunctionRule, QueryRule, Reporter, SchemaRule,
        TableRule,
        reporter::{Allowances, ResolvedAllowance},
    },
};

/// A registered rule with its configured level.
struct Registered<R: ?Sized> {
    rule: Box<R>,
    floor: Level,
    level: Level,
}

/// Level overrides set on a constrainer.
#[derive(Default)]
struct Levels {
    rules: Vec<(String, Level)>,
    groups: [Option<Level>; LintGroup::ALL.len()],
}

impl Levels {
    fn resolve(&self, metadata: &RuleMetadata, floor: Level) -> Level {
        self.rules
            .iter()
            .find_map(|(name, level)| (name == metadata.name).then_some(*level))
            .or(self.groups[metadata.group.index()])
            .unwrap_or_else(|| metadata.group.default_level().max(floor))
    }

    fn refresh<R: Rule + ?Sized>(&self, registered: &mut [Registered<R>]) {
        for entry in registered {
            entry.level = self.resolve(entry.rule.metadata(), entry.floor);
        }
    }
}

/// A constrainer holding rules, their levels, allowances and the deployment
/// its rules read.
pub struct GenericConstrainer<DB: DatabaseLike> {
    tables: Vec<Registered<dyn TableRule<Database = DB>>>,
    columns: Vec<Registered<dyn ColumnRule<Database = DB>>>,
    foreign_keys: Vec<Registered<dyn ForeignKeyRule<Database = DB>>>,
    schemas: Vec<Registered<dyn SchemaRule<Database = DB>>>,
    functions: Vec<Registered<dyn FunctionRule<Database = DB>>>,
    queries: Vec<Registered<dyn QueryRule<Database = DB>>>,
    levels: Levels,
    allowances: Vec<PolicyAllowance>,
    statement_allowances: Vec<StatementAllowance>,
    deployment: Deployment,
}

impl<DB: DatabaseLike> Default for GenericConstrainer<DB> {
    fn default() -> Self {
        Self {
            tables: Vec::new(),
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            schemas: Vec::new(),
            functions: Vec::new(),
            queries: Vec::new(),
            levels: Levels::default(),
            allowances: Vec::new(),
            statement_allowances: Vec::new(),
            deployment: Deployment::default(),
        }
    }
}

/// Shared state of one traversal, lent to each rule's reporter.
struct Run<'run, DB: DatabaseLike> {
    database: &'run DB,
    deployment: &'run Deployment,
    allowances: Vec<ResolvedAllowance<'run, DB>>,
    used: Vec<bool>,
    statements: &'run [StatementAllowance],
}

impl<'run, DB: DatabaseLike> Run<'run, DB> {
    /// A run consulting only the given statement allowances.
    fn for_statements(
        database: &'run DB,
        deployment: &'run Deployment,
        statements: &'run [StatementAllowance],
    ) -> Self {
        Self {
            database,
            deployment,
            allowances: Vec::new(),
            used: Vec::new(),
            statements,
        }
    }

    /// Runs one rule check through a reporter and forwards its lookup failure.
    fn check(
        &mut self,
        rule: &'static RuleMetadata,
        level: Level,
        sink: &mut dyn FnMut(Error<DB>) -> ControlFlow<()>,
        check: impl FnOnce(&mut Reporter<'_, DB>) -> Result<(), Interruption>,
    ) -> ControlFlow<()> {
        let outcome = check(&mut Reporter::new(
            self.database,
            self.deployment,
            rule,
            level,
            Allowances {
                policies: &self.allowances,
                used: &mut self.used,
                statements: self.statements,
            },
            sink,
        ));
        match outcome {
            Ok(()) => ControlFlow::Continue(()),
            Err(Interruption::Halted) => ControlFlow::Break(()),
            Err(Interruption::Lookup(error)) => sink(Error::Lookup(error)),
        }
    }
}

/// The first declaration a rule reads that the deployment lacks.
fn missing_declaration<R: Rule + ?Sized>(
    rule: &R,
    deployment: &Deployment,
) -> Option<crate::deployment::Declaration> {
    rule.requires()
        .iter()
        .copied()
        .find(|declaration| !deployment.declares(*declaration))
}

/// Registered rules that run: above `allow`, with every declaration they read.
fn enabled<'a, R: Rule + ?Sized>(
    registered: &'a [Registered<R>],
    deployment: &'a Deployment,
) -> impl Iterator<Item = &'a Registered<R>> {
    registered.iter().filter(move |entry| {
        entry.level > Level::Allow && missing_declaration(entry.rule.as_ref(), deployment).is_none()
    })
}

/// Registered rules above `allow` that do not run for lack of a declaration.
fn inactive<R: Rule + ?Sized>(
    registered: &[Registered<R>],
    deployment: &Deployment,
) -> impl Iterator<Item = InactiveRule> {
    registered
        .iter()
        .filter(|entry| entry.level > Level::Allow)
        .filter_map(|entry| {
            missing_declaration(entry.rule.as_ref(), deployment).map(|missing| InactiveRule {
                rule: entry.rule.metadata(),
                missing,
            })
        })
}

/// Each entry of `registered` as a rule of `kind`.
fn listed<R: Rule + ?Sized>(
    registered: &[Registered<R>],
    kind: RuleKind,
) -> impl Iterator<Item = RegisteredRule> {
    registered.iter().map(move |entry| RegisteredRule {
        metadata: entry.rule.metadata(),
        requires: entry.rule.requires(),
        kind,
        level: entry.level,
    })
}

/// The single PostgreSQL statement `sql` holds.
fn single_statement(sql: &str) -> Option<Statement> {
    let [statement] = Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .ok()?
        .try_into()
        .ok()?;
    Some(statement)
}

impl<DB: DatabaseLike> GenericConstrainer<DB> {
    fn registered<R: Rule + ?Sized>(&self, rule: Box<R>, floor: Level) -> Registered<R> {
        let level = self.levels.resolve(rule.metadata(), floor);
        Registered { rule, floor, level }
    }

    pub(crate) fn register_table_rule_with_floor(
        &mut self,
        rule: Box<dyn TableRule<Database = DB>>,
        floor: Level,
    ) {
        let registered = self.registered(rule, floor);
        self.tables.push(registered);
    }

    pub(crate) fn register_column_rule_with_floor(
        &mut self,
        rule: Box<dyn ColumnRule<Database = DB>>,
        floor: Level,
    ) {
        let registered = self.registered(rule, floor);
        self.columns.push(registered);
    }

    pub(crate) fn register_foreign_key_rule_with_floor(
        &mut self,
        rule: Box<dyn ForeignKeyRule<Database = DB>>,
        floor: Level,
    ) {
        let registered = self.registered(rule, floor);
        self.foreign_keys.push(registered);
    }

    pub(crate) fn register_schema_rule_with_floor(
        &mut self,
        rule: Box<dyn SchemaRule<Database = DB>>,
        floor: Level,
    ) {
        let registered = self.registered(rule, floor);
        self.schemas.push(registered);
    }

    pub(crate) fn register_function_rule_with_floor(
        &mut self,
        rule: Box<dyn FunctionRule<Database = DB>>,
        floor: Level,
    ) {
        let registered = self.registered(rule, floor);
        self.functions.push(registered);
    }

    pub(crate) fn register_query_rule_with_floor(
        &mut self,
        rule: Box<dyn QueryRule<Database = DB>>,
        floor: Level,
    ) {
        let registered = self.registered(rule, floor);
        self.queries.push(registered);
    }

    pub(crate) fn set_rule_level(&mut self, rule: &str, level: Level) {
        match self.levels.rules.iter_mut().find(|(name, _)| name == rule) {
            Some(entry) => entry.1 = level,
            None => self.levels.rules.push((rule.to_owned(), level)),
        }
        self.refresh();
    }

    pub(crate) fn set_group_level(&mut self, group: LintGroup, level: Level) {
        self.levels.groups[group.index()] = Some(level);
        self.refresh();
    }

    pub(crate) fn allow_policy(&mut self, rule: &str, table: TargetName<'_>, policy: &str) {
        self.allowances.push(PolicyAllowance {
            rule: rule.to_owned(),
            table: table.into_owned(),
            policy: policy.to_owned(),
        });
    }

    pub(crate) fn allow_statement(&mut self, rule: &str, statement: &str) {
        let parsed = single_statement(statement);
        self.statement_allowances.push(StatementAllowance {
            rule: rule.to_owned(),
            statement: parsed
                .as_ref()
                .map_or_else(|| statement.to_owned(), ToString::to_string),
            parsed: parsed.map(Box::new),
        });
    }

    pub(crate) fn set_deployment(&mut self, deployment: Deployment) {
        self.deployment = deployment;
    }

    pub(crate) fn inactive_rules(&self) -> Vec<InactiveRule> {
        let deployment = &self.deployment;
        inactive(&self.tables, deployment)
            .chain(inactive(&self.columns, deployment))
            .chain(inactive(&self.foreign_keys, deployment))
            .chain(inactive(&self.schemas, deployment))
            .chain(inactive(&self.functions, deployment))
            .chain(inactive(&self.queries, deployment))
            .collect()
    }

    pub(crate) fn rules(&self) -> Vec<RegisteredRule> {
        listed(&self.tables, RuleKind::Table)
            .chain(listed(&self.columns, RuleKind::Column))
            .chain(listed(&self.foreign_keys, RuleKind::ForeignKey))
            .chain(listed(&self.schemas, RuleKind::Schema))
            .chain(listed(&self.functions, RuleKind::Function))
            .chain(listed(&self.queries, RuleKind::Query))
            .collect()
    }

    fn refresh(&mut self) {
        self.levels.refresh(&mut self.tables);
        self.levels.refresh(&mut self.columns);
        self.levels.refresh(&mut self.foreign_keys);
        self.levels.refresh(&mut self.schemas);
        self.levels.refresh(&mut self.functions);
        self.levels.refresh(&mut self.queries);
    }

    pub(crate) fn visit(
        &self,
        database: &DB,
        sink: &mut dyn FnMut(Error<DB>) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        let deployment = &self.deployment;
        let mut run = Run {
            database,
            deployment,
            allowances: self
                .allowances
                .iter()
                .map(|allowance| ResolvedAllowance {
                    rule: &allowance.rule,
                    table: database
                        .table_by_target(allowance.table.clone(), IdentifierCase::Folded)
                        .ok()
                        .flatten(),
                    policy: &allowance.policy,
                })
                .collect(),
            used: vec![false; self.allowances.len()],
            statements: &[],
        };
        for table in database.tables() {
            for entry in enabled(&self.tables, deployment) {
                run.check(entry.rule.metadata(), entry.level, sink, |reporter| {
                    entry.rule.check_table(database, table, reporter)
                })?;
            }
            match table.columns(database) {
                Ok(columns) => {
                    for column in columns {
                        for entry in enabled(&self.columns, deployment) {
                            run.check(entry.rule.metadata(), entry.level, sink, |reporter| {
                                entry.rule.check_column(database, column, reporter)
                            })?;
                        }
                    }
                }
                Err(error) => sink(Error::Lookup(error))?,
            }
            match table.foreign_keys(database) {
                Ok(foreign_keys) => {
                    for foreign_key in foreign_keys {
                        for entry in enabled(&self.foreign_keys, deployment) {
                            run.check(entry.rule.metadata(), entry.level, sink, |reporter| {
                                entry
                                    .rule
                                    .check_foreign_key(database, foreign_key, reporter)
                            })?;
                        }
                    }
                }
                Err(error) => sink(Error::Lookup(error))?,
            }
        }
        for function in database.functions() {
            for entry in enabled(&self.functions, deployment) {
                run.check(entry.rule.metadata(), entry.level, sink, |reporter| {
                    entry.rule.check_function(database, function, reporter)
                })?;
            }
        }
        for entry in enabled(&self.schemas, deployment) {
            run.check(entry.rule.metadata(), entry.level, sink, |reporter| {
                entry.rule.check_schema(database, reporter)
            })?;
        }
        let mut stale = Vec::new();
        for allowance in &self.statement_allowances {
            if !self.allowance_holds(database, allowance, sink)? {
                stale.push(allowance);
            }
        }
        for (allowance, used) in self.allowances.iter().zip(&run.used) {
            if !used {
                sink(Error::UnusedAllowance(Allowance::Policy(allowance.clone())))?;
            }
        }
        for allowance in stale {
            sink(Error::UnusedAllowance(Allowance::Statement(
                allowance.clone(),
            )))?;
        }
        ControlFlow::Continue(())
    }

    /// Whether the rule a statement allowance names, at its configured level,
    /// still reports the allowance's own statement. A lookup failure goes to
    /// `sink` and keeps the allowance, since the rule could not decide.
    fn allowance_holds(
        &self,
        database: &DB,
        allowance: &StatementAllowance,
        sink: &mut dyn FnMut(Error<DB>) -> ControlFlow<()>,
    ) -> ControlFlow<(), bool> {
        let Some(statement) = &allowance.parsed else {
            return ControlFlow::Continue(false);
        };
        let deployment = &self.deployment;
        let mut run = Run::for_statements(database, deployment, &[]);
        let (mut fired, mut failed) = (false, false);
        for entry in enabled(&self.queries, deployment)
            .filter(|entry| entry.rule.metadata().name == allowance.rule)
        {
            let flow = run.check(
                entry.rule.metadata(),
                entry.level,
                &mut |error| match error {
                    Error::Violation(_) => {
                        fired = true;
                        ControlFlow::Break(())
                    }
                    other => {
                        failed = true;
                        sink(other)
                    }
                },
                |reporter| entry.rule.check_statement(database, statement, reporter),
            );
            if fired {
                return ControlFlow::Continue(true);
            }
            flow?;
        }
        ControlFlow::Continue(failed)
    }

    pub(crate) fn visit_statement(
        &self,
        database: &DB,
        statement: &Statement,
        sink: &mut dyn FnMut(Error<DB>) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        let deployment = &self.deployment;
        let mut run = Run::for_statements(database, deployment, &self.statement_allowances);
        for entry in enabled(&self.queries, deployment) {
            run.check(entry.rule.metadata(), entry.level, sink, |reporter| {
                entry.rule.check_statement(database, statement, reporter)
            })?;
        }
        ControlFlow::Continue(())
    }
}

impl<DB: DatabaseLike> Constrainer for GenericConstrainer<DB> {
    type Database = DB;

    fn constrainer(&self) -> &GenericConstrainer<DB> {
        self
    }

    fn constrainer_mut(&mut self) -> &mut GenericConstrainer<DB> {
        self
    }
}
