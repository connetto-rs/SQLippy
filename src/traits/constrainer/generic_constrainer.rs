//! Submodule defining a generic constrainer for SQL rules.

use std::ops::ControlFlow;

use sql_traits::{
    structs::{IdentifierCase, TargetName},
    traits::{DatabaseLike, TableLike},
};

use crate::{
    deployment::Deployment,
    error::{Error, InactiveRule, Interruption, PolicyAllowance},
    lint::{Level, LintGroup, Rule, RuleMetadata},
    traits::{
        ColumnRule, Constrainer, ForeignKeyRule, Reporter, SchemaRule, TableRule,
        reporter::ResolvedAllowance,
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

/// A constrainer holding rules, their levels, policy allowances and the
/// deployment its rules read.
pub struct GenericConstrainer<DB: DatabaseLike> {
    tables: Vec<Registered<dyn TableRule<Database = DB>>>,
    columns: Vec<Registered<dyn ColumnRule<Database = DB>>>,
    foreign_keys: Vec<Registered<dyn ForeignKeyRule<Database = DB>>>,
    schemas: Vec<Registered<dyn SchemaRule<Database = DB>>>,
    levels: Levels,
    allowances: Vec<PolicyAllowance>,
    deployment: Deployment,
}

impl<DB: DatabaseLike> Default for GenericConstrainer<DB> {
    fn default() -> Self {
        Self {
            tables: Vec::new(),
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            schemas: Vec::new(),
            levels: Levels::default(),
            allowances: Vec::new(),
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
}

impl<DB: DatabaseLike> Run<'_, DB> {
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
            &self.allowances,
            &mut self.used,
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

    pub(crate) fn set_deployment(&mut self, deployment: Deployment) {
        self.deployment = deployment;
    }

    pub(crate) fn inactive_rules(&self) -> Vec<InactiveRule> {
        let deployment = &self.deployment;
        inactive(&self.tables, deployment)
            .chain(inactive(&self.columns, deployment))
            .chain(inactive(&self.foreign_keys, deployment))
            .chain(inactive(&self.schemas, deployment))
            .collect()
    }

    fn refresh(&mut self) {
        self.levels.refresh(&mut self.tables);
        self.levels.refresh(&mut self.columns);
        self.levels.refresh(&mut self.foreign_keys);
        self.levels.refresh(&mut self.schemas);
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
        for entry in enabled(&self.schemas, deployment) {
            run.check(entry.rule.metadata(), entry.level, sink, |reporter| {
                entry.rule.check_schema(database, reporter)
            })?;
        }
        for (allowance, used) in self.allowances.iter().zip(&run.used) {
            if !used {
                sink(Error::UnusedAllowance(allowance.clone()))?;
            }
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
