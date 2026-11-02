//! Submodule defining the `Constrainer` trait, which applies registered rules
//! to a schema at their configured levels.

use std::ops::ControlFlow;

use sql_traits::{structs::TargetName, traits::DatabaseLike};

use crate::{
    deployment::Deployment,
    error::{Error, InactiveRule},
    lint::{Level, LintGroup},
    traits::{ColumnRule, ForeignKeyRule, SchemaRule, TableRule},
};

pub mod generic_constrainer;
pub use generic_constrainer::GenericConstrainer;
pub mod default_constrainer;
pub use default_constrainer::DefaultConstrainer;

/// Trait for types that apply rules to a schema.
///
/// A rule's level is the level set for its type name, otherwise the level set
/// for its group, otherwise its group's default. A rule registered through
/// this trait runs at least at [`Level::Warn`] unless a level is set for it or
/// its group.
pub trait Constrainer: Default {
    /// Associated database type for the constrainer.
    type Database: DatabaseLike;

    /// Returns the registered rules and their levels.
    fn constrainer(&self) -> &GenericConstrainer<Self::Database>;

    /// Returns the registered rules and their levels for configuration.
    fn constrainer_mut(&mut self) -> &mut GenericConstrainer<Self::Database>;

    /// Registers a table rule.
    fn register_table_rule(&mut self, rule: Box<dyn TableRule<Database = Self::Database>>) {
        self.constrainer_mut()
            .register_table_rule_with_floor(rule, Level::Warn);
    }

    /// Registers a column rule.
    fn register_column_rule(&mut self, rule: Box<dyn ColumnRule<Database = Self::Database>>) {
        self.constrainer_mut()
            .register_column_rule_with_floor(rule, Level::Warn);
    }

    /// Registers a foreign key rule.
    fn register_foreign_key_rule(
        &mut self,
        rule: Box<dyn ForeignKeyRule<Database = Self::Database>>,
    ) {
        self.constrainer_mut()
            .register_foreign_key_rule_with_floor(rule, Level::Warn);
    }

    /// Registers a schema rule.
    fn register_schema_rule(&mut self, rule: Box<dyn SchemaRule<Database = Self::Database>>) {
        self.constrainer_mut()
            .register_schema_rule_with_floor(rule, Level::Warn);
    }

    /// Excuses the violations of a rule that list the given policy.
    ///
    /// An allowance that excuses nothing, because the policy was fixed, the
    /// names do not match or the rule is at [`Level::Allow`], is reported as
    /// [`Error::UnusedAllowance`].
    fn allow_policy(&mut self, rule: &str, table: TargetName<'_>, policy: &str) {
        self.constrainer_mut().allow_policy(rule, table, policy);
    }

    /// Sets the level of every rule with the given type name, overriding its
    /// group's level.
    fn set_rule_level(&mut self, rule: &str, level: Level) {
        self.constrainer_mut().set_rule_level(rule, level);
    }

    /// Sets the level of every rule in the given group without a level of
    /// its own.
    fn set_group_level(&mut self, group: LintGroup, level: Level) {
        self.constrainer_mut().set_group_level(group, level);
    }

    /// Sets the deployment the rules read, replacing any set before.
    fn set_deployment(&mut self, deployment: Deployment) {
        self.constrainer_mut().set_deployment(deployment);
    }

    /// Returns every rule above [`Level::Allow`] that does not run because
    /// the deployment lacks a declaration it reads.
    ///
    /// # Example
    ///
    /// ```
    /// use sql_rules::prelude::*;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> =
    ///     TruncateGrantedToAppRole::default().into();
    /// assert_eq!(constrainer.inactive_rules().len(), 1);
    /// constrainer.set_deployment(Deployment::default().with_app_role("authenticated"));
    /// assert!(constrainer.inactive_rules().is_empty());
    /// ```
    fn inactive_rules(&self) -> Vec<InactiveRule> {
        self.constrainer().inactive_rules()
    }

    /// Passes every violation, lookup failure and unused allowance to `sink`
    /// until it breaks.
    ///
    /// A lookup failure ends the rule that hit it on that object, and the
    /// traversal continues with the next rule and object. Unused allowances
    /// are reported only after a complete traversal.
    fn visit_schema(
        &self,
        database: &Self::Database,
        sink: &mut dyn FnMut(Error<Self::Database>) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        self.constrainer().visit(database, sink)
    }

    /// Returns every inactive rule, then every violation raised at `warn` or
    /// `deny`, every lookup failure and every unused allowance, in traversal
    /// order.
    ///
    /// # Example
    ///
    /// ```
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::GenericDialect;
    ///
    /// let database = ParserDB::parse::<GenericDialect>(
    ///     "CREATE TABLE Users (Id INT PRIMARY KEY); CREATE TABLE Teams (Id INT PRIMARY KEY);",
    /// )
    /// .unwrap();
    /// let constrainer: GenericConstrainer<ParserDB> = LowercaseTableName::default().into();
    /// assert_eq!(constrainer.diagnostics(&database).len(), 2);
    /// ```
    fn diagnostics(&self, database: &Self::Database) -> Vec<Error<Self::Database>> {
        let mut diagnostics: Vec<Error<Self::Database>> = self
            .inactive_rules()
            .into_iter()
            .map(Error::Inactive)
            .collect();
        let _ = self.visit_schema(database, &mut |error| {
            diagnostics.push(error);
            ControlFlow::Continue(())
        });
        diagnostics
    }

    /// Validates the schema, stopping at the first violation raised at `warn`
    /// or `deny`, the first lookup failure or the first unused allowance.
    ///
    /// # Errors
    ///
    /// Returns the first [`Error::Violation`], [`Error::Lookup`] or
    /// [`Error::UnusedAllowance`] in traversal order.
    fn validate_schema(&self, database: &Self::Database) -> Result<(), Error<Self::Database>> {
        let mut first = None;
        let _ = self.visit_schema(database, &mut |error| {
            first = Some(error);
            ControlFlow::Break(())
        });
        first.map_or(Ok(()), Err)
    }
}
