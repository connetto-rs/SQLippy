//! Submodule defining the `Constrainer` trait, which applies registered rules
//! to a schema at their configured levels.

use std::ops::ControlFlow;

use sql_traits::{structs::TargetName, traits::DatabaseLike};
use sqlparser::ast::Statement;

use crate::{
    deployment::Deployment,
    engine::Engine,
    error::{AllowedObject, Error, InactiveRule},
    lint::{Level, LintGroup, RegisteredRule},
    traits::{
        ColumnRule, ForeignKeyRule, FunctionRule, QueryRule, SchemaRule, ScriptRule, TableRule,
    },
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

    /// Registers a function rule.
    fn register_function_rule(&mut self, rule: Box<dyn FunctionRule<Database = Self::Database>>) {
        self.constrainer_mut()
            .register_function_rule_with_floor(rule, Level::Warn);
    }

    /// Registers a query rule, which checks the statements passed to
    /// [`Constrainer::visit_statement`] and never runs on the schema.
    fn register_query_rule(&mut self, rule: Box<dyn QueryRule<Database = Self::Database>>) {
        self.constrainer_mut()
            .register_query_rule_with_floor(rule, Level::Warn);
    }

    /// Registers a script rule, which checks the statements passed to
    /// [`Constrainer::visit_script`] in order and never runs on the schema
    /// alone.
    fn register_script_rule(&mut self, rule: Box<dyn ScriptRule<Database = Self::Database>>) {
        self.constrainer_mut()
            .register_script_rule_with_floor(rule, Level::Warn);
    }

    /// Excuses the violations of a rule reported on the given table itself.
    /// A view takes [`Constrainer::allow_view`] and a materialized view
    /// [`Constrainer::allow_materialized_view`].
    ///
    /// An allowance that excuses nothing, because the finding was fixed, the
    /// names do not match, the rule is at [`Level::Allow`] or the rule does
    /// not run on the schema's [`Engine`], is reported as
    /// [`Error::UnusedAllowance`].
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE grantees (id INT); ALTER TABLE grantees ENABLE ROW LEVEL SECURITY;",
    /// )
    /// .unwrap();
    /// let mut constrainer: GenericConstrainer<ParserDB> =
    ///     RowLevelSecurityWithoutPolicies::default().into();
    /// constrainer.allow_table(
    ///     "row_level_security_without_policies",
    ///     TargetName::new("grantees", false),
    /// );
    /// assert!(constrainer.validate_schema(&database).is_ok());
    /// ```
    fn allow_table(&mut self, rule: &str, table: TargetName<'_>) {
        self.constrainer_mut()
            .allow(rule, table, AllowedObject::Table);
    }

    /// Excuses the violations of a rule reported on the given view itself.
    ///
    /// An allowance that excuses nothing, because the finding was fixed, the
    /// names do not match, the rule is at [`Level::Allow`] or the rule does
    /// not run on the schema's [`Engine`], is reported as
    /// [`Error::UnusedAllowance`].
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE entries (id INT, body TEXT);
    ///      CREATE VIEW visible AS SELECT * FROM entries;",
    /// )
    /// .unwrap();
    /// let mut constrainer: GenericConstrainer<ParserDB> = WildcardView::default().into();
    /// constrainer.allow_view("wildcard_view", TargetName::new("visible", false));
    /// assert!(constrainer.validate_schema(&database).is_ok());
    /// ```
    fn allow_view(&mut self, rule: &str, view: TargetName<'_>) {
        self.constrainer_mut()
            .allow(rule, view, AllowedObject::View);
    }

    /// Excuses the violations of a rule reported on the given materialized
    /// view itself.
    ///
    /// An allowance that excuses nothing is reported as
    /// [`Error::UnusedAllowance`].
    fn allow_materialized_view(&mut self, rule: &str, view: TargetName<'_>) {
        self.constrainer_mut()
            .allow(rule, view, AllowedObject::MaterializedView);
    }

    /// Excuses the violations of a rule reported on one foreign key of a
    /// table, named by its constraint name as PostgreSQL stores it. A key
    /// declared without a name goes by the one PostgreSQL generates, such as
    /// `posts_author_id_fkey`, which the violation's object shows.
    ///
    /// An allowance that excuses nothing is reported as
    /// [`Error::UnusedAllowance`].
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE ROLE app;
    ///      CREATE TABLE users (id INT PRIMARY KEY);
    ///      GRANT DELETE ON users TO app;
    ///      CREATE TABLE posts (author_id INT REFERENCES users (id) ON DELETE CASCADE);
    ///      ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
    ///      CREATE POLICY posts_delete ON posts FOR DELETE USING (false);",
    /// )
    /// .unwrap();
    /// let mut constrainer: GenericConstrainer<ParserDB> =
    ///     CascadeIntoRowLevelSecurityTable::default().into();
    /// constrainer.set_deployment(Deployment::default().with_app_role("app"));
    /// constrainer.allow_foreign_key(
    ///     "cascade_into_row_level_security_table",
    ///     TargetName::new("posts", false),
    ///     "posts_author_id_fkey",
    /// );
    /// assert!(constrainer.validate_schema(&database).is_ok());
    /// ```
    fn allow_foreign_key(&mut self, rule: &str, table: TargetName<'_>, foreign_key: &str) {
        self.constrainer_mut().allow(
            rule,
            table,
            AllowedObject::ForeignKey(foreign_key.to_owned()),
        );
    }

    /// Excuses the violations of a rule reported on one index of a table, or
    /// on the unique constraint that owns it, named as PostgreSQL stores it.
    /// A constraint declared without a name goes by the one PostgreSQL
    /// generates, such as `users_email_key`, which the violation's object
    /// shows.
    ///
    /// An allowance that excuses nothing is reported as
    /// [`Error::UnusedAllowance`].
    fn allow_index(&mut self, rule: &str, table: TargetName<'_>, index: &str) {
        self.constrainer_mut()
            .allow(rule, table, AllowedObject::Index(index.to_owned()));
    }

    /// Excuses the violations of a rule that list the given policy.
    ///
    /// An allowance that excuses nothing, because the policy was fixed, the
    /// names do not match, the rule is at [`Level::Allow`] or the rule does
    /// not run on the schema's [`Engine`], is reported as
    /// [`Error::UnusedAllowance`].
    fn allow_policy(&mut self, rule: &str, table: TargetName<'_>, policy: &str) {
        self.constrainer_mut()
            .allow(rule, table, AllowedObject::Policy(policy.to_owned()));
    }

    /// Excuses a rule's function findings for the given schema and name, including all overloads.
    ///
    /// An allowance that excuses nothing is reported as [`Error::UnusedAllowance`].
    ///
    /// ```
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE memberships (id INT, parent_id INT);
    ///      CREATE TABLE resources (id INT);
    ///      CREATE FUNCTION global_ids() RETURNS SETOF INT LANGUAGE sql AS $$
    ///        WITH RECURSIVE reachable(id) AS (SELECT id FROM memberships UNION
    ///        SELECT memberships.id FROM memberships JOIN reachable ON memberships.parent_id = reachable.id)
    ///        SELECT id FROM reachable $$;
    ///      ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
    ///      CREATE POLICY resources_read ON resources USING (id IN (SELECT global_ids()));",
    /// ).unwrap();
    /// let mut constrainer: GenericConstrainer<ParserDB> = UnseededPolicySet::default().into();
    /// constrainer.set_deployment(Deployment::example());
    /// constrainer.allow_function("unseeded_policy_set", TargetName::new("global_ids", false));
    /// assert!(constrainer.validate_schema(&database).is_ok());
    /// ```
    fn allow_function(&mut self, rule: &str, function: TargetName<'_>) {
        self.constrainer_mut().allow_function(rule, function);
    }

    /// Excuses the violations of a rule in one statement, matched in the form
    /// sqlparser renders it, so spacing and keyword case do not matter.
    ///
    /// [`Constrainer::visit_schema`] runs the rule on the allowance's own
    /// statement and reports an allowance as [`Error::UnusedAllowance`] when
    /// the rule finds nothing there, because the schema was fixed, the rule
    /// name does not match, the rule is at [`Level::Allow`], the rule does
    /// not run on the schema's [`Engine`] or `statement` is not one PostgreSQL
    /// statement. An application that stops sending the statement leaves the
    /// allowance unreported.
    fn allow_statement(&mut self, rule: &str, statement: &str) {
        self.constrainer_mut().allow_statement(rule, statement);
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

    /// Returns every rule above [`Level::Allow`] that runs on `engine` and
    /// does not run because the deployment lacks a declaration it reads.
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> =
    ///     TruncateGrantedToAppRole::default().into();
    /// assert_eq!(constrainer.inactive_rules(Engine::PostgreSql).len(), 1);
    /// assert!(constrainer.inactive_rules(Engine::Sqlite).is_empty());
    /// constrainer.set_deployment(Deployment::default().with_app_role("authenticated"));
    /// assert!(constrainer.inactive_rules(Engine::PostgreSql).is_empty());
    /// ```
    fn inactive_rules(&self, engine: Engine) -> Vec<InactiveRule> {
        self.constrainer().inactive_rules(engine)
    }

    /// Returns every registered rule with what it runs on, the level it runs
    /// at here, the declarations it needs and the engines it checks, in
    /// registration order.
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    ///
    /// let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    /// constrainer.set_group_level(LintGroup::Style, Level::Deny);
    /// let rule = constrainer
    ///     .rules()
    ///     .into_iter()
    ///     .find(|rule| rule.metadata().name == "singular_table_name")
    ///     .unwrap();
    /// assert_eq!(rule.kind(), RuleKind::Table);
    /// assert_eq!(rule.level(), Level::Deny);
    /// ```
    fn rules(&self) -> Vec<RegisteredRule> {
        self.constrainer().rules()
    }

    /// Passes every unresolved external foreign key, violation, lookup
    /// failure and unused allowance to `sink` until it breaks.
    ///
    /// Unresolved external foreign keys come first. A lookup failure ends
    /// the rule that hit it on that object, and the traversal continues with
    /// the next rule and object. Unused allowances are reported only after a
    /// complete traversal.
    fn visit_schema(
        &self,
        database: &Self::Database,
        sink: &mut dyn FnMut(Error<Self::Database>) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        self.constrainer().visit(database, sink)
    }

    /// Returns every rule inactive on the engine `database` runs on, then
    /// every unresolved external foreign key, every violation raised at
    /// `warn` or `deny`, every lookup failure and every unused allowance, in
    /// traversal order.
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::GenericDialect;
    ///
    /// let database = ParserDB::parse::<GenericDialect>(
    ///     "CREATE TABLE Users (Id INT PRIMARY KEY); CREATE TABLE Teams (Id INT PRIMARY KEY);",
    /// )
    /// .unwrap();
    /// let constrainer: GenericConstrainer<ParserDB> = MixedCaseTableName::default().into();
    /// assert_eq!(constrainer.diagnostics(&database).len(), 2);
    /// ```
    fn diagnostics(&self, database: &Self::Database) -> Vec<Error<Self::Database>> {
        let mut diagnostics: Vec<Error<Self::Database>> = self
            .inactive_rules(Engine::of(database))
            .into_iter()
            .map(Error::Inactive)
            .collect();
        let _ = self.visit_schema(database, &mut |error| {
            diagnostics.push(error);
            ControlFlow::Continue(())
        });
        diagnostics
    }

    /// Validates the schema, stopping at the first unresolved external
    /// foreign key, the first violation raised at `warn` or `deny`, the first
    /// lookup failure or the first unused allowance.
    ///
    /// # Errors
    ///
    /// Returns the first [`Error::UnresolvedForeignKey`],
    /// [`Error::Violation`], [`Error::Lookup`] or [`Error::UnusedAllowance`]
    /// in traversal order.
    fn validate_schema(&self, database: &Self::Database) -> Result<(), Error<Self::Database>> {
        let mut first = None;
        let _ = self.visit_schema(database, &mut |error| {
            first = Some(error);
            ControlFlow::Break(())
        });
        first.map_or(Ok(()), Err)
    }

    /// Passes every violation and lookup failure the query rules raise on
    /// `statement` to `sink` until it breaks.
    ///
    /// Only query rules run, and statement allowances excuse their
    /// violations without being reported as unused.
    fn visit_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        sink: &mut dyn FnMut(Error<Self::Database>) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        self.constrainer()
            .visit_statement(database, statement, sink)
    }

    /// Returns every violation raised at `warn` or `deny` and every lookup
    /// failure the query rules raise on `statement`, in rule order.
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let database =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE a (id INT); CREATE TABLE b (a_id INT);")
    ///         .unwrap();
    /// let constrainer = DefaultConstrainer::<ParserDB>::default();
    /// let statement = &Parser::parse_sql(
    ///     &PostgreSqlDialect {},
    ///     "SELECT id FROM a WHERE id NOT IN (SELECT a_id FROM b)",
    /// )
    /// .unwrap()[0];
    /// assert_eq!(constrainer.statement_diagnostics(&database, statement).len(), 1);
    /// ```
    fn statement_diagnostics(
        &self,
        database: &Self::Database,
        statement: &Statement,
    ) -> Vec<Error<Self::Database>> {
        let mut diagnostics = Vec::new();
        let _ = self.visit_statement(database, statement, &mut |error| {
            diagnostics.push(error);
            ControlFlow::Continue(())
        });
        diagnostics
    }

    /// Validates one statement, stopping at the first violation raised at
    /// `warn` or `deny` or the first lookup failure.
    ///
    /// # Errors
    ///
    /// Returns the first [`Error::Violation`] or [`Error::Lookup`] the query
    /// rules raise on `statement`.
    fn validate_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
    ) -> Result<(), Error<Self::Database>> {
        let mut first = None;
        let _ = self.visit_statement(database, statement, &mut |error| {
            first = Some(error);
            ControlFlow::Break(())
        });
        first.map_or(Ok(()), Err)
    }

    /// Passes every violation and lookup failure the script rules raise on
    /// `statements`, read in order, to `sink` until it breaks.
    ///
    /// `statements` are the script `database` was built from. Only script
    /// rules run, and statement allowances excuse their violations.
    fn visit_script(
        &self,
        database: &Self::Database,
        statements: &[Statement],
        sink: &mut dyn FnMut(Error<Self::Database>) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        self.constrainer().visit_script(database, statements, sink)
    }

    /// Returns every violation raised at `warn` or `deny` and every lookup
    /// failure the script rules raise on `statements`, in rule order.
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let sql = "SET search_path = \"pg_catalog, pg_temp\";";
    /// let database = ParserDB::parse::<PostgreSqlDialect>(sql).unwrap();
    /// let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap();
    /// let constrainer = DefaultConstrainer::<ParserDB>::default();
    /// assert_eq!(constrainer.script_diagnostics(&database, &statements).len(), 1);
    /// ```
    fn script_diagnostics(
        &self,
        database: &Self::Database,
        statements: &[Statement],
    ) -> Vec<Error<Self::Database>> {
        let mut diagnostics = Vec::new();
        let _ = self.visit_script(database, statements, &mut |error| {
            diagnostics.push(error);
            ControlFlow::Continue(())
        });
        diagnostics
    }
}
