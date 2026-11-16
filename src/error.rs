//! Violations and failures raised while applying rules.

use std::fmt::{self, Display};

use sql_traits::{
    errors::LookupError,
    structs::{IdentifierCase, TargetName},
    traits::{DatabaseLike, PolicyLike, TableLike},
};
use sqlparser::ast::Statement;

use crate::{
    deployment::Declaration,
    lint::{Level, RuleMetadata},
};

/// Schema object a violation was raised on.
#[derive(Debug)]
pub enum Location<DB: DatabaseLike> {
    /// A table.
    Table(Box<DB::Table>),
    /// A column.
    Column(Box<DB::Column>),
    /// A foreign key.
    ForeignKey(Box<DB::ForeignKey>),
    /// A unique constraint.
    UniqueIndex(Box<DB::UniqueIndex>),
    /// An index created with `CREATE INDEX`.
    Index(Box<DB::Index>),
    /// Policy clauses, in the order the finding traverses them.
    Policies(Vec<PolicySite<DB>>),
    /// A view.
    View(Box<DB::View>),
    /// A materialized view.
    MaterializedView(Box<DB::MaterializedView>),
    /// A role.
    Role(Box<DB::Role>),
    /// A function.
    Function(Box<DB::Function>),
    /// A domain.
    Domain(Box<DB::Domain>),
    /// A grant statement.
    Grant(Box<DB::TableGrant>),
    /// An extension.
    Extension(Box<DB::Extension>),
    /// A sequence.
    Sequence(Box<DB::Sequence>),
    /// A statement an application sends.
    Statement(StatementSite),
}

/// Clause of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyClause {
    /// The `TO` list, which names the roles the policy applies to.
    To,
    /// The `USING` clause, which filters existing rows.
    Using,
    /// The `WITH CHECK` clause, which checks new rows.
    WithCheck,
}

impl Display for PolicyClause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::To => "TO",
            Self::Using => "USING",
            Self::WithCheck => "WITH CHECK",
        })
    }
}

/// One policy clause and the offending sub-expression within it.
#[derive(Debug)]
pub struct PolicySite<DB: DatabaseLike> {
    pub(crate) table: Box<DB::Table>,
    pub(crate) policy: Box<DB::Policy>,
    pub(crate) clause: PolicyClause,
    pub(crate) expression: String,
}

impl<DB: DatabaseLike> PolicySite<DB> {
    /// Returns the table the policy is defined on.
    #[must_use]
    pub fn table(&self) -> &DB::Table {
        &self.table
    }

    /// Returns the policy.
    #[must_use]
    pub fn policy(&self) -> &DB::Policy {
        &self.policy
    }

    /// Returns the clause holding the offending sub-expression.
    #[must_use]
    pub fn clause(&self) -> PolicyClause {
        self.clause
    }

    /// Returns the offending sub-expression rendered as SQL.
    #[must_use]
    pub fn expression(&self) -> &str {
        &self.expression
    }
}

impl<DB: DatabaseLike> Display for PolicySite<DB> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (table, policy) = (self.table.table_name(), self.policy.name());
        write!(
            formatter,
            "{table}.{policy} {}: {}",
            self.clause, self.expression
        )
    }
}

/// One statement and the offending sub-expression within it.
#[derive(Debug)]
pub struct StatementSite {
    pub(crate) statement: String,
    pub(crate) expression: String,
}

impl StatementSite {
    /// Returns the statement as sqlparser renders it, the form statement
    /// allowances are matched in.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Returns the offending sub-expression rendered as SQL.
    #[must_use]
    pub fn expression(&self) -> &str {
        &self.expression
    }
}

/// The schema object a [`SchemaAllowance`] names on its table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedObject {
    /// The table itself.
    Table,
    /// A foreign key of the table, by its constraint name.
    ForeignKey(String),
    /// An index of the table, or the unique constraint that owns one, by its
    /// name.
    Index(String),
    /// A policy on the table, by its name.
    Policy(String),
}

impl Display for AllowedObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Table => formatter.write_str("the table"),
            Self::ForeignKey(name) => write!(formatter, "foreign key '{name}'"),
            Self::Index(name) => write!(formatter, "index '{name}'"),
            Self::Policy(name) => write!(formatter, "policy '{name}'"),
        }
    }
}

/// A reviewed exception excusing one rule's violations on one schema object.
#[derive(Debug, Clone)]
pub struct SchemaAllowance {
    pub(crate) rule: String,
    pub(crate) table: TargetName<'static>,
    pub(crate) object: AllowedObject,
}

impl SchemaAllowance {
    /// Returns the type name of the excused rule.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// Returns the table the excused object belongs to.
    #[must_use]
    pub fn table(&self) -> &TargetName<'static> {
        &self.table
    }

    /// Returns the excused object.
    #[must_use]
    pub fn object(&self) -> &AllowedObject {
        &self.object
    }
}

impl Display for SchemaAllowance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (rule, table) = (&self.rule, self.table.name());
        if self.object == AllowedObject::Table {
            write!(formatter, "the allowance for {rule} on table '{table}'")?;
        } else {
            let object = &self.object;
            write!(
                formatter,
                "the allowance for {rule} on {object} of table '{table}'"
            )?;
        }
        formatter.write_str(" excuses no violation")
    }
}

/// A reviewed exception for a function's stored schema and name, including its overloads.
#[derive(Debug, Clone)]
pub struct FunctionAllowance {
    pub(crate) rule: String,
    pub(crate) function: TargetName<'static>,
}

impl FunctionAllowance {
    /// Returns the type name of the excused rule.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// Returns the excused function's schema and name.
    #[must_use]
    pub fn function(&self) -> &TargetName<'static> {
        &self.function
    }

    /// Whether the allowance names this function under the schema allowance's identifier rules.
    pub(crate) fn excuses(&self, rule: &RuleMetadata, function: &TargetName<'_>) -> bool {
        self.rule == rule.name
            && IdentifierCase::Folded.identifiers_match(
                self.function.name(),
                self.function.name_is_quoted(),
                function.name(),
                function.name_is_quoted(),
            )
            && IdentifierCase::Folded.identifiers_match(
                self.function.schema().unwrap_or("public"),
                self.function.schema_is_quoted(),
                function.schema().unwrap_or("public"),
                function.schema_is_quoted(),
            )
    }
}

impl Display for FunctionAllowance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the allowance for {} on function '{}' excuses no violation",
            self.rule, self.function
        )
    }
}

/// A reviewed exception excusing one rule's violations in one statement.
#[derive(Debug, Clone)]
pub struct StatementAllowance {
    pub(crate) rule: String,
    pub(crate) statement: String,
    pub(crate) parsed: Option<Box<Statement>>,
}

impl StatementAllowance {
    /// Returns the type name of the excused rule.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// Returns the excused statement as sqlparser renders it, or as written
    /// when it does not parse as one PostgreSQL statement.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Whether this allowance excuses `rule` on the statement rendered as
    /// `statement`.
    pub(crate) fn excuses(&self, rule: &RuleMetadata, statement: &str) -> bool {
        self.parsed.is_some() && self.rule == rule.name && self.statement == statement
    }
}

impl Display for StatementAllowance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the allowance for {} on statement '{}' excuses no violation",
            self.rule, self.statement
        )
    }
}

/// A reviewed exception excusing a rule's violations.
#[derive(Debug, Clone)]
pub enum Allowance {
    /// An allowance naming a table or an object on it.
    Schema(SchemaAllowance),
    /// An allowance naming a statement.
    Statement(StatementAllowance),
    /// An allowance naming a function's schema and name.
    Function(FunctionAllowance),
}

impl Display for Allowance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(allowance) => allowance.fmt(formatter),
            Self::Statement(allowance) => allowance.fmt(formatter),
            Self::Function(allowance) => allowance.fmt(formatter),
        }
    }
}

/// A registered rule that does not run because the deployment lacks a
/// declaration it reads.
#[derive(Debug, Clone, Copy)]
pub struct InactiveRule {
    pub(crate) rule: &'static RuleMetadata,
    pub(crate) missing: Declaration,
}

impl InactiveRule {
    /// Returns the metadata of the inactive rule.
    #[must_use]
    pub fn rule(&self) -> &'static RuleMetadata {
        self.rule
    }

    /// Returns the declaration the deployment lacks.
    #[must_use]
    pub fn missing(&self) -> Declaration {
        self.missing
    }
}

impl Display for InactiveRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} does not run because the deployment does not declare {}",
            self.rule.name, self.missing
        )
    }
}

/// One occurrence of a rule violation.
#[derive(Debug)]
pub struct Violation<DB: DatabaseLike> {
    pub(crate) rule: &'static RuleMetadata,
    pub(crate) level: Level,
    pub(crate) location: Location<DB>,
    pub(crate) object: String,
    pub(crate) message: String,
    pub(crate) resolution: String,
}

impl<DB: DatabaseLike> Violation<DB> {
    /// Returns the metadata of the violated rule.
    #[must_use]
    pub fn rule(&self) -> &'static RuleMetadata {
        self.rule
    }

    /// Returns the level the violation was raised at.
    #[must_use]
    pub fn level(&self) -> Level {
        self.level
    }

    /// Returns the schema object the violation was raised on.
    #[must_use]
    pub fn location(&self) -> &Location<DB> {
        &self.location
    }

    /// Returns the name of the offending schema object.
    #[must_use]
    pub fn object(&self) -> &str {
        &self.object
    }

    /// Returns what is wrong with this object.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the corrected shape.
    #[must_use]
    pub fn resolution(&self) -> &str {
        &self.resolution
    }
}

impl<DB: DatabaseLike> Display for Violation<DB> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            rule,
            level,
            object,
            message,
            resolution,
            ..
        } = self;
        let RuleMetadata {
            name,
            group,
            rationale,
            ..
        } = rule;
        write!(formatter, "{level} [{group}::{name}] {object}: {message}")?;
        write!(formatter, "\n  why: {rationale}\n  fix: {resolution}")?;
        if let Location::Policies(sites) = &self.location {
            for site in sites {
                write!(formatter, "\n  at {site}")?;
            }
        }
        if let Location::Statement(site) = &self.location {
            write!(formatter, "\n  in {}", site.statement)?;
        }
        if let Some(source) = self.rule.source {
            write!(formatter, "\n  source: {source}")?;
        }
        Ok(())
    }
}

/// Failure raised while applying rules.
#[derive(Debug, thiserror::Error)]
pub enum Error<DB: DatabaseLike> {
    /// A rule was violated at `warn` or `deny`.
    #[error("{0}")]
    Violation(Box<Violation<DB>>),
    /// A rule could not resolve a schema object it depends on, such as the
    /// table a foreign key references.
    #[error("Schema lookup failed: {0}")]
    Lookup(#[from] LookupError),
    /// An allowance excused no violation, so it is stale or misspelled.
    #[error("Unused allowance: {0}")]
    UnusedAllowance(Allowance),
    /// A registered rule does not run because the deployment lacks a
    /// declaration it reads.
    #[error("Inactive rule: {0}")]
    Inactive(InactiveRule),
}

/// Why a rule stopped before checking everything it covers.
#[derive(Debug)]
pub enum Interruption {
    /// A schema object the rule reads could not be resolved.
    Lookup(LookupError),
    /// The caller asked to stop after the last reported violation.
    Halted,
}

impl From<LookupError> for Interruption {
    fn from(error: LookupError) -> Self {
        Self::Lookup(error)
    }
}
