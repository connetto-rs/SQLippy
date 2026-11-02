//! Violations and failures raised while applying rules.

use std::fmt::{self, Display};

use sql_traits::{
    errors::LookupError,
    structs::TargetName,
    traits::{DatabaseLike, PolicyLike, TableLike},
};

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
    /// Policy clauses, in the order the finding traverses them.
    Policies(Vec<PolicySite<DB>>),
}

/// Clause of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyClause {
    /// The `USING` clause, which filters existing rows.
    Using,
    /// The `WITH CHECK` clause, which checks new rows.
    WithCheck,
}

impl Display for PolicyClause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
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

/// A reviewed exception excusing one rule's violations that list a policy.
#[derive(Debug, Clone)]
pub struct PolicyAllowance {
    pub(crate) rule: String,
    pub(crate) table: TargetName<'static>,
    pub(crate) policy: String,
}

impl PolicyAllowance {
    /// Returns the type name of the excused rule.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// Returns the table the excused policy is defined on.
    #[must_use]
    pub fn table(&self) -> &TargetName<'static> {
        &self.table
    }

    /// Returns the name of the excused policy.
    #[must_use]
    pub fn policy(&self) -> &str {
        &self.policy
    }
}

impl Display for PolicyAllowance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the allowance for {} on policy '{}' of table '{}' excuses no violation",
            self.rule,
            self.policy,
            self.table.name()
        )
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
            "{} does not run because the deployment declares no {}",
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
    UnusedAllowance(PolicyAllowance),
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
