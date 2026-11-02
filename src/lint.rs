//! Lint groups, levels and the metadata every rule carries.

use std::fmt::{self, Display};

use crate::deployment::Declaration;

/// Category of a rule, following Clippy's lint groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LintGroup {
    /// Schemas that are outright wrong or useless.
    Correctness,
    /// Schemas that are most likely wrong.
    Suspicious,
    /// Schemas that can be written to run faster.
    Perf,
    /// Schemas that can be written more simply.
    Complexity,
    /// Conventions a schema should follow.
    Style,
    /// Strict checks with occasional false positives.
    Pedantic,
    /// Checks that only some projects want.
    Restriction,
}

impl LintGroup {
    /// Every group, in severity order.
    pub const ALL: [Self; 7] = [
        Self::Correctness,
        Self::Suspicious,
        Self::Perf,
        Self::Complexity,
        Self::Style,
        Self::Pedantic,
        Self::Restriction,
    ];

    /// Returns the level a rule of this group runs at unless configured.
    ///
    /// # Example
    ///
    /// ```
    /// use sql_rules::prelude::*;
    ///
    /// assert_eq!(LintGroup::Correctness.default_level(), Level::Deny);
    /// assert_eq!(LintGroup::Style.default_level(), Level::Warn);
    /// assert_eq!(LintGroup::Pedantic.default_level(), Level::Allow);
    /// ```
    #[must_use]
    pub const fn default_level(self) -> Level {
        match self {
            Self::Correctness => Level::Deny,
            Self::Suspicious | Self::Perf | Self::Complexity | Self::Style => Level::Warn,
            Self::Pedantic | Self::Restriction => Level::Allow,
        }
    }

    /// Returns the group's lowercase name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Correctness => "correctness",
            Self::Suspicious => "suspicious",
            Self::Perf => "perf",
            Self::Complexity => "complexity",
            Self::Style => "style",
            Self::Pedantic => "pedantic",
            Self::Restriction => "restriction",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Correctness => 0,
            Self::Suspicious => 1,
            Self::Perf => 2,
            Self::Complexity => 3,
            Self::Style => 4,
            Self::Pedantic => 5,
            Self::Restriction => 6,
        }
    }
}

impl Display for LintGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Severity a rule runs at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// The rule does not run.
    Allow,
    /// Violations are warnings.
    Warn,
    /// Violations are errors.
    Deny,
}

impl Display for Level {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Deny => "deny",
        })
    }
}

/// Identity, group and explanation shared by every violation of a rule.
#[derive(Debug)]
pub struct RuleMetadata {
    /// The rule's type name, which is its stable configuration key.
    pub name: &'static str,
    /// The rule's group.
    pub group: LintGroup,
    /// Why the flagged shape is bad.
    pub rationale: &'static str,
    /// URL of a source documenting the problem, when one exists.
    pub source: Option<&'static str>,
}

/// A rule with lint metadata.
pub trait Rule {
    /// Returns the rule's metadata.
    fn metadata(&self) -> &'static RuleMetadata;

    /// Returns the declarations the rule cannot run without. A rule whose
    /// declaration the deployment lacks is inactive.
    fn requires(&self) -> &'static [Declaration] {
        &[]
    }
}
