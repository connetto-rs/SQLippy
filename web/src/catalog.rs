//! Every rule SQLippy registers by default, described for the rule explorer.

use sqlippy::prelude::*;

/// One rule as the explorer shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogEntry {
    /// The rule's name, its configuration key.
    pub name: &'static str,
    /// The rule's group.
    pub group: LintGroup,
    /// The level the rule runs at by default.
    pub level: Level,
    /// Whether the rule decides from declared structure or guesses from names.
    pub basis: Basis,
    /// Why the flagged shape is bad.
    pub rationale: &'static str,
    /// URL of a source documenting the problem.
    pub source: Option<&'static str>,
    /// What the rule runs on, more than one for a rule registered twice.
    pub kinds: Vec<RuleKind>,
    /// Deployment declarations the rule cannot run without.
    pub requires: &'static [Declaration],
    /// SQL the rule reports and its corrected form.
    pub example: RuleExample,
}

/// Every rule of the default constrainer, by group in severity order and by
/// name within a group.
pub fn catalog() -> Vec<CatalogEntry> {
    let mut entries: Vec<CatalogEntry> = Vec::new();
    for rule in DefaultConstrainer::<ParserDB>::default().rules() {
        let metadata = rule.metadata();
        match entries.iter_mut().find(|entry| entry.name == metadata.name) {
            Some(entry) => entry.kinds.push(rule.kind()),
            None => entries.push(CatalogEntry {
                name: metadata.name,
                group: metadata.group,
                level: rule.level(),
                basis: metadata.basis,
                rationale: metadata.rationale,
                source: metadata.source,
                kinds: vec![rule.kind()],
                requires: rule.requires(),
                example: metadata.example,
            }),
        }
    }
    entries.sort_by_key(|entry| {
        let rank = LintGroup::ALL
            .iter()
            .position(|group| *group == entry.group)
            .unwrap_or(LintGroup::ALL.len());
        (rank, entry.name)
    });
    entries
}

/// What a rule kind runs on, as a phrase.
pub fn kind_phrase(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::Table => "each table",
        RuleKind::Column => "each column",
        RuleKind::ForeignKey => "each foreign key",
        RuleKind::Schema => "the whole schema",
        RuleKind::Function => "each function",
        RuleKind::Query => "each application statement",
    }
}
