//! Submodule defining a constrainer holding every generic rule at its group's
//! default level.

use sql_traits::traits::DatabaseLike;

use crate::{
    lint::Level,
    rules::{
        CascadeIntoRowLevelSecurityTable, ChildWithoutRowLevelSecurity,
        ClientRoleBypassesRowLevelSecurity, CompatibleForeignKey, CredentialFreeWrite,
        DeadPermissivePolicy, ExtensionForeignKeyOnDeleteCascade, GrantOptionToClientRole,
        HasPrimaryKey, LatentPolicyReadCycle, LowercaseColumnName, LowercaseForeignKeyName,
        LowercaseTableName, NoForbiddenColumnInExtension, NoNegationCheckRule,
        NoRustKeywordColumnName, NoRustKeywordForeignKeyName, NoRustKeywordTableName,
        NoSurrogatePrimaryKeyInExtension, NoTautologicalCheckRule, NonCompositePrimaryKeyNamedId,
        NonEmptyTextualColumnRule, NonRedundantExtensionDag, PastTimeColumnRule, PluralTableName,
        PoliciesRequireRowLevelSecurity, PolicyReadCycle, PolicyToCreatingRole,
        PrimaryKeyReferenceEndsWithId, ReachableMaterializedView,
        ReachableTableWithoutRowLevelSecurity, ReferencesGrantedToClientRole,
        RoleKeyedPolicyWhenPooled, SettableMembershipInBypassingRole, SingularColumnName,
        SnakeCaseColumnName, SnakeCaseTableName, TautologicalWithCheck, TextualColumnRule,
        TruncateGrantedToAnonymousRole, TruncateGrantedToAppRole, UnforcedRowLevelSecurity,
        UniqueCheckRule, UniqueColumnNamesInExtensionGraph, UniqueForeignKey, UniqueUniqueIndex,
    },
    traits::{ColumnRule, Constrainer, ForeignKeyRule, GenericConstrainer, SchemaRule, TableRule},
};

/// A constrainer holding every generic rule at its group's default level.
///
/// `correctness` rules deny, `suspicious`, `perf`, `complexity` and `style`
/// rules warn, and `pedantic` and `restriction` rules stay at `allow` until a
/// level is set for them or their group.
///
/// # Example
///
/// ```
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let database = ParserDB::parse::<GenericDialect>("CREATE TABLE t (type INT);").unwrap();
/// let mut constrainer = DefaultConstrainer::<ParserDB>::default();
/// let raised_by = |constrainer: &DefaultConstrainer<ParserDB>, rule: &str| {
///     constrainer.diagnostics(&database).iter().any(|error| {
///         matches!(error, Error::Violation(violation) if violation.rule().name == rule)
///     })
/// };
/// assert!(!raised_by(&constrainer, "NoRustKeywordColumnName"));
/// constrainer.set_group_level(LintGroup::Restriction, Level::Warn);
/// assert!(raised_by(&constrainer, "NoRustKeywordColumnName"));
/// ```
pub struct DefaultConstrainer<DB: DatabaseLike> {
    constrainer: GenericConstrainer<DB>,
}

impl<DB: DatabaseLike + 'static> Default for DefaultConstrainer<DB> {
    fn default() -> Self {
        let mut constrainer = GenericConstrainer::default();
        let table_rules: [Box<dyn TableRule<Database = DB>>; 26] = [
            Box::new(HasPrimaryKey::default()),
            Box::new(LowercaseTableName::default()),
            Box::new(SnakeCaseTableName::default()),
            Box::new(PluralTableName::default()),
            Box::new(PoliciesRequireRowLevelSecurity::default()),
            Box::new(NoRustKeywordTableName::default()),
            Box::new(NoTautologicalCheckRule::default()),
            Box::new(NoNegationCheckRule::default()),
            Box::new(NoForbiddenColumnInExtension::new("most_concrete_table")),
            Box::new(NonRedundantExtensionDag::default()),
            Box::new(UniqueCheckRule::default()),
            Box::new(UniqueColumnNamesInExtensionGraph::default()),
            Box::new(UniqueForeignKey::default()),
            Box::new(UniqueUniqueIndex::default()),
            Box::new(DeadPermissivePolicy::default()),
            Box::new(TautologicalWithCheck::default()),
            Box::new(UnforcedRowLevelSecurity::default()),
            Box::new(ReachableTableWithoutRowLevelSecurity::default()),
            Box::new(TruncateGrantedToAnonymousRole::default()),
            Box::new(TruncateGrantedToAppRole::default()),
            Box::new(ReferencesGrantedToClientRole::default()),
            Box::new(GrantOptionToClientRole::default()),
            Box::new(ChildWithoutRowLevelSecurity::default()),
            Box::new(PolicyToCreatingRole::default()),
            Box::new(RoleKeyedPolicyWhenPooled::default()),
            Box::new(CredentialFreeWrite::default()),
        ];
        for rule in table_rules {
            constrainer.register_table_rule_with_floor(rule, Level::Allow);
        }
        let column_rules: [Box<dyn ColumnRule<Database = DB>>; 9] = [
            Box::new(LowercaseColumnName::default()),
            Box::new(NonCompositePrimaryKeyNamedId::default()),
            Box::new(NoSurrogatePrimaryKeyInExtension::default()),
            Box::new(SnakeCaseColumnName::default()),
            Box::new(SingularColumnName::default()),
            Box::new(NoRustKeywordColumnName::default()),
            Box::new(TextualColumnRule::default()),
            Box::new(NonEmptyTextualColumnRule::default()),
            Box::new(PastTimeColumnRule::default()),
        ];
        for rule in column_rules {
            constrainer.register_column_rule_with_floor(rule, Level::Allow);
        }
        let foreign_key_rules: [Box<dyn ForeignKeyRule<Database = DB>>; 6] = [
            Box::new(CompatibleForeignKey::default()),
            Box::new(LowercaseForeignKeyName::default()),
            Box::new(PrimaryKeyReferenceEndsWithId::default()),
            Box::new(ExtensionForeignKeyOnDeleteCascade::default()),
            Box::new(NoRustKeywordForeignKeyName::default()),
            Box::new(CascadeIntoRowLevelSecurityTable::default()),
        ];
        for rule in foreign_key_rules {
            constrainer.register_foreign_key_rule_with_floor(rule, Level::Allow);
        }
        let schema_rules: [Box<dyn SchemaRule<Database = DB>>; 5] = [
            Box::new(PolicyReadCycle::default()),
            Box::new(LatentPolicyReadCycle::default()),
            Box::new(ReachableMaterializedView::default()),
            Box::new(ClientRoleBypassesRowLevelSecurity::default()),
            Box::new(SettableMembershipInBypassingRole::default()),
        ];
        for rule in schema_rules {
            constrainer.register_schema_rule_with_floor(rule, Level::Allow);
        }
        Self { constrainer }
    }
}

impl<DB: DatabaseLike + 'static> Constrainer for DefaultConstrainer<DB> {
    type Database = DB;

    fn constrainer(&self) -> &GenericConstrainer<DB> {
        &self.constrainer
    }

    fn constrainer_mut(&mut self) -> &mut GenericConstrainer<DB> {
        &mut self.constrainer
    }
}
