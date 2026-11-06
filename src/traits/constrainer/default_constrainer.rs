//! Submodule defining a constrainer holding every generic rule at its group's
//! default level.

use sql_traits::traits::DatabaseLike;

use crate::{
    lint::Level,
    rules::{
        ArrayMembershipPolicy, AutovacuumDisabledTable, BlankPaddedCharacter,
        CascadeIntoRowLevelSecurityTable, ChildWithoutRowLevelSecurity,
        ClientRoleBypassesRowLevelSecurity, ClientWrittenCounterKey, ClientWrittenScaledNumeric,
        CompatibleForeignKey, CorrelatedPolicySubquery, CredentialFreeWrite,
        CredentialSettingWrite, DeadPermissivePolicy, DefinerTakesActingUser,
        DefinerTemporarySchemaNotLast, DefinerWithoutSearchPath, DenyListPolicy,
        ExposedDefinerOverProtectedTable, ExtensionForeignKeyOnDeleteCascade,
        ExtensionInExposedSchema, FunctionMediatedPolicyCycle, GrantOptionToClientRole,
        HasPrimaryKey, ImpureImmutableFunction, JsonType, KeyWithoutExactEquality,
        LatentPolicyReadCycle, LowercaseColumnName, LowercaseForeignKeyName, LowercaseTableName,
        MoneyType, MultiplePermissivePolicies, NarrowIntegerKey, NestedPolicySubquery,
        NoForbiddenColumnInExtension, NoNegationCheckRule, NoRustKeywordColumnName,
        NoRustKeywordForeignKeyName, NoRustKeywordTableName, NoSurrogatePrimaryKeyInExtension,
        NoTautologicalCheckRule, NonCompositePrimaryKeyNamedId, NonEmptyTextualColumnRule,
        NonRedundantExtensionDag, NotInNullableSubquery, NotInSubquery,
        NullableCompositeForeignKey, NullableUniqueColumn, OffsetPaging, OuterColumnCapture,
        OwnerRightsView, PastTimeColumnRule, PluralTableName, PoliciesRequireRowLevelSecurity,
        PolicyReadCycle, PolicyToCreatingRole, PrefixRedundantIndex, PrimaryKeyReferenceEndsWithId,
        PublicSchemaCreate, QueryRewriteRule, RandomOrderLimit, ReachableForeignTable,
        ReachableMaterializedView, ReachableSequence, ReachableTableWithoutRowLevelSecurity,
        ReferencesGrantedToClientRole, RegColumnType, ReservedKeywordIdentifier,
        RoleKeyedPolicyWhenPooled, RowLevelSecurityWithoutPolicies, ScaledNumeric,
        SecurityBarrierMissingOnFilteringView, SecurityDefinerFunctionExposed,
        SelfAssertedClaimPolicy, SelfGrantingWrite, SerialColumn, SessionTimeZoneDependence,
        SettableMembershipInBypassingRole, SingularColumnName, SnakeCaseColumnName,
        SnakeCaseTableName, SubjectSettableAttribute, TableInheritance, TautologicalWithCheck,
        TextualColumnRule, TimeDependentCheck, TimeWithTimeZone, TimestampBetween,
        TimestampWithoutTimeZone, TruncateGrantedToAnonymousRole, TruncateGrantedToAppRole,
        TruncatedIdentifier, TruncatingIntegerDivision, UncachedPolicyCall, UnfilteredWrite,
        UnforcedRowLevelSecurity, UnindexedForeignKey, UnindexedPolicyFilter, UniqueCheckRule,
        UniqueColumnNamesInExtensionGraph, UniqueForeignKey, UniqueUniqueIndex, UnloggedTable,
        UnscopedUniqueConstraintOnRowLevelSecurityTable, UnvalidatedConstraint, WildcardView,
        ZeroPrecisionTimestamp,
    },
    traits::{
        ColumnRule, Constrainer, ForeignKeyRule, FunctionRule, GenericConstrainer, QueryRule,
        SchemaRule, TableRule,
    },
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
        let table_rules: [Box<dyn TableRule<Database = DB>>; 35] = [
            Box::new(TimeDependentCheck::default()),
            Box::new(PrefixRedundantIndex::default()),
            Box::new(HasPrimaryKey::default()),
            Box::new(KeyWithoutExactEquality::default()),
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
            Box::new(CorrelatedPolicySubquery::default()),
            Box::new(NestedPolicySubquery::default()),
            Box::new(UncachedPolicyCall::default()),
            Box::new(UnindexedPolicyFilter::default()),
            Box::new(ArrayMembershipPolicy::default()),
            Box::new(DenyListPolicy::default()),
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
        let column_rules: [Box<dyn ColumnRule<Database = DB>>; 12] = [
            Box::new(SerialColumn::default()),
            Box::new(NarrowIntegerKey::default()),
            Box::new(ClientWrittenCounterKey::default()),
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
        let foreign_key_rules: [Box<dyn ForeignKeyRule<Database = DB>>; 8] = [
            Box::new(NullableCompositeForeignKey::default()),
            Box::new(UnindexedForeignKey::default()),
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
        register_schema_rules(&mut constrainer);
        let function_rules: [Box<dyn FunctionRule<Database = DB>>; 5] = [
            Box::new(ImpureImmutableFunction::default()),
            Box::new(DefinerWithoutSearchPath::default()),
            Box::new(DefinerTemporarySchemaNotLast::default()),
            Box::new(ExposedDefinerOverProtectedTable::default()),
            Box::new(GrantOptionToClientRole::default()),
        ];
        for rule in function_rules {
            constrainer.register_function_rule_with_floor(rule, Level::Allow);
        }
        let query_rules: [Box<dyn QueryRule<Database = DB>>; 10] = [
            Box::new(NotInNullableSubquery::default()),
            Box::new(NotInSubquery::default()),
            Box::new(RandomOrderLimit::default()),
            Box::new(OffsetPaging::default()),
            Box::new(UnfilteredWrite::default()),
            Box::new(CredentialSettingWrite::default()),
            Box::new(OuterColumnCapture::default()),
            Box::new(TimestampBetween::default()),
            Box::new(SessionTimeZoneDependence::default()),
            Box::new(TruncatingIntegerDivision::default()),
        ];
        for rule in query_rules {
            constrainer.register_query_rule_with_floor(rule, Level::Allow);
        }
        Self { constrainer }
    }
}

/// Registers every built-in schema rule at its group's default level.
fn register_schema_rules<DB: DatabaseLike + 'static>(constrainer: &mut GenericConstrainer<DB>) {
    let schema_rules: [Box<dyn SchemaRule<Database = DB>>; 42] = [
        Box::new(UnscopedUniqueConstraintOnRowLevelSecurityTable::default()),
        Box::new(NullableUniqueColumn::default()),
        Box::new(SecurityDefinerFunctionExposed::default()),
        Box::new(ExtensionInExposedSchema::default()),
        Box::new(ReachableSequence::default()),
        Box::new(SecurityBarrierMissingOnFilteringView::default()),
        Box::new(RowLevelSecurityWithoutPolicies::default()),
        Box::new(MultiplePermissivePolicies::default()),
        Box::new(RegColumnType::default()),
        Box::new(AutovacuumDisabledTable::default()),
        Box::new(QueryRewriteRule::default()),
        Box::new(TableInheritance::default()),
        Box::new(TruncatedIdentifier::default()),
        Box::new(ReservedKeywordIdentifier::default()),
        Box::new(UnvalidatedConstraint::default()),
        Box::new(PublicSchemaCreate::default()),
        Box::new(UnloggedTable::default()),
        Box::new(WildcardView::default()),
        Box::new(NotInNullableSubquery::default()),
        Box::new(NotInSubquery::default()),
        Box::new(TimestampWithoutTimeZone::default()),
        Box::new(TimeWithTimeZone::default()),
        Box::new(ZeroPrecisionTimestamp::default()),
        Box::new(BlankPaddedCharacter::default()),
        Box::new(MoneyType::default()),
        Box::new(JsonType::default()),
        Box::new(ScaledNumeric::default()),
        Box::new(ClientWrittenScaledNumeric::default()),
        Box::new(PolicyReadCycle::default()),
        Box::new(LatentPolicyReadCycle::default()),
        Box::new(FunctionMediatedPolicyCycle::default()),
        Box::new(ReachableMaterializedView::default()),
        Box::new(ReachableForeignTable::default()),
        Box::new(ChildWithoutRowLevelSecurity::default()),
        Box::new(OwnerRightsView::default()),
        Box::new(ClientRoleBypassesRowLevelSecurity::default()),
        Box::new(SettableMembershipInBypassingRole::default()),
        Box::new(GrantOptionToClientRole::default()),
        Box::new(SelfAssertedClaimPolicy::default()),
        Box::new(SelfGrantingWrite::default()),
        Box::new(DefinerTakesActingUser::default()),
        Box::new(SubjectSettableAttribute::default()),
    ];
    for rule in schema_rules {
        constrainer.register_schema_rule_with_floor(rule, Level::Allow);
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
