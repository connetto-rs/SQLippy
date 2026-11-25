//! Submodule defining a constrainer holding every generic rule at its group's
//! default level.

use sql_traits::traits::DatabaseLike;

use crate::{
    lint::Level,
    rules::{
        AddressStoredAsText, AliasShadowedByColumn, AlwaysRaisingExpression, ArrayMembershipPolicy,
        AssignmentConjunction, AuthorityAttributeWritableBelowThreshold, AuthorizationInTrigger,
        AutovacuumDisabledTable, BeforeTriggerWritesOtherTable, BinarySendFailure,
        BlankPaddedCharacter, BooleanStateWithoutTime, CascadeIntoRowLevelSecurityTable,
        CaseSensitiveEmail, CatalogNameAsText, ChildWithoutRowLevelSecurity, ClientChosenTimestamp,
        ClientRoleBypassesRowLevelSecurity, ClientWrittenCounterKey, ClientWrittenScaledNumeric,
        ClosedSetAsText, ConditionalCreationWithoutTrustedSchema, ConstantColumnNotGenerated,
        ContradictoryChecks, CopiedColumnThroughSuperkey, CorrelatedPolicySubquery,
        CredentialFreeWrite, CredentialPatternPolicy, CredentialSettingWrite, CrossTenantCap,
        CteShadowsRelation, DeadPermissivePolicy, DecidedBranch,
        DefinerMaintainedColumnClientWritable, DefinerPathCreatableSchema,
        DefinerSchemaWithoutDefaultRevoke, DefinerTakesActingUser, DefinerTemporarySchemaNotLast,
        DefinerWithoutSearchPath, DenyListPolicy, DistinctOverReferencedSide, DuplicateCheck,
        DuplicateColumnAssignment, DuplicateColumnNameInExtensionGraph, DuplicateForeignKey,
        DuplicateIndex, DuplicatePolicy, DuplicateUniqueIndex, DuplicatingRecursiveCte,
        DynamicSqlInjection, EmptyPartialIndex, EmptyTextAllowed, EqualityIndexOnArray,
        ExposedDefinerOverProtectedTable, ExpressionDefeatsIndex,
        ExtensionForeignKeyOnDeleteCascade, ExtensionInExposedSchema, ExtensionWithoutVersion,
        FlagNotBoolean, FloatingPointMoney, ForbiddenColumnInExtension, ForeignKeyExistenceOracle,
        FractionalCount, FunctionMediatedPolicyCycle, FunctionWithoutSafeSearchPath,
        GrantOptionToClientRole, ImpureImmutableFunction, IncompatibleForeignKey,
        InvokerWithoutSearchPath, JsonStoredAsText, JsonType, KeyWithoutExactEquality,
        LatentPolicyReadCycle, LeakproofUserFunction, MaterializedViewExposed, MisquotedSearchPath,
        MissingPrimaryKey, MixedCaseColumnName, MixedCaseForeignKeyName, MixedCaseTableName,
        MomentStoredAsText, MoneyType, MonotonicFlagReset, MultiplePermissivePolicies,
        NarrowIntegerKey, NarrowerReferencingColumn, NeedlessIndexPredicate, NestedPolicySubquery,
        NilUuidSentinel, NonFiniteNumberAllowed, NonSnakeCaseColumnName, NonSnakeCaseTableName,
        NonterminatingRecursiveCte, NotInNullList, NotInNullableSubquery, NotInSubquery,
        NullComparison, NullCredentialRead, NullOnlyCheck, NullableCompositeForeignKey,
        NullableConcatenation, NullableTenantKey, NullableUniqueColumn, NumberedColumns,
        OffsetPaging, OrderedSetAsDisjunction, OuterColumnCapture, OwnerRightsView,
        OwnerRightsViewExposed, ParallelTables, PlpgsqlAmbiguousName, PluralColumnName,
        PolicyExpressionDefeatsIndex, PolicyReadCycle, PolicyReadsUnprotectedTable,
        PolicyTargetsBypassRole, PolicyToCreatingRole, PolicyWithoutRowLevelSecurity,
        PolicyWithoutRowReference, PrefixRedundantIndex, PrimaryKeyNotNamedId,
        PublicDefaultPrivilege, PublicSchemaCreate, QueryRewriteRule, RaisingSettingRead,
        RandomOrderLimit, ReachableForeignTable, ReachableMaterializedView, ReachableSequence,
        ReachableTableWithoutRowLevelSecurity, RecursiveStepOverUnion, RedundantCheck,
        RedundantExtensionEdge, RedundantTerm, ReferenceWithoutIdSuffix,
        ReferencesGrantedToClientRole, RegColumnType, RepeatedFunctionSearchPath,
        RepeatedIndexColumn, RepeatedPolicyCall, RepeatedRecursionBound, RepeatedSettingRead,
        ReplacementWithoutTrustedCreation, ReservedKeywordIdentifier, RestrictiveWithoutPermissive,
        RoleDefinedInSchema, RoleKeyedPolicyWhenPooled, RowLevelSecurityWithoutPolicies,
        RustKeywordColumnName, RustKeywordForeignKeyName, RustKeywordTableName, ScaledNumeric,
        SecurityBarrierMissingOnFilteringView, SecurityDefinerFunctionExposed,
        SelfAssertedClaimPolicy, SelfComparison, SelfGrantingWrite, SensitiveColumnsExposed,
        SerialColumn, SessionTimeZoneDependence, SettableMembershipInBypassingRole,
        SimpleCaseUnderUnsafeSearchPath, SingularTableName, SnapshotBeforeLock,
        SubjectSettableAttribute, SuperkeyPrimaryKey, SurrogatePrimaryKeyInExtension,
        TableInheritance, TableNameDispatch, TautologicalCheck, TautologicalPolicy,
        TautologicalWithCheck, TenantLocalReference, TimeDependentCheck, TimeWithTimeZone,
        TimestampBetween, TimestampWithoutTimeZone, TriggerFilterInBody,
        TruncateGrantedToAnonymousRole, TruncateGrantedToAppRole, TruncatedIdentifier,
        TruncatingIntegerDivision, TypeNameCaseCollision, UnauditedAuthorityTable,
        UnboundedTextColumn, UncachedHelperQuery, UncachedPolicyCall,
        UnconditionalClientWritePolicy, UndeletableReference, UnfilteredChangeTrigger,
        UnfilteredWrite, UnforcedRowLevelSecurity, UnindexedCorrelatedSelect, UnindexedFilter,
        UnindexedForeignKey, UnindexedPolicyFilter, UnindexedRecursiveJoin,
        UniqueKeyExistenceOracle, UnknownBinarySend, UnlinkedFromItem, UnloggedTable,
        UnorderedDistinctOn, UnorderedLimit, UnqualifiedNameUnderUnsafeSearchPath, UnreadOuterJoin,
        UnsatisfiableCheck, UnsatisfiablePolicy, UnscopedUniqueConstraintOnRowLevelSecurityTable,
        UnseededPolicySet, UnstreamableReplicaIdentity, UnusedCte, UnvalidatedConstraint,
        UuidStoredAsText, WildcardView, WritingNonVolatileFunction, ZeroPrecisionTimestamp,
    },
    traits::{
        ColumnRule, Constrainer, ForeignKeyRule, FunctionRule, GenericConstrainer, QueryRule,
        SchemaRule, ScriptRule, TableRule,
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
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let database = ParserDB::parse::<GenericDialect>("CREATE TABLE t (type INT);").unwrap();
/// let mut constrainer = DefaultConstrainer::<ParserDB>::default();
/// let raised_by = |constrainer: &DefaultConstrainer<ParserDB>, rule: &str| {
///     constrainer.diagnostics(&database).iter().any(|error| {
///         matches!(error, Error::Violation(violation) if violation.rule().name == rule)
///     })
/// };
/// assert!(!raised_by(&constrainer, "rust_keyword_column_name"));
/// constrainer.set_group_level(LintGroup::Restriction, Level::Warn);
/// assert!(raised_by(&constrainer, "rust_keyword_column_name"));
/// ```
pub struct DefaultConstrainer<DB: DatabaseLike> {
    constrainer: GenericConstrainer<DB>,
}

impl<DB: DatabaseLike + 'static> Default for DefaultConstrainer<DB> {
    fn default() -> Self {
        let mut constrainer = GenericConstrainer::default();
        register_table_rules(&mut constrainer);
        let column_rules: [Box<dyn ColumnRule<Database = DB>>; 25] = [
            Box::new(SerialColumn::default()),
            Box::new(NarrowIntegerKey::default()),
            Box::new(ClientWrittenCounterKey::default()),
            Box::new(MixedCaseColumnName::default()),
            Box::new(PrimaryKeyNotNamedId::default()),
            Box::new(SurrogatePrimaryKeyInExtension::default()),
            Box::new(NonSnakeCaseColumnName::default()),
            Box::new(PluralColumnName::default()),
            Box::new(RustKeywordColumnName::default()),
            Box::new(UnboundedTextColumn::default()),
            Box::new(EmptyTextAllowed::default()),
            Box::new(NonFiniteNumberAllowed::default()),
            Box::new(ClientChosenTimestamp::default()),
            Box::new(FloatingPointMoney::default()),
            Box::new(FlagNotBoolean::default()),
            Box::new(UuidStoredAsText::default()),
            Box::new(MomentStoredAsText::default()),
            Box::new(AddressStoredAsText::default()),
            Box::new(JsonStoredAsText::default()),
            Box::new(FractionalCount::default()),
            Box::new(BooleanStateWithoutTime::default()),
            Box::new(ClosedSetAsText::default()),
            Box::new(ConstantColumnNotGenerated::default()),
            Box::new(BinarySendFailure::default()),
            Box::new(UnknownBinarySend::default()),
        ];
        for rule in column_rules {
            constrainer.register_column_rule_with_floor(rule, Level::Allow);
        }
        let foreign_key_rules: [Box<dyn ForeignKeyRule<Database = DB>>; 13] = [
            Box::new(NullableCompositeForeignKey::default()),
            Box::new(UnindexedForeignKey::default()),
            Box::new(IncompatibleForeignKey::default()),
            Box::new(NarrowerReferencingColumn::default()),
            Box::new(MixedCaseForeignKeyName::default()),
            Box::new(ReferenceWithoutIdSuffix::default()),
            Box::new(ExtensionForeignKeyOnDeleteCascade::default()),
            Box::new(RustKeywordForeignKeyName::default()),
            Box::new(CascadeIntoRowLevelSecurityTable::default()),
            Box::new(CopiedColumnThroughSuperkey::default()),
            Box::new(UndeletableReference::default()),
            Box::new(ForeignKeyExistenceOracle::default()),
            Box::new(TenantLocalReference::default()),
        ];
        for rule in foreign_key_rules {
            constrainer.register_foreign_key_rule_with_floor(rule, Level::Allow);
        }
        register_schema_rules(&mut constrainer);
        let function_rules: [Box<dyn FunctionRule<Database = DB>>; 15] = [
            Box::new(ImpureImmutableFunction::default()),
            Box::new(WritingNonVolatileFunction::default()),
            Box::new(DefinerWithoutSearchPath::default()),
            Box::new(InvokerWithoutSearchPath::default()),
            Box::new(FunctionWithoutSafeSearchPath::default()),
            Box::new(DefinerTemporarySchemaNotLast::default()),
            Box::new(DefinerPathCreatableSchema::default()),
            Box::new(LeakproofUserFunction::default()),
            Box::new(ExposedDefinerOverProtectedTable::default()),
            Box::new(GrantOptionToClientRole::default()),
            Box::new(DynamicSqlInjection::default()),
            Box::new(TableNameDispatch::default()),
            Box::new(SnapshotBeforeLock::default()),
            Box::new(PlpgsqlAmbiguousName::default()),
            Box::new(DecidedBranch::default()),
        ];
        for rule in function_rules {
            constrainer.register_function_rule_with_floor(rule, Level::Allow);
        }
        register_query_rules(&mut constrainer);
        let script_rules: [Box<dyn ScriptRule<Database = DB>>; 6] = [
            Box::new(UnqualifiedNameUnderUnsafeSearchPath::default()),
            Box::new(SimpleCaseUnderUnsafeSearchPath::default()),
            Box::new(ReplacementWithoutTrustedCreation::default()),
            Box::new(ConditionalCreationWithoutTrustedSchema::default()),
            Box::new(MisquotedSearchPath::default()),
            Box::new(RepeatedFunctionSearchPath::default()),
        ];
        for rule in script_rules {
            constrainer.register_script_rule_with_floor(rule, Level::Allow);
        }
        Self { constrainer }
    }
}

/// Registers every built-in table rule at its group's default level.
fn register_table_rules<DB: DatabaseLike + 'static>(constrainer: &mut GenericConstrainer<DB>) {
    let table_rules: [Box<dyn TableRule<Database = DB>>; 65] = [
        Box::new(AlwaysRaisingExpression::default()),
        Box::new(TimeDependentCheck::default()),
        Box::new(PrefixRedundantIndex::default()),
        Box::new(DuplicateIndex::default()),
        Box::new(RepeatedIndexColumn::default()),
        Box::new(EqualityIndexOnArray::default()),
        Box::new(EmptyPartialIndex::default()),
        Box::new(NeedlessIndexPredicate::default()),
        Box::new(NumberedColumns::default()),
        Box::new(MissingPrimaryKey::default()),
        Box::new(KeyWithoutExactEquality::default()),
        Box::new(MixedCaseTableName::default()),
        Box::new(NonSnakeCaseTableName::default()),
        Box::new(SingularTableName::default()),
        Box::new(PolicyWithoutRowLevelSecurity::default()),
        Box::new(RustKeywordTableName::default()),
        Box::new(TautologicalCheck::default()),
        Box::new(UnsatisfiableCheck::default()),
        Box::new(NullOnlyCheck::default()),
        Box::new(ContradictoryChecks::default()),
        Box::new(ForbiddenColumnInExtension::new("most_concrete_table")),
        Box::new(RedundantExtensionEdge::default()),
        Box::new(DuplicateCheck::default()),
        Box::new(RedundantCheck::default()),
        Box::new(RedundantTerm::default()),
        Box::new(DuplicateColumnNameInExtensionGraph::default()),
        Box::new(DuplicateForeignKey::default()),
        Box::new(DuplicateUniqueIndex::default()),
        Box::new(DeadPermissivePolicy::default()),
        Box::new(DuplicatePolicy::default()),
        Box::new(TautologicalWithCheck::default()),
        Box::new(TautologicalPolicy::default()),
        Box::new(PolicyWithoutRowReference::default()),
        Box::new(CredentialPatternPolicy::default()),
        Box::new(UnsatisfiablePolicy::default()),
        Box::new(RestrictiveWithoutPermissive::default()),
        Box::new(UnforcedRowLevelSecurity::default()),
        Box::new(CorrelatedPolicySubquery::default()),
        Box::new(NestedPolicySubquery::default()),
        Box::new(UncachedPolicyCall::default()),
        Box::new(UncachedHelperQuery::default()),
        Box::new(RepeatedPolicyCall::default()),
        Box::new(RaisingSettingRead::default()),
        Box::new(UnindexedPolicyFilter::default()),
        Box::new(PolicyExpressionDefeatsIndex::default()),
        Box::new(ArrayMembershipPolicy::default()),
        Box::new(DenyListPolicy::default()),
        Box::new(PolicyReadsUnprotectedTable::default()),
        Box::new(ReachableTableWithoutRowLevelSecurity::default()),
        Box::new(TruncateGrantedToAnonymousRole::default()),
        Box::new(TruncateGrantedToAppRole::default()),
        Box::new(ReferencesGrantedToClientRole::default()),
        Box::new(GrantOptionToClientRole::default()),
        Box::new(ChildWithoutRowLevelSecurity::default()),
        Box::new(PolicyToCreatingRole::default()),
        Box::new(PolicyTargetsBypassRole::default()),
        Box::new(RoleKeyedPolicyWhenPooled::default()),
        Box::new(CredentialFreeWrite::default()),
        Box::new(SuperkeyPrimaryKey::default()),
        Box::new(UniqueKeyExistenceOracle::default()),
        Box::new(NullCredentialRead::default()),
        Box::new(NullableTenantKey::default()),
        Box::new(SensitiveColumnsExposed::default()),
        Box::new(UnconditionalClientWritePolicy::default()),
        Box::new(UnstreamableReplicaIdentity::default()),
    ];
    for rule in table_rules {
        constrainer.register_table_rule_with_floor(rule, Level::Allow);
    }
}

/// Registers every built-in query rule at its group's default level.
fn register_query_rules<DB: DatabaseLike + 'static>(constrainer: &mut GenericConstrainer<DB>) {
    let query_rules: [Box<dyn QueryRule<Database = DB>>; 33] = [
        Box::new(NullableConcatenation::default()),
        Box::new(NotInNullableSubquery::default()),
        Box::new(NotInSubquery::default()),
        Box::new(NotInNullList::default()),
        Box::new(NullComparison::default()),
        Box::new(NilUuidSentinel::default()),
        Box::new(UnusedCte::default()),
        Box::new(CteShadowsRelation::default()),
        Box::new(NonterminatingRecursiveCte::default()),
        Box::new(DuplicatingRecursiveCte::default()),
        Box::new(UnindexedRecursiveJoin::default()),
        Box::new(RecursiveStepOverUnion::default()),
        Box::new(RandomOrderLimit::default()),
        Box::new(OffsetPaging::default()),
        Box::new(UnfilteredWrite::default()),
        Box::new(DuplicateColumnAssignment::default()),
        Box::new(AssignmentConjunction::default()),
        Box::new(CredentialSettingWrite::default()),
        Box::new(OuterColumnCapture::default()),
        Box::new(TimestampBetween::default()),
        Box::new(SessionTimeZoneDependence::default()),
        Box::new(TruncatingIntegerDivision::default()),
        Box::new(UnorderedLimit::default()),
        Box::new(UnorderedDistinctOn::default()),
        Box::new(UnlinkedFromItem::default()),
        Box::new(DistinctOverReferencedSide::default()),
        Box::new(ExpressionDefeatsIndex::default()),
        Box::new(UnindexedFilter::default()),
        Box::new(UnindexedCorrelatedSelect::default()),
        Box::new(AliasShadowedByColumn::default()),
        Box::new(SelfComparison::default()),
        Box::new(UnreadOuterJoin::default()),
        Box::new(RedundantTerm::default()),
    ];
    for rule in query_rules {
        constrainer.register_query_rule_with_floor(rule, Level::Allow);
    }
}

/// Registers every built-in schema rule at its group's default level.
fn register_schema_rules<DB: DatabaseLike + 'static>(constrainer: &mut GenericConstrainer<DB>) {
    let schema_rules: [Box<dyn SchemaRule<Database = DB>>; 77] = [
        Box::new(DuplicateIndex::default()),
        Box::new(NullableConcatenation::default()),
        Box::new(RedundantTerm::default()),
        Box::new(UnscopedUniqueConstraintOnRowLevelSecurityTable::default()),
        Box::new(NullableUniqueColumn::default()),
        Box::new(SecurityDefinerFunctionExposed::default()),
        Box::new(DefinerSchemaWithoutDefaultRevoke::default()),
        Box::new(PublicDefaultPrivilege::default()),
        Box::new(ExtensionInExposedSchema::default()),
        Box::new(ExtensionWithoutVersion::default()),
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
        Box::new(NotInNullList::default()),
        Box::new(NullComparison::default()),
        Box::new(NilUuidSentinel::default()),
        Box::new(UnusedCte::default()),
        Box::new(CteShadowsRelation::default()),
        Box::new(NonterminatingRecursiveCte::default()),
        Box::new(DuplicatingRecursiveCte::default()),
        Box::new(UnindexedRecursiveJoin::default()),
        Box::new(RecursiveStepOverUnion::default()),
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
        Box::new(MaterializedViewExposed::default()),
        Box::new(OwnerRightsViewExposed::default()),
        Box::new(ChildWithoutRowLevelSecurity::default()),
        Box::new(OwnerRightsView::default()),
        Box::new(ClientRoleBypassesRowLevelSecurity::default()),
        Box::new(SettableMembershipInBypassingRole::default()),
        Box::new(RoleDefinedInSchema::default()),
        Box::new(GrantOptionToClientRole::default()),
        Box::new(SelfAssertedClaimPolicy::default()),
        Box::new(SelfGrantingWrite::default()),
        Box::new(DefinerTakesActingUser::default()),
        Box::new(SubjectSettableAttribute::default()),
        Box::new(ParallelTables::default()),
        Box::new(AuthorityAttributeWritableBelowThreshold::default()),
        Box::new(UnseededPolicySet::default()),
        Box::new(CrossTenantCap::default()),
        Box::new(DefinerMaintainedColumnClientWritable::default()),
        Box::new(UnauditedAuthorityTable::default()),
        Box::new(MonotonicFlagReset::default()),
        Box::new(RepeatedSettingRead::default()),
        Box::new(CatalogNameAsText::default()),
        Box::new(CaseSensitiveEmail::default()),
        Box::new(RepeatedRecursionBound::default()),
        Box::new(OrderedSetAsDisjunction::default()),
        Box::new(TypeNameCaseCollision::default()),
        Box::new(BeforeTriggerWritesOtherTable::default()),
        Box::new(UnfilteredChangeTrigger::default()),
        Box::new(AuthorizationInTrigger::default()),
        Box::new(TriggerFilterInBody::default()),
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
