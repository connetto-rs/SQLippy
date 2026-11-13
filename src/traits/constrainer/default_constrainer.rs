//! Submodule defining a constrainer holding every generic rule at its group's
//! default level.

use sql_traits::traits::DatabaseLike;

use crate::{
    lint::Level,
    rules::{
        AddressStoredAsText, AliasShadowedByColumn, ArrayMembershipPolicy, AutovacuumDisabledTable,
        BinarySendFailure, BlankPaddedCharacter, CascadeIntoRowLevelSecurityTable,
        ChildWithoutRowLevelSecurity, ClientRoleBypassesRowLevelSecurity, ClientWrittenCounterKey,
        ClientWrittenScaledNumeric, CorrelatedPolicySubquery, CredentialFreeWrite,
        CredentialSettingWrite, DeadPermissivePolicy, DefinerTakesActingUser,
        DefinerTemporarySchemaNotLast, DefinerWithoutSearchPath, DenyListPolicy,
        DistinctOverReferencedSide, DuplicateCheck, DuplicateColumnNameInExtensionGraph,
        DuplicateForeignKey, DuplicatePolicy, DuplicateUniqueIndex, EmptyTextAllowed,
        ExposedDefinerOverProtectedTable, ExpressionDefeatsIndex,
        ExtensionForeignKeyOnDeleteCascade, ExtensionInExposedSchema, FlagNotBoolean,
        FloatingPointMoney, ForbiddenColumnInExtension, FractionalCount,
        FunctionMediatedPolicyCycle, GrantOptionToClientRole, ImpureImmutableFunction,
        IncompatibleForeignKey, JsonStoredAsText, JsonType, KeyWithoutExactEquality,
        LatentPolicyReadCycle, MissingPrimaryKey, MixedCaseColumnName, MixedCaseForeignKeyName,
        MixedCaseTableName, MomentStoredAsText, MoneyType, MultiplePermissivePolicies,
        NarrowIntegerKey, NestedPolicySubquery, NonSnakeCaseColumnName, NonSnakeCaseTableName,
        NotInNullableSubquery, NotInSubquery, NullableCompositeForeignKey, NullableUniqueColumn,
        OffsetPaging, OuterColumnCapture, OwnerRightsView, PluralColumnName, PolicyReadCycle,
        PolicyToCreatingRole, PolicyWithoutRowLevelSecurity, PrefixRedundantIndex,
        PrimaryKeyNotNamedId, PublicSchemaCreate, QueryRewriteRule, RandomOrderLimit,
        ReachableForeignTable, ReachableMaterializedView, ReachableSequence,
        ReachableTableWithoutRowLevelSecurity, RedundantExtensionEdge, ReferenceWithoutIdSuffix,
        ReferencesGrantedToClientRole, RegColumnType, ReservedKeywordIdentifier,
        RoleKeyedPolicyWhenPooled, RowLevelSecurityWithoutPolicies, RustKeywordColumnName,
        RustKeywordForeignKeyName, RustKeywordTableName, ScaledNumeric,
        SecurityBarrierMissingOnFilteringView, SecurityDefinerFunctionExposed,
        SelfAssertedClaimPolicy, SelfComparison, SelfGrantingWrite, SerialColumn,
        SessionTimeZoneDependence, SettableMembershipInBypassingRole, SingularTableName,
        SubjectSettableAttribute, SurrogatePrimaryKeyInExtension, TableInheritance,
        TautologicalCheck, TautologicalWithCheck, TimeDependentCheck, TimeWithTimeZone,
        TimestampBetween, TimestampWithoutTimeZone, TruncateGrantedToAnonymousRole,
        TruncateGrantedToAppRole, TruncatedIdentifier, TruncatingIntegerDivision,
        UnboundedTextColumn, UncachedPolicyCall, UncheckedPastTimestamp, UnfilteredWrite,
        UnforcedRowLevelSecurity, UnindexedCorrelatedSelect, UnindexedFilter, UnindexedForeignKey,
        UnindexedPolicyFilter, UnknownBinarySend, UnlinkedFromItem, UnloggedTable,
        UnorderedDistinctOn, UnorderedLimit, UnreadOuterJoin, UnsatisfiableCheck,
        UnscopedUniqueConstraintOnRowLevelSecurityTable, UnvalidatedConstraint, UuidStoredAsText,
        WildcardView, ZeroPrecisionTimestamp,
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
/// level is set for them or their group. The exceptions are
/// [`BinarySendFailure`] at `deny` and [`UnknownBinarySend`] at `warn`, which
/// report only on tables the deployment selects for binary replication.
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
        let table_rules: [Box<dyn TableRule<Database = DB>>; 36] = [
            Box::new(TimeDependentCheck::default()),
            Box::new(PrefixRedundantIndex::default()),
            Box::new(MissingPrimaryKey::default()),
            Box::new(KeyWithoutExactEquality::default()),
            Box::new(MixedCaseTableName::default()),
            Box::new(NonSnakeCaseTableName::default()),
            Box::new(SingularTableName::default()),
            Box::new(PolicyWithoutRowLevelSecurity::default()),
            Box::new(RustKeywordTableName::default()),
            Box::new(TautologicalCheck::default()),
            Box::new(UnsatisfiableCheck::default()),
            Box::new(ForbiddenColumnInExtension::new("most_concrete_table")),
            Box::new(RedundantExtensionEdge::default()),
            Box::new(DuplicateCheck::default()),
            Box::new(DuplicateColumnNameInExtensionGraph::default()),
            Box::new(DuplicateForeignKey::default()),
            Box::new(DuplicateUniqueIndex::default()),
            Box::new(DeadPermissivePolicy::default()),
            Box::new(DuplicatePolicy::default()),
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
        let column_rules: [Box<dyn ColumnRule<Database = DB>>; 19] = [
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
            Box::new(UncheckedPastTimestamp::default()),
            Box::new(FloatingPointMoney::default()),
            Box::new(FlagNotBoolean::default()),
            Box::new(UuidStoredAsText::default()),
            Box::new(MomentStoredAsText::default()),
            Box::new(AddressStoredAsText::default()),
            Box::new(JsonStoredAsText::default()),
            Box::new(FractionalCount::default()),
        ];
        for rule in column_rules {
            constrainer.register_column_rule_with_floor(rule, Level::Allow);
        }
        constrainer
            .register_column_rule_with_floor(Box::new(BinarySendFailure::default()), Level::Deny);
        constrainer
            .register_column_rule_with_floor(Box::new(UnknownBinarySend::default()), Level::Warn);
        let foreign_key_rules: [Box<dyn ForeignKeyRule<Database = DB>>; 8] = [
            Box::new(NullableCompositeForeignKey::default()),
            Box::new(UnindexedForeignKey::default()),
            Box::new(IncompatibleForeignKey::default()),
            Box::new(MixedCaseForeignKeyName::default()),
            Box::new(ReferenceWithoutIdSuffix::default()),
            Box::new(ExtensionForeignKeyOnDeleteCascade::default()),
            Box::new(RustKeywordForeignKeyName::default()),
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
        register_query_rules(&mut constrainer);
        Self { constrainer }
    }
}

/// Registers every built-in query rule at its group's default level.
fn register_query_rules<DB: DatabaseLike + 'static>(constrainer: &mut GenericConstrainer<DB>) {
    let query_rules: [Box<dyn QueryRule<Database = DB>>; 20] = [
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
    ];
    for rule in query_rules {
        constrainer.register_query_rule_with_floor(rule, Level::Allow);
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
