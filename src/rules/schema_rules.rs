//! Submodule providing rules that span several schema objects.

/// Defines a schema rule's struct, constructor, registration and metadata.
macro_rules! schema_rule {
    (
        $(#[$doc:meta])*
        $name:ident, $group:expr, $rationale:literal, $source:expr, $example:expr
    ) => {
        rule_definition!(
            $(#[$doc])* $name, register_schema_rule, $group, $rationale, $source, $example
        );
    };
}

mod policy_read_cycle;
pub use policy_read_cycle::{FunctionMediatedPolicyCycle, LatentPolicyReadCycle, PolicyReadCycle};
mod reachable_materialized_view;
pub use reachable_materialized_view::ReachableMaterializedView;
mod reachable_foreign_table;
pub use reachable_foreign_table::ReachableForeignTable;
mod catalogue_rules;
mod exposure_rules;
mod nil_uuid_sentinel;
mod not_in_null_list;
mod not_in_nullable_subquery;
mod not_in_subquery;
mod null_comparison;
mod nullable_concatenation;
pub use nullable_concatenation::NullableConcatenation;
mod nullable_unique;
mod owner_rights_view;
pub use exposure_rules::{
    DefinerSchemaWithoutDefaultRevoke, ExtensionInExposedSchema, ReachableSequence,
    SecurityBarrierMissingOnFilteringView, SecurityDefinerFunctionExposed,
};
pub use nullable_unique::NullableUniqueColumn;
mod table_hygiene_rules;
pub use catalogue_rules::{
    PublicSchemaCreate, QueryRewriteRule, ReservedKeywordIdentifier, TableInheritance,
    TruncatedIdentifier, UnloggedTable, UnvalidatedConstraint, WildcardView,
};
pub use nil_uuid_sentinel::NilUuidSentinel;
pub use not_in_null_list::NotInNullList;
pub use not_in_nullable_subquery::NotInNullableSubquery;
pub use not_in_subquery::NotInSubquery;
pub use null_comparison::NullComparison;
pub use table_hygiene_rules::{
    AutovacuumDisabledTable, MultiplePermissivePolicies, RegColumnType,
    RowLevelSecurityWithoutPolicies,
};
mod type_rules;
pub use owner_rights_view::OwnerRightsView;
pub use type_rules::{
    BlankPaddedCharacter, ClientWrittenScaledNumeric, JsonType, MoneyType, ScaledNumeric,
    TimeWithTimeZone, TimestampWithoutTimeZone, ZeroPrecisionTimestamp,
};
mod self_asserted_claim_policy;
pub use self_asserted_claim_policy::SelfAssertedClaimPolicy;
mod self_granting_write;
pub use self_granting_write::SelfGrantingWrite;
mod subject_settable_attribute;
pub use subject_settable_attribute::SubjectSettableAttribute;
mod authority_attribute_writable_below_threshold;
pub use authority_attribute_writable_below_threshold::AuthorityAttributeWritableBelowThreshold;
mod unaudited_authority_table;
pub use unaudited_authority_table::UnauditedAuthorityTable;
mod monotonic_flag_reset;
pub use monotonic_flag_reset::MonotonicFlagReset;
mod repeated_setting_read;
pub use repeated_setting_read::RepeatedSettingRead;
mod role_defined_in_schema;
pub use role_defined_in_schema::RoleDefinedInSchema;
mod definer_takes_acting_user;
mod unscoped_unique_constraint;
pub use definer_takes_acting_user::DefinerTakesActingUser;
pub use unscoped_unique_constraint::UnscopedUniqueConstraintOnRowLevelSecurityTable;
mod client_role_bypass;
pub use client_role_bypass::{
    ClientRoleBypassesRowLevelSecurity, SettableMembershipInBypassingRole,
};
mod unused_cte;
pub use unused_cte::UnusedCte;
mod cte_shadows_relation;
pub use cte_shadows_relation::CteShadowsRelation;
mod nonterminating_recursive_cte;
pub use nonterminating_recursive_cte::NonterminatingRecursiveCte;
mod duplicating_recursive_cte;
pub use duplicating_recursive_cte::DuplicatingRecursiveCte;
mod unindexed_recursive_join;
pub use unindexed_recursive_join::UnindexedRecursiveJoin;
mod parallel_tables;
pub use parallel_tables::ParallelTables;
mod recursive_step_over_union;
pub use recursive_step_over_union::RecursiveStepOverUnion;
mod unseeded_policy_set;
pub use unseeded_policy_set::UnseededPolicySet;
mod cross_tenant_cap;
pub use cross_tenant_cap::CrossTenantCap;
mod definer_maintained_column_client_writable;
pub use definer_maintained_column_client_writable::DefinerMaintainedColumnClientWritable;
