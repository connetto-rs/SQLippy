//! Submodule providing rules that span several schema objects.

/// Defines a schema rule's struct, constructor, registration and metadata.
macro_rules! schema_rule {
    (
        $(#[$doc:meta])*
        $name:ident, $group:expr, $rationale:literal, $source:expr
    ) => {
        rule_definition!($(#[$doc])* $name, register_schema_rule, $group, $rationale, $source);
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
mod not_in_nullable_subquery;
mod not_in_subquery;
mod nullable_unique;
mod owner_rights_view;
pub use exposure_rules::{
    ExtensionInExposedSchema, ReachableSequence, SecurityBarrierMissingOnFilteringView,
    SecurityDefinerFunctionExposed,
};
pub use nullable_unique::NullableUniqueColumn;
mod table_hygiene_rules;
pub use catalogue_rules::{
    PublicSchemaCreate, QueryRewriteRule, ReservedKeywordIdentifier, TableInheritance,
    TruncatedIdentifier, UnloggedTable, UnvalidatedConstraint, WildcardView,
};
pub use not_in_nullable_subquery::NotInNullableSubquery;
pub use not_in_subquery::NotInSubquery;
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
mod definer_takes_acting_user;
mod unscoped_unique_constraint;
pub use definer_takes_acting_user::DefinerTakesActingUser;
pub use unscoped_unique_constraint::UnscopedUniqueConstraintOnRowLevelSecurityTable;
mod client_role_bypass;
pub use client_role_bypass::{
    ClientRoleBypassesRowLevelSecurity, SettableMembershipInBypassingRole,
};
