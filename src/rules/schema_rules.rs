//! Submodule providing rules that span several schema objects.

mod policy_read_cycle;
pub use policy_read_cycle::{FunctionMediatedPolicyCycle, LatentPolicyReadCycle, PolicyReadCycle};
mod reachable_materialized_view;
pub use reachable_materialized_view::ReachableMaterializedView;
mod reachable_foreign_table;
pub use reachable_foreign_table::ReachableForeignTable;
mod catalogue_rules;
mod not_in_nullable_subquery;
mod owner_rights_view;
pub use catalogue_rules::{
    PublicSchemaCreate, QueryRewriteRule, ReservedKeywordIdentifier, TableInheritance,
    TruncatedIdentifier, UnloggedTable, UnvalidatedConstraint, WildcardView,
};
pub use not_in_nullable_subquery::NotInNullableSubquery;
mod type_rules;
pub use owner_rights_view::OwnerRightsView;
pub use type_rules::{
    BlankPaddedCharacter, ClientWrittenScaledNumeric, JsonType, MoneyType, ScaledNumeric,
    TimeWithTimeZone, TimestampWithoutTimeZone, ZeroPrecisionTimestamp,
};
mod client_role_bypass;
pub use client_role_bypass::{
    ClientRoleBypassesRowLevelSecurity, SettableMembershipInBypassingRole,
};
