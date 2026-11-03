//! Submodule providing rules that span several schema objects.

mod policy_read_cycle;
pub use policy_read_cycle::{FunctionMediatedPolicyCycle, LatentPolicyReadCycle, PolicyReadCycle};
mod reachable_materialized_view;
pub use reachable_materialized_view::ReachableMaterializedView;
mod reachable_foreign_table;
pub use reachable_foreign_table::ReachableForeignTable;
mod owner_rights_view;
pub use owner_rights_view::OwnerRightsView;
mod client_role_bypass;
pub use client_role_bypass::{
    ClientRoleBypassesRowLevelSecurity, SettableMembershipInBypassingRole,
};
