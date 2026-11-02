//! Submodule providing rules that span several schema objects.

mod policy_read_cycle;
pub use policy_read_cycle::{LatentPolicyReadCycle, PolicyReadCycle};
mod reachable_materialized_view;
pub use reachable_materialized_view::ReachableMaterializedView;
mod client_role_bypass;
pub use client_role_bypass::{
    ClientRoleBypassesRowLevelSecurity, SettableMembershipInBypassingRole,
};
