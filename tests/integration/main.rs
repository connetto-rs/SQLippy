//! Integration tests of the public constrainer API, built as one test binary
//! so the suite links `sql-rules` and its dependencies once.

mod common;
mod rule_findings;

mod catalog_checks;
mod catalogue_objects;
mod client_grants;
mod column_types;
mod correlated_policy_subqueries;
mod credential_free_writes;
mod definer_acting_user;
mod definer_functions;
mod expressions_and_functions;
mod generated_keys;
mod key_equality;
mod keys_and_indexes;
mod lint_candidates;
mod lint_levels;
mod nested_policy_subqueries;
mod nullable_unique;
mod owner_rights_views;
mod policy_advisories;
mod policy_checks;
mod policy_read_cycles;
mod role_memberships;
mod self_asserted_claims;
mod self_granting_writes;
mod statement_lints;
mod statement_shapes;
mod subject_settable_attributes;
mod tenant_unique_constraints;
mod uncached_policy_calls;
