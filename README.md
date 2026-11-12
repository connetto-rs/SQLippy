# SQLippy

[![CI](https://github.com/connetto-rs/SQLippy/workflows/Rust%20CI/badge.svg)](https://github.com/connetto-rs/SQLippy/actions)
[![Security Audit](https://github.com/connetto-rs/SQLippy/workflows/Security%20Audit/badge.svg)](https://github.com/connetto-rs/SQLippy/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Codecov](https://codecov.io/gh/connetto-rs/SQLippy/branch/main/graph/badge.svg)](https://codecov.io/gh/connetto-rs/SQLippy)

[SQL-traits](https://github.com/connetto-rs/sql-traits)-based lints for SQL schemas and for the statements applications send to them. Every rule belongs to a Clippy-style group whose default level is `allow`, `warn` or `deny`, and every violation explains why the shape is bad and how to fix it. Rules are configured and reported by their `snake_case` names.

## Usage

```rust
use sqlippy::prelude::*;
use sqlparser::dialect::GenericDialect;

let database = ParserDB::parse::<GenericDialect>(
    "CREATE TABLE Users (id INT PRIMARY KEY, name TEXT CHECK (LENGTH(name) <= 100));",
)
.unwrap();

let mut constrainer = DefaultConstrainer::<ParserDB>::default();
constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
constrainer.set_rule_level("singular_table_name", Level::Allow);

// `validate_schema` stops at the first violation raised at `warn` or `deny`.
assert!(constrainer.validate_schema(&database).is_err());

// `diagnostics` returns every violation and lookup failure.
for error in constrainer.diagnostics(&database) {
    if let Error::Violation(violation) = error {
        println!("{violation}");
    }
}
```

A rule registered on its own, including a single rule converted with `.into()`, runs at least at `warn`. `DefaultConstrainer` registers every rule at its group's default. `allow_policy` excuses one rule's findings on a reviewed policy, and an allowance that excuses nothing fails validation.

`validate_statement` and `statement_diagnostics` check one parsed statement against the schema with the query rules, such as `outer_column_capture` and `credential_setting_write`. `allow_statement` excuses one rule on a reviewed statement, and schema validation fails once that rule no longer reports it.

## Rules

| Group | Default | Rules |
| :--- | :--- | :--- |
| `correctness` | `deny` | `policy_without_row_level_security`, `policy_read_cycle`, `dead_permissive_policy`, `truncate_granted_to_anonymous_role`, `client_role_bypasses_row_level_security`, `definer_without_search_path`, `definer_temporary_schema_not_last`, `tautological_check`, `unsatisfiable_check`, `surrogate_primary_key_in_extension`, `self_asserted_claim_policy`, `credential_setting_write`, `outer_column_capture` |
| `suspicious` | `warn` | `latent_policy_read_cycle`, `function_mediated_policy_cycle`, `tautological_with_check`, `unforced_row_level_security`, `deny_list_policy`, `credential_free_write`, `reachable_table_without_row_level_security`, `owner_rights_view`, `reachable_materialized_view`, `truncate_granted_to_app_role`, `child_without_row_level_security`, `settable_membership_in_bypassing_role`, `policy_to_creating_role`, `role_keyed_policy_when_pooled`, `grant_option_to_client_role`, `exposed_definer_over_protected_table`, `unbounded_text_column`, `incompatible_foreign_key`, `missing_primary_key`, `key_without_exact_equality`, `extension_foreign_key_on_delete_cascade`, `forbidden_column_in_extension`, `duplicate_column_name_in_extension_graph`, `reachable_foreign_table`, `timestamp_without_time_zone`, `time_with_time_zone`, `zero_precision_timestamp`, `blank_padded_character`, `money_type`, `floating_point_money`, `client_written_scaled_numeric`, `nullable_composite_foreign_key`, `client_written_counter_key`, `not_in_nullable_subquery`, `time_dependent_check`, `impure_immutable_function`, `query_rewrite_rule`, `table_inheritance`, `truncated_identifier`, `unvalidated_constraint`, `public_schema_create`, `row_level_security_without_policies`, `security_definer_function_exposed`, `extension_in_exposed_schema`, `reachable_sequence`, `reg_column_type`, `self_granting_write`, `unscoped_unique_constraint_on_row_level_security_table`, `unfiltered_write`, `timestamp_between`, `session_time_zone_dependence`, `truncating_integer_division`, `unordered_limit`, `unordered_distinct_on`, `unlinked_from_item`, `subject_settable_attribute`, `alias_shadowed_by_column`, `self_comparison`, `unread_outer_join` |
| `perf` | `warn` | `correlated_policy_subquery`, `nested_policy_subquery`, `uncached_policy_call`, `unindexed_policy_filter`, `json_type`, `unindexed_foreign_key`, `prefix_redundant_index`, `multiple_permissive_policies`, `autovacuum_disabled_table`, `not_in_subquery`, `expression_defeats_index`, `unindexed_correlated_select` |
| `complexity` | `warn` | `duplicate_foreign_key`, `duplicate_check`, `duplicate_unique_index`, `redundant_extension_edge` |
| `style` | `warn` | `mixed_case_table_name`, `mixed_case_column_name`, `mixed_case_foreign_key_name`, `non_snake_case_table_name`, `non_snake_case_column_name`, `singular_table_name`, `plural_column_name`, `reference_without_id_suffix`, `primary_key_not_named_id`, `serial_column`, `reserved_keyword_identifier` |
| `pedantic` | `allow` | `array_membership_policy`, `references_granted_to_client_role`, `cascade_into_row_level_security_table`, `unchecked_past_timestamp`, `empty_text_allowed`, `scaled_numeric`, `narrow_integer_key`, `unlogged_table`, `wildcard_view`, `security_barrier_missing_on_filtering_view`, `nullable_unique_column`, `definer_takes_acting_user`, `random_order_limit`, `offset_paging`, `distinct_over_referenced_side`, `unindexed_filter`, `flag_not_boolean`, `uuid_stored_as_text`, `moment_stored_as_text`, `address_stored_as_text`, `json_stored_as_text`, `fractional_count` |
| `restriction` | `allow` | `rust_keyword_table_name`, `rust_keyword_column_name`, `rust_keyword_foreign_key_name` |

Each rule's documentation states what it reports, and its violations carry the rationale and source.
