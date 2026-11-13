//! The Font Awesome icon that marks each rule in the demo.

use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::fa_brands_icons::FaRust;
use dioxus_free_icons::icons::fa_solid_icons::{
    FaAnchor, FaAnglesDown, FaArrowDownShortWide, FaArrowRightArrowLeft, FaArrowUp19,
    FaArrowsLeftRightToLine, FaArrowsRotate, FaArrowsSpin, FaAsterisk, FaBarcode, FaBezierCurve,
    FaBinoculars, FaBolt, FaBorderAll, FaBoxesStacked, FaBroom, FaCalculator, FaCalendarDays,
    FaCalendarXmark, FaChartPie, FaCheckDouble, FaChild, FaCircleHalfStroke, FaCircleQuestion,
    FaCircleXmark, FaClipboardList, FaClock, FaClockRotateLeft, FaClone, FaCodeBranch, FaCodeMerge,
    FaCoins, FaCompress, FaCopy, FaCrown, FaCubes, FaDice, FaDiceOne, FaDiceSix, FaDivide,
    FaDoorOpen, FaEarthAmericas, FaEarthEurope, FaEquals, FaEraser, FaFileCircleXmark, FaFileCode,
    FaFileLines, FaFilter, FaFilterCircleXmark, FaFingerprint, FaFlag, FaFlask, FaFont, FaForward,
    FaGhost, FaGlobe, FaGripLines, FaHand, FaHandshake, FaHashtag, FaHourglassEnd, FaICursor,
    FaIdBadge, FaIdCard, FaInfinity, FaKey, FaLink, FaLinkSlash, FaListOl, FaListUl, FaLocationDot,
    FaLockOpen, FaMagnet, FaMagnifyingGlass, FaMagnifyingGlassArrowRight, FaMagnifyingGlassChart,
    FaMask, FaMoneyBill, FaNotEqual, FaObjectGroup, FaPaperclip, FaPeopleArrowsLeftRight,
    FaPeopleGroup, FaPlug, FaPlugCircleExclamation, FaPlugCircleXmark, FaPuzzlePiece, FaQuoteLeft,
    FaRegistered, FaRepeat, FaRotateRight, FaRuler, FaScissors, FaShareNodes, FaShield, FaShuffle,
    FaSignsPost, FaSitemap, FaSkull, FaSliders, FaSnowflake, FaSort, FaSpellCheck, FaSquareMinus,
    FaSquareRootVariable, FaStopwatch, FaTable, FaTableList, FaTag, FaTags, FaTextHeight,
    FaTextWidth, FaTrashCan, FaUnderline, FaUserCheck, FaUserGear, FaUserNinja, FaUserPen,
    FaUserSlash, FaUserTag, FaWater, FaWaterLadder,
};

/// Defines `RuleIcon`, rendering the icon each listed rule name maps to, and
/// `ICON_NAMES`, the names it covers.
macro_rules! rule_icons {
    ($($rule:literal => $icon:ident),* $(,)?) => {
        /// The rule names that have an icon.
        #[cfg(test)]
        pub(crate) const ICON_NAMES: &[&str] = &[$($rule),*];

        /// The icon of the rule named `rule`, nothing for an unknown name.
        #[component]
        pub(crate) fn RuleIcon(rule: &'static str, size: u32) -> Element {
            match rule {
                $($rule => rsx! { Icon { width: size, height: size, icon: $icon, class: "rule-icon".to_string() } },)*
                _ => rsx! {},
            }
        }
    };
}

rule_icons! {
    "client_role_bypasses_row_level_security" => FaDoorOpen,
    "credential_setting_write" => FaUserPen,
    "dead_permissive_policy" => FaSkull,
    "definer_temporary_schema_not_last" => FaHourglassEnd,
    "definer_without_search_path" => FaSignsPost,
    "unsatisfiable_check" => FaCircleXmark,
    "surrogate_primary_key_in_extension" => FaPuzzlePiece,
    "tautological_check" => FaEquals,
    "outer_column_capture" => FaMagnet,
    "policy_without_row_level_security" => FaLockOpen,
    "policy_read_cycle" => FaArrowsRotate,
    "self_asserted_claim_policy" => FaIdBadge,
    "truncate_granted_to_anonymous_role" => FaTrashCan,
    "alias_shadowed_by_column" => FaCircleHalfStroke,
    "blank_padded_character" => FaTextWidth,
    "child_without_row_level_security" => FaChild,
    "client_written_counter_key" => FaListOl,
    "client_written_scaled_numeric" => FaRuler,
    "incompatible_foreign_key" => FaLinkSlash,
    "credential_free_write" => FaUserSlash,
    "deny_list_policy" => FaClipboardList,
    "exposed_definer_over_protected_table" => FaUserNinja,
    "extension_foreign_key_on_delete_cascade" => FaAnglesDown,
    "extension_in_exposed_schema" => FaPlug,
    "floating_point_money" => FaCoins,
    "function_mediated_policy_cycle" => FaArrowsSpin,
    "grant_option_to_client_role" => FaShareNodes,
    "missing_primary_key" => FaKey,
    "impure_immutable_function" => FaFlask,
    "key_without_exact_equality" => FaNotEqual,
    "latent_policy_read_cycle" => FaRotateRight,
    "money_type" => FaMoneyBill,
    "forbidden_column_in_extension" => FaHand,
    "not_in_nullable_subquery" => FaGhost,
    "nullable_composite_foreign_key" => FaLink,
    "owner_rights_view" => FaBinoculars,
    "policy_to_creating_role" => FaUserCheck,
    "public_schema_create" => FaPeopleGroup,
    "query_rewrite_rule" => FaShuffle,
    "reachable_foreign_table" => FaGlobe,
    "reachable_materialized_view" => FaCubes,
    "reachable_sequence" => FaArrowUp19,
    "reachable_table_without_row_level_security" => FaTable,
    "reg_column_type" => FaRegistered,
    "role_keyed_policy_when_pooled" => FaWaterLadder,
    "row_level_security_without_policies" => FaShield,
    "security_definer_function_exposed" => FaMask,
    "self_comparison" => FaArrowRightArrowLeft,
    "self_granting_write" => FaUserGear,
    "session_time_zone_dependence" => FaEarthEurope,
    "settable_membership_in_bypassing_role" => FaPeopleArrowsLeftRight,
    "subject_settable_attribute" => FaSliders,
    "table_inheritance" => FaCodeBranch,
    "tautological_with_check" => FaCheckDouble,
    "unbounded_text_column" => FaInfinity,
    "time_dependent_check" => FaCalendarXmark,
    "time_with_time_zone" => FaEarthAmericas,
    "timestamp_between" => FaArrowsLeftRightToLine,
    "timestamp_without_time_zone" => FaClock,
    "truncate_granted_to_app_role" => FaEraser,
    "truncated_identifier" => FaScissors,
    "truncating_integer_division" => FaDivide,
    "unfiltered_write" => FaFilterCircleXmark,
    "unforced_row_level_security" => FaCrown,
    "duplicate_column_name_in_extension_graph" => FaSitemap,
    "unlinked_from_item" => FaBorderAll,
    "unordered_distinct_on" => FaSort,
    "unordered_limit" => FaArrowDownShortWide,
    "unread_outer_join" => FaCodeMerge,
    "unscoped_unique_constraint_on_row_level_security_table" => FaFingerprint,
    "unvalidated_constraint" => FaCircleQuestion,
    "zero_precision_timestamp" => FaStopwatch,
    "autovacuum_disabled_table" => FaBroom,
    "correlated_policy_subquery" => FaRepeat,
    "expression_defeats_index" => FaSquareRootVariable,
    "json_type" => FaFileCode,
    "multiple_permissive_policies" => FaListUl,
    "nested_policy_subquery" => FaBoxesStacked,
    "not_in_subquery" => FaSquareMinus,
    "prefix_redundant_index" => FaTags,
    "uncached_policy_call" => FaBolt,
    "unindexed_correlated_select" => FaMagnifyingGlassArrowRight,
    "unindexed_foreign_key" => FaTag,
    "unindexed_policy_filter" => FaMagnifyingGlassChart,
    "redundant_extension_edge" => FaBezierCurve,
    "duplicate_check" => FaCopy,
    "duplicate_foreign_key" => FaPaperclip,
    "duplicate_unique_index" => FaClone,
    "duplicate_policy" => FaCopy,
    "mixed_case_column_name" => FaTextHeight,
    "mixed_case_foreign_key_name" => FaICursor,
    "mixed_case_table_name" => FaFont,
    "primary_key_not_named_id" => FaIdCard,
    "singular_table_name" => FaDiceOne,
    "reference_without_id_suffix" => FaAnchor,
    "reserved_keyword_identifier" => FaSpellCheck,
    "serial_column" => FaHashtag,
    "plural_column_name" => FaDiceSix,
    "non_snake_case_column_name" => FaGripLines,
    "non_snake_case_table_name" => FaUnderline,
    "address_stored_as_text" => FaLocationDot,
    "array_membership_policy" => FaTableList,
    "cascade_into_row_level_security_table" => FaWater,
    "definer_takes_acting_user" => FaUserTag,
    "distinct_over_referenced_side" => FaObjectGroup,
    "flag_not_boolean" => FaFlag,
    "fractional_count" => FaChartPie,
    "json_stored_as_text" => FaFileLines,
    "moment_stored_as_text" => FaCalendarDays,
    "narrow_integer_key" => FaCompress,
    "empty_text_allowed" => FaQuoteLeft,
    "nullable_unique_column" => FaSnowflake,
    "offset_paging" => FaForward,
    "unchecked_past_timestamp" => FaClockRotateLeft,
    "random_order_limit" => FaDice,
    "references_granted_to_client_role" => FaHandshake,
    "scaled_numeric" => FaCalculator,
    "security_barrier_missing_on_filtering_view" => FaFilter,
    "unindexed_filter" => FaMagnifyingGlass,
    "unlogged_table" => FaFileCircleXmark,
    "uuid_stored_as_text" => FaBarcode,
    "wildcard_view" => FaAsterisk,
    "rust_keyword_column_name" => FaRust,
    "rust_keyword_foreign_key_name" => FaRust,
    "rust_keyword_table_name" => FaRust,
    "binary_send_failure" => FaPlugCircleXmark,
    "unknown_binary_send" => FaPlugCircleExclamation,
}
#[cfg(test)]
mod tests {
    use super::ICON_NAMES;
    use crate::catalog::catalog;

    #[test]
    fn every_rule_has_exactly_one_icon() {
        let rules = catalog();
        for rule in &rules {
            assert!(ICON_NAMES.contains(&rule.name), "{} has no icon", rule.name);
        }
        assert_eq!(ICON_NAMES.len(), rules.len(), "an icon names no rule");
    }
}
