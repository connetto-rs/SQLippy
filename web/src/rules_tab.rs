//! The Rules tab, a searchable list of every rule and one page per rule with
//! its reported and corrected example, both checked live.

use std::rc::Rc;

use dioxus::prelude::*;
use dioxus_code_editor::{CodeEditor, Language};
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::fa_solid_icons::{
    FaBan, FaBook, FaBug, FaCircleCheck, FaDiagramProject, FaEye, FaGaugeHigh, FaGlasses,
    FaLayerGroup, FaPaintbrush, FaTriangleExclamation, FaWrench,
};
use sqlippy::prelude::{Basis, DefaultConstrainer, LintGroup, ParserDB};

use crate::analysis::analyze;
use crate::catalog::{CatalogEntry, catalog, kind_phrase};
use crate::route::Route;
use crate::rule_icons::RuleIcon;
use crate::{Tone, code_theme, settings};

/// The rule list beside the opened rule, or a prompt to open one.
#[component]
pub fn RulesTab(selected: Option<String>) -> Element {
    let rules = use_hook(|| Rc::new(catalog()));
    let mut query = use_signal(String::new);
    let mut group = use_signal::<Option<LintGroup>>(|| None);
    let needle = query.read().trim().to_lowercase();
    let snake_needle = needle.replace(' ', "_");
    let chosen = group();
    let shown: Vec<&CatalogEntry> = rules
        .iter()
        .filter(|rule| chosen.is_none_or(|group| group == rule.group))
        .filter(|rule| {
            needle.is_empty()
                || rule.name.contains(&snake_needle)
                || rule.rationale.to_lowercase().contains(&needle)
        })
        .collect();
    let opened = selected
        .as_deref()
        .and_then(|name| rules.iter().find(|rule| rule.name == name));

    rsx! {
        div { class: if opened.is_some() { "rules-layout has-rule" } else { "rules-layout" },
            aside { class: "panel rule-index",
                div { class: "panel-header",
                    h2 {
                        Icon { width: 16, height: 16, icon: FaBook, class: "section-icon".to_string() }
                        "Rules"
                        span { class: "panel-sub", "{shown.len()} of {rules.len()}" }
                    }
                }
                input {
                    class: "rule-search",
                    r#type: "search",
                    placeholder: "Search by name or rationale",
                    aria_label: "Search the rules",
                    value: query(),
                    oninput: move |evt| query.set(evt.value()),
                }
                div { class: "pills",
                    button {
                        class: if chosen.is_none() { "pill active" } else { "pill" },
                        "aria-pressed": chosen.is_none().to_string(),
                        onclick: move |_| group.set(None),
                        Icon { width: 12, height: 12, icon: FaLayerGroup }
                        "all"
                    }
                    for candidate in LintGroup::ALL {
                        button {
                            class: if chosen == Some(candidate) { "pill group-pill active {group_tone(candidate)}" } else { "pill group-pill {group_tone(candidate)}" },
                            "aria-pressed": (chosen == Some(candidate)).to_string(),
                            onclick: move |_| group.set(Some(candidate)),
                            GroupIcon { group: candidate }
                            "{candidate}"
                        }
                    }
                }
                nav { class: "rule-links", aria_label: "Rules",
                    for heading in LintGroup::ALL {
                        if shown.iter().any(|rule| rule.group == heading) {
                            h3 { key: "{heading}", class: "rule-group-heading {group_tone(heading)}",
                                span { class: "rule-group-name",
                                    GroupIcon { group: heading }
                                    "{heading}"
                                }
                                span { class: "rule-group-level", "{heading.default_level()} by default" }
                            }
                            for rule in shown.iter().filter(|rule| rule.group == heading) {
                                a {
                                    key: "{rule.name}",
                                    class: if opened.is_some_and(|open| open.name == rule.name) { "rule-link active {Tone::of(rule.level, rule.group).class()}" } else { "rule-link {Tone::of(rule.level, rule.group).class()}" },
                                    href: Route::Rules(Some(rule.name.to_owned())).href(),
                                    title: "{rule.name}",
                                    RuleIcon { rule: rule.name, size: 12 }
                                    "{rule.name}"
                                }
                            }
                        }
                    }
                    if shown.is_empty() {
                        p { class: "output-empty", "No rule matches." }
                    }
                }
            }
            match opened {
                Some(rule) => rsx! { RulePage { key: "{rule.name}", rule: rule.clone() } },
                None => rsx! {
                    section { class: "panel rule-overview",
                        p {
                            "SQLippy has {rules.len()} rules in {LintGroup::ALL.len()} groups. Each page explains what its rule reports and why, and shows a reported example beside the same SQL corrected."
                        }
                        ul { class: "rule-overview-groups",
                            for heading in LintGroup::ALL {
                                li { key: "{heading}",
                                    button {
                                        class: "pill group-pill {group_tone(heading)}",
                                        onclick: move |_| group.set(Some(heading)),
                                        GroupIcon { group: heading }
                                        "{heading}"
                                    }
                                    span {
                                        "{rules.iter().filter(|rule| rule.group == heading).count()} rules, {heading.default_level()} by default"
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}

/// The tone class a group's rules run at by default.
fn group_tone(group: LintGroup) -> &'static str {
    Tone::of(group.default_level(), group).class()
}

/// The icon that marks `group` in the pills and the rule index.
#[component]
fn GroupIcon(group: LintGroup) -> Element {
    match group {
        LintGroup::Correctness => rsx! { Icon { width: 12, height: 12, icon: FaBug } },
        LintGroup::Suspicious => rsx! { Icon { width: 12, height: 12, icon: FaEye } },
        LintGroup::Perf => rsx! { Icon { width: 12, height: 12, icon: FaGaugeHigh } },
        LintGroup::Complexity => rsx! { Icon { width: 12, height: 12, icon: FaDiagramProject } },
        LintGroup::Style => rsx! { Icon { width: 12, height: 12, icon: FaPaintbrush } },
        LintGroup::Pedantic => rsx! { Icon { width: 12, height: 12, icon: FaGlasses } },
        LintGroup::Restriction => rsx! { Icon { width: 12, height: 12, icon: FaBan } },
    }
}

/// One rule, explained, with its reported and corrected example.
#[component]
fn RulePage(rule: CatalogEntry) -> Element {
    let tone = Tone::of(rule.level, rule.group).class();
    let kinds = rule
        .kinds
        .iter()
        .map(|kind| kind_phrase(*kind))
        .collect::<Vec<_>>()
        .join(" and ");
    let requires = rule
        .requires
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" and ");

    rsx! {
        section { class: "panel rule-page {tone}",
            a { class: "rule-back", href: Route::Rules(None).href(), "← All rules" }
            div { class: "finding-head",
                h2 { class: "rule-title",
                    RuleIcon { rule: rule.name, size: 18 }
                    "{rule.name}"
                }
                if rule.basis == Basis::Names {
                    span {
                        class: "heuristic",
                        title: "This rule guesses what an object holds from words in its name.",
                        "heuristic"
                    }
                }
                span {
                    class: "chip {tone}",
                    title: "Runs at {rule.level} by default, in the {rule.group} group",
                    "{rule.level} · {rule.group}"
                }
            }
            p { class: "rule-rationale", "{rule.rationale}" }
            p { class: "rule-meta",
                "Runs on {kinds}."
                if !rule.requires.is_empty() {
                    " Needs the deployment to declare {requires}."
                }
            }
            if let Some(source) = rule.source {
                p { class: "rule-meta",
                    "Source: "
                    a { href: source, target: "_blank", rel: "noopener", "{source_host(source)}" }
                }
            }
            p { class: "field-help",
                "Both examples are live: edit either one and SQLippy checks it again. They run with every rule enabled, for an API that serves the public schema to the roles anon and authenticated through a pooler and names the caller with current_setting('app.user_id', true)."
            }
            div { class: "example-pair",
                ExamplePanel {
                    rule: rule.name,
                    title: "Reported",
                    initial: rule.example.bad,
                    expects_findings: true,
                }
                ExamplePanel {
                    rule: rule.name,
                    title: "Corrected",
                    initial: rule.example.good,
                    expects_findings: false,
                }
            }
        }
    }
}

/// The host part of `url`, which names a source more readably than the full
/// link.
fn source_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split('/').next().unwrap_or(rest)
}

/// An editable example and what `rule` reports on it.
#[component]
fn ExamplePanel(
    rule: &'static str,
    title: &'static str,
    initial: &'static str,
    expects_findings: bool,
) -> Element {
    let constrainer: Rc<DefaultConstrainer<ParserDB>> = use_hook(|| Rc::new(settings::examples()));
    let mut sql = use_signal(|| initial.to_owned());
    let outcome = use_memo(move || {
        analyze(&sql.read(), &constrainer)
            .map(|report| {
                report
                    .findings
                    .into_iter()
                    .filter(|finding| finding.rule == rule)
                    .collect::<Vec<_>>()
            })
            .map_err(|failure| failure.to_string())
    });
    let class = if expects_findings {
        "example bad"
    } else {
        "example good"
    };

    rsx! {
        div { class: "{class}",
            h3 { "{title}" }
            CodeEditor {
                value: sql(),
                language: Language::Sql,
                theme: code_theme(),
                line_numbers: true,
                spellcheck: false,
                aria_label: format!("{title} example of {rule}"),
                class: "editor".to_string(),
                oninput: move |value| sql.set(value),
            }
            match &*outcome.read() {
                Err(failure) => rsx! {
                    div { class: "parse-error",
                        Icon { width: 14, height: 14, icon: FaTriangleExclamation }
                        span { "{failure}" }
                    }
                },
                Ok(findings) if findings.is_empty() => rsx! {
                    p { class: "example-verdict clean",
                        Icon { width: 13, height: 13, icon: FaCircleCheck }
                        span { "{rule} reports nothing here." }
                    }
                },
                Ok(findings) => rsx! {
                    ul { class: "example-findings",
                        for (i, finding) in findings.iter().enumerate() {
                            li { key: "{i}",
                                p { class: "finding-message",
                                    span { class: "finding-object", "{finding.object}" }
                                    " {finding.message}"
                                }
                                p { class: "finding-fix",
                                    Icon { width: 12, height: 12, icon: FaWrench }
                                    span { "{finding.resolution}" }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}
