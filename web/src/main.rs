//! SQLippy web app. Lints PostgreSQL schemas and the statements applications
//! send to them, entirely client-side in WebAssembly.

mod analysis;
mod catalog;
mod examples;
mod proposal;
mod route;
mod rule_icons;
mod rules_tab;
mod settings;

use dioxus::html::FileData;
use dioxus::prelude::*;
use dioxus_code::{CodeTheme, Theme};
use dioxus_code_editor::{CodeEditor, Language};
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::fa_brands_icons::FaGithub;
use dioxus_free_icons::icons::fa_solid_icons::{
    FaBook, FaCircleCheck, FaCode, FaDatabase, FaFolderOpen, FaFont, FaGripVertical, FaHeart,
    FaKey, FaListCheck, FaMagnifyingGlass, FaShieldHalved, FaTriangleExclamation, FaUpload,
    FaUserSecret, FaWrench, FaXmark,
};
use sqlippy::prelude::{Basis, Level, LintGroup};

use crate::analysis::{Finding, Report, analyze};
use crate::examples::{EXAMPLES, ExampleIcon};
use crate::proposal::{ProposeLint, proposal_url};
use crate::route::{Route, use_route};
use crate::rule_icons::RuleIcon;
use crate::rules_tab::RulesTab;

const REPO_URL: &str = "https://github.com/connetto-rs/SQLippy";
const SPONSOR_URL: &str = "https://github.com/sponsors/LucaCappelletti94";
const CLIPPY_URL: &str = "https://doc.rust-lang.org/clippy/";

fn main() {
    dioxus::launch(App);
}

/// Runs the rules over the current editor contents. Never blanks the findings
/// on error: the last good report stays and the failure shows in the input pane.
fn run_check(
    sql: Signal<String>,
    pedantic: Signal<bool>,
    mut report: Signal<Option<Report>>,
    mut error: Signal<Option<String>>,
) {
    if sql.peek().trim().is_empty() {
        report.set(None);
        error.set(None);
        return;
    }
    let checked = settings::playground(*pedantic.peek())
        .map_err(|failure| failure.to_string())
        .and_then(|constrainer| {
            analyze(&sql.peek(), &constrainer).map_err(|failure| failure.to_string())
        });
    match checked {
        Ok(checked) => {
            report.set(Some(checked));
            error.set(None);
        }
        Err(failure) => error.set(Some(failure)),
    }
}

/// Reads uploaded files in filename order, or relative-path order for a
/// folder, into the editor and checks them.
fn load_files(
    mut uploaded: Vec<FileData>,
    by_path: bool,
    mut sql: Signal<String>,
    mut files: Signal<Vec<(String, String)>>,
    pedantic: Signal<bool>,
    report: Signal<Option<Report>>,
    error: Signal<Option<String>>,
) {
    if by_path {
        uploaded.sort_by_key(FileData::path);
    } else {
        uploaded.sort_by_key(FileData::name);
    }
    spawn(async move {
        let mut collected: Vec<(String, String)> = Vec::new();
        for file in &uploaded {
            if let Ok(text) = file.read_string().await {
                collected.push((file.name(), text));
            }
        }
        if !collected.is_empty() {
            sql.set(concat_files(&collected));
            files.set(collected);
            run_check(sql, pedantic, report, error);
        }
    });
}

/// Concatenates uploaded file contents in list order.
fn concat_files(files: &[(String, String)]) -> String {
    files
        .iter()
        .map(|(_, content)| content.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Syntax theme following the OS light or dark preference.
pub(crate) fn code_theme() -> CodeTheme {
    CodeTheme::system(Theme::GITHUB_LIGHT, Theme::GITHUB_DARK)
}

/// How a finding or rule is colored: red when denied, violet for the opt-in
/// pedantic and restriction groups, amber for every other warning.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    Deny,
    Warn,
    Pedantic,
}

impl Tone {
    pub(crate) fn of(level: Level, group: LintGroup) -> Self {
        match (level, group) {
            (Level::Deny, _) => Self::Deny,
            (_, LintGroup::Pedantic | LintGroup::Restriction) => Self::Pedantic,
            _ => Self::Warn,
        }
    }

    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::Deny => "tone-deny",
            Self::Warn => "tone-warn",
            Self::Pedantic => "tone-pedantic",
        }
    }
}

/// Font Awesome glyph for an example pill.
fn example_icon(icon: ExampleIcon) -> Element {
    match icon {
        ExampleIcon::Naming => rsx! { Icon { width: 12, height: 12, icon: FaFont } },
        ExampleIcon::Types => rsx! { Icon { width: 12, height: 12, icon: FaDatabase } },
        ExampleIcon::Keys => rsx! { Icon { width: 12, height: 12, icon: FaKey } },
        ExampleIcon::Security => rsx! { Icon { width: 12, height: 12, icon: FaShieldHalved } },
        ExampleIcon::Functions => rsx! { Icon { width: 12, height: 12, icon: FaUserSecret } },
        ExampleIcon::Queries => rsx! { Icon { width: 12, height: 12, icon: FaMagnifyingGlass } },
        ExampleIcon::Clean => rsx! { Icon { width: 12, height: 12, icon: FaCircleCheck } },
    }
}

#[component]
fn App() -> Element {
    let mut sql = use_signal(|| EXAMPLES[0].sql.to_string());
    let mut pedantic = use_signal(|| false);
    let report = use_signal::<Option<Report>>(|| None);
    let error = use_signal::<Option<String>>(|| None);
    let mut files = use_signal::<Vec<(String, String)>>(Vec::new);
    let mut drag_from = use_signal::<Option<usize>>(|| None);
    let mut active_example = use_signal::<Option<usize>>(|| Some(0));
    let route = use_route();

    // `peek` inside keeps this from re-subscribing, so it runs once on mount.
    use_effect(move || run_check(sql, pedantic, report, error));

    rsx! {
        main {
            header {
                div { class: "subtitle-row",
                    h1 { "SQLippy" }
                    nav { class: "topbar-actions", aria_label: "Project resources",
                        a {
                            class: "icon-link",
                            href: REPO_URL,
                            target: "_blank",
                            rel: "noopener",
                            title: "GitHub repository. Opens in a new tab.",
                            "aria-label": "GitHub repository. Opens in a new tab.",
                            Icon { width: 15, height: 15, icon: FaGithub }
                        }
                        a {
                            class: if report.read().is_some() { "icon-link heartbtn heart-attention" } else { "icon-link heartbtn" },
                            href: SPONSOR_URL,
                            target: "_blank",
                            rel: "noopener",
                            title: "Support this project. Opens in a new tab.",
                            "aria-label": "Support this project. Opens in a new tab.",
                            Icon { width: 15, height: 15, icon: FaHeart }
                        }
                    }
                }
                p { class: "tagline",
                    "A Rust crate of "
                    a { href: CLIPPY_URL, target: "_blank", rel: "noopener", "Clippy" }
                    "-style lints for PostgreSQL schemas and the queries sent to them, each explaining what is wrong and how to fix it, running in your browser. "
                    "Something wrong in this SQL that SQLippy misses? "
                    ProposeLint { label: "Propose a lint", href: proposal_url(Some(&sql.read())) }
                }
            }
            nav { class: "tabs", aria_label: "Sections",
                a {
                    class: if *route.read() == Route::Playground { "tab active" } else { "tab" },
                    href: Route::Playground.href(),
                    Icon { width: 14, height: 14, icon: FaCode }
                    "Playground"
                }
                a {
                    class: if matches!(*route.read(), Route::Rules(_)) { "tab active" } else { "tab" },
                    href: Route::Rules(None).href(),
                    Icon { width: 14, height: 14, icon: FaBook }
                    "Rules"
                }
            }
            if let Route::Rules(selected) = &*route.read() {
                RulesTab { selected: selected.clone() }
            } else {
            div { class: "layout",
                InputPane {
                    sql,
                    pedantic,
                    error: error.read().clone(),
                    files: files.read().clone(),
                    active_example: active_example(),
                    on_pick_example: move |i: usize| {
                        sql.set(EXAMPLES[i].sql.to_string());
                        files.set(Vec::new());
                        active_example.set(Some(i));
                        run_check(sql, pedantic, report, error);
                    },
                    on_set_pedantic: move |value: bool| {
                        pedantic.set(value);
                        run_check(sql, pedantic, report, error);
                    },
                    on_upload: move |uploaded: Vec<FileData>| {
                        active_example.set(None);
                        load_files(uploaded, false, sql, files, pedantic, report, error);
                    },
                    on_upload_folder: move |uploaded: Vec<FileData>| {
                        active_example.set(None);
                        load_files(uploaded, true, sql, files, pedantic, report, error);
                    },
                    on_edit: move |value: String| {
                        active_example.set(None);
                        sql.set(value);
                        run_check(sql, pedantic, report, error);
                    },
                    on_drag_start: move |i: usize| drag_from.set(Some(i)),
                    on_drop: move |i: usize| {
                        if let Some(from) = drag_from.take()
                            && from != i
                            && from < files.read().len()
                        {
                            let mut list = files.write();
                            let item = list.remove(from);
                            let at = i.min(list.len());
                            list.insert(at, item);
                        }
                        sql.set(concat_files(&files.read()));
                        run_check(sql, pedantic, report, error);
                    },
                    on_remove: move |i: usize| {
                        files.write().remove(i);
                        sql.set(concat_files(&files.read()));
                        run_check(sql, pedantic, report, error);
                    },
                }
                FindingsPane { report: report.read().clone(), stale: error.read().is_some() }
            }
            }
        }
    }
}

#[component]
fn InputPane(
    sql: Signal<String>,
    pedantic: Signal<bool>,
    error: Option<String>,
    files: Vec<(String, String)>,
    active_example: Option<usize>,
    on_pick_example: EventHandler<usize>,
    on_set_pedantic: EventHandler<bool>,
    on_upload: EventHandler<Vec<FileData>>,
    on_upload_folder: EventHandler<Vec<FileData>>,
    on_edit: EventHandler<String>,
    on_drag_start: EventHandler<usize>,
    on_drop: EventHandler<usize>,
    on_remove: EventHandler<usize>,
) -> Element {
    rsx! {
        section { class: "panel",
            div { class: "panel-header",
                h2 {
                    Icon { width: 16, height: 16, icon: FaDatabase, class: "section-icon".to_string() }
                    "Input"
                    span { class: "panel-sub", "PostgreSQL schema & queries" }
                }
                div { class: "actions",
                    label { class: "icon-link", title: "Upload one or more .sql files, sorted by filename and concatenated in that order",
                        Icon { width: 16, height: 16, icon: FaUpload }
                        input {
                            class: "file-input",
                            r#type: "file",
                            accept: ".sql",
                            multiple: true,
                            aria_label: "Upload one or more .sql files, ordered by filename",
                            onchange: move |evt| on_upload.call(evt.files()),
                        }
                    }
                    label { class: "icon-link", title: "Upload a folder of migrations, sorted by relative path and concatenated in that order",
                        Icon { width: 16, height: 16, icon: FaFolderOpen }
                        input {
                            class: "file-input",
                            r#type: "file",
                            directory: true,
                            aria_label: "Upload a folder of .sql migrations, ordered by relative path",
                            onchange: move |evt| on_upload_folder.call(evt.files()),
                        }
                    }
                }
            }

            div { class: "pills",
                for (i, example) in EXAMPLES.iter().enumerate() {
                    button {
                        class: if active_example == Some(i) { "pill active" } else { "pill" },
                        title: "{example.description}",
                        aria_label: "Load the {example.label} example",
                        "aria-pressed": (active_example == Some(i)).to_string(),
                        onclick: move |_| on_pick_example.call(i),
                        {example_icon(example.icon)}
                        "{example.label}"
                    }
                }
            }

            if !files.is_empty() {
                div {
                    span { class: "field-label", "Ordered input files (drag to reorder)" }
                    ul { class: "file-list",
                        for (i, (name, _)) in files.iter().enumerate() {
                            li {
                                key: "{name}-{i}",
                                draggable: true,
                                ondragstart: move |_| on_drag_start.call(i),
                                ondragover: move |e| e.prevent_default(),
                                ondrop: move |e| { e.prevent_default(); on_drop.call(i); },
                                Icon { width: 12, height: 12, icon: FaGripVertical, class: "drag-handle".to_string() }
                                span { class: "file-order", "{i + 1}." }
                                span { "{name}" }
                                button {
                                    class: "file-remove",
                                    title: "Remove this file from the input",
                                    aria_label: "Remove {name} from the input",
                                    onclick: move |_| on_remove.call(i),
                                    Icon { width: 12, height: 12, icon: FaXmark }
                                }
                            }
                        }
                    }
                }
            }

            CodeEditor {
                value: sql(),
                language: Language::Sql,
                theme: code_theme(),
                line_numbers: true,
                spellcheck: false,
                placeholder: "Paste PostgreSQL DDL, policies and the queries your application sends".to_string(),
                aria_label: "SQL input".to_string(),
                class: "editor".to_string(),
                oninput: move |value| on_edit.call(value),
            }

            if let Some(failure) = error {
                div { class: "parse-error",
                    Icon { width: 14, height: 14, icon: FaTriangleExclamation }
                    span { "{failure}" }
                }
            }

            div { class: "control-group",
                label { class: "toggle",
                    input {
                        r#type: "checkbox",
                        checked: pedantic(),
                        onchange: move |evt| on_set_pedantic.call(evt.checked()),
                    }
                    "Also run the pedantic and restriction rules"
                }
                p { class: "field-help",
                    "Rules run at their group's default level: correctness denies, suspicious, perf, complexity and style warn. "
                    "The row-level security rules assume an API connecting as "
                    code { "{settings::ANONYMOUS_ROLE}" }
                    " or "
                    code { "{settings::APP_ROLE}" }
                    " that names the caller with "
                    code { "{settings::CREDENTIAL}" }
                    ". SELECT, INSERT, UPDATE, DELETE and MERGE statements are checked against the schema as queries."
                }
            }
        }
    }
}

/// `stale` marks a report of the last SQL that parsed, kept while the editor
/// holds SQL that does not.
#[component]
fn FindingsPane(report: Option<Report>, stale: bool) -> Element {
    let Some(report) = report else {
        return rsx! {
            section { class: "panel",
                div { class: "panel-header",
                    h2 {
                        Icon { width: 16, height: 16, icon: FaListCheck, class: "section-icon".to_string() }
                        "Findings"
                    }
                }
                p { class: "output-empty", "Paste or upload a PostgreSQL schema, or pick an example, to see what SQLippy reports." }
            }
        };
    };

    let count = |tone: Tone| {
        report
            .findings
            .iter()
            .filter(|finding| Tone::of(finding.level, finding.group) == tone)
            .count()
    };
    let (denied, warned, pedantic) = (count(Tone::Deny), count(Tone::Warn), count(Tone::Pedantic));
    let statements = report.statements;

    rsx! {
        section { class: "panel",
            div { class: "panel-header",
                h2 {
                    Icon { width: 16, height: 16, icon: FaListCheck, class: "section-icon".to_string() }
                    "Findings"
                    span { class: "panel-sub",
                        if statements == 1 { "schema and 1 query" } else if statements > 1 { "schema and {statements} queries" } else { "schema" }
                    }
                }
                div { class: "summary",
                    if !stale && report.findings.is_empty() && report.lookups.is_empty() {
                        span { class: "chip tone-ok",
                            Icon { width: 12, height: 12, icon: FaCircleCheck }
                            "Nothing to report"
                        }
                    }
                    if denied > 0 {
                        span { class: "chip tone-deny", "{denied} deny" }
                    }
                    if warned > 0 {
                        span { class: "chip tone-warn", "{warned} warn" }
                    }
                    if pedantic > 0 {
                        span { class: "chip tone-pedantic", "{pedantic} pedantic" }
                    }
                }
            }
            if stale {
                div { class: "stale-banner",
                    Icon { width: 14, height: 14, icon: FaTriangleExclamation }
                    span { "These findings are for the last SQL that parsed, not the SQL in the editor." }
                }
            }
            if !report.lookups.is_empty() {
                div {
                    span { class: "field-label", "Lookups that failed" }
                    ul { class: "lookup-list",
                        for lookup in report.lookups.iter() {
                            li { "{lookup}" }
                        }
                    }
                }
            }
            div { class: "finding-list",
                for (i, finding) in report.findings.iter().enumerate() {
                    FindingCard { key: "{i}", finding: finding.clone() }
                }
            }
        }
    }
}

#[component]
fn FindingCard(finding: Finding) -> Element {
    let tone = Tone::of(finding.level, finding.group).class();
    let href = Route::Rules(Some(finding.rule.to_owned())).href();
    rsx! {
        article { class: "finding {tone}",
            div { class: "finding-head",
                a {
                    class: "finding-rule",
                    href: "{href}",
                    title: "Read about {finding.rule} in the Rules tab",
                    RuleIcon { rule: finding.rule, size: 12 }
                    "{finding.rule}"
                }
                if finding.basis == Basis::Names {
                    span {
                        class: "heuristic",
                        title: "This rule guesses what the object holds from words in its name, so the finding can be wrong.",
                        "heuristic"
                    }
                }
                span { class: "finding-object", "{finding.object}" }
                span {
                    class: "chip {tone}",
                    title: "Raised at {finding.level} by a rule of the {finding.group} group",
                    "{finding.level} · {finding.group}"
                }
            }
            p { class: "finding-message", "{finding.message}" }
            p { class: "finding-fix",
                Icon { width: 12, height: 12, icon: FaWrench }
                span { "{finding.resolution}" }
            }
            if !finding.sites.is_empty() {
                ul { class: "finding-sites",
                    for site in finding.sites.iter() {
                        li { "{site}" }
                    }
                }
            }
            details {
                summary { "Why" }
                p { "{finding.rationale}" }
                if let Some(source) = finding.source {
                    p {
                        a { href: source, target: "_blank", rel: "noopener", "{source}" }
                    }
                }
            }
        }
    }
}
