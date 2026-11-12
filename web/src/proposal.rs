//! Links that open the repository's lint proposal issue form.

use std::fmt::Write;

use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::fa_solid_icons::FaLightbulb;

use crate::REPO_URL;

/// Prefilled SQL past this many bytes would push the link beyond the length
/// GitHub accepts.
const PREFILL_LIMIT: usize = 4000;

/// The lint proposal form, with `bad` prefilled as its reported example when
/// it is non-empty and short enough to fit in the link.
pub(crate) fn proposal_url(bad: Option<&str>) -> String {
    let mut url = format!("{REPO_URL}/issues/new?template=lint_proposal.yml");
    if let Some(sql) = bad
        .map(str::trim)
        .filter(|sql| !sql.is_empty() && sql.len() <= PREFILL_LIMIT)
    {
        url.push_str("&bad=");
        for byte in sql.bytes() {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                url.push(char::from(byte));
            } else {
                let _ = write!(url, "%{byte:02X}");
            }
        }
    }
    url
}

/// A link to `href`, a lint proposal built by [`proposal_url`].
#[component]
pub(crate) fn ProposeLint(label: &'static str, href: String) -> Element {
    rsx! {
        a {
            class: "propose-link",
            href: "{href}",
            target: "_blank",
            rel: "noopener",
            title: "Open a lint proposal on GitHub. Opens in a new tab.",
            Icon { width: 13, height: 13, icon: FaLightbulb }
            "{label}"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PREFILL_LIMIT, proposal_url};

    #[test]
    fn prefills_the_reported_example_percent_encoded() {
        let url = proposal_url(Some(" SELECT 'é' AS a_b;\n"));
        assert!(
            url.ends_with("&bad=SELECT%20%27%C3%A9%27%20AS%20a_b%3B"),
            "{url}"
        );
    }

    #[test]
    fn leaves_empty_and_overlong_sql_out() {
        let bare = proposal_url(None);
        assert!(bare.ends_with("/issues/new?template=lint_proposal.yml"));
        assert_eq!(proposal_url(Some("  \n")), bare);
        assert_eq!(proposal_url(Some(&"x".repeat(PREFILL_LIMIT + 1))), bare);
        assert_ne!(proposal_url(Some(&"x".repeat(PREFILL_LIMIT))), bare);
    }
}
