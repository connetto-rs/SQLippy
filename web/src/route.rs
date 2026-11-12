//! The page section the URL fragment selects, so tabs and rules are linkable
//! and the back button works.

use dioxus::prelude::*;

/// What the page shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// The editor and its findings.
    Playground,
    /// The rule list, with one rule opened when named.
    Rules(Option<String>),
}

impl Route {
    /// Reads a `location.hash` such as `#/rules/OuterColumnCapture`.
    pub fn parse(hash: &str) -> Self {
        let path = hash.trim_start_matches('#').trim_start_matches('/');
        match path.split_once('/') {
            Some(("rules", name)) if !name.is_empty() => Self::Rules(Some(name.to_owned())),
            _ if path == "rules" || path.starts_with("rules/") => Self::Rules(None),
            _ => Self::Playground,
        }
    }

    /// The fragment that opens this route.
    pub fn href(&self) -> String {
        match self {
            Self::Playground => "#/".to_owned(),
            Self::Rules(None) => "#/rules".to_owned(),
            Self::Rules(Some(name)) => format!("#/rules/{name}"),
        }
    }
}

/// The route of the current `location.hash`, following every later change.
pub fn use_route() -> Signal<Route> {
    let mut route = use_signal(|| Route::Playground);
    use_future(move || async move {
        let mut fragments = document::eval(
            "window.addEventListener('hashchange', () => dioxus.send(location.hash));
             dioxus.send(location.hash);",
        );
        while let Ok(hash) = fragments.recv::<String>().await {
            route.set(Route::parse(&hash));
            let _ = document::eval("window.scrollTo(0, 0);").await;
        }
    });
    route
}
