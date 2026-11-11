//! The deployments and rule levels the page checks SQL with.

use sqlippy::prelude::*;
use sqlparser::parser::ParserError;

/// Role a caller without a credential runs as.
pub const ANONYMOUS_ROLE: &str = "anon";
/// Role a signed-in caller runs as.
pub const APP_ROLE: &str = "authenticated";
/// Expression naming the caller, `NULL` without a credential.
pub const CREDENTIAL: &str = "current_setting('app.user_id', true)";
/// Claim the caller can set on their own token.
pub const SELF_ASSERTED_CLAIM: &str = "current_setting('app.user_metadata', true)";

/// The playground's rules, every rule at its group's default level, checked
/// against an API that connects as [`ANONYMOUS_ROLE`] or [`APP_ROLE`] without
/// a connection pooler. The pedantic and restriction groups are raised to
/// `warn` when `pedantic` is set.
///
/// No schema is declared exposed, since a pasted schema says nothing about
/// which of its schemas an API serves.
///
/// # Errors
///
/// Returns the parser error when [`CREDENTIAL`] or [`SELF_ASSERTED_CLAIM`] is
/// not a PostgreSQL expression.
pub fn playground(pedantic: bool) -> Result<DefaultConstrainer<ParserDB>, ParserError> {
    let deployment = Deployment::default()
        .with_anonymous_role(ANONYMOUS_ROLE)
        .with_app_role(APP_ROLE)
        .with_pooled(false)
        .with_credential(CREDENTIAL)?
        .with_self_asserted_claim(SELF_ASSERTED_CLAIM)?;
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    constrainer.set_deployment(deployment);
    if pedantic {
        enable_opt_in_groups(&mut constrainer);
    }
    Ok(constrainer)
}

/// The rules the rule pages run their examples with, every rule at `warn` or
/// above under [`Deployment::example`], the deployment the examples are
/// written for.
pub fn examples() -> DefaultConstrainer<ParserDB> {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    constrainer.set_deployment(Deployment::example());
    enable_opt_in_groups(&mut constrainer);
    constrainer
}

/// Raises the groups that are off by default to `warn`.
fn enable_opt_in_groups(constrainer: &mut DefaultConstrainer<ParserDB>) {
    for group in LintGroup::ALL {
        if group.default_level() == Level::Allow {
            constrainer.set_group_level(group, Level::Warn);
        }
    }
}
