//! Facts about grants to the client roles a deployment declares, shared by the
//! grant rules.

use std::collections::BTreeSet;

use sql_traits::{
    traits::{ColumnGrantLike, DatabaseLike, GrantLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{Action, GranteeName};

use crate::{deployment::Deployment, rules::policy_support::held_by_name};

/// Roles whose privileges the declared client roles hold, by kind.
pub(crate) struct ClientRoles {
    anonymous: BTreeSet<String>,
    app: BTreeSet<String>,
}

impl ClientRoles {
    pub(crate) fn new<DB: DatabaseLike>(database: &DB, deployment: &Deployment) -> Self {
        Self {
            anonymous: held_by_any(database, deployment.anonymous_roles()),
            app: held_by_any(database, deployment.app_roles()),
        }
    }

    /// Whether the grant reaches `PUBLIC` or a declared anonymous role.
    pub(crate) fn reach_anonymous<DB: DatabaseLike>(
        &self,
        database: &DB,
        grant: &impl GrantLike<DB = DB>,
    ) -> bool {
        grant.applies_to_public() || names_any(database, grant, &self.anonymous)
    }

    /// Whether the grant reaches a declared app role.
    pub(crate) fn reach_app<DB: DatabaseLike>(
        &self,
        database: &DB,
        grant: &impl GrantLike<DB = DB>,
    ) -> bool {
        names_any(database, grant, &self.app)
    }

    /// Whether the grant reaches any client role, `PUBLIC` included.
    pub(crate) fn reach_client<DB: DatabaseLike>(
        &self,
        database: &DB,
        grant: &impl GrantLike<DB = DB>,
    ) -> bool {
        self.reach_anonymous(database, grant) || self.reach_app(database, grant)
    }
}

/// Roles whose privileges any of `roles` holds.
fn held_by_any<'a, DB: DatabaseLike>(
    database: &DB,
    roles: impl Iterator<Item = &'a str>,
) -> BTreeSet<String> {
    roles
        .flat_map(|role| held_by_name(database, role))
        .collect()
}

fn names_any<DB: DatabaseLike>(
    database: &DB,
    grant: &impl GrantLike<DB = DB>,
    roles: &BTreeSet<String>,
) -> bool {
    grant.grantees(database).any(|grantee| match &grantee.name {
        Some(GranteeName::ObjectName(name)) => name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .is_some_and(|ident| {
                roles.contains(
                    normalize_identifier(&ident.value, ident.quote_style.is_some()).as_ref(),
                )
            }),
        Some(GranteeName::UserHost { .. }) | None => false,
    })
}

/// Grantees of a grant as written, for messages.
pub(crate) fn grantee_list<DB: DatabaseLike>(
    database: &DB,
    grant: &impl GrantLike<DB = DB>,
) -> String {
    if grant.applies_to_public() {
        return "PUBLIC".to_owned();
    }
    grant
        .grantees(database)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether the grant carries a privilege matching `wanted`, `ALL` included.
pub(crate) fn grants_privilege<DB: DatabaseLike>(
    database: &DB,
    grant: &impl GrantLike<DB = DB>,
    wanted: impl Fn(&Action) -> bool,
) -> bool {
    grant.is_all_privileges() || grant.privileges(database).any(wanted)
}

/// Column grants covering `table`.
pub(crate) fn column_grants_on<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
) -> impl Iterator<Item = &'db DB::ColumnGrant> {
    database.column_grants().filter(move |grant| {
        grant
            .table(database)
            .is_some_and(|granted| granted == table)
    })
}
