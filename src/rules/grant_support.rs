//! Facts about grants to the client roles a deployment declares, shared by the
//! grant rules.

use std::{borrow::Cow, cell::LazyCell, collections::BTreeSet};

use sql_traits::{
    errors::LookupError,
    traits::{ColumnGrantLike, DatabaseLike, GrantLike, Relation, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{Action, Grantee, GranteeName};

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
        reaches_any(database, grant, &self.anonymous)
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

/// Whether the grant names one of `roles`.
fn names_any<DB: DatabaseLike>(
    database: &DB,
    grant: &impl GrantLike<DB = DB>,
    roles: &BTreeSet<String>,
) -> bool {
    grant
        .grantees(database)
        .any(|grantee| grantee_names(grantee, roles))
}

/// Whether the grantee names one of `roles`.
pub(crate) fn grantee_names(grantee: &Grantee, roles: &BTreeSet<String>) -> bool {
    match &grantee.name {
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
    }
}

/// Whether the grant reaches `PUBLIC` or names one of `roles`.
pub(crate) fn reaches_any<DB: DatabaseLike>(
    database: &DB,
    grant: &impl GrantLike<DB = DB>,
    roles: &BTreeSet<String>,
) -> bool {
    grant.applies_to_public() || names_any(database, grant, roles)
}

/// The schema a relation sits in: its own, or the first schema on the search
/// path when it was created unqualified.
pub(crate) fn schema_of<'a, DB: DatabaseLike>(
    database: &'a DB,
    schema: Option<Cow<'a, str>>,
) -> Cow<'a, str> {
    schema
        .or_else(|| {
            database
                .search_path()
                .next()
                .map(|(name, quoted)| normalize_identifier(name, quoted))
        })
        .unwrap_or_default()
}

/// Whether the deployment declares `table` client-written.
pub(crate) fn is_client_written<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    table: &DB::Table,
) -> bool {
    deployment.is_client_written(
        &schema_of(database, table.stored_table_schema()),
        &table.stored_table_name(),
    )
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

/// Column grants covering `table`, foreign or not.
pub(crate) fn column_grants_on<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
) -> impl Iterator<Item = &'db DB::ColumnGrant> {
    database.column_grants().filter(move |grant| {
        matches!(
            grant.relation(database),
            Some(Relation::Table(granted) | Relation::ForeignTable(granted)) if granted == table
        )
    })
}

/// How a client role reaches `table`: an exposed schema, or a table or column
/// grant reaching a client role, phrased for messages.
pub(crate) fn client_reach<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    table: &DB::Table,
) -> Result<BTreeSet<String>, LookupError> {
    let mut reasons = BTreeSet::new();
    let schema = schema_of(database, table.stored_table_schema());
    if deployment.exposes_schema(&schema) {
        reasons.insert(format!("sits in the exposed schema '{schema}'"));
    }
    let roles = LazyCell::new(|| ClientRoles::new(database, deployment));
    for grant in table.grants(database)? {
        if roles.reach_client(database, grant) {
            reasons.insert(format!("is granted to {}", grantee_list(database, grant)));
        }
    }
    for grant in column_grants_on(database, table) {
        if roles.reach_client(database, grant) {
            reasons.insert(format!("is granted to {}", grantee_list(database, grant)));
        }
    }
    Ok(reasons)
}
