//! Facts about grants to the client roles a deployment declares, shared by the
//! grant rules.

use std::{borrow::Cow, cell::LazyCell, collections::BTreeSet};

use sql_traits::{
    errors::LookupError,
    traits::{
        ColumnGrantLike, ColumnLike, DatabaseLike, FunctionLike, GrantLike, Relation, RoleLike,
        TableLike,
    },
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{Action, Grantee, GranteeName};

use crate::{
    deployment::Deployment,
    engine::Engine,
    rules::policy_support::{Command, held_by_name, policy_roles},
};

/// Whether the schema proves that every role writing through `policy` lacks
/// `command`'s privilege on `attribute` of `table`, for an `INSERT` or an
/// `UPDATE`.
///
/// The writers are the policy's roles, or the declared client roles for a
/// policy applying to `PUBLIC`. A writer the schema never creates may hold
/// the privilege from outside it.
pub(crate) fn withheld<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    table: &DB::Table,
    policy: &DB::Policy,
    command: Command,
    attribute: &DB::Column,
) -> Result<bool, LookupError> {
    let writers = policy_roles(database, policy).unwrap_or_else(|| {
        deployment
            .app_roles()
            .chain(deployment.anonymous_roles())
            .map(str::to_owned)
            .collect()
    });
    if writers.is_empty() {
        return Ok(false);
    }
    for writer in writers {
        let Some(role) = database.role(&writer) else {
            return Ok(false);
        };
        let possible = table.possible_privileges(role, database)?;
        let privilege = if command == Command::Insert {
            &possible.insert
        } else {
            &possible.update
        };
        if privilege.on_column(attribute) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The callers that may execute `function`, quoted for messages. They are
/// `PUBLIC` alone while it holds `EXECUTE`, else the
/// [granted callers](granted_callers).
pub(crate) fn function_callers<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    function: &DB::Function,
) -> Result<Vec<String>, LookupError> {
    if function.is_executable_by_public(database)? {
        return Ok(vec!["PUBLIC".to_owned()]);
    }
    Ok(granted_callers(database, deployment, function)?
        .into_iter()
        .map(|role| format!("'{}'", role.name()))
        .collect())
}

/// Each declared anonymous and app role the schema creates that holds
/// `EXECUTE` on `function`, by a grant to the role or a role it inherits, or
/// by default privileges.
pub(crate) fn granted_callers<'db, DB: DatabaseLike>(
    database: &'db DB,
    deployment: &Deployment,
    function: &DB::Function,
) -> Result<Vec<&'db DB::Role>, LookupError> {
    let mut callers = Vec::new();
    for role in deployment
        .anonymous_roles()
        .chain(deployment.app_roles())
        .filter_map(|name| database.role(name))
    {
        if function.can_execute(role, database)? {
            callers.push(role);
        }
    }
    Ok(callers)
}

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

/// The role a grantee names, folded as PostgreSQL stores it, or `None` for
/// `PUBLIC` and a MySQL user and host.
pub(crate) fn grantee_role(grantee: &Grantee) -> Option<Cow<'_, str>> {
    match &grantee.name {
        Some(GranteeName::ObjectName(name)) => name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .map(|ident| normalize_identifier(&ident.value, ident.quote_style.is_some())),
        Some(GranteeName::UserHost { .. }) | None => None,
    }
}

/// Whether the grantee names one of `roles`.
pub(crate) fn grantee_names(grantee: &Grantee, roles: &BTreeSet<String>) -> bool {
    grantee_role(grantee).is_some_and(|role| roles.contains(role.as_ref()))
}

/// Whether the grant reaches `PUBLIC` or names one of `roles`.
pub(crate) fn reaches_any<DB: DatabaseLike>(
    database: &DB,
    grant: &impl GrantLike<DB = DB>,
    roles: &BTreeSet<String>,
) -> bool {
    grant.applies_to_public() || names_any(database, grant, roles)
}

/// The schema a relation sits in: its own, or the one an unqualified creation
/// puts it in, which is `main` under SQLite and the first schema on the search
/// path under PostgreSQL.
pub(crate) fn schema_of<'a, DB: DatabaseLike>(
    database: &'a DB,
    schema: Option<Cow<'a, str>>,
) -> Cow<'a, str> {
    schema.unwrap_or_else(|| match Engine::of(database) {
        Engine::Sqlite => Cow::Borrowed("main"),
        Engine::PostgreSql => database
            .search_path()
            .next()
            .map_or_else(Cow::default, |(name, quoted)| {
                normalize_identifier(name, quoted)
            }),
    })
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

/// Whether the deployment declares `table` subscribed.
pub(crate) fn is_subscribed<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    table: &DB::Table,
) -> bool {
    deployment.is_subscribed(
        &schema_of(database, table.stored_table_schema()),
        &table.stored_table_name(),
    )
}

/// The column of `table` the deployment declares as its tenant key.
pub(crate) fn tenant_column<'db, DB: DatabaseLike>(
    database: &'db DB,
    deployment: &Deployment,
    table: &'db DB::Table,
) -> Result<Option<&'db DB::Column>, LookupError> {
    let schema = schema_of(database, table.stored_table_schema());
    let Some(key) = deployment.tenant_key(&schema, &table.stored_table_name()) else {
        return Ok(None);
    };
    Ok(table
        .columns(database)?
        .find(|column| column.stored_column_name() == key))
}

/// Whether the deployment selects `table` for binary replication, by its own
/// name or through a partitioned table above it, which a publication naming it
/// publishes along with every partition below.
pub(crate) fn is_binary_replicated<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    table: &DB::Table,
) -> Result<bool, LookupError> {
    let mut current = Some(table);
    while let Some(candidate) = current {
        if deployment.is_binary_replicated(
            &schema_of(database, candidate.stored_table_schema()),
            &candidate.stored_table_name(),
        ) {
            return Ok(true);
        }
        current = candidate.partition_root(database)?;
    }
    Ok(false)
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
