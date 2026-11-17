//! The roles a cluster bootstrap provisions, recorded so the rules can tell
//! them from the role changes a database-local schema makes.

use sql_traits::{
    structs::RoleSetting,
    traits::{DatabaseLike, RoleLike, RoleMembershipLike},
};

/// The `CREATE ROLE` keywords of the boolean role attributes, in the order
/// [`RoleAttributes`] holds them.
const FLAG_KEYWORDS: [&str; 7] = [
    "SUPERUSER",
    "CREATEDB",
    "CREATEROLE",
    "INHERIT",
    "LOGIN",
    "BYPASSRLS",
    "REPLICATION",
];

/// The attributes `CREATE ROLE` and `ALTER ROLE` set on a role.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RoleAttributes {
    /// Whether the role holds each attribute [`FLAG_KEYWORDS`] names.
    flags: [bool; FLAG_KEYWORDS.len()],
    connection_limit: Option<i32>,
}

impl RoleAttributes {
    /// The attributes `role` holds.
    pub(crate) fn of<R: RoleLike>(role: &R) -> Self {
        Self {
            flags: [
                role.is_superuser(),
                role.can_create_db(),
                role.can_create_role(),
                role.inherits(),
                role.can_login(),
                role.can_bypass_rls(),
                role.is_replication(),
            ],
            connection_limit: role.connection_limit(),
        }
    }

    /// The attribute clauses that give a role holding `bootstrap` the
    /// attributes in `self`, spelled as `ALTER ROLE` takes them.
    pub(crate) fn clauses_from(self, bootstrap: Self) -> Vec<String> {
        let mut clauses: Vec<String> = FLAG_KEYWORDS
            .into_iter()
            .zip(self.flags.into_iter().zip(bootstrap.flags))
            .filter(|(_, (held, provisioned))| held != provisioned)
            .map(|(keyword, (held, _))| {
                if held {
                    keyword.to_owned()
                } else {
                    format!("NO{keyword}")
                }
            })
            .collect();
        if self.connection_limit != bootstrap.connection_limit {
            clauses.push(format!(
                "CONNECTION LIMIT {}",
                self.connection_limit.unwrap_or(-1)
            ));
        }
        clauses
    }
}

/// A membership of one role in another with its options, by stored names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Membership {
    pub(crate) role: String,
    pub(crate) member: String,
    admin: bool,
    inherit: bool,
    set: bool,
}

impl Membership {
    /// The membership `membership` grants.
    pub(crate) fn of<M: RoleMembershipLike>(membership: &M) -> Self {
        Self {
            role: membership.stored_role_name().into_owned(),
            member: membership.stored_member_name().into_owned(),
            admin: membership.admin_option(),
            inherit: membership.inherit_option(),
            set: membership.set_option(),
        }
    }

    /// Whether both memberships make the same member a member of the same
    /// role, whatever their options.
    pub(crate) fn joins_same_roles(&self, other: &Self) -> bool {
        self.role == other.role && self.member == other.member
    }
}

/// The roles, memberships and role settings a cluster bootstrap provisions.
#[derive(Debug, Clone)]
pub(crate) struct ClusterBootstrap {
    roles: Vec<(String, RoleAttributes)>,
    memberships: Vec<Membership>,
    settings: Vec<RoleSetting>,
}

impl ClusterBootstrap {
    /// The bootstrap of an undeclared cluster, provisioning nothing.
    pub(crate) const EMPTY: Self = Self {
        roles: Vec::new(),
        memberships: Vec::new(),
        settings: Vec::new(),
    };

    /// Records what `cluster`, a database built from the bootstrap alone,
    /// holds.
    pub(crate) fn of<DB: DatabaseLike>(cluster: &DB) -> Self {
        Self {
            roles: cluster
                .roles()
                .map(|role| (role.stored_name().into_owned(), RoleAttributes::of(role)))
                .collect(),
            memberships: cluster.role_memberships().map(Membership::of).collect(),
            settings: cluster.role_settings().cloned().collect(),
        }
    }

    /// The attributes the bootstrap gives the role stored as `name`, or
    /// [`None`] when it does not create that role.
    pub(crate) fn role(&self, name: &str) -> Option<RoleAttributes> {
        self.roles
            .iter()
            .find_map(|(role, attributes)| (role == name).then_some(*attributes))
    }

    /// The memberships the bootstrap grants.
    pub(crate) fn memberships(&self) -> &[Membership] {
        &self.memberships
    }

    /// The role settings the bootstrap makes.
    pub(crate) fn settings(&self) -> &[RoleSetting] {
        &self.settings
    }
}
