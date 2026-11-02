//! Declarations describing how a deployment connects to its database, which
//! the row-level security rules read and never guess.

use std::fmt::{self, Display};

/// Roles and schemas of the deployment a schema serves.
///
/// Role and schema names are compared with the names PostgreSQL stores, so an
/// unquoted name is written in lowercase. `PUBLIC` is always an anonymous role
/// and needs no declaration.
///
/// # Example
///
/// ```
/// use sql_rules::prelude::*;
///
/// let supabase = Deployment::default()
///     .with_anonymous_role("anon")
///     .with_app_role("authenticated")
///     .with_exposed_schema("public");
/// assert!(supabase.declares(Declaration::AppRoles));
/// assert!(!Deployment::default().declares(Declaration::AppRoles));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Deployment {
    anonymous_roles: Vec<String>,
    app_roles: Vec<String>,
    exposed_schemas: Vec<String>,
}

impl Deployment {
    /// Declares a role that callers holding no credential act as.
    #[must_use]
    pub fn with_anonymous_role(mut self, role: impl Into<String>) -> Self {
        self.anonymous_roles.push(role.into());
        self
    }

    /// Declares a role the application connects as or switches to for its
    /// callers.
    #[must_use]
    pub fn with_app_role(mut self, role: impl Into<String>) -> Self {
        self.app_roles.push(role.into());
        self
    }

    /// Declares a schema a client API serves directly.
    #[must_use]
    pub fn with_exposed_schema(mut self, schema: impl Into<String>) -> Self {
        self.exposed_schemas.push(schema.into());
        self
    }

    /// Returns the declared anonymous roles, `PUBLIC` excluded.
    pub fn anonymous_roles(&self) -> impl Iterator<Item = &str> {
        self.anonymous_roles.iter().map(String::as_str)
    }

    /// Returns the declared app roles.
    pub fn app_roles(&self) -> impl Iterator<Item = &str> {
        self.app_roles.iter().map(String::as_str)
    }

    /// Returns whether a client API serves the schema directly.
    #[must_use]
    pub fn exposes_schema(&self, schema: &str) -> bool {
        self.exposed_schemas.iter().any(|exposed| exposed == schema)
    }

    /// Returns whether the deployment makes the given declaration.
    #[must_use]
    pub fn declares(&self, declaration: Declaration) -> bool {
        match declaration {
            Declaration::AppRoles => !self.app_roles.is_empty(),
        }
    }
}

/// A part of a [`Deployment`] a rule cannot run without.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Declaration {
    /// At least one app role.
    AppRoles,
}

impl Display for Declaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AppRoles => "app roles",
        })
    }
}
