//! Declarations describing how a deployment connects to its database, which
//! the row-level security rules read and never guess.

use std::fmt::{self, Display};

use sqlparser::{
    ast::Expr,
    dialect::PostgreSqlDialect,
    parser::{Parser, ParserError},
};

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
    credentials: Vec<Expr>,
    pooled: Option<bool>,
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

    /// Declares whether every caller shares one database role, so the role
    /// does not identify the caller.
    #[must_use]
    pub fn with_pooled(mut self, pooled: bool) -> Self {
        self.pooled = Some(pooled);
        self
    }

    /// Returns whether the deployment is declared pooled.
    #[must_use]
    pub fn is_pooled(&self) -> bool {
        self.pooled == Some(true)
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

    /// Declares an expression that identifies the caller, such as
    /// `current_setting('app.user_id', true)` or `auth.uid()`, which reads
    /// `NULL` for a caller holding no credential.
    ///
    /// The expression is matched as written, so a policy must spell it the
    /// same way, and a deployment whose credential can read `''` declares it
    /// wrapped in `NULLIF(..., '')`.
    ///
    /// # Errors
    ///
    /// Returns the parser error when `expression` is not one PostgreSQL SQL
    /// expression.
    pub fn with_credential(mut self, expression: &str) -> Result<Self, ParserError> {
        let parsed = Parser::new(&PostgreSqlDialect {})
            .try_with_sql(expression)?
            .parse_expr()?;
        self.credentials.push(parsed);
        Ok(self)
    }

    /// Returns whether `expression` is a declared credential, as written.
    #[must_use]
    pub fn is_credential(&self, expression: &Expr) -> bool {
        self.credentials.contains(expression)
    }

    /// Returns whether the deployment makes the given declaration.
    #[must_use]
    pub fn declares(&self, declaration: Declaration) -> bool {
        match declaration {
            Declaration::AppRoles => !self.app_roles.is_empty(),
            Declaration::ClientRoles => {
                !self.anonymous_roles.is_empty() || !self.app_roles.is_empty()
            }
            Declaration::Credentials => !self.credentials.is_empty(),
            Declaration::Pooled => self.pooled.is_some(),
        }
    }
}

/// A part of a [`Deployment`] a rule cannot run without.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Declaration {
    /// At least one app role.
    AppRoles,
    /// At least one anonymous or app role besides `PUBLIC`.
    ClientRoles,
    /// At least one credential expression.
    Credentials,
    /// Whether the deployment is pooled.
    Pooled,
}

impl Display for Declaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AppRoles => "app roles",
            Self::ClientRoles => "anonymous or app roles",
            Self::Credentials => "credential expressions",
            Self::Pooled => "whether it is pooled",
        })
    }
}
