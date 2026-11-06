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
    client_written_tables: Vec<(String, String)>,
    self_asserted_claims: Vec<Expr>,
    self_asserted_columns: Vec<SelfAssertedColumn>,
    pooled: Option<bool>,
}

/// A column whose value its row's subject sets, by stored names.
#[derive(Debug, Clone)]
struct SelfAssertedColumn {
    schema: String,
    table: String,
    column: String,
}

/// Parses one PostgreSQL expression.
fn parse_expression(expression: &str) -> Result<Expr, ParserError> {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(expression)?
        .parse_expr()
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

    /// Declares a table whose rows clients author in a local replica and
    /// push later, by the stored names of its schema and table.
    #[must_use]
    pub fn with_client_written_table(
        mut self,
        schema: impl Into<String>,
        table: impl Into<String>,
    ) -> Self {
        self.client_written_tables
            .push((schema.into(), table.into()));
        self
    }

    /// Returns whether clients author the rows of the table with these
    /// stored schema and table names.
    #[must_use]
    pub fn is_client_written(&self, schema: &str, table: &str) -> bool {
        self.client_written_tables
            .iter()
            .any(|(written_schema, written_table)| {
                written_schema == schema && written_table == table
            })
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
        self.credentials.push(parse_expression(expression)?);
        Ok(self)
    }

    /// Declares an expression reading a claim the caller can set, such as
    /// `auth.jwt() -> 'user_metadata'` where end users edit their own
    /// metadata.
    ///
    /// The expression is matched as written, also inside a longer path such
    /// as `auth.jwt() -> 'user_metadata' ->> 'role'`, so each spelling a
    /// policy may use is declared.
    ///
    /// # Errors
    ///
    /// Returns the parser error when `expression` is not one PostgreSQL SQL
    /// expression.
    pub fn with_self_asserted_claim(mut self, expression: &str) -> Result<Self, ParserError> {
        self.self_asserted_claims
            .push(parse_expression(expression)?);
        Ok(self)
    }

    /// Returns whether `expression` is a declared self-asserted claim, as
    /// written.
    #[must_use]
    pub fn is_self_asserted_claim(&self, expression: &Expr) -> bool {
        self.self_asserted_claims.contains(expression)
    }

    /// Declares a column whose value the subject of its row sets, by the
    /// stored names of its schema, table and column, such as `auth`, `users`
    /// and `raw_user_meta_data`.
    ///
    /// The table must be part of the schema the rules read, since a column of
    /// an unknown table cannot be told apart from another.
    #[must_use]
    pub fn with_self_asserted_column(
        mut self,
        schema: impl Into<String>,
        table: impl Into<String>,
        column: impl Into<String>,
    ) -> Self {
        self.self_asserted_columns.push(SelfAssertedColumn {
            schema: schema.into(),
            table: table.into(),
            column: column.into(),
        });
        self
    }

    /// Returns the declared self-asserted columns as stored schema, table and
    /// column names.
    pub fn self_asserted_columns(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.self_asserted_columns.iter().map(|column| {
            (
                column.schema.as_str(),
                column.table.as_str(),
                column.column.as_str(),
            )
        })
    }

    /// Returns whether `expression` is a declared credential, as written.
    #[must_use]
    pub fn is_credential(&self, expression: &Expr) -> bool {
        self.credentials.contains(expression)
    }

    /// Returns the declared credential expressions.
    pub(crate) fn credentials(&self) -> &[Expr] {
        &self.credentials
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
            Declaration::SelfAssertedSources => {
                !self.self_asserted_claims.is_empty() || !self.self_asserted_columns.is_empty()
            }
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
    /// At least one self-asserted claim or column.
    SelfAssertedSources,
    /// Whether the deployment is pooled.
    Pooled,
}

impl Display for Declaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AppRoles => "app roles",
            Self::ClientRoles => "anonymous or app roles",
            Self::Credentials => "credential expressions",
            Self::SelfAssertedSources => "self-asserted claims or columns",
            Self::Pooled => "whether it is pooled",
        })
    }
}
