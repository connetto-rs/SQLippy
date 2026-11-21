//! Declarations describing how a deployment connects to its database, which
//! the row-level security rules read and never guess.

use std::{
    fmt::{self, Display},
    time::Duration,
};

use sql_traits::{prelude::ParserDB, traits::DatabaseLike};
use sqlparser::{
    ast::Expr,
    dialect::PostgreSqlDialect,
    parser::{Parser, ParserError},
};

use crate::vocabulary::Vocabulary;

mod cluster;
pub(crate) use cluster::{ClusterBootstrap, Membership, RoleAttributes};

/// Roles and schemas of the deployment a schema serves.
///
/// Role and schema names are compared with the names PostgreSQL stores, so an
/// unquoted name is written in lowercase. `PUBLIC` is always an anonymous role
/// and needs no declaration.
///
/// A list-valued fact, such as the app roles, is undeclared until one of its
/// entries is declared or its `without_` method declares it has none, and a
/// rule reading an undeclared fact does not run.
///
/// # Example
///
/// ```
/// use sqlippy::prelude::*;
///
/// let supabase = Deployment::default()
///     .with_anonymous_role("anon")
///     .with_app_role("authenticated")
///     .with_exposed_schema("public");
/// assert!(supabase.declares(Declaration::AppRoles));
/// assert!(!Deployment::default().declares(Declaration::AppRoles));
/// assert!(Deployment::default().without_app_roles().declares(Declaration::AppRoles));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Deployment {
    anonymous_roles: Fact<String>,
    app_roles: Fact<String>,
    exposed_schemas: Vec<String>,
    credentials: Fact<Expr>,
    request_settings: Vec<Expr>,
    sets_within: Vec<(Expr, Expr)>,
    client_written_tables: Vec<(String, String)>,
    binary_replication_tables: Fact<(String, String)>,
    binary_replication_all_tables: bool,
    self_asserted_claims: Fact<Expr>,
    self_asserted_columns: Fact<StoredColumn>,
    tenant_keys: Fact<StoredColumn>,
    irreversible_columns: Fact<StoredColumn>,
    audit_functions: Fact<AuditFunction>,
    pooled: Option<bool>,
    clock_tolerance: Option<Duration>,
    vocabularies: Vec<Vocabulary>,
    cluster_bootstrap: Option<ClusterBootstrap>,
}

/// The entries of a list-valued fact, undeclared until an entry or the
/// absence of any is declared.
#[derive(Debug, Clone)]
struct Fact<T>(Option<Vec<T>>);

impl<T> Default for Fact<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T> Fact<T> {
    fn push(&mut self, entry: T) {
        self.0.get_or_insert_default().push(entry);
    }

    /// Declares that the fact has no entry, dropping any declared before.
    fn declare_none(&mut self) {
        self.0 = Some(Vec::new());
    }

    fn is_declared(&self) -> bool {
        self.0.is_some()
    }

    fn entries(&self) -> &[T] {
        self.0.as_deref().unwrap_or_default()
    }
}

/// A column, by the stored names of its schema, table and column.
#[derive(Debug, Clone)]
struct StoredColumn {
    schema: String,
    table: String,
    column: String,
}

impl StoredColumn {
    fn new(schema: impl Into<String>, table: impl Into<String>, column: impl Into<String>) -> Self {
        Self {
            schema: schema.into(),
            table: table.into(),
            column: column.into(),
        }
    }

    fn names(&self) -> (&str, &str, &str) {
        (&self.schema, &self.table, &self.column)
    }
}

/// A trigger function that records the writes to the tables it is attached
/// to, by stored names.
#[derive(Debug, Clone)]
struct AuditFunction {
    schema: String,
    function: String,
    events: Vec<WriteEvent>,
}

/// A command that writes rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriteEvent {
    /// `INSERT`.
    Insert,
    /// `UPDATE`.
    Update,
    /// `DELETE`.
    Delete,
}

/// Parses one PostgreSQL expression.
fn parse_expression(expression: &str) -> Result<Expr, ParserError> {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(expression)?
        .parse_expr()
}

impl Deployment {
    /// The deployment every [`RuleExample`](crate::lint::RuleExample) is
    /// written for, a pooled API serving the `public` schema to the
    /// anonymous role `anon` and the app role `authenticated`, which a
    /// cluster bootstrap creates with `NOLOGIN`, naming the caller with
    /// `current_setting('app.user_id', true)`, selecting the acting
    /// installation with `current_setting('app.installation_id', true)`,
    /// trusting no `current_setting('app.user_metadata', true)` claim, and
    /// taking the rows of `public.drafts` from clients that author them
    /// offline, and streaming `public.events` over binary logical
    /// replication. Its tenants are keyed by `organization_id` in
    /// `public.resources` and `public.caps`, a token's `public.tokens.revoked_at`
    /// is never cleared, and `public.record_authority` audits every write.
    ///
    /// # Panics
    ///
    /// Never panics, since the declared expressions and the bootstrap are
    /// fixed PostgreSQL.
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    ///
    /// let deployment = Deployment::example();
    /// assert!(deployment.is_pooled());
    /// assert!(deployment.is_client_written("public", "drafts"));
    /// assert!(deployment.is_binary_replicated("public", "events"));
    /// assert_eq!(deployment.tenant_key("public", "caps"), Some("organization_id"));
    /// ```
    #[must_use]
    pub fn example() -> Self {
        Self::default()
            .with_anonymous_role("anon")
            .with_app_role("authenticated")
            .with_exposed_schema("public")
            .with_pooled(true)
            .with_client_written_table("public", "drafts")
            .with_binary_replication_table("public", "events")
            .with_tenant_key("public", "resources", "organization_id")
            .with_tenant_key("public", "caps", "organization_id")
            .with_irreversible_column("public", "tokens", "revoked_at")
            .with_audit_function(
                "public",
                "record_authority",
                [WriteEvent::Insert, WriteEvent::Update, WriteEvent::Delete],
            )
            .with_credential("current_setting('app.user_id', true)")
            .and_then(|deployment| {
                deployment.with_request_setting("current_setting('app.installation_id', true)")
            })
            .and_then(|deployment| {
                deployment.with_self_asserted_claim("current_setting('app.user_metadata', true)")
            })
            .expect("the example's expressions are PostgreSQL")
            .with_cluster_bootstrap(
                &ParserDB::parse::<PostgreSqlDialect>(
                    "CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN;",
                )
                .expect("the example's bootstrap is PostgreSQL"),
            )
    }

    /// Declares a role that callers holding no credential act as.
    #[must_use]
    pub fn with_anonymous_role(mut self, role: impl Into<String>) -> Self {
        self.anonymous_roles.push(role.into());
        self
    }

    /// Declares that no role besides `PUBLIC` serves callers holding no
    /// credential, dropping any anonymous role declared before.
    #[must_use]
    pub fn without_anonymous_roles(mut self) -> Self {
        self.anonymous_roles.declare_none();
        self
    }

    /// Declares a role the application connects as or switches to for its
    /// callers.
    #[must_use]
    pub fn with_app_role(mut self, role: impl Into<String>) -> Self {
        self.app_roles.push(role.into());
        self
    }

    /// Declares that the application has no role of its own, dropping any app
    /// role declared before.
    #[must_use]
    pub fn without_app_roles(mut self) -> Self {
        self.app_roles.declare_none();
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

    /// Declares how far ahead of the database's clock the clocks stamping
    /// rows may run, such as the devices of a client that authors rows
    /// offline.
    #[must_use]
    pub fn with_clock_tolerance(mut self, tolerance: Duration) -> Self {
        self.clock_tolerance = Some(tolerance);
        self
    }

    /// Returns the declared clock tolerance.
    #[must_use]
    pub fn clock_tolerance(&self) -> Option<Duration> {
        self.clock_tolerance
    }

    /// Declares the cluster bootstrap, the script provisioning the roles
    /// every database of the cluster shares, from a database built from
    /// that script alone. The roles it creates with their attributes, the
    /// memberships it grants and the role settings it makes are the
    /// cluster's, replacing any bootstrap declared before.
    ///
    /// A schema checked under this declaration is the bootstrap followed by
    /// the database-local schema, so the rules resolving roles see the
    /// cluster's roles.
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let bootstrap = "CREATE ROLE app NOLOGIN;";
    /// let cluster = ParserDB::parse::<PostgreSqlDialect>(bootstrap).unwrap();
    /// let deployment = Deployment::default().with_cluster_bootstrap(&cluster);
    /// assert!(deployment.declares(Declaration::ClusterBootstrap));
    /// ```
    #[must_use]
    pub fn with_cluster_bootstrap<DB: DatabaseLike>(mut self, cluster: &DB) -> Self {
        self.cluster_bootstrap = Some(ClusterBootstrap::of(cluster));
        self
    }

    /// Returns what the declared cluster bootstrap provisions, nothing when
    /// none is declared.
    pub(crate) fn cluster_bootstrap(&self) -> &ClusterBootstrap {
        static UNDECLARED: ClusterBootstrap = ClusterBootstrap::EMPTY;
        self.cluster_bootstrap.as_ref().unwrap_or(&UNDECLARED)
    }

    /// Selects a vocabulary the rules reading column names match against,
    /// beside any selected before. English applies only while none is
    /// selected.
    #[must_use]
    pub fn with_vocabulary(mut self, vocabulary: Vocabulary) -> Self {
        self.vocabularies.push(vocabulary);
        self
    }

    /// Returns the selected vocabularies, or English when none is selected.
    #[must_use]
    pub fn vocabularies(&self) -> &[Vocabulary] {
        if self.vocabularies.is_empty() {
            std::slice::from_ref(Vocabulary::english_default())
        } else {
            &self.vocabularies
        }
    }

    /// Returns the declared anonymous roles, `PUBLIC` excluded.
    pub fn anonymous_roles(&self) -> impl Iterator<Item = &str> {
        self.anonymous_roles.entries().iter().map(String::as_str)
    }

    /// Returns the declared app roles.
    pub fn app_roles(&self) -> impl Iterator<Item = &str> {
        self.app_roles.entries().iter().map(String::as_str)
    }

    /// Returns whether a client API serves the schema directly.
    #[must_use]
    pub fn exposes_schema(&self, schema: &str) -> bool {
        self.exposed_schemas.iter().any(|exposed| exposed == schema)
    }

    /// Declares a table whose rows clients author in a local replica and
    /// push later, by the stored names of its schema and table. A SQLite table
    /// created without a database name sits in `main`.
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

    /// Selects a binary-replicated table by its stored schema and table names.
    ///
    /// A partitioned table selects every partition below it, as a publication
    /// naming it publishes them.
    #[must_use]
    pub fn with_binary_replication_table(
        mut self,
        schema: impl Into<String>,
        table: impl Into<String>,
    ) -> Self {
        self.binary_replication_tables
            .push((schema.into(), table.into()));
        self
    }

    /// Selects every table for binary replication checks.
    #[must_use]
    pub fn with_binary_replication_all_tables(mut self) -> Self {
        self.binary_replication_all_tables = true;
        self
    }

    /// Declares that no table is binary-replicated, dropping any selection
    /// made before.
    #[must_use]
    pub fn without_binary_replication_tables(mut self) -> Self {
        self.binary_replication_tables.declare_none();
        self.binary_replication_all_tables = false;
        self
    }

    /// Returns whether the stored schema and table names select a binary-replicated table.
    #[must_use]
    pub fn is_binary_replicated(&self, schema: &str, table: &str) -> bool {
        self.binary_replication_all_tables
            || self.binary_replication_tables.entries().iter().any(
                |(selected_schema, selected_table)| {
                    selected_schema == schema && selected_table == table
                },
            )
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

    /// Declares that nothing identifies the caller, dropping any credential
    /// declared before.
    #[must_use]
    pub fn without_credentials(mut self) -> Self {
        self.credentials.declare_none();
        self
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

    /// Declares that the caller sets no claim or column a policy may read,
    /// dropping any self-asserted claim or column declared before.
    #[must_use]
    pub fn without_self_asserted_sources(mut self) -> Self {
        self.self_asserted_claims.declare_none();
        self.self_asserted_columns.declare_none();
        self
    }

    /// Returns whether `expression` is a declared self-asserted claim, as
    /// written.
    #[must_use]
    pub fn is_self_asserted_claim(&self, expression: &Expr) -> bool {
        self.self_asserted_claims.entries().contains(expression)
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
        self.self_asserted_columns
            .push(StoredColumn::new(schema, table, column));
        self
    }

    /// Returns the declared self-asserted columns as stored schema, table and
    /// column names.
    pub fn self_asserted_columns(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.self_asserted_columns
            .entries()
            .iter()
            .map(StoredColumn::names)
    }

    /// Declares an expression reading a setting that selects what a request
    /// acts on without identifying the caller, such as
    /// `current_setting('app.installation_id', true)` naming the acting
    /// installation.
    ///
    /// The expression is matched as written, like a credential, and the
    /// rules reading credentials do not take it for one.
    ///
    /// # Errors
    ///
    /// Returns the parser error when `expression` is not one PostgreSQL SQL
    /// expression.
    pub fn with_request_setting(mut self, expression: &str) -> Result<Self, ParserError> {
        self.request_settings.push(parse_expression(expression)?);
        Ok(self)
    }

    /// Returns whether `expression` is a declared request setting, as
    /// written.
    #[must_use]
    pub fn is_request_setting(&self, expression: &Expr) -> bool {
        self.request_settings.contains(expression)
    }

    /// Declares the column holding the tenant a table's rows belong to, by
    /// the stored names of its schema, table and column. Rows of two tables
    /// belong to the same tenant when their tenant keys are equal.
    #[must_use]
    pub fn with_tenant_key(
        mut self,
        schema: impl Into<String>,
        table: impl Into<String>,
        column: impl Into<String>,
    ) -> Self {
        self.tenant_keys
            .push(StoredColumn::new(schema, table, column));
        self
    }

    /// Declares that no table belongs to a tenant, dropping any tenant key
    /// declared before.
    #[must_use]
    pub fn without_tenant_keys(mut self) -> Self {
        self.tenant_keys.declare_none();
        self
    }

    /// Returns the stored name of the declared tenant key of the table with
    /// these stored schema and table names.
    #[must_use]
    pub fn tenant_key(&self, schema: &str, table: &str) -> Option<&str> {
        self.tenant_keys
            .entries()
            .iter()
            .find(|key| key.schema == schema && key.table == table)
            .map(|key| key.column.as_str())
    }

    /// Declares a column whose value, once set, is never cleared back to
    /// `NULL`, such as the `revoked_at` of a revocation that is permanent, by
    /// the stored names of its schema, table and column.
    #[must_use]
    pub fn with_irreversible_column(
        mut self,
        schema: impl Into<String>,
        table: impl Into<String>,
        column: impl Into<String>,
    ) -> Self {
        self.irreversible_columns
            .push(StoredColumn::new(schema, table, column));
        self
    }

    /// Declares that every column may be cleared back to `NULL`, dropping any
    /// irreversible column declared before.
    #[must_use]
    pub fn without_irreversible_columns(mut self) -> Self {
        self.irreversible_columns.declare_none();
        self
    }

    /// Returns the declared irreversible columns as stored schema, table and
    /// column names.
    pub fn irreversible_columns(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.irreversible_columns
            .entries()
            .iter()
            .map(StoredColumn::names)
    }

    /// Declares a trigger function that records the `events` written to the
    /// tables carrying it, by the stored names of its schema and function.
    #[must_use]
    pub fn with_audit_function(
        mut self,
        schema: impl Into<String>,
        function: impl Into<String>,
        events: impl IntoIterator<Item = WriteEvent>,
    ) -> Self {
        self.audit_functions.push(AuditFunction {
            schema: schema.into(),
            function: function.into(),
            events: events.into_iter().collect(),
        });
        self
    }

    /// Declares that no trigger function records writes, dropping any audit
    /// function declared before.
    #[must_use]
    pub fn without_audit_functions(mut self) -> Self {
        self.audit_functions.declare_none();
        self
    }

    /// Returns the declared audit functions as stored schema and function
    /// names with the events each records.
    pub fn audit_functions(&self) -> impl Iterator<Item = (&str, &str, &[WriteEvent])> {
        self.audit_functions.entries().iter().map(|audit| {
            (
                audit.schema.as_str(),
                audit.function.as_str(),
                audit.events.as_slice(),
            )
        })
    }

    /// Declares that every value the expression `narrower` yields is also one
    /// `wider` yields, such as `authz.resources_with('writer')` within
    /// `authz.resources_with('reader')` where every writer of a resource may
    /// read it. The declarations compose, and identical expressions need
    /// none.
    ///
    /// The expressions are matched as written, as the operand of `=` or the
    /// projection of the subquery a policy compares a column with through
    /// `IN` or `= ANY (ARRAY(...))`.
    ///
    /// # Errors
    ///
    /// Returns the parser error when either expression is not one PostgreSQL
    /// SQL expression.
    pub fn with_set_within(mut self, narrower: &str, wider: &str) -> Result<Self, ParserError> {
        self.sets_within
            .push((parse_expression(narrower)?, parse_expression(wider)?));
        Ok(self)
    }

    /// Returns whether every value `narrower` yields is one `wider` yields,
    /// as written, through identical expressions or the declared sets.
    #[must_use]
    pub fn is_set_within(&self, narrower: &Expr, wider: &Expr) -> bool {
        let mut reached = vec![narrower];
        let mut next = 0;
        while let Some(&set) = reached.get(next) {
            if set == wider {
                return true;
            }
            for (inner, outer) in &self.sets_within {
                if inner == set && !reached.contains(&outer) {
                    reached.push(outer);
                }
            }
            next += 1;
        }
        false
    }

    /// Returns whether `expression` is a declared credential, as written.
    #[must_use]
    pub fn is_credential(&self, expression: &Expr) -> bool {
        self.credentials.entries().contains(expression)
    }

    /// Returns the declared credential expressions.
    pub(crate) fn credentials(&self) -> &[Expr] {
        self.credentials.entries()
    }

    /// Returns whether the deployment makes the given declaration.
    #[must_use]
    pub fn declares(&self, declaration: Declaration) -> bool {
        match declaration {
            Declaration::AppRoles => self.app_roles.is_declared(),
            Declaration::ClientRoles => {
                self.anonymous_roles.is_declared() || self.app_roles.is_declared()
            }
            Declaration::Credentials => self.credentials.is_declared(),
            Declaration::SelfAssertedSources => {
                self.self_asserted_claims.is_declared() || self.self_asserted_columns.is_declared()
            }
            Declaration::TenantKeys => self.tenant_keys.is_declared(),
            Declaration::IrreversibleColumns => self.irreversible_columns.is_declared(),
            Declaration::AuditFunctions => self.audit_functions.is_declared(),
            Declaration::Pooled => self.pooled.is_some(),
            Declaration::BinaryReplicationTables => {
                self.binary_replication_all_tables || self.binary_replication_tables.is_declared()
            }
            Declaration::ClusterBootstrap => self.cluster_bootstrap.is_some(),
        }
    }
}

/// A part of a [`Deployment`] a rule cannot run without.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Declaration {
    /// The app roles, which may be none.
    AppRoles,
    /// The anonymous roles besides `PUBLIC` or the app roles, which may be
    /// none.
    ClientRoles,
    /// The credential expressions, which may be none.
    Credentials,
    /// The self-asserted claims or columns, which may be none.
    SelfAssertedSources,
    /// The tenant keys, which may be none.
    TenantKeys,
    /// The irreversible columns, which may be none.
    IrreversibleColumns,
    /// The audit functions, which may be none.
    AuditFunctions,
    /// Whether the deployment is pooled.
    Pooled,
    /// The binary-replicated tables, which may be none.
    BinaryReplicationTables,
    /// The cluster bootstrap provisioning the roles databases share.
    ClusterBootstrap,
}

impl Display for Declaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AppRoles => "app roles",
            Self::ClientRoles => "anonymous or app roles",
            Self::Credentials => "credential expressions",
            Self::SelfAssertedSources => "self-asserted claims or columns",
            Self::TenantKeys => "tenant keys",
            Self::IrreversibleColumns => "irreversible columns",
            Self::AuditFunctions => "audit functions",
            Self::Pooled => "whether it is pooled",
            Self::BinaryReplicationTables => "binary-replicated tables",
            Self::ClusterBootstrap => "its cluster bootstrap",
        })
    }
}
