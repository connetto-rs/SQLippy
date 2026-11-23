//! Submodule providing the rules on objects a client role reaches: definer
//! functions, extensions, sequences, row-filtering, owner-rights and
//! materialized views.

use std::{borrow::Cow, cell::LazyCell};

use sql_traits::{
    structs::{DefaultGrantee, DefaultPrivilegeKind},
    traits::{
        ColumnGrantLike, DataStatementLike, DatabaseLike, ExtensionLike, FunctionLike, Relation,
        SequenceLike, TableGrantLike, TableLike, ViewLike,
    },
};
use sqlparser::ast::{Action, FunctionSecurity, SetExpr};

use crate::{
    deployment::Deployment,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::grant_support::{
        ClientRoles, function_callers, grantee_list, grants_privilege, schema_of,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

/// The reasons a client role reaches a relation: an exposed schema, or a
/// table or column grant reaching a client role with a privilege `wanted`
/// accepts.
fn reach_reasons<DB: DatabaseLike>(
    database: &DB,
    deployment: &Deployment,
    schema: &str,
    reaches: impl Fn(&Relation<'_, DB>) -> bool,
    wanted: impl Fn(&Action) -> bool,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if deployment.exposes_schema(schema) {
        reasons.push(format!("sits in the exposed schema '{schema}'"));
    }
    let roles = LazyCell::new(|| ClientRoles::new(database, deployment));
    for grant in database.table_grants() {
        if grant.relations(database).any(|relation| reaches(&relation))
            && grants_privilege(database, grant, &wanted)
            && roles.reach_client(database, grant)
        {
            reasons.push(format!("is granted to {}", grantee_list(database, grant)));
        }
    }
    for grant in database.column_grants() {
        if grant
            .relation(database)
            .is_some_and(|relation| reaches(&relation))
            && grants_privilege(database, grant, &wanted)
            && roles.reach_client(database, grant)
        {
            reasons.push(format!("is granted to {}", grantee_list(database, grant)));
        }
    }
    reasons
}

rule_definition!(
    /// Struct defining a rule that reports a `SECURITY DEFINER` function in
    /// an exposed schema that `PUBLIC` or a declared anonymous or app role
    /// can execute.
    ///
    /// The rule does not run on SQLite, which has no stored functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> = SecurityDefinerFunctionExposed::default().into();
    /// constrainer.set_deployment(Deployment::default().with_exposed_schema("public"));
    /// let schema = "CREATE FUNCTION bump() RETURNS INT LANGUAGE sql SECURITY DEFINER
    ///     SET search_path = pg_catalog, pg_temp AS 'SELECT 1';";
    /// let open = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    /// assert!(constrainer.validate_schema(&open).is_err());
    /// let closed = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} REVOKE EXECUTE ON FUNCTION bump() FROM PUBLIC;"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&closed).is_ok());
    /// ```
    SecurityDefinerFunctionExposed,
    register_schema_rule,
    LintGroup::Suspicious,
    "A SECURITY DEFINER function runs with its owner's privileges, so a client role that can call it in an exposed schema gets them for whatever the function does.",
    Some(
        "https://github.com/supabase/splinter/blob/main/lints/0028_anon_security_definer_function_executable.sql"
    ),
    RuleExample {
        bad: "CREATE FUNCTION bump() RETURNS INT LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS 'SELECT 1';",
        good: "CREATE FUNCTION bump() RETURNS INT LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS 'SELECT 1';\n\
REVOKE EXECUTE ON FUNCTION bump() FROM PUBLIC;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> SchemaRule for SecurityDefinerFunctionExposed<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let definers = database.functions().filter(|function| {
            function.security_mode() == FunctionSecurity::Definer
                && function.target_name().schema() != Some("pg_catalog")
        });
        for function in definers {
            let target = function.target_name();
            let schema = schema_of(database, target.schema().map(Cow::Borrowed));
            if !deployment.exposes_schema(&schema) {
                continue;
            }
            let callers = function_callers(database, deployment, function)?;
            if callers.is_empty() {
                continue;
            }
            let signature = signature(function, database);
            reporter.function_privilege(
                function,
                format!(
                    "SECURITY DEFINER function '{signature}' sits in the exposed schema '{schema}' and {} can execute it with its owner's privileges.",
                    callers.join(", ")
                ),
                format!("REVOKE EXECUTE ON FUNCTION {signature} FROM PUBLIC; and from the client roles, or move it to a schema clients do not reach."),
            )?;
        }
        Ok(())
    }
}

rule_definition!(
    /// Struct defining a rule that reports a schema holding `SECURITY
    /// DEFINER` functions whose owner's default privileges still give
    /// `PUBLIC` `EXECUTE` on the next function it creates there.
    ///
    /// The defaults read are the ones the schema leaves in place once it has
    /// run. Only the owner's default without `IN SCHEMA` takes away the
    /// built-in grant, since a default limited to a schema can only add to
    /// it. One violation is raised per schema and owner, on its first
    /// definer function.
    ///
    /// The rule does not run on SQLite, which has no default privileges.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     DefinerSchemaWithoutDefaultRevoke::default().into();
    /// let schema = "CREATE SCHEMA private;
    ///     CREATE FUNCTION private.answer() RETURNS INT LANGUAGE sql SECURITY DEFINER
    ///     SET search_path = pg_catalog, pg_temp AS 'SELECT 42';
    ///     REVOKE EXECUTE ON FUNCTION private.answer() FROM PUBLIC;";
    /// let revoked_once = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    /// assert!(constrainer.validate_schema(&revoked_once).is_err());
    /// let revoked_by_default = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC; {schema}"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&revoked_by_default).is_ok());
    /// ```
    DefinerSchemaWithoutDefaultRevoke,
    register_schema_rule,
    LintGroup::Suspicious,
    "PostgreSQL grants EXECUTE to PUBLIC on every new function unless its creator's default privileges take it away, so revoking each SECURITY DEFINER function one by one leaves the next one callable by every role.",
    Some("https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html"),
    RuleExample {
        bad: "CREATE SCHEMA private;\n\
CREATE FUNCTION private.answer() RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 42 $$;\n\
REVOKE EXECUTE ON FUNCTION private.answer() FROM PUBLIC;",
        good: "ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;\n\
CREATE SCHEMA private;\n\
CREATE FUNCTION private.answer() RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 42 $$;\n\
REVOKE EXECUTE ON FUNCTION private.answer() FROM PUBLIC;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> SchemaRule for DefinerSchemaWithoutDefaultRevoke<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut checked: Vec<(String, Option<&str>)> = Vec::new();
        let definers = database.functions().filter(|function| {
            function.security_mode() == FunctionSecurity::Definer
                && function.target_name().schema() != Some("pg_catalog")
        });
        for function in definers {
            let target = function.target_name();
            let schema = schema_of(database, target.schema().map(Cow::Borrowed)).into_owned();
            let owner = function.owner(database)?;
            if checked
                .iter()
                .any(|(seen, seen_owner)| *seen == schema && *seen_owner == owner)
            {
                continue;
            }
            if database.new_function_executable_by_public(owner, &schema) == Some(true) {
                let (creator, for_role) = owner.map_or_else(
                    || ("the role the schema runs as".to_owned(), String::new()),
                    |owner| (format!("role '{owner}'"), format!(" FOR ROLE {owner}")),
                );
                reporter.function_privilege(
                    function,
                    format!("SECURITY DEFINER functions in schema '{schema}' are created by {creator}, whose default privileges still grant EXECUTE on the next function to PUBLIC."),
                    format!("ALTER DEFAULT PRIVILEGES{for_role} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC; before creating functions, and grant EXECUTE to the intended callers."),
                )?;
            }
            checked.push((schema, owner));
        }
        Ok(())
    }
}

rule_definition!(
    /// Struct defining a rule that reports a standing default privilege
    /// granting a table or sequence privilege to `PUBLIC`.
    ///
    /// The defaults read are the ones the schema leaves in place once it has
    /// run, so a later `REVOKE` of the same default clears the report. One
    /// violation is raised per standing default.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = PublicDefaultPrivilege::default().into();
    /// let open = ParserDB::parse::<PostgreSqlDialect>(
    ///     "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&open).is_err());
    /// let explicit = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE notes (id INT PRIMARY KEY);
    ///      ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
    ///      CREATE POLICY notes_read ON notes FOR SELECT USING (true);
    ///      GRANT SELECT ON notes TO PUBLIC;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&explicit).is_ok());
    /// ```
    PublicDefaultPrivilege,
    register_schema_rule,
    LintGroup::Suspicious,
    "A default privilege granting a table or sequence privilege to PUBLIC hands every table or sequence created later to every role, a table before its author enables row-level security or writes a policy.",
    Some("https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html"),
    RuleExample {
        bad: "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC;\n\
CREATE TABLE notes (id INT PRIMARY KEY);",
        good: "CREATE TABLE notes (id INT PRIMARY KEY);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY notes_read ON notes FOR SELECT USING (true);\n\
GRANT SELECT ON notes TO PUBLIC;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> SchemaRule for PublicDefaultPrivilege<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for entry in database.default_privileges().into_iter().flatten() {
            let (objects, noun, before, explicit) = match entry.kind() {
                DefaultPrivilegeKind::Tables => (
                    "TABLES",
                    "table",
                    ", before its row-level security or policies exist",
                    "each table explicitly once its row-level security and policies exist",
                ),
                DefaultPrivilegeKind::Sequences => (
                    "SEQUENCES",
                    "sequence",
                    "",
                    "each sequence explicitly to the roles that need it",
                ),
                _ => continue,
            };
            let Some(grant) = entry
                .grant_to(&DefaultGrantee::Public)
                .filter(|grant| !grant.privileges().is_empty())
            else {
                continue;
            };
            let privileges = grant
                .privileges()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let (creator, for_role) = entry.role().map_or_else(
                || ("the role the schema runs as".to_owned(), String::new()),
                |role| (format!("role '{role}'"), format!(" FOR ROLE {role}")),
            );
            let (place, in_schema) = entry.schema().map_or_else(
                || ("any schema".to_owned(), String::new()),
                |schema| (format!("schema '{schema}'"), format!(" IN SCHEMA {schema}")),
            );
            let object = format!("DEFAULT PRIVILEGES{for_role}{in_schema} ON {objects}");
            reporter.default_privilege(
                &entry,
                object,
                format!("Default privileges grant {privileges} to PUBLIC on every {noun} {creator} creates in {place}{before}."),
                format!("ALTER DEFAULT PRIVILEGES{for_role}{in_schema} REVOKE {privileges} ON {objects} FROM PUBLIC; and grant {explicit}."),
            )?;
        }
        Ok(())
    }
}

rule_definition!(
    /// Struct defining a rule that reports an extension installed in an
    /// exposed schema. `plpgsql` is not reported.
    ///
    /// The rule does not run on SQLite, which has no schema-owned extensions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> = ExtensionInExposedSchema::default().into();
    /// constrainer.set_deployment(Deployment::default().with_exposed_schema("public"));
    /// let exposed =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE EXTENSION pgcrypto WITH SCHEMA public;").unwrap();
    /// assert!(constrainer.validate_schema(&exposed).is_err());
    /// let private = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE SCHEMA extensions; CREATE EXTENSION pgcrypto WITH SCHEMA extensions;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&private).is_ok());
    /// ```
    ExtensionInExposedSchema,
    register_schema_rule,
    LintGroup::Suspicious,
    "An extension's functions and objects in a schema clients reach widen what clients can call, and a schema on the search path trusts every role that can create objects in it.",
    Some("https://github.com/supabase/splinter/blob/main/lints/0014_extension_in_public.sql"),
    RuleExample {
        bad: "CREATE SCHEMA extensions;\n\
CREATE EXTENSION pgcrypto WITH SCHEMA public;",
        good: "CREATE SCHEMA extensions;\n\
CREATE EXTENSION pgcrypto WITH SCHEMA extensions;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> SchemaRule for ExtensionInExposedSchema<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        for extension in database.extensions() {
            let schema = schema_of(database, extension.stored_schema());
            if extension.stored_name() == "plpgsql" || !deployment.exposes_schema(&schema) {
                continue;
            }
            let name = extension.name();
            reporter.extension(
                extension,
                format!("Extension '{name}' is installed in the exposed schema '{schema}', where clients reach its objects."),
                format!("Install '{name}' in a schema of its own, such as `CREATE EXTENSION {name} WITH SCHEMA extensions`."),
            )?;
        }
        Ok(())
    }
}

rule_definition!(
    /// Struct defining a rule that reports a sequence a client role reaches,
    /// through an exposed schema or a `USAGE`, `SELECT` or `UPDATE` grant.
    /// The sequences behind serial and identity columns count too.
    ///
    /// The rule does not run on SQLite, which has no sequence objects.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ReachableSequence::default().into();
    /// let granted = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE SEQUENCE ticket_seq; GRANT USAGE ON SEQUENCE ticket_seq TO PUBLIC;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&granted).is_err());
    /// let kept = ParserDB::parse::<PostgreSqlDialect>("CREATE SEQUENCE ticket_seq;").unwrap();
    /// assert!(constrainer.validate_schema(&kept).is_ok());
    /// ```
    ReachableSequence,
    register_schema_rule,
    LintGroup::Suspicious,
    "SELECT on a sequence reveals its current value and UPDATE or USAGE lets a role advance it, so a client role can read or burn the numbers other tables draw from.",
    Some("https://www.postgresql.org/docs/current/ddl-priv.html"),
    RuleExample {
        bad: "CREATE SCHEMA private;\n\
CREATE SEQUENCE private.ticket_seq;\n\
GRANT USAGE ON SEQUENCE private.ticket_seq TO PUBLIC;",
        good: "CREATE SCHEMA private;\n\
CREATE SEQUENCE private.ticket_seq;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> SchemaRule for ReachableSequence<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        for sequence in database.sequences() {
            let schema = schema_of(database, sequence.stored_sequence_schema());
            let reasons = reach_reasons(
                database,
                deployment,
                &schema,
                |relation| matches!(relation, Relation::Sequence(granted) if *granted == sequence),
                |action| {
                    matches!(
                        action,
                        Action::Usage | Action::Select { .. } | Action::Update { .. }
                    )
                },
            );
            if reasons.is_empty() {
                continue;
            }
            let name = sequence.sequence_name();
            reporter.sequence(
                sequence,
                format!(
                    "Sequence '{name}' {}, so a client role can read or advance it.",
                    reasons.join(" and ")
                ),
                format!("Revoke the client roles' privileges on sequence '{name}' and keep it out of exposed schemas."),
            )?;
        }
        Ok(())
    }
}

rule_definition!(
    /// Struct defining a rule that reports a view a client role reaches that
    /// filters rows in its own `WHERE` without `security_barrier`.
    ///
    /// The rule does not run on SQLite, which has no `security_barrier` view option.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     SecurityBarrierMissingOnFilteringView::default().into();
    /// let schema = "CREATE TABLE phones (person TEXT, phone TEXT);";
    /// let leaky = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE VIEW visible AS SELECT person FROM phones WHERE phone NOT LIKE '412%';
    ///      GRANT SELECT ON visible TO PUBLIC;"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&leaky).is_err());
    /// let barrier = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE VIEW visible WITH (security_barrier = true)
    ///        AS SELECT person FROM phones WHERE phone NOT LIKE '412%';
    ///      GRANT SELECT ON visible TO PUBLIC;"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&barrier).is_ok());
    /// ```
    SecurityBarrierMissingOnFilteringView,
    register_schema_rule,
    LintGroup::Pedantic,
    "A view without security_barrier cannot reliably conceal the rows its WHERE hides, since a caller's leaky function or an index scan can run before the view's filter.",
    Some("https://www.postgresql.org/docs/current/rules-privileges.html"),
    RuleExample {
        bad: "CREATE TABLE phones (person TEXT, phone TEXT);\n\
CREATE VIEW visible AS SELECT person FROM phones WHERE phone NOT LIKE '412%';",
        good: "CREATE TABLE phones (person TEXT, phone TEXT);\n\
CREATE VIEW visible WITH (security_barrier = true) AS SELECT person FROM phones WHERE phone NOT LIKE '412%';",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> SchemaRule for SecurityBarrierMissingOnFilteringView<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let filtering = database.views().filter(|view| {
            !view.is_security_barrier()
                && matches!(view.definition().body.as_ref(), SetExpr::Select(select)
                    if select.selection.is_some())
        });
        for view in filtering {
            let schema = schema_of(database, view.stored_view_schema());
            let reasons = reach_reasons(
                database,
                deployment,
                &schema,
                |relation| matches!(relation, Relation::View(granted) if *granted == view),
                |action| matches!(action, Action::Select { .. }),
            );
            if reasons.is_empty() {
                continue;
            }
            let name = view.view_name();
            reporter.view(
                view,
                format!(
                    "View '{name}' filters rows in its WHERE and {}, without security_barrier, so a caller's leaky function or an index scan can see the hidden rows.",
                    reasons.join(" and ")
                ),
                format!("ALTER VIEW {name} SET (security_barrier = true); if the filter hides rows on purpose."),
            )?;
        }
        Ok(())
    }
}

rule_definition!(
    /// Struct defining a rule that reports a view without `security_invoker`
    /// that a client role reaches, through an exposed schema or a `SELECT`
    /// grant, whatever its sources.
    ///
    /// The rule does not run on SQLite, which has no `security_invoker` view option.
    ///
    /// The view reads its sources with its owner's privileges and row-level
    /// security, so a client reads through it what the owner may read.
    /// `owner_rights_view` reports the narrower case of a source whose
    /// policies the owner bypasses or misses, and stays on by default.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = OwnerRightsViewExposed::default().into();
    /// let owner_rights = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE docs (id INT);
    ///      CREATE VIEW doc_ids AS SELECT id FROM docs;
    ///      GRANT SELECT ON doc_ids TO PUBLIC;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&owner_rights).is_err());
    /// let invoker = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE docs (id INT);
    ///      CREATE VIEW doc_ids WITH (security_invoker = true) AS SELECT id FROM docs;
    ///      GRANT SELECT ON doc_ids TO PUBLIC;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&invoker).is_ok());
    /// ```
    OwnerRightsViewExposed,
    register_schema_rule,
    LintGroup::Restriction,
    "A view without `security_invoker` reads its sources with its owner's privileges and policies, so a client reaching the view reads data its own grants on those sources would refuse.",
    Some("https://github.com/supabase/splinter/blob/main/lints/0010_security_definer_view.sql"),
    RuleExample {
        bad: "CREATE TABLE public.documents (identifier INT PRIMARY KEY);\n\
CREATE VIEW public.document_identifiers AS SELECT identifier FROM public.documents;\n\
GRANT SELECT ON public.document_identifiers TO PUBLIC;",
        good: "CREATE TABLE public.documents (identifier INT PRIMARY KEY);\n\
CREATE VIEW public.document_identifiers WITH (security_invoker = true)\n\
AS SELECT identifier FROM public.documents;\n\
GRANT SELECT ON public.document_identifiers TO PUBLIC;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> SchemaRule for OwnerRightsViewExposed<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let owner_rights = database
            .views()
            .filter(|view| !view.is_materialized() && !view.is_security_invoker());
        for view in owner_rights {
            let schema = schema_of(database, view.stored_view_schema());
            let reasons = reach_reasons(
                database,
                deployment,
                &schema,
                |relation| matches!(relation, Relation::View(granted) if *granted == view),
                |action| matches!(action, Action::Select { .. }),
            );
            if reasons.is_empty() {
                continue;
            }
            let name = view.view_name();
            let owner = view
                .owner(database)?
                .map_or_else(|| "its owner".to_owned(), |owner| format!("'{owner}'"));
            reporter.view(
                view,
                format!(
                    "View '{name}' {} and reads its sources with the privileges and policies of {owner}, so a client reads what {owner} may read.",
                    reasons.join(" and ")
                ),
                format!("ALTER VIEW {name} SET (security_invoker = true); and grant client roles what they may read from its sources."),
            )?;
        }
        Ok(())
    }
}

rule_definition!(
    /// Struct defining a rule that reports a materialized view a client role
    /// reaches, through an exposed schema or a `SELECT` grant, over sources
    /// without row-level security.
    ///
    /// PostgreSQL refuses row-level security on a materialized view, so every
    /// reader sees every stored row, whatever grants and policies its sources
    /// carry later. `reachable_materialized_view` reports one reading a
    /// row-level-security table and stays on by default.
    ///
    /// The rule does not run on SQLite, which has no materialized views.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = MaterializedViewExposed::default().into();
    /// let granted = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE docs (id INT);
    ///      CREATE MATERIALIZED VIEW doc_ids AS SELECT id FROM docs;
    ///      GRANT SELECT ON doc_ids TO PUBLIC;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&granted).is_err());
    /// let kept = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE docs (id INT); CREATE MATERIALIZED VIEW doc_ids AS SELECT id FROM docs;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&kept).is_ok());
    /// ```
    MaterializedViewExposed,
    register_schema_rule,
    LintGroup::Restriction,
    "A materialized view cannot have row-level security, so a client reaching it reads every stored row, and later grants or policies on its sources never filter them.",
    Some("https://github.com/supabase/splinter/blob/main/lints/0016_materialized_view_in_api.sql"),
    RuleExample {
        bad: "CREATE TABLE public.documents (identifier INT PRIMARY KEY);\n\
CREATE MATERIALIZED VIEW public.document_identifiers AS SELECT identifier FROM public.documents;\n\
GRANT SELECT ON public.document_identifiers TO PUBLIC;",
        good: "CREATE SCHEMA private;\n\
CREATE TABLE public.documents (identifier INT PRIMARY KEY);\n\
CREATE MATERIALIZED VIEW private.document_identifiers AS SELECT identifier FROM public.documents;\n\
REVOKE ALL ON private.document_identifiers FROM PUBLIC;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

impl<DB: DatabaseLike> SchemaRule for MaterializedViewExposed<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        'views: for view in database.materialized_views() {
            for table in view.definition().referenced_tables(database)? {
                if table.has_row_level_security(database)? {
                    continue 'views;
                }
            }
            let schema = schema_of(database, view.stored_view_schema());
            let reasons = reach_reasons(
                database,
                deployment,
                &schema,
                |relation| matches!(relation, Relation::MaterializedView(granted) if *granted == view),
                |action| matches!(action, Action::Select { .. }),
            );
            if reasons.is_empty() {
                continue;
            }
            let name = view.view_name();
            reporter.materialized_view(
                view,
                format!(
                    "Materialized view '{name}' {}, so a client reads every row it stored, which no policy filters.",
                    reasons.join(" and ")
                ),
                format!("Move {name} to a schema no client role reaches and revoke the client roles' grants on it, or replace it with a view WITH (security_invoker = true)."),
            )?;
        }
        Ok(())
    }
}
