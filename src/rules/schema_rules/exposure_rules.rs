//! Submodule providing the rules on objects a client role reaches: definer
//! functions, extensions, sequences and row-filtering views.

use std::{borrow::Cow, cell::LazyCell};

use sql_traits::traits::{
    DatabaseLike, ExtensionLike, FunctionLike, Relation, RoleLike, SequenceLike, TableGrantLike,
    ViewLike,
};
use sqlparser::ast::{Action, FunctionSecurity, SetExpr};

use crate::{
    deployment::Deployment,
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::grant_support::{ClientRoles, grantee_list, grants_privilege, schema_of},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

/// The reasons a client role reaches a relation: an exposed schema, or a
/// grant reaching a client role with a privilege `wanted` accepts.
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
    reasons
}

schema_rule!(
    /// Struct defining a rule that reports a `SECURITY DEFINER` function in
    /// an exposed schema that `PUBLIC` or a declared anonymous or app role
    /// can execute.
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
    ///     SET search_path = '' AS 'SELECT 1';";
    /// let open = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    /// assert!(constrainer.validate_schema(&open).is_err());
    /// let closed = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} REVOKE EXECUTE ON FUNCTION bump() FROM PUBLIC;"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&closed).is_ok());
    /// ```
    SecurityDefinerFunctionExposed,
    LintGroup::Suspicious,
    "A SECURITY DEFINER function runs with its owner's privileges, so a client role that can call it in an exposed schema gets them for whatever the function does.",
    Some(
        "https://github.com/supabase/splinter/blob/main/lints/0028_anon_security_definer_function_executable.sql"
    )
);

impl<DB: DatabaseLike> SchemaRule for SecurityDefinerFunctionExposed<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let clients: Vec<&DB::Role> = deployment
            .anonymous_roles()
            .chain(deployment.app_roles())
            .filter_map(|name| database.role(name))
            .collect();
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
            let mut callers = Vec::new();
            if function.is_executable_by_public(database)? {
                callers.push("PUBLIC".to_owned());
            } else {
                for role in &clients {
                    if function.can_execute(role, database)? {
                        callers.push(format!("'{}'", role.name()));
                    }
                }
            }
            if callers.is_empty() {
                continue;
            }
            let signature = signature(function, database);
            reporter.function(
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

schema_rule!(
    /// Struct defining a rule that reports an extension installed in an
    /// exposed schema. `plpgsql` is not reported.
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
    LintGroup::Suspicious,
    "An extension's functions and objects in a schema clients reach widen what clients can call, and a schema on the search path trusts every role that can create objects in it.",
    Some("https://github.com/supabase/splinter/blob/main/lints/0014_extension_in_public.sql")
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

schema_rule!(
    /// Struct defining a rule that reports a sequence a client role reaches,
    /// through an exposed schema or a `USAGE`, `SELECT` or `UPDATE` grant.
    /// The sequences behind serial and identity columns count too.
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
    LintGroup::Suspicious,
    "SELECT on a sequence reveals its current value and UPDATE or USAGE lets a role advance it, so a client role can read or burn the numbers other tables draw from.",
    Some("https://www.postgresql.org/docs/current/ddl-priv.html")
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

schema_rule!(
    /// Struct defining a rule that reports a view a client role reaches that
    /// filters rows in its own `WHERE` without `security_barrier`.
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
    LintGroup::Pedantic,
    "A view without security_barrier cannot reliably conceal the rows its WHERE hides, since a caller's leaky function or an index scan can run before the view's filter.",
    Some("https://www.postgresql.org/docs/current/rules-privileges.html")
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
