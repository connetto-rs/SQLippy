//! Submodule providing the `OwnerRightsView` rule.

use sql_traits::{
    errors::LookupError,
    traits::{
        DataStatementLike, DatabaseLike, PolicyLike, Relation, RoleLike, TableLike, ViewLike,
    },
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{Command, held_by_name, policy_roles},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

/// Tables with row-level security a view reads with its own rights, through
/// the views it reads with their reader's rights.
fn protected_reads<'db, DB: DatabaseLike>(
    database: &'db DB,
    view: &'db DB::View,
    tables: &mut Vec<&'db DB::Table>,
) -> Result<(), LookupError> {
    for relation in DataStatementLike::<DB>::referenced_relations(view.definition(), database)? {
        match relation {
            Relation::Table(table) => {
                if table.has_row_level_security(database)? && !tables.contains(&table) {
                    tables.push(table);
                }
            }
            Relation::View(inner) if inner.is_security_invoker() => {
                protected_reads(database, inner, tables)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Why the view's owner reads a table past its policies, if it does.
fn bypass<DB: DatabaseLike>(
    database: &DB,
    owner: Option<&str>,
    table: &DB::Table,
) -> Result<Option<String>, LookupError> {
    let Some(owner) = owner else {
        return Ok(Some("its owner is not named in the schema".to_owned()));
    };
    Ok(match database.role(owner) {
        None => Some(format!("its owner '{owner}' is not declared in the schema")),
        Some(role) if role.is_superuser() => Some(format!("its owner '{owner}' is a superuser")),
        Some(role) if role.can_bypass_rls() => Some(format!("its owner '{owner}' has BYPASSRLS")),
        Some(_)
            if table.owner(database)? == Some(owner)
                && !table.has_forced_row_level_security(database)? =>
        {
            Some(format!(
                "its owner '{owner}' owns '{}' without FORCE ROW LEVEL SECURITY",
                table.table_name()
            ))
        }
        Some(_) => None,
    })
}

/// Whether the table has `SELECT` policies and none of them applies to the
/// owner, which then reads no row of it.
fn hidden_from<DB: DatabaseLike>(
    database: &DB,
    owner: &str,
    table: &DB::Table,
) -> Result<bool, LookupError> {
    let held = held_by_name(database, owner);
    let mut selecting = false;
    for policy in table.policies(database)? {
        if !Command::Select.covered_by(policy.command()) {
            continue;
        }
        selecting = true;
        match policy_roles(database, policy) {
            None => return Ok(false),
            Some(roles) if roles.iter().any(|role| held.contains(role)) => return Ok(false),
            Some(_) => {}
        }
    }
    Ok(selecting)
}

/// Struct defining a rule that reports a view reading a table with row-level
/// security with its owner's rights, where that owner bypasses the table's
/// policies or no `SELECT` policy of the table applies to it.
///
/// Without `security_invoker`, PostgreSQL applies the table's policies as the
/// view's owner. An owner that bypasses them, being a superuser, a `BYPASSRLS`
/// role or the table's owner without `FORCE`, shows every caller every row.
/// An owner the schema does not name is whoever ran it, often such a role. An
/// owner no policy applies to shows every caller no row. `current_user` keeps
/// naming the caller inside the view, so policies on it, like those on
/// session settings, work through it.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = OwnerRightsView::default().into();
/// let schema = "CREATE TABLE docs (id INT, owner TEXT); ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY own ON docs USING (owner = current_user);";
///
/// let owner_rights =
///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} CREATE VIEW doc_titles AS SELECT id FROM docs;"))
///         .unwrap();
/// assert!(constrainer.validate_schema(&owner_rights).is_err());
///
/// let invoker = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW doc_titles WITH (security_invoker = true) AS SELECT id FROM docs;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&invoker).is_ok());
/// ```
pub struct OwnerRightsView<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for OwnerRightsView<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<OwnerRightsView<DB>> for GenericConstrainer<DB> {
    fn from(rule: OwnerRightsView<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for OwnerRightsView<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "OwnerRightsView",
            group: LintGroup::Suspicious,
            rationale: "A view without `security_invoker` applies its tables' row-level security as its owner, so an owner that bypasses the policies shows every caller every row, and an owner no policy applies to shows them none.",
            source: Some("https://www.postgresql.org/docs/current/sql-createview.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (id INT, owner TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs USING (owner = current_setting('app.user_id', true));\n\
CREATE VIEW doc_ids AS SELECT id FROM docs;",
                good: "CREATE TABLE docs (id INT, owner TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs USING (owner = current_setting('app.user_id', true));\n\
CREATE VIEW doc_ids WITH (security_invoker = true) AS SELECT id FROM docs;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for OwnerRightsView<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for view in database.views() {
            if view.is_materialized() || view.is_security_invoker() {
                continue;
            }
            let mut tables = Vec::new();
            protected_reads(database, view, &mut tables)?;
            let owner = view.owner(database)?;
            let name = view.view_name();
            let resolution = format!(
                "ALTER VIEW {name} SET (security_invoker = true); so the tables' policies apply to each caller."
            );
            for table in tables {
                let table_name = table.table_name();
                if let Some(reason) = bypass(database, owner, table)? {
                    reporter.view(
                        view,
                        format!(
                            "View '{name}' reads '{table_name}' with its owner's rights, and {reason}, so every caller sees every row."
                        ),
                        resolution.clone(),
                    )?;
                } else if let Some(owner) = owner
                    && hidden_from(database, owner, table)?
                {
                    reporter.view(
                        view,
                        format!(
                            "View '{name}' reads '{table_name}' with the rights of '{owner}', and no SELECT policy on '{table_name}' applies to '{owner}', so callers see no row through it."
                        ),
                        resolution.clone(),
                    )?;
                }
            }
        }
        Ok(())
    }
}
