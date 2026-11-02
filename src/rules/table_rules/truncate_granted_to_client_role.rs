//! Submodule providing the `TruncateGrantedToAnonymousRole` and
//! `TruncateGrantedToAppRole` rules.

use std::{cell::LazyCell, collections::BTreeSet};

use sql_traits::traits::{DatabaseLike, TableLike};
use sqlparser::ast::Action;

use crate::{
    deployment::Declaration,
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::grant_support::{ClientRoles, grantee_list, grants_privilege},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

const RATIONALE: &str = "Row-level security does not govern TRUNCATE, so the grantee empties the table whatever its DELETE policies allow.";
const SOURCE: Option<&str> = Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html");

/// Struct defining a rule that reports `TRUNCATE` on a row-level-security
/// table granted to `PUBLIC` or a declared anonymous role.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> =
///     TruncateGrantedToAnonymousRole::default().into();
/// let schema = "CREATE TABLE docs (id INT); ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";
///
/// let truncatable =
///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} GRANT TRUNCATE ON docs TO PUBLIC;"))
///         .unwrap();
/// assert!(constrainer.validate_schema(&truncatable).is_err());
///
/// let deletable =
///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} GRANT DELETE ON docs TO PUBLIC;"))
///         .unwrap();
/// assert!(constrainer.validate_schema(&deletable).is_ok());
/// ```
pub struct TruncateGrantedToAnonymousRole<DB>(std::marker::PhantomData<DB>);

/// Struct defining a rule that reports `TRUNCATE` on a row-level-security
/// table granted to a declared app role and to no anonymous role.
///
/// The rule is inactive until the deployment declares an app role.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = TruncateGrantedToAppRole::default().into();
/// constrainer.set_deployment(Deployment::default().with_app_role("authenticated"));
///
/// let truncatable = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE ROLE authenticated;
///      CREATE TABLE docs (id INT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      GRANT TRUNCATE ON docs TO authenticated;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&truncatable).is_err());
/// ```
pub struct TruncateGrantedToAppRole<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for TruncateGrantedToAnonymousRole<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB> Default for TruncateGrantedToAppRole<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<TruncateGrantedToAnonymousRole<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: TruncateGrantedToAnonymousRole<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB: DatabaseLike + 'static> From<TruncateGrantedToAppRole<DB>> for GenericConstrainer<DB> {
    fn from(rule: TruncateGrantedToAppRole<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for TruncateGrantedToAnonymousRole<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "TruncateGrantedToAnonymousRole",
            group: LintGroup::Correctness,
            rationale: RATIONALE,
            source: SOURCE,
        };
        &METADATA
    }
}

impl<DB> Rule for TruncateGrantedToAppRole<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "TruncateGrantedToAppRole",
            group: LintGroup::Suspicious,
            rationale: RATIONALE,
            source: SOURCE,
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::AppRoles]
    }
}

/// Reports the table when grants accepted by `reaches` hand out `TRUNCATE`.
fn report_truncate<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    reporter: &mut Reporter<'_, DB>,
    reaches: impl Fn(&ClientRoles, &DB::TableGrant) -> bool,
) -> Result<(), Interruption> {
    if !table.has_row_level_security(database)? {
        return Ok(());
    }
    let deployment = reporter.deployment();
    let roles = LazyCell::new(|| ClientRoles::new(database, deployment));
    let grantees: BTreeSet<String> = table
        .grants(database)?
        .filter(|grant| {
            grants_privilege(database, *grant, |action| {
                matches!(action, Action::Truncate)
            }) && reaches(&roles, grant)
        })
        .map(|grant| grantee_list(database, grant))
        .collect();
    if grantees.is_empty() {
        return Ok(());
    }
    let name = table.table_name();
    let grantees = grantees.into_iter().collect::<Vec<_>>().join(", ");
    reporter.table(
        table,
        format!("TRUNCATE on '{name}' is granted to {grantees}, which empties the table whatever its row-level security policies allow."),
        format!("REVOKE TRUNCATE ON {name} FROM {grantees}; and delete through policies instead."),
    )?;
    Ok(())
}

impl<DB: DatabaseLike> TableRule for TruncateGrantedToAnonymousRole<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report_truncate(database, table, reporter, |roles, grant| {
            roles.reach_anonymous(database, grant)
        })
    }
}

impl<DB: DatabaseLike> TableRule for TruncateGrantedToAppRole<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report_truncate(database, table, reporter, |roles, grant| {
            roles.reach_app(database, grant) && !roles.reach_anonymous(database, grant)
        })
    }
}
