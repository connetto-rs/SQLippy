//! Submodule providing the `ExposedDefinerOverProtectedTable` rule.

use sql_traits::traits::{DatabaseLike, FunctionLike, TableLike};
use sqlparser::ast::FunctionSecurity;

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Struct defining a rule that reports a `SECURITY DEFINER` function that
/// `PUBLIC` or a declared anonymous role can execute while its body reads or
/// writes a table with row-level security.
///
/// Every such caller reads and writes those tables as the function's owner.
/// PostgreSQL grants `PUBLIC` `EXECUTE` on every new function, and default
/// privileges such as Supabase's grant it to anonymous roles, so the rule reads
/// the privileges the schema leaves after both. SQL and PL/pgSQL bodies are
/// read for the tables they touch. A body whose tables cannot be known, such as
/// C code or one running dynamic SQL through `EXECUTE`, is reported as well,
/// since nothing shows it stays away from protected tables.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ExposedDefinerOverProtectedTable::default().into();
///
/// let exposed = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT, owner TEXT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
///        SET search_path = '' AS 'SELECT count(*) FROM public.docs';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&exposed).is_err());
///
/// let revoked = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT, owner TEXT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
///        SET search_path = '' AS 'SELECT count(*) FROM public.docs';
///      REVOKE EXECUTE ON FUNCTION doc_count() FROM PUBLIC;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&revoked).is_ok());
/// ```
pub struct ExposedDefinerOverProtectedTable<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ExposedDefinerOverProtectedTable<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ExposedDefinerOverProtectedTable<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: ExposedDefinerOverProtectedTable<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ExposedDefinerOverProtectedTable<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "ExposedDefinerOverProtectedTable",
            group: LintGroup::Suspicious,
            rationale: "A `SECURITY DEFINER` function reads and writes with its owner's rights, so letting `PUBLIC` or an anonymous role execute it hands every such caller the owner's view of the row-level-security tables its body touches.",
            source: Some("https://supabase.com/docs/guides/database/database-advisors"),
            basis: Basis::Declared,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> FunctionRule for ExposedDefinerOverProtectedTable<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if function.security_mode() != FunctionSecurity::Definer {
            return Ok(());
        }
        let mut callers = Vec::new();
        if function.is_executable_by_public(database)? {
            callers.push("PUBLIC".to_owned());
        } else {
            for name in reporter.deployment().anonymous_roles() {
                if let Some(role) = database.role(name)
                    && function.can_execute(role, database)?
                {
                    callers.push(format!("'{name}'"));
                }
            }
        }
        if callers.is_empty() {
            return Ok(());
        }
        let touched = match function.referenced_tables(database) {
            Ok(tables) => {
                let mut protected = Vec::new();
                for table in tables {
                    if table.has_row_level_security(database)? {
                        protected.push(format!("'{}'", table.table_name()));
                    }
                }
                if protected.is_empty() {
                    return Ok(());
                }
                format!(
                    "reads or writes {}, which has row-level security,",
                    protected.join(", ")
                )
            }
            Err(error) if super::unreadable_body(&error) => format!(
                "has a body whose tables cannot be checked ({error}), so it may read or write tables with row-level security"
            ),
            Err(error) => return Err(error.into()),
        };
        let signature = signature(function, database);
        let callers = callers.join(", ");
        reporter.function(
            function,
            format!(
                "`SECURITY DEFINER` function '{signature}' {touched} as its owner, and {callers} can execute it."
            ),
            format!(
                "REVOKE EXECUTE ON FUNCTION {signature} FROM {}; and grant it only to the roles that need it.",
                callers.replace('\'', "")
            ),
        )
    }
}
