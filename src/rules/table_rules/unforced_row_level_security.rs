//! Submodule providing the `UnforcedRowLevelSecurity` rule.

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a table whose row-level security its
/// owner bypasses.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UnforcedRowLevelSecurity::default().into();
///
/// let unforced = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      CREATE POLICY p ON docs USING (id > 0);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&unforced).is_err());
///
/// let forced = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      ALTER TABLE docs FORCE ROW LEVEL SECURITY;
///      CREATE POLICY p ON docs USING (id > 0);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&forced).is_ok());
/// ```
pub struct UnforcedRowLevelSecurity<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnforcedRowLevelSecurity<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnforcedRowLevelSecurity<DB>> for GenericConstrainer<DB> {
    fn from(rule: UnforcedRowLevelSecurity<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UnforcedRowLevelSecurity<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "UnforcedRowLevelSecurity",
            group: LintGroup::Suspicious,
            rationale: "The table owner bypasses every policy unless row-level security is forced, and applications often connect as the role that owns the tables.",
            source: Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE notes (id INT PRIMARY KEY);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY readable ON notes USING (true);",
                good: "CREATE TABLE notes (id INT PRIMARY KEY);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY readable ON notes USING (true);\n\
ALTER TABLE notes FORCE ROW LEVEL SECURITY;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for UnforcedRowLevelSecurity<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if table.has_row_level_security(database)?
            && !table.has_forced_row_level_security(database)?
            && table.policies(database)?.next().is_some()
        {
            let name = table.table_name();
            reporter.table(
                table,
                format!("Table '{name}' enables row-level security without forcing it, so its owner bypasses every policy."),
                format!("ALTER TABLE {name} FORCE ROW LEVEL SECURITY; or connect as a role that does not own the table."),
            )?;
        }
        Ok(())
    }
}
