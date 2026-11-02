//! Submodule providing the `ChildWithoutRowLevelSecurity` rule.

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports an inheritance or partition child
/// without row-level security below an ancestor that has it.
///
/// A query naming the child directly applies only the child's own policies.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ChildWithoutRowLevelSecurity::default().into();
///
/// let open_partition = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE events (at DATE) PARTITION BY RANGE (at);
///      ALTER TABLE events ENABLE ROW LEVEL SECURITY;
///      CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&open_partition).is_err());
/// ```
pub struct ChildWithoutRowLevelSecurity<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ChildWithoutRowLevelSecurity<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ChildWithoutRowLevelSecurity<DB>> for GenericConstrainer<DB> {
    fn from(rule: ChildWithoutRowLevelSecurity<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ChildWithoutRowLevelSecurity<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "ChildWithoutRowLevelSecurity",
            group: LintGroup::Suspicious,
            rationale: "A child table's own policies apply when a query names it directly and its parents' policies are ignored, so a child without row-level security shows every row to a role granted on it.",
            source: Some("https://www.postgresql.org/docs/current/ddl-inherit.html"),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for ChildWithoutRowLevelSecurity<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if table.has_row_level_security(database)? {
            return Ok(());
        }
        let mut seen = vec![table];
        let mut frontier = vec![table];
        while let Some(child) = frontier.pop() {
            let parents = child
                .inherits_from(database)?
                .chain(child.partition_root(database)?);
            for parent in parents {
                if seen.contains(&parent) {
                    continue;
                }
                if parent.has_row_level_security(database)? {
                    let (name, parent) = (table.table_name(), parent.table_name());
                    reporter.table(
                        table,
                        format!("Table '{name}' descends from '{parent}', which has row-level security, but has none itself, so naming '{name}' directly applies no policy."),
                        format!("ALTER TABLE {name} ENABLE ROW LEVEL SECURITY; and give it the policies of '{parent}'."),
                    )?;
                    return Ok(());
                }
                seen.push(parent);
                frontier.push(parent);
            }
        }
        Ok(())
    }
}
