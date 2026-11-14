//! Submodule providing the `UnindexedPolicyFilter` rule.

use sql_traits::{
    structs::{ColumnDefinition, PolicyExpression},
    traits::{ColumnLike, DatabaseLike, PolicyLike, TableLike},
};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        index_support::indexed, policy_filter_support::caller_filters,
        policy_support::is_column_reference,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a column a policy filters on by the
/// caller when no index leads with it.
///
/// The rule reads `USING` clauses, where PostgreSQL filters existing rows. A
/// column is reported when it is compared (`=`, `<`, `<=`, `>`, `>=`, `IN`,
/// `= ANY`) with a side derived from the caller alone: a declared credential,
/// a `current_setting` call, a read of the current role, or a set computed
/// from them. That holds for the policy's own table and for the table a
/// policy subquery filters. A column counts as indexed when an index without
/// a predicate, a unique constraint or the primary key leads with it. A small
/// or rarely read table is a legitimate exception.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UnindexedPolicyFilter::default().into();
/// let schema = "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY own ON docs USING (owner = current_user);";
///
/// let unindexed = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&unindexed).is_err());
///
/// let indexed = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE INDEX docs_owner ON docs (owner);"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&indexed).is_ok());
/// ```
pub struct UnindexedPolicyFilter<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UnindexedPolicyFilter<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UnindexedPolicyFilter<DB>> for GenericConstrainer<DB> {
    fn from(rule: UnindexedPolicyFilter<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UnindexedPolicyFilter<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UnindexedPolicyFilter),
            group: LintGroup::Perf,
            rationale: "PostgreSQL evaluates the policy against each candidate row, so a column the policy filters on without an index led by it turns a read into a sequential scan.",
            source: Some(
                "https://supabase.com/docs/guides/database/postgres/row-level-security#add-indexes",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON notes USING (owner = current_setting('app.user_id', true));",
                good: "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON notes USING (owner = current_setting('app.user_id', true));\n\
CREATE INDEX notes_owner ON notes (owner);",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for UnindexedPolicyFilter<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for policy in table.policies(database)? {
            let Some(expression) = policy
                .using_clause(database)?
                .as_ref()
                .map(PolicyExpression::expression)
            else {
                continue;
            };
            let mut found: Vec<(String, String, String)> = Vec::new();
            for ((filtered, column), comparison) in caller_filters(
                database,
                table,
                reporter.deployment(),
                expression,
                &mut |scope, column| {
                    if !is_column_reference(column) {
                        return Ok(None);
                    }
                    let Some(ColumnDefinition::Base { table, column, .. }) =
                        scope.resolve_column_definition(column)?
                    else {
                        return Ok(None);
                    };
                    if indexed(database, table, column)? {
                        return Ok(None);
                    }
                    Ok(Some((
                        table.table_name().to_owned(),
                        column.column_name().to_owned(),
                    )))
                },
            )? {
                if !found.iter().any(|(seen_table, seen_column, _)| {
                    *seen_table == filtered && *seen_column == column
                }) {
                    found.push((filtered, column, comparison));
                }
            }
            for (filtered, column, comparison) in found {
                let name = policy.name();
                reporter.policies(
                    vec![PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new(policy.clone()),
                        clause: PolicyClause::Using,
                        expression: comparison,
                    }],
                    format!(
                        "Policy '{name}' on '{}' filters '{filtered}' on column '{column}' by the caller, and no index on '{filtered}' leads with '{column}'.",
                        table.table_name()
                    ),
                    format!("Create an index led by '{column}', such as `CREATE INDEX ON {filtered} ({column})`."),
                )?;
            }
        }
        Ok(())
    }
}
