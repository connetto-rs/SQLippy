//! Submodule providing the `PolicyExpressionDefeatsIndex` rule.

use sql_traits::{
    structs::{ColumnDefinition, PolicyExpression},
    traits::{ColumnLike, DatabaseLike, PolicyLike, TableLike},
};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        index_support::{defeats_index, wrapping},
        policy_filter_support::caller_filters,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a rule that reports a policy comparing a function, a
/// type-changing cast or arithmetic around a column that leads an index with
/// the caller, when no expression index matches it.
///
/// The rule reads `USING` clauses, where PostgreSQL filters existing rows,
/// and the comparisons [`UnindexedPolicyFilter`](super::UnindexedPolicyFilter)
/// reads: those whose other side derives from the caller alone, on the
/// policy's own table and on the table a policy subquery filters. PostgreSQL
/// can only use an index for the expression it indexes. Measured on
/// PostgreSQL 18.6 with two hundred thousand rows read through a policy,
/// `lower(owner) = current_setting('app.user_id', true)`,
/// `coalesce(team, 0) = …`, `team + 0 = …` and `created::date = …` each ran
/// a sequential scan where the bare column used its index, as did
/// `lower(member) = …` inside a policy subquery on the table it reads. A
/// cast of a textual column to `text` kept the index and is not reported,
/// and `CREATE INDEX ON docs (lower(owner))` turned the read into an index
/// scan.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> =
///     PolicyExpressionDefeatsIndex::default().into();
/// let schema = "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);
///     CREATE INDEX docs_owner ON docs (owner);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY own ON docs USING (lower(owner) = current_setting('app.user_id', true));";
///
/// let wrapped = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
/// assert!(constrainer.validate_schema(&wrapped).is_err());
///
/// let indexed = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE INDEX docs_lower_owner ON docs (lower(owner));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&indexed).is_ok());
/// ```
pub struct PolicyExpressionDefeatsIndex<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for PolicyExpressionDefeatsIndex<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<PolicyExpressionDefeatsIndex<DB>> for GenericConstrainer<DB> {
    fn from(rule: PolicyExpressionDefeatsIndex<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for PolicyExpressionDefeatsIndex<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(PolicyExpressionDefeatsIndex),
            group: LintGroup::Perf,
            rationale: "PostgreSQL can only use an index for the expression it indexes, so a policy that wraps an indexed column in a function, a cast or arithmetic reads the whole table on every read it guards.",
            source: Some("https://www.postgresql.org/docs/current/indexes-expressional.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);\n\
CREATE INDEX notes_owner ON notes (owner);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON notes USING (lower(owner) = current_setting('app.user_id', true));",
                good: "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);\n\
CREATE INDEX notes_owner ON notes (lower(owner));\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON notes USING (lower(owner) = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for PolicyExpressionDefeatsIndex<DB> {
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
            let mut found: Vec<((String, String), String)> = Vec::new();
            for (defeated, comparison) in caller_filters(
                database,
                table,
                reporter.deployment(),
                expression,
                &mut |scope, side| {
                    let Some((wrapper, reference)) = wrapping(side)? else {
                        return Ok(None);
                    };
                    let Some(ColumnDefinition::Base { table, column, .. }) =
                        scope.resolve_column_definition(&reference)?
                    else {
                        return Ok(None);
                    };
                    if !defeats_index(database, table, column, wrapper)? {
                        return Ok(None);
                    }
                    Ok(Some((
                        wrapper.to_string(),
                        format!("{}.{}", table.table_name(), column.column_name()),
                    )))
                },
            )? {
                if !found.iter().any(|(seen, _)| *seen == defeated) {
                    found.push((defeated, comparison));
                }
            }
            for ((wrapper, column), comparison) in found {
                let name = policy.name();
                reporter.policies(
                    vec![PolicySite {
                        table: Box::new(table.clone()),
                        policy: Box::new(policy.clone()),
                        clause: PolicyClause::Using,
                        expression: comparison,
                    }],
                    format!(
                        "Policy '{name}' on '{}' compares `{wrapper}` with the caller, which wraps '{column}', so PostgreSQL cannot use the index that leads with it and reads the whole table.",
                        table.table_name()
                    ),
                    "Compare the bare column and move the computation to the caller's side, or create an index on the expression when it is immutable.".to_owned(),
                )?;
            }
        }
        Ok(())
    }
}
