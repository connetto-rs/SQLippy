//! Submodule providing the `MisquotedSearchPath` rule.

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::{
    AlterFunctionAction, AlterFunctionOperation, AlterRoleOperation, Expr, FunctionSetValue, Set,
    SetConfigValue, Statement,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::script_support::{is_search_path, misquoted_path},
    traits::{Constrainer, GenericConstrainer, Reporter, ScriptRule},
};

rule_definition!(
    /// Struct defining a rule that reports a `search_path` set to one quoted
    /// name holding a comma, as several schemas written inside one pair of
    /// quotes.
    ///
    /// Session `SET` statements, function `SET` clauses and role settings are
    /// read. PostgreSQL quotes each string of the list as one name, so
    /// `'pg_catalog, pg_temp'` misquotes as `"pg_catalog, pg_temp"` does.
    /// Allow a schema genuinely named with a comma with `allow_statement`.
    ///
    /// The rule does not run on SQLite, which has no configuration settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = MisquotedSearchPath::default().into();
    /// for (sql, findings) in [
    ///     ("SET search_path = \"pg_catalog, pg_temp\";", 1),
    ///     ("SET search_path = pg_catalog, pg_temp;", 0),
    /// ] {
    ///     let database = ParserDB::parse::<PostgreSqlDialect>(sql).unwrap();
    ///     let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap();
    ///     assert_eq!(constrainer.script_diagnostics(&database, &statements).len(), findings);
    /// }
    /// ```
    MisquotedSearchPath,
    register_script_rule,
    LintGroup::Suspicious,
    "A `search_path` quoted as one name searches a single schema named with a comma, so the intended schemas are never searched and a temporary relation can stand in for them.",
    Some("https://github.com/timescale/pgspot/blob/main/src/pgspot/visitors.py"),
    RuleExample {
        bad: "SET search_path = \"pg_catalog, pg_temp\";",
        good: "SET search_path = pg_catalog, pg_temp;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

/// The misquoted name of each `search_path` value `statement` sets.
fn misquoted_values(statement: &Statement) -> Vec<&str> {
    let values: Vec<&[Expr]> = match statement {
        Statement::Set(Set::SingleAssignment {
            variable, values, ..
        }) if is_search_path(variable) => vec![values],
        Statement::CreateFunction(function) => function
            .set_params
            .iter()
            .filter(|param| is_search_path(&param.name))
            .filter_map(|param| match &param.value {
                FunctionSetValue::Values(values) => Some(values.as_slice()),
                _ => None,
            })
            .collect(),
        Statement::AlterFunction(alter) => match &alter.operation {
            AlterFunctionOperation::Actions { actions, .. } => actions
                .iter()
                .filter_map(|action| match action {
                    AlterFunctionAction::Set(param) if is_search_path(&param.name) => {
                        match &param.value {
                            FunctionSetValue::Values(values) => Some(values.as_slice()),
                            _ => None,
                        }
                    }
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        },
        Statement::AlterRole {
            operation:
                AlterRoleOperation::Set {
                    config_name,
                    config_value: SetConfigValue::Value(value),
                    ..
                },
            ..
        } if is_search_path(config_name) => vec![std::slice::from_ref(value)],
        _ => Vec::new(),
    };
    values.into_iter().filter_map(misquoted_path).collect()
}

impl<DB: DatabaseLike> ScriptRule for MisquotedSearchPath<DB> {
    type Database = DB;

    fn check_script(
        &self,
        _database: &Self::Database,
        statements: &[sqlparser::ast::Statement],
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for statement in statements {
            for name in misquoted_values(statement) {
                let schemas = name
                    .split(',')
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .join(", ");
                reporter.statement(
                    statement,
                    format!("\"{name}\""),
                    format!(
                        "The search_path names the single schema \"{name}\", since the quotes hold the comma, so none of {schemas} is searched."
                    ),
                    format!("Write the schemas unquoted and separated by commas: search_path = {schemas}."),
                )?;
            }
        }
        Ok(())
    }
}
