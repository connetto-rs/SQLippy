//! Submodule providing the `RepeatedSettingRead` rule.

use std::{collections::BTreeMap, ops::ControlFlow};

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Value, Visitor};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        function_body_support::function_body,
        function_reach_support::{builtin_schema, literal_key, split},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

/// Borrows an unnamed literal argument.
fn literal(argument: &FunctionArg) -> Option<&Value> {
    match argument {
        FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(value))) => Some(&value.value),
        _ => None,
    }
}

/// Collects literal setting keys and missing-value flags.
#[derive(Default)]
struct Settings(Vec<(String, bool)>);

impl Visitor for Settings {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if let Expr::Function(function) = expression {
            let setting = split(&function.name).is_some_and(|(schema, name)| {
                builtin_schema(schema) && name.eq_ignore_ascii_case("current_setting")
            });
            if !setting {
                return ControlFlow::Continue(());
            }
            if let FunctionArguments::List(arguments) = &function.args
                && let Some(key) = literal_key(function)
            {
                let missing = match arguments.args.as_slice() {
                    [_] => Some(false),
                    [_, flag] => match literal(flag) {
                        Some(Value::Boolean(flag)) => Some(*flag),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(missing) = missing {
                    self.0.push((key.to_owned(), missing));
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// Reports the same setting read in distinct functions so its type and
/// missing-value handling can live in one typed accessor.
///
/// Policies are not counted because the credential convention spells the
/// credential inline in each policy. Reads with different literal keys or
/// missing-value flags are separate, and dynamic arguments are not counted.
///
/// The rule does not run on SQLite, which has no configuration settings.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = RepeatedSettingRead::default().into();
/// constrainer.set_rule_level("repeated_setting_read", Level::Deny);
/// let first = "CREATE FUNCTION actor_id() RETURNS UUID LANGUAGE sql AS $$
///     SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;";
///
/// let bad = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{first} CREATE FUNCTION other() RETURNS UUID LANGUAGE sql AS $$
///        SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&bad).is_err());
///
/// let good = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{first} CREATE FUNCTION other() RETURNS UUID LANGUAGE sql
///        AS $$ SELECT actor_id() $$;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&good).is_ok());
/// ```
pub struct RepeatedSettingRead<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RepeatedSettingRead<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RepeatedSettingRead<DB>> for GenericConstrainer<DB> {
    fn from(rule: RepeatedSettingRead<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for RepeatedSettingRead<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RepeatedSettingRead),
            group: LintGroup::Pedantic,
            rationale: "Reading the same request setting in several functions duplicates its type conversion and missing-value handling. One typed accessor centralizes that contract without caching the value.",
            source: Some(
                "https://www.postgresql.org/docs/17/functions-admin.html#FUNCTIONS-ADMIN-SET",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE FUNCTION first() RETURNS UUID LANGUAGE sql AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;\n\
CREATE FUNCTION second() RETURNS UUID LANGUAGE sql AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;",
                good: "CREATE FUNCTION actor_id() RETURNS UUID LANGUAGE sql AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;\n\
CREATE FUNCTION first() RETURNS UUID LANGUAGE sql AS $$ SELECT actor_id() $$;\n\
CREATE FUNCTION second() RETURNS UUID LANGUAGE sql AS $$ SELECT actor_id() $$;",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

impl<DB: DatabaseLike> SchemaRule for RepeatedSettingRead<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &DB,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        let mut readers = BTreeMap::<_, Vec<&DB::Function>>::new();
        for function in database.functions() {
            let mut settings = Settings::default();
            function_body(
                database,
                function,
                |node| -> Result<(), sql_traits::errors::LookupError> {
                    let _ = node.walk(&mut settings);
                    Ok(())
                },
            )?;
            settings.0.sort();
            settings.0.dedup();
            for setting in settings.0 {
                readers.entry(setting).or_default().push(function);
            }
        }
        for ((key, missing), functions) in readers {
            if functions.len() < 2 {
                continue;
            }
            let names = functions
                .iter()
                .map(|function| signature(*function, database))
                .collect::<Vec<_>>()
                .join(", ");
            reporter.function(
                functions[0],
                format!(
                    "Functions {names} each read setting '{key}' with `missing_ok = {missing}`."
                ),
                "Read the setting in one typed accessor function and call that accessor from these functions."
                    .to_owned(),
            )?;
        }
        Ok(())
    }
}
