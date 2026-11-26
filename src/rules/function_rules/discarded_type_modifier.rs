//! Submodule providing the `DiscardedTypeModifier` rule.

use sql_traits::traits::{DataTypeLike, DatabaseLike, FunctionLike, TypeModifier};
use sqlparser::ast::ArgMode;

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::type_support::describe,
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Struct defining a rule that reports a type modifier on a function's
/// argument, return or `RETURNS TABLE` column type.
///
/// `CREATE FUNCTION` discards these modifiers, so `OUT id VARCHAR(3)` returns
/// `abcd`, `OUT a NUMERIC(5,2)` returns `1.23456` and `pg_get_function_arguments`
/// answers `character varying`. The declaration promises a bound nothing
/// enforces. A `char` or `bit` written without a length declares the length 1
/// PostgreSQL discards as well. A domain over the modified type keeps its
/// bound, since PostgreSQL coerces a value to the domain. Modifiers of a type
/// whose modifier the database does not model are not read, and PostgreSQL's
/// own functions in `pg_catalog` are not reported.
///
/// The rule does not run on SQLite, which has no stored functions.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DiscardedTypeModifier::default().into();
/// let modified = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE FUNCTION installation(OUT id VARCHAR(3)) LANGUAGE sql AS 'SELECT ''abc''';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&modified).is_err());
/// let unmodified = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE FUNCTION installation(OUT id VARCHAR) LANGUAGE sql AS 'SELECT ''abc''';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&unmodified).is_ok());
/// ```
pub struct DiscardedTypeModifier<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DiscardedTypeModifier<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DiscardedTypeModifier<DB>> for GenericConstrainer<DB> {
    fn from(rule: DiscardedTypeModifier<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DiscardedTypeModifier<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DiscardedTypeModifier),
            group: LintGroup::Suspicious,
            rationale: "PostgreSQL discards a type modifier on a function's argument and result types, so a declared length or precision promises a bound nothing enforces.",
            source: Some("https://www.postgresql.org/docs/current/sql-createfunction.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE FUNCTION installation(OUT id VARCHAR(3)) LANGUAGE sql AS $$ SELECT 'abc' $$;",
                good: "CREATE FUNCTION installation(OUT id VARCHAR) LANGUAGE sql AS $$ SELECT 'abc' $$;",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

/// Whether `data_type` applies a type modifier.
fn modified<T: DataTypeLike>(data_type: &T, database: &T::DB) -> bool {
    matches!(data_type.typmod(database), Some(TypeModifier::Modified(_)))
}

impl<DB: DatabaseLike> FunctionRule for DiscardedTypeModifier<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if function.target_name().schema() == Some("pg_catalog") {
            return Ok(());
        }
        let mut sites = Vec::new();
        let arguments = function
            .argument_names(database)
            .zip(function.argument_modes())
            .zip(function.argument_types(database));
        for (position, ((name, mode), declared)) in arguments.enumerate() {
            if !modified(declared, database) {
                continue;
            }
            let mode = match mode {
                ArgMode::In => "",
                ArgMode::Out => "OUT ",
                ArgMode::InOut => "INOUT ",
                ArgMode::Variadic => "VARIADIC ",
            };
            let site = match name {
                Some(name) => format!("{mode}parameter `{}`", name.name()),
                None => format!("{mode}parameter {}", position + 1),
            };
            sites.push((site, declared));
        }
        if let Some(declared) = function
            .return_type(database)
            .filter(|declared| modified(*declared, database))
        {
            sites.push(("its return type".to_owned(), declared));
        }
        for (name, declared) in function.returned_columns(database) {
            if modified(declared, database) {
                sites.push((format!("returned column `{}`", name.name()), declared));
            }
        }
        if sites.is_empty() {
            return Ok(());
        }
        let signature = signature(function, database);
        for (site, declared) in sites {
            let written = describe(declared, database);
            reporter.function(
                function,
                format!(
                    "Function '{signature}' declares {site} as `{written}`, and PostgreSQL discards the type modifier of a function's argument and result types, so nothing enforces it."
                ),
                format!(
                    "Declare {site} with a type that has no modifier, such as `text`, `varchar` or `numeric`, or with a domain over `{written}`, whose bound PostgreSQL enforces."
                ),
            )?;
        }
        Ok(())
    }
}
