//! Submodule providing the `SettingCastThroughModifier` rule.

use std::{convert::Infallible, ops::ControlFlow};

use sql_traits::{errors::LookupError, traits::DatabaseLike};
use sqlparser::ast::{Expr, Function, FunctionArg, FunctionArgExpr, Statement, Visit, Visitor};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        function_reach_support::{builtin_schema, call_arguments, literal_key, split},
        type_support::cast_applies_modifier,
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Struct defining a rule that reports a `current_setting` read cast to a
/// type that applies a modifier.
///
/// An explicit cast to `varchar(3)` truncates `abcd` to `abc`, one to
/// `numeric(5,2)` rounds, one to `interval day` drops the hours, and one to
/// `char` or `bit` written without a length truncates to a single character,
/// so a policy comparing the cast value can match a row the request did not
/// name. The read is followed through parentheses, casts that apply no
/// modifier, the first argument of `NULLIF` and the arguments of `COALESCE`.
/// The rule reads views, materialized views, policies, table check
/// constraints, SQL and PL/pgSQL function bodies and, as a query rule,
/// statements.
///
/// The rule does not run on SQLite, which has no configuration settings.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = SettingCastThroughModifier::default().into();
/// let truncated = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE objects (installation_id TEXT);
///      CREATE POLICY local ON objects USING (installation_id =
///        NULLIF(current_setting('app.installation_id', true), '')::varchar(3));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&truncated).is_err());
/// let whole = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE objects (installation_id TEXT);
///      CREATE POLICY local ON objects USING (installation_id =
///        NULLIF(current_setting('app.installation_id', true), '')::varchar);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&whole).is_ok());
/// ```
pub struct SettingCastThroughModifier<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for SettingCastThroughModifier<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<SettingCastThroughModifier<DB>> for GenericConstrainer<DB> {
    fn from(rule: SettingCastThroughModifier<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(SettingCastThroughModifier::default()));
        constrainer
    }
}

impl<DB> Rule for SettingCastThroughModifier<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(SettingCastThroughModifier),
            group: LintGroup::Suspicious,
            rationale: "A cast of a request setting to a type with a modifier truncates, rounds or rejects the value the request sent, so the expression uses a different value than the request names.",
            source: Some("https://www.postgresql.org/docs/current/datatype-character.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE objects (installation_id TEXT);\n\
CREATE POLICY local ON objects USING (installation_id = NULLIF(current_setting('app.installation_id', true), '')::varchar(3));",
                good: "CREATE TABLE objects (installation_id TEXT);\n\
CREATE POLICY local ON objects USING (installation_id = NULLIF(current_setting('app.installation_id', true), '')::varchar);",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

/// The `current_setting` call whose value `expression` passes on unchanged
/// in length and precision.
fn setting_read(expression: &Expr) -> Option<&Function> {
    match expression {
        Expr::Nested(inner) => setting_read(inner),
        Expr::Cast {
            expr, data_type, ..
        } if !cast_applies_modifier(data_type) => setting_read(expr),
        Expr::Function(call) => {
            let (schema, name) = split(&call.name)?;
            if !builtin_schema(schema) {
                return None;
            }
            let mut arguments = call_arguments(call)
                .iter()
                .filter_map(|argument| match argument {
                    FunctionArg::Unnamed(FunctionArgExpr::Expr(argument)) => Some(argument),
                    _ => None,
                });
            if name.eq_ignore_ascii_case("current_setting") {
                Some(call)
            } else if name.eq_ignore_ascii_case("nullif") {
                arguments.next().and_then(setting_read)
            } else if name.eq_ignore_ascii_case("coalesce") {
                arguments.find_map(setting_read)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Collects each setting read cast through a modifier, described.
#[derive(Default)]
struct ModifiedCasts(Vec<(String, String)>);

impl Visitor for ModifiedCasts {
    type Break = Infallible;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Infallible> {
        if let Expr::Cast {
            expr, data_type, ..
        } = expression
            && cast_applies_modifier(data_type)
            && let Some(read) = setting_read(expr)
        {
            let setting = literal_key(read).map_or_else(
                || format!("setting read `{read}`"),
                |key| format!("setting '{key}'"),
            );
            self.0.push((
                format!("{setting} cast to `{data_type}`"),
                expression.to_string(),
            ));
        }
        ControlFlow::Continue(())
    }
}

/// Finds and explains setting reads cast through a modifier.
struct Finder;

impl ExpressionFinder for Finder {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        _database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let mut casts = ModifiedCasts::default();
        let ControlFlow::Continue(()) = walk(node, &mut casts);
        Ok(casts.0)
    }

    fn problem(&self) -> &'static str {
        "so the modifier truncates, rounds or rejects the value the request sent before it is used"
    }

    fn resolution(&self) -> &'static str {
        "Cast the setting to a type without a modifier, such as `text`, `varchar` or `numeric`, or to the type it holds, such as `uuid`."
    }
}

impl<DB: DatabaseLike> SchemaRule for SettingCastThroughModifier<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&Finder, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for SettingCastThroughModifier<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&Finder, database, statement, reporter)
    }
}
