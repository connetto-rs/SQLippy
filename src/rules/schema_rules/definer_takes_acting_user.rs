//! Submodule providing the `DefinerTakesActingUser` rule.

use std::ops::ControlFlow;

use sql_traits::{
    traits::{DatabaseLike, FunctionLike, RoleLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::{
    ast::{BinaryOperator, Expr, FunctionSecurity, Value, Visit, Visitor},
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::{
    deployment::Declaration,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{authority_support::authority_columns, function_rules::unreadable_body},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

/// The stored name of the column or parameter an identifier names.
fn last_name(expression: &Expr) -> Option<String> {
    let ident = match expression {
        Expr::Identifier(ident) => ident,
        Expr::CompoundIdentifier(parts) => parts.last()?,
        _ => return None,
    };
    Some(normalize_identifier(&ident.value, ident.quote_style.is_some()).into_owned())
}

/// Finds a comparison of a credential-compared column with a parameter, and
/// any read of a declared credential.
struct BodyReads<'a> {
    columns: &'a [String],
    parameters: &'a [String],
    credential: &'a dyn Fn(&Expr) -> bool,
    compared: Option<String>,
    reads_credential: bool,
}

impl BodyReads<'_> {
    fn is_parameter(&self, expression: &Expr) -> bool {
        match expression {
            Expr::Value(value) => matches!(&value.value, Value::Placeholder(placeholder)
                if placeholder.starts_with('$')),
            Expr::Identifier(_) => {
                last_name(expression).is_some_and(|name| self.parameters.contains(&name))
            }
            _ => false,
        }
    }
}

impl Visitor for BodyReads<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if (self.credential)(expression) {
            self.reads_credential = true;
            return ControlFlow::Break(());
        }
        if let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = expression
        {
            for (column, other) in [(left, right), (right, left)] {
                if self.compared.is_none()
                    && self.is_parameter(other)
                    && last_name(column).is_some_and(|name| self.columns.contains(&name))
                {
                    self.compared = Some(expression.to_string());
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// Struct defining a rule that reports a `SECURITY DEFINER` function a
/// client role can execute whose body takes the acting user as an argument.
///
/// The rule reads `LANGUAGE sql` bodies. It reports a body that compares a
/// parameter, by name or as `$n`, with a column a policy compares with a
/// declared credential, directly or in an authority read, on a table the
/// body reads or writes, while reading no credential itself. Any caller then
/// passes another user's identifier and acts as them. Client roles are
/// `PUBLIC` and the declared anonymous and app roles. The column is matched
/// by name, so the rule is `pedantic`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let mut constrainer: GenericConstrainer<ParserDB> = DefinerTakesActingUser::default().into();
/// constrainer.set_deployment(
///     Deployment::default().with_credential("current_setting('app.user_id', true)").unwrap(),
/// );
/// let schema = "CREATE TABLE docs (owner TEXT, body TEXT);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///     CREATE POLICY own ON docs USING (owner = current_setting('app.user_id', true));";
///
/// let acting = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE FUNCTION user_docs(who TEXT) RETURNS SETOF TEXT LANGUAGE sql SECURITY DEFINER
///        SET search_path = '' AS $$ SELECT body FROM public.docs WHERE owner = who $$;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&acting).is_err());
///
/// let own = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE FUNCTION my_docs() RETURNS SETOF TEXT LANGUAGE sql SECURITY DEFINER
///        SET search_path = '' AS $$ SELECT body FROM public.docs
///        WHERE owner = current_setting('app.user_id', true) $$;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&own).is_ok());
/// ```
pub struct DefinerTakesActingUser<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DefinerTakesActingUser<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DefinerTakesActingUser<DB>> for GenericConstrainer<DB> {
    fn from(rule: DefinerTakesActingUser<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DefinerTakesActingUser<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "DefinerTakesActingUser",
            group: LintGroup::Pedantic,
            rationale: "A definer function bypasses the caller's policies, so one that takes the acting user as an argument instead of reading the credential lets any caller act as anyone.",
            source: Some("https://makerkit.dev/blog/tutorials/supabase-rls-best-practices"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (owner TEXT, body TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs USING (owner = current_setting('app.user_id', true));\n\
CREATE FUNCTION user_docs(who TEXT) RETURNS SETOF TEXT LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT body FROM public.docs WHERE owner = who $$;",
                good: "CREATE TABLE docs (owner TEXT, body TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON docs USING (owner = current_setting('app.user_id', true));\n\
CREATE FUNCTION user_docs() RETURNS SETOF TEXT LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT body FROM public.docs WHERE owner = current_setting('app.user_id', true) $$;",
            },
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Credentials]
    }
}

impl<DB: DatabaseLike> SchemaRule for DefinerTakesActingUser<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let deployment = reporter.deployment();
        let subjects = authority_columns(database, deployment)?.subjects;
        let clients: Vec<&DB::Role> = deployment
            .anonymous_roles()
            .chain(deployment.app_roles())
            .filter_map(|name| database.role(name))
            .collect();
        for function in database.functions() {
            if function.security_mode() != FunctionSecurity::Definer
                || function
                    .stored_language()
                    .is_some_and(|language| language != "sql")
            {
                continue;
            }
            let mut callers = Vec::new();
            if function.is_executable_by_public(database)? {
                callers.push("PUBLIC".to_owned());
            } else {
                for role in &clients {
                    if function.can_execute(role, database)? {
                        callers.push(format!("'{}'", role.name()));
                    }
                }
            }
            let Some(tables) = function
                .referenced_tables(database)
                .map(Some)
                .or_else(|error| unreadable_body(&error).then_some(None).ok_or(error))?
            else {
                continue;
            };
            let columns: Vec<String> = subjects
                .iter()
                .filter(|(table, _)| {
                    tables
                        .iter()
                        .any(|read| database.table_id(read) == Some(*table))
                })
                .map(|(_, column)| column.clone())
                .collect();
            if callers.is_empty() || columns.is_empty() {
                continue;
            }
            let parameters: Vec<String> = function
                .stored_argument_names(database)
                .flatten()
                .map(std::borrow::Cow::into_owned)
                .collect();
            let credential = |expression: &Expr| deployment.is_credential(expression);
            let mut reads = BodyReads {
                columns: &columns,
                parameters: &parameters,
                credential: &credential,
                compared: None,
                reads_credential: false,
            };
            let statements = function
                .body()
                .and_then(|body| Parser::parse_sql(&PostgreSqlDialect {}, body).ok())
                .unwrap_or_default();
            let _ = statements.visit(&mut reads);
            if let Ok(Some(body)) = function.body_expression(database) {
                let _ = body.as_ref().visit(&mut reads);
            }
            let (false, Some(compared)) = (reads.reads_credential, reads.compared) else {
                continue;
            };
            let signature = signature(function, database);
            reporter.function(
                function,
                format!(
                    "SECURITY DEFINER function '{signature}', executable by {}, matches `{compared}` against a parameter where policies match the credential, and reads no credential itself, so a caller passes another user's identifier and acts as them.",
                    callers.join(", ")
                ),
                format!(
                    "Compare the column with the caller's credential inside '{signature}' instead of a parameter, or revoke EXECUTE from client roles."
                ),
            )?;
        }
        Ok(())
    }
}
