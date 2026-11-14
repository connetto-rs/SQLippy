//! Submodule providing the `RaisingSettingRead` rule.

use sql_traits::traits::{DatabaseLike, PolicyLike, TableLike};
use sqlparser::{
    ast::{Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, Statement, Value},
    keywords::Keyword,
    tokenizer::Token,
};

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::function_reach_support::{Reach, Sought, literal_key, split},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// How a policy clause reads a custom setting in a way that raises.
enum Read {
    /// It calls `current_setting` on the named setting.
    Key(String),
    /// It calls a function whose body reads one that way.
    Call,
}

/// Whether a key names a custom setting, which PostgreSQL spells with a
/// prefix and a dot and only knows once a session sets it. A name without a
/// dot is a built-in parameter, which every session holds.
fn is_custom(key: &str) -> bool {
    key.contains('.')
}

/// Whether a call qualified by `schema` reaches PostgreSQL's
/// `current_setting`: unqualified, since `pg_catalog` comes first on every
/// search path that does not name it later, or qualified by `pg_catalog`.
/// Any other schema holds a function of the user's.
fn builtin_schema(schema: Option<&str>) -> bool {
    schema.is_none_or(|schema| schema.eq_ignore_ascii_case("pg_catalog"))
}

/// Whether a `current_setting` call may raise when its setting is missing:
/// it passes no `missing_ok`, or one that is neither the literal `true` nor
/// `NULL`, which the strict function answers with `NULL` before reading the
/// setting.
fn raises(function: &Function) -> bool {
    !matches!(
        &function.args,
        FunctionArguments::List(list) if matches!(
            list.args.get(1),
            Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(value))))
                if matches!(value.value, Value::Boolean(true) | Value::Null)
        )
    )
}

/// The `current_setting` reads of custom settings that raise when the
/// session never set them.
struct RaisingReads;

impl Sought for RaisingReads {
    type Found = Read;

    fn expression(&self, expression: &Expr) -> Option<Read> {
        let Expr::Function(function) = expression else {
            return None;
        };
        let (schema, name) = split(&function.name)?;
        let key = literal_key(function)?;
        (name.eq_ignore_ascii_case("current_setting")
            && builtin_schema(schema)
            && raises(function)
            && is_custom(key))
        .then(|| Read::Key(key.to_owned()))
    }

    fn statement(&self, _statement: &Statement) -> Option<Read> {
        None
    }

    /// A `current_setting` call in a function body, read as tokens.
    fn tokens(&self, tokens: &[&Token], at: usize) -> Option<bool> {
        let Some(Token::Word(word)) = tokens.get(at) else {
            return None;
        };
        let rest = &tokens[at + 1..];
        if !word.value.eq_ignore_ascii_case("current_setting")
            || !matches!(rest.first(), Some(Token::LParen))
        {
            return None;
        }
        let schema = match at
            .checked_sub(2)
            .map(|before| (tokens[before], tokens[at - 1]))
        {
            Some((Token::Word(schema), Token::Period)) => Some(schema.value.as_str()),
            _ => None,
        };
        if !builtin_schema(schema) {
            return None;
        }
        Some(match &rest[1..] {
            [Token::SingleQuotedString(key), after @ ..] => {
                is_custom(key)
                    && !matches!(
                        after,
                        [Token::Comma, Token::Word(missing_ok), Token::RParen, ..]
                            if matches!(missing_ok.keyword, Keyword::TRUE | Keyword::NULL)
                    )
            }
            _ => false,
        })
    }

    fn call(&self) -> Read {
        Read::Call
    }
}

/// Struct defining a rule that reports a policy reading a custom setting
/// with `current_setting` in a way that raises when the session never set
/// it.
///
/// `current_setting('app.user_id')` raises `unrecognized configuration
/// parameter` in a session that never set the setting, and so does a
/// `missing_ok` other than `true` or `NULL`, while
/// `current_setting('app.user_id', true)` reads `NULL` there, as the strict
/// function does for a `NULL` `missing_ok`. Measured on PostgreSQL 18.6 as a
/// role the policy applies to, every read under such a `USING` clause and
/// every insert under such a `WITH CHECK` clause failed, with `missing_ok`
/// left out, given as `false` or read from a column that held `false`, also
/// when another arm of an `OR` was true for the row. So did a policy calling
/// a SQL or PL/pgSQL function that reads the setting that way, directly or
/// through other calls. A session that set the setting once, even if it
/// reset it since, read `''` instead. Only custom settings, spelled with a
/// dot, are reported, since every session holds the built-in parameters. A
/// `current_setting` qualified by a schema other than `pg_catalog` is the
/// user's own function and is followed like any other call. A setting named
/// by an expression and a read built in dynamic SQL are not seen.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = RaisingSettingRead::default().into();
/// let policy = |read: &str| {
///     ParserDB::parse::<PostgreSqlDialect>(&format!(
///         "CREATE TABLE docs (owner TEXT);
///          ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///          CREATE POLICY own ON docs USING (owner = {read});"
///     ))
///     .unwrap()
/// };
/// assert!(constrainer.validate_schema(&policy("current_setting('app.user_id')")).is_err());
/// assert!(constrainer.validate_schema(&policy("current_setting('app.user_id', true)")).is_ok());
/// ```
pub struct RaisingSettingRead<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for RaisingSettingRead<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<RaisingSettingRead<DB>> for GenericConstrainer<DB> {
    fn from(rule: RaisingSettingRead<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for RaisingSettingRead<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(RaisingSettingRead),
            group: LintGroup::Suspicious,
            rationale: "A policy reading a custom setting with one-argument current_setting makes every statement it guards fail with an error in a session that never set the setting, where the two-argument form matches no row.",
            source: Some(
                "https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADMIN-SET",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON notes USING (owner = current_setting('app.user_id'));",
                good: "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON notes USING (owner = current_setting('app.user_id', true));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for RaisingSettingRead<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut reach = Reach::new(database, RaisingReads);
        for policy in table.policies(database)? {
            for (clause, expression) in [
                (PolicyClause::Using, policy.using_expression(database)?),
                (PolicyClause::WithCheck, policy.check_expression(database)?),
            ] {
                let Some(expression) = expression else {
                    continue;
                };
                for (found, read) in reach.occurrences(expression) {
                    let name = policy.name();
                    let (reads, key) = match read {
                        Read::Key(key) => (format!("`{found}` reads"), format!("'{key}'")),
                        Read::Call => (
                            format!("`{found}` calls a function that reads"),
                            "its setting".to_owned(),
                        ),
                    };
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: found,
                        }],
                        format!(
                            "Policy '{name}' on '{}' {reads} a custom setting with current_setting, which raises an error in every session that never set {key}, so each statement the policy guards fails there.",
                            table.table_name()
                        ),
                        "Pass `true` as current_setting's second argument, so a missing setting reads as NULL and the policy matches no row.".to_owned(),
                    )?;
                }
            }
        }
        Ok(())
    }
}
