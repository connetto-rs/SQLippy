//! Submodule providing the `CredentialSettingWrite` rule.

use std::ops::ControlFlow;

use sql_traits::traits::DatabaseLike;
use sqlparser::{
    ast::{
        DiscardObject, Expr, Function, ObjectName, Reset, ResetStatement, Set, Statement, Visitor,
    },
    keywords::Keyword,
    tokenizer::{Token, Word},
};

use crate::rules::walk_support::walk;
use crate::{
    deployment::{Declaration, Deployment},
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::function_reach_support::{Reach, Sought, calls, literal_key},
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// How a statement or a function body writes a credential setting.
enum Write {
    /// It writes the named credential setting.
    Key(String),
    /// It calls `set_config` with a key that is not a literal.
    Unnamed,
    /// It resets every setting.
    All,
    /// It calls a function that writes a credential setting.
    Call,
}

/// A setting name as PostgreSQL looks it up, its parts without their
/// quotes.
fn setting_name(name: &ObjectName) -> String {
    let parts: Vec<&str> = name
        .0
        .iter()
        .filter_map(|part| part.as_ident())
        .map(|ident| ident.value.as_str())
        .collect();
    parts.join(".")
}

/// Collects the setting keys the declared credentials read through
/// `current_setting`.
struct CredentialKeys(Vec<String>);

impl Visitor for CredentialKeys {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if let Expr::Function(function) = expression
            && calls(function, "current_setting")
            && let Some(key) = literal_key(function)
        {
            self.0.push(key.to_lowercase());
        }
        ControlFlow::Continue(())
    }
}

/// The credential settings of a deployment, whose writes the rule looks
/// for.
struct Credentials {
    keys: Vec<String>,
}

impl Credentials {
    fn new(deployment: &Deployment) -> Self {
        let mut keys = CredentialKeys(Vec::new());
        for credential in deployment.credentials() {
            let _ = walk(credential, &mut keys);
        }
        Self { keys: keys.0 }
    }

    /// The write of `key`, when it names a credential setting.
    fn key(&self, key: &str) -> Option<Write> {
        let key = key.to_lowercase();
        self.keys.contains(&key).then_some(Write::Key(key))
    }

    /// How a `set_config` call writes a credential setting.
    fn set_config(&self, function: &Function) -> Option<Write> {
        if !calls(function, "set_config") {
            return None;
        }
        // Expression evaluator: every key that is not a string literal counts
        // as possibly naming a credential. The evaluator folds constant keys
        // such as `'app.' || 'theme'`, so one naming another setting passes.
        literal_key(function).map_or(Some(Write::Unnamed), |key| self.key(key))
    }
}

impl Sought for Credentials {
    type Found = Write;

    fn expression(&self, expression: &Expr) -> Option<Write> {
        let Expr::Function(function) = expression else {
            return None;
        };
        self.set_config(function)
    }

    /// How a `SET`, `RESET` or `DISCARD` statement writes a credential
    /// setting.
    fn statement(&self, statement: &Statement) -> Option<Write> {
        match statement {
            Statement::Set(Set::SingleAssignment { variable, .. })
            | Statement::Reset(ResetStatement {
                reset: Reset::ConfigurationParameter(variable),
            }) => self.key(&setting_name(variable)),
            Statement::Reset(ResetStatement { reset: Reset::ALL })
            | Statement::Discard {
                object_type: DiscardObject::ALL,
            } => Some(Write::All),
            _ => None,
        }
    }

    /// A `set_config` call, or a `SET` or `RESET` of a credential setting or
    /// of every setting.
    fn tokens(&self, tokens: &[&Token], at: usize) -> Option<bool> {
        let Some(Token::Word(word)) = tokens.get(at) else {
            return None;
        };
        let rest = &tokens[at + 1..];
        if let Some(Token::LParen) = rest.first() {
            if word.value.eq_ignore_ascii_case("set_config") {
                return Some(match rest.get(1) {
                    Some(Token::SingleQuotedString(key)) => self.key(key).is_some(),
                    _ => true,
                });
            }
            return None;
        }
        let rest = match (word.keyword, rest.first()) {
            (Keyword::SET, Some(Token::Word(scope)))
                if matches!(scope.keyword, Keyword::SESSION | Keyword::LOCAL) =>
            {
                &rest[1..]
            }
            (Keyword::SET | Keyword::RESET, _) => rest,
            _ => return None,
        };
        if word.keyword == Keyword::RESET
            && matches!(rest.first(), Some(Token::Word(all)) if all.keyword == Keyword::ALL)
        {
            return Some(true);
        }
        let mut parts = Vec::new();
        let mut rest = rest.iter();
        while let Some(Token::Word(Word { value: part, .. }) | Token::DoubleQuotedString(part)) =
            rest.next()
        {
            parts.push(part.as_str());
            if !matches!(rest.next(), Some(Token::Period)) {
                break;
            }
        }
        Some(self.key(&parts.join(".")).is_some())
    }

    fn call(&self) -> Write {
        Write::Call
    }
}

/// Struct defining a rule that reports a client statement writing a setting
/// the deployment declares as a credential.
///
/// A policy that reads `current_setting('app.user_id', true)` trusts the
/// server to set it. Measured on PostgreSQL 17.11 and 18.6, a role with
/// `app.user_id = 'bob'` that ran `set_config('app.user_id', 'alice', false)`
/// inside a `WHERE` read alice's rows for the rest of the session, and a
/// prepared `set_config($1, $2, false)` did the same. The rule reports
/// `set_config` naming a credential setting or with a key that is not a
/// literal, `SET` and `RESET` of a credential setting, `RESET ALL`,
/// `DISCARD ALL`, and calls to functions whose SQL or PL/pgSQL bodies call
/// `set_config` or run `SET` or `RESET` that way, directly or through other
/// calls. A write built in dynamic SQL is not seen. It needs the
/// deployment's credentials.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
///
/// let mut constrainer: GenericConstrainer<ParserDB> = CredentialSettingWrite::default().into();
/// constrainer.set_deployment(
///     Deployment::default().with_credential("current_setting('app.user_id', true)").unwrap(),
/// );
/// let database = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT);").unwrap();
/// let check = |sql: &str| {
///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
///     constrainer.validate_statement(&database, statement)
/// };
/// assert!(check("SELECT set_config('app.user_id', 'alice', false)").is_err());
/// assert!(check("SELECT current_setting('app.user_id', true)").is_ok());
/// ```
pub struct CredentialSettingWrite<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for CredentialSettingWrite<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<CredentialSettingWrite<DB>> for GenericConstrainer<DB> {
    fn from(rule: CredentialSettingWrite<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_query_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for CredentialSettingWrite<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(CredentialSettingWrite),
            group: LintGroup::Correctness,
            rationale: "A client that writes the setting policies read as the caller's identity can act as any user.",
            source: Some("https://www.postgresql.org/docs/current/functions-admin.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "SELECT set_config('app.user_id', 'alice', false);",
                good: "SELECT current_setting('app.user_id', true);",
            },
        };
        &METADATA
    }

    fn requires(&self) -> &'static [Declaration] {
        &[Declaration::Credentials]
    }
}

impl<DB: DatabaseLike> QueryRule for CredentialSettingWrite<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut reach = Reach::new(database, Credentials::new(reporter.deployment()));
        for (found, write) in reach.occurrences(statement) {
            let effect = match write {
                Write::Key(key) => format!("writes the credential setting '{key}'"),
                Write::Unnamed => {
                    "calls set_config with a key that is not a literal, which can name a credential setting".to_owned()
                }
                Write::All => "resets every setting, including the credential settings".to_owned(),
                Write::Call => "calls a function that writes a credential setting".to_owned(),
            };
            reporter.statement(
                statement,
                found.clone(),
                format!("`{found}` {effect}, so the client can change who it acts as for the rest of the session."),
                "Set credential settings only on the server, from the authenticated session, and refuse client statements that write them.".to_owned(),
            )?;
        }
        Ok(())
    }
}
