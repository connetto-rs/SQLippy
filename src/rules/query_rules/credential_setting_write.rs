//! Submodule providing the `CredentialSettingWrite` rule.

use std::{borrow::Cow, collections::HashMap, ops::ControlFlow};

use sql_traits::{
    structs::FunctionBody,
    traits::{DatabaseLike, FunctionLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::{
    ast::{
        DiscardObject, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, ObjectName,
        Reset, ResetStatement, Set, Statement, Value, ValueWithSpan, Visit, Visitor,
    },
    dialect::PostgreSqlDialect,
    keywords::Keyword,
    tokenizer::{Token, Tokenizer, Word},
};

use crate::{
    deployment::{Declaration, Deployment},
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::grant_support::schema_of,
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, reporter::signature},
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

/// The last part of a name and the schema before it, if any.
fn split(name: &ObjectName) -> Option<(Option<&str>, &str)> {
    let mut parts = name.0.iter().rev();
    let last = parts.next()?.as_ident()?;
    let schema = parts
        .next()
        .and_then(|part| part.as_ident())
        .map(|ident| ident.value.as_str());
    Some((schema, last.value.as_str()))
}

/// The string literal a call passes as its first argument.
fn literal_key(function: &Function) -> Option<&str> {
    if let FunctionArguments::List(list) = &function.args
        && let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(ValueWithSpan {
            value: Value::SingleQuotedString(key),
            ..
        })))) = list.args.first()
    {
        return Some(key);
    }
    None
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

/// The number of arguments of the call whose opening parenthesis starts
/// `tokens`.
fn token_arguments(tokens: &[&Token]) -> usize {
    let mut depth = 0_usize;
    let mut arguments = 0;
    for token in tokens {
        match token {
            Token::LParen => {
                arguments = arguments.max(usize::from(depth == 1));
                depth += 1;
            }
            Token::RParen if depth == 1 => break,
            Token::RParen => depth -= 1,
            Token::Comma if depth == 1 => arguments += 1,
            _ => arguments = arguments.max(usize::from(depth == 1)),
        }
    }
    arguments
}

/// Whether `function` calls the function named `name`, in any schema.
fn calls(function: &Function, name: &str) -> bool {
    split(&function.name).is_some_and(|(_, called)| called.eq_ignore_ascii_case(name))
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

/// The credential settings of a deployment and the functions known to write
/// them.
struct Credentials<'db, DB: DatabaseLike> {
    database: &'db DB,
    keys: Vec<String>,
    writers: HashMap<String, bool>,
}

impl<'db, DB: DatabaseLike> Credentials<'db, DB> {
    fn new(database: &'db DB, deployment: &Deployment) -> Self {
        let mut keys = CredentialKeys(Vec::new());
        for credential in deployment.credentials() {
            let _ = credential.visit(&mut keys);
        }
        Self {
            database,
            keys: keys.0,
            writers: HashMap::new(),
        }
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

    /// Whether the function a call to `name` with `arguments` arguments
    /// reaches writes a credential setting. A call without a schema reaches
    /// the first schema on the search path that holds a function of that
    /// name accepting that many arguments.
    fn calls_writer(&mut self, schema: Option<&str>, name: &str, arguments: usize) -> bool {
        let database = self.database;
        let declared_in = |function: &DB::Function, schema: &str| {
            schema_of(database, function.target_name().schema().map(Cow::Borrowed))
                .eq_ignore_ascii_case(schema)
        };
        let named: Vec<&DB::Function> = database
            .functions()
            .filter(|function| {
                function.name().eq_ignore_ascii_case(name)
                    && function.accepts_argument_count(arguments)
            })
            .collect();
        let schema = schema.map(Cow::Borrowed).or_else(|| {
            database
                .search_path()
                .map(|(path, quoted)| normalize_identifier(path, quoted))
                .find(|path| named.iter().any(|function| declared_in(function, path)))
        });
        named
            .into_iter()
            .filter(|function| {
                schema
                    .as_deref()
                    .is_some_and(|schema| declared_in(function, schema))
            })
            .any(|function| self.writes(function))
    }

    /// Whether a function's body writes a credential setting, directly or
    /// through the functions it calls.
    fn writes(&mut self, function: &DB::Function) -> bool {
        let identity = format!(
            "{}.{}",
            schema_of(
                self.database,
                function.target_name().schema().map(Cow::Borrowed)
            ),
            signature(function, self.database)
        );
        if let Some(writes) = self.writers.get(&identity) {
            return *writes;
        }
        self.writers.insert(identity.clone(), false);
        let writes = match function.written_body() {
            Some(FunctionBody::Text(body)) => self.body_writes(body),
            Some(FunctionBody::Statements(statements)) => statements
                .iter()
                .any(|statement| self.node_writes(statement)),
            Some(FunctionBody::Expression(expression)) => self.node_writes(expression),
            Some(FunctionBody::Select(select)) => self.node_writes(select),
            Some(
                FunctionBody::Return(_)
                | FunctionBody::Atomic(_)
                | FunctionBody::BoundDefinition(_),
            )
            | None => {
                function
                    .body_expression(self.database)
                    .ok()
                    .flatten()
                    .is_some_and(|body| self.node_writes(body.as_ref()))
                    || function
                        .atomic_statements(self.database)
                        .ok()
                        .flatten()
                        .is_some_and(|statements| {
                            statements
                                .iter()
                                .any(|statement| self.node_writes(statement))
                        })
            }
        };
        self.writers.insert(identity, writes);
        writes
    }

    /// Whether a parsed body writes a credential setting.
    fn node_writes<V: Visit + ?Sized>(&mut self, node: &V) -> bool {
        let mut writes = Writes {
            credentials: self,
            found: Vec::new(),
        };
        let _ = node.visit(&mut writes);
        !writes.found.is_empty()
    }

    /// Whether a function body, in SQL or PL/pgSQL, writes a credential
    /// setting, read as tokens so either language is covered.
    fn body_writes(&mut self, body: &str) -> bool {
        let tokens = Tokenizer::new(&PostgreSqlDialect {}, body)
            .tokenize()
            .unwrap_or_default();
        let tokens: Vec<&Token> = tokens
            .iter()
            .filter(|token| !matches!(token, Token::Whitespace(_)))
            .collect();
        (0..tokens.len()).any(|at| self.writes_at(&tokens, at))
    }

    /// Whether the body tokens starting at `at` write a credential setting:
    /// a `set_config` call, a call to a writing function, or a `SET` or
    /// `RESET` of a credential setting or of every setting.
    fn writes_at(&mut self, tokens: &[&Token], at: usize) -> bool {
        let Some(Token::Word(word)) = tokens.get(at) else {
            return false;
        };
        let rest = &tokens[at + 1..];
        if let Some(Token::LParen) = rest.first() {
            if word.value.eq_ignore_ascii_case("set_config") {
                return match rest.get(1) {
                    Some(Token::SingleQuotedString(key)) => self.key(key).is_some(),
                    _ => true,
                };
            }
            let schema = match at
                .checked_sub(2)
                .map(|before| (tokens[before], tokens[at - 1]))
            {
                Some((Token::Word(schema), Token::Period)) => Some(schema.value.as_str()),
                _ => None,
            };
            return self.calls_writer(schema, &word.value, token_arguments(rest));
        }
        let rest = match (word.keyword, rest.first()) {
            (Keyword::SET, Some(Token::Word(scope)))
                if matches!(scope.keyword, Keyword::SESSION | Keyword::LOCAL) =>
            {
                &rest[1..]
            }
            (Keyword::SET | Keyword::RESET, _) => rest,
            _ => return false,
        };
        if word.keyword == Keyword::RESET
            && matches!(rest.first(), Some(Token::Word(all)) if all.keyword == Keyword::ALL)
        {
            return true;
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
        self.key(&parts.join(".")).is_some()
    }
}

/// Collects the credential writes of a statement or expression.
struct Writes<'run, 'db, DB: DatabaseLike> {
    credentials: &'run mut Credentials<'db, DB>,
    found: Vec<(String, Write)>,
}

impl<DB: DatabaseLike> Visitor for Writes<'_, '_, DB> {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        if let Some(write) = self.credentials.statement(statement) {
            self.found.push((statement.to_string(), write));
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        let Expr::Function(function) = expression else {
            return ControlFlow::Continue(());
        };
        let write = self.credentials.set_config(function).or_else(|| {
            let (schema, name) = split(&function.name)?;
            let arguments = match &function.args {
                FunctionArguments::List(list) => list.args.len(),
                _ => 0,
            };
            self.credentials
                .calls_writer(schema, name, arguments)
                .then_some(Write::Call)
        });
        if let Some(write) = write {
            self.found.push((expression.to_string(), write));
        }
        ControlFlow::Continue(())
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
/// use sql_rules::prelude::*;
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
            name: "CredentialSettingWrite",
            group: LintGroup::Correctness,
            rationale: "A client that writes the setting policies read as the caller's identity can act as any user.",
            source: Some("https://www.postgresql.org/docs/current/functions-admin.html"),
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
        let mut credentials = Credentials::new(database, reporter.deployment());
        let mut writes = Writes {
            credentials: &mut credentials,
            found: Vec::new(),
        };
        let _ = statement.visit(&mut writes);
        for (found, write) in writes.found {
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
