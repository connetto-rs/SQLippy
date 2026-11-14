//! Whether a statement or an expression reaches something a rule looks for,
//! directly or through the SQL and PL/pgSQL bodies of the functions it calls.

use std::{borrow::Cow, collections::HashMap, ops::ControlFlow};

use sql_traits::{
    structs::FunctionBody,
    traits::{DatabaseLike, FunctionLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::{
    ast::{
        Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, ObjectName, Statement,
        Value, ValueWithSpan, Visit, Visitor,
    },
    dialect::PostgreSqlDialect,
    tokenizer::{Token, Tokenizer},
};

use crate::{
    rules::{grant_support::schema_of, walk_support::walk},
    traits::reporter::signature,
};

/// The last part of a name and the schema before it, if any.
pub(crate) fn split(name: &ObjectName) -> Option<(Option<&str>, &str)> {
    let mut parts = name.0.iter().rev();
    let last = parts.next()?.as_ident()?;
    let schema = parts
        .next()
        .and_then(|part| part.as_ident())
        .map(|ident| ident.value.as_str());
    Some((schema, last.value.as_str()))
}

/// The string literal a call passes as its first argument.
pub(crate) fn literal_key(function: &Function) -> Option<&str> {
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

/// Whether `function` calls the function named `name`, in any schema.
pub(crate) fn calls(function: &Function, name: &str) -> bool {
    split(&function.name).is_some_and(|(_, called)| called.eq_ignore_ascii_case(name))
}

/// The number of arguments of the call whose opening parenthesis starts
/// `tokens`.
pub(crate) fn token_arguments(tokens: &[&Token]) -> usize {
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

/// What a rule looks for, beyond calls to the functions that reach it.
pub(crate) trait Sought {
    /// What one occurrence is.
    type Found;

    /// The occurrence a parsed expression is itself, if any. A call that is
    /// not one is followed into the function it reaches.
    fn expression(&self, expression: &Expr) -> Option<Self::Found>;

    /// The occurrence a parsed statement is itself, if any.
    fn statement(&self, statement: &Statement) -> Option<Self::Found>;

    /// Whether the body tokens starting at `at` hold an occurrence, or
    /// `None` when they hold nothing the rule looks for, so a call there is
    /// followed into the function it reaches.
    fn tokens(&self, tokens: &[&Token], at: usize) -> Option<bool>;

    /// The occurrence a call to a function that reaches one stands for.
    fn call(&self) -> Self::Found;
}

/// Follows calls into the bodies of the functions they reach, remembering
/// each function's answer by its identity.
pub(crate) struct Reach<'db, DB: DatabaseLike, S> {
    database: &'db DB,
    sought: S,
    reached: HashMap<String, bool>,
}

impl<'db, DB: DatabaseLike, S: Sought> Reach<'db, DB, S> {
    pub(crate) fn new(database: &'db DB, sought: S) -> Self {
        Self {
            database,
            sought,
            reached: HashMap::new(),
        }
    }

    /// The occurrences in `node`, rendered, with what each one is: those it
    /// holds and the calls to functions that reach one.
    pub(crate) fn occurrences<V: Visit + ?Sized>(&mut self, node: &V) -> Vec<(String, S::Found)> {
        let mut occurrences = Occurrences {
            reach: self,
            found: Vec::new(),
        };
        let _ = walk(node, &mut occurrences);
        occurrences.found
    }

    /// Whether the function a call to `name` with `arguments` arguments
    /// reaches holds an occurrence. A call without a schema reaches the first
    /// schema on the search path that holds a function of that name
    /// accepting that many arguments.
    fn calls_reaching(&mut self, schema: Option<&str>, name: &str, arguments: usize) -> bool {
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
            .any(|function| self.reaches(function))
    }

    /// Whether a function's body holds an occurrence, directly or through
    /// the functions it calls.
    fn reaches(&mut self, function: &DB::Function) -> bool {
        let identity = format!(
            "{}.{}",
            schema_of(
                self.database,
                function.target_name().schema().map(Cow::Borrowed)
            ),
            signature(function, self.database)
        );
        if let Some(reaches) = self.reached.get(&identity) {
            return *reaches;
        }
        self.reached.insert(identity.clone(), false);
        let reaches = match function.written_body() {
            Some(FunctionBody::Text(body)) => self.body_reaches(body),
            Some(FunctionBody::Statements(statements)) => statements
                .iter()
                .any(|statement| self.node_reaches(statement)),
            Some(FunctionBody::Expression(expression)) => self.node_reaches(expression),
            Some(FunctionBody::Select(select)) => self.node_reaches(select),
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
                    .is_some_and(|body| self.node_reaches(body.as_ref()))
                    || function
                        .atomic_statements(self.database)
                        .ok()
                        .flatten()
                        .is_some_and(|statements| {
                            statements
                                .iter()
                                .any(|statement| self.node_reaches(statement))
                        })
            }
        };
        self.reached.insert(identity, reaches);
        reaches
    }

    /// Whether a parsed body holds an occurrence.
    fn node_reaches<V: Visit + ?Sized>(&mut self, node: &V) -> bool {
        !self.occurrences(node).is_empty()
    }

    /// Whether a function body, in SQL or PL/pgSQL, holds an occurrence,
    /// read as tokens so either language is covered.
    fn body_reaches(&mut self, body: &str) -> bool {
        let tokens = Tokenizer::new(&PostgreSqlDialect {}, body)
            .tokenize()
            .unwrap_or_default();
        let tokens: Vec<&Token> = tokens
            .iter()
            .filter(|token| !matches!(token, Token::Whitespace(_)))
            .collect();
        (0..tokens.len()).any(|at| self.reaches_at(&tokens, at))
    }

    /// Whether the body tokens starting at `at` hold an occurrence or call a
    /// function that reaches one.
    fn reaches_at(&mut self, tokens: &[&Token], at: usize) -> bool {
        if let Some(found) = self.sought.tokens(tokens, at) {
            return found;
        }
        let Some(Token::Word(word)) = tokens.get(at) else {
            return false;
        };
        let rest = &tokens[at + 1..];
        if !matches!(rest.first(), Some(Token::LParen)) {
            return false;
        }
        let schema = match at
            .checked_sub(2)
            .map(|before| (tokens[before], tokens[at - 1]))
        {
            Some((Token::Word(schema), Token::Period)) => Some(schema.value.as_str()),
            _ => None,
        };
        self.calls_reaching(schema, &word.value, token_arguments(rest))
    }
}

/// Collects the occurrences of a statement or expression.
struct Occurrences<'r, 'db, DB: DatabaseLike, S: Sought> {
    reach: &'r mut Reach<'db, DB, S>,
    found: Vec<(String, S::Found)>,
}

impl<DB: DatabaseLike, S: Sought> Visitor for Occurrences<'_, '_, DB, S> {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        if let Some(found) = self.reach.sought.statement(statement) {
            self.found.push((statement.to_string(), found));
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        let found = self.reach.sought.expression(expression).or_else(|| {
            let Expr::Function(function) = expression else {
                return None;
            };
            let (schema, name) = split(&function.name)?;
            let arguments = match &function.args {
                FunctionArguments::List(list) => list.args.len(),
                _ => 0,
            };
            self.reach
                .calls_reaching(schema, name, arguments)
                .then(|| self.reach.sought.call())
        });
        if let Some(found) = found {
            self.found.push((expression.to_string(), found));
        }
        ControlFlow::Continue(())
    }
}
