//! Submodule providing the `NilUuidSentinel` rule.

use std::{convert::Infallible, ops::ControlFlow};

use sql_traits::{errors::LookupError, traits::DatabaseLike};
use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, InTarget,
    Statement, Visit, Visitor,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        function_reach_support::split,
        literal_support::string_value,
        policy_support::conjuncts,
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Struct defining a rule that reports a test of a value against the nil
/// UUID, `00000000-0000-0000-0000-000000000000`, standing for a missing
/// value.
///
/// SQL marks absence with `NULL`, and a nil UUID sentinel replaces it with a
/// convention every reader must know and every writer must bind. The rule
/// reports `=`, `<>`, `IS [NOT] DISTINCT FROM`, `[NOT] IN`, `= ANY`,
/// `<> ALL`, a simple `CASE` and `NULLIF` with the nil UUID, in every
/// spelling PostgreSQL's uuid input reads as it and as `uuid_nil()`. A check
/// constraint whose top-level `AND` rejects the nil UUID keeps the sentinel
/// out of the stored rows and is not reported. The rule reads views,
/// materialized views, policies, table check constraints, SQL and PL/pgSQL
/// function bodies and, as a query rule, statements.
/// `NULLIF(current_setting(name, true), '')` reads an unset request setting
/// as `NULL`, which `IS NULL` tests directly.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NilUuidSentinel::default().into();
/// let sentinel = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id UUID, installation_id UUID);
///      CREATE POLICY p ON docs USING (
///        current_setting('app.installation_id', true)::uuid = '00000000-0000-0000-0000-000000000000'
///        OR installation_id = current_setting('app.installation_id', true)::uuid);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&sentinel).is_err());
/// let absent = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id UUID, installation_id UUID);
///      CREATE POLICY p ON docs USING (
///        NULLIF(current_setting('app.installation_id', true), '')::uuid IS NULL
///        OR installation_id = NULLIF(current_setting('app.installation_id', true), '')::uuid);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&absent).is_ok());
/// ```
pub struct NilUuidSentinel<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NilUuidSentinel<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NilUuidSentinel<DB>> for GenericConstrainer<DB> {
    fn from(rule: NilUuidSentinel<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(NilUuidSentinel::default()));
        constrainer
    }
}

impl<DB> Rule for NilUuidSentinel<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NilUuidSentinel),
            group: LintGroup::Suspicious,
            rationale: "A test against the nil UUID encodes absence as a magic value every writer must bind and every reader must know, where NULL states it directly.",
            source: Some("https://www.rfc-editor.org/rfc/rfc9562#section-5.9"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (id UUID PRIMARY KEY, installation_id UUID);\n\
CREATE POLICY docs_installation ON docs USING (\n\
  current_setting('app.installation_id', true)::uuid = '00000000-0000-0000-0000-000000000000'\n\
  OR installation_id = current_setting('app.installation_id', true)::uuid);",
                good: "CREATE TABLE docs (id UUID PRIMARY KEY, installation_id UUID);\n\
CREATE POLICY docs_installation ON docs USING (\n\
  NULLIF(current_setting('app.installation_id', true), '')::uuid IS NULL\n\
  OR installation_id = NULLIF(current_setting('app.installation_id', true), '')::uuid);",
            },
        };
        &METADATA
    }
}

/// Whether PostgreSQL's uuid input reads `text` as the nil UUID: 32 zero
/// digits with a hyphen allowed after any group of four but the last, the
/// whole optionally in braces.
fn is_nil_uuid_text(text: &str) -> bool {
    let digits = match text.strip_prefix('{') {
        Some(braced) => match braced.strip_suffix('}') {
            Some(digits) => digits,
            None => return false,
        },
        None => text,
    };
    let mut bytes = digits.bytes().peekable();
    for group in 0..8 {
        for _ in 0..4 {
            if bytes.next() != Some(b'0') {
                return false;
            }
        }
        if group < 7 {
            bytes.next_if_eq(&b'-');
        }
    }
    bytes.next().is_none()
}

/// Whether PostgreSQL's array input reads an element of `text` as the nil
/// UUID, after its dimension decoration, around each element's unquoted
/// whitespace and through its quotes and backslash escapes.
fn array_holds_nil(text: &str) -> bool {
    let body = if text.starts_with('[') {
        match text.split_once('=') {
            Some((_, body)) => body,
            None => return false,
        }
    } else {
        text
    };
    let mut element = String::new();
    let mut kept = 0;
    let mut quoted = false;
    let mut escaped = false;
    for character in body.chars() {
        if escaped {
            escaped = false;
            element.push(character);
            kept = element.len();
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => {
                quoted = !quoted;
                kept = element.len();
            }
            '{' | '}' | ',' if !quoted => {
                element.truncate(kept);
                if is_nil_uuid_text(&element) {
                    return true;
                }
                element.clear();
                kept = 0;
            }
            ' ' | '\t' | '\n' | '\r' | '\x0B' | '\x0C' if !quoted => {
                if !element.is_empty() {
                    element.push(character);
                }
            }
            _ => {
                element.push(character);
                kept = element.len();
            }
        }
    }
    false
}

/// Whether `function` is a `uuid_nil()` call, in any schema `uuid-ossp`
/// was installed in.
fn is_uuid_nil_call(function: &Function) -> bool {
    split(&function.name).is_some_and(|(_, name)| name.eq_ignore_ascii_case("uuid_nil"))
        && matches!(&function.args, FunctionArguments::List(list) if list.args.is_empty())
}

/// Whether `expression`, under casts and parentheses, is the nil UUID.
fn is_nil(mut expression: &Expr) -> bool {
    loop {
        match expression {
            Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => expression = inner,
            Expr::Value(literal) => {
                return string_value(&literal.value).is_some_and(is_nil_uuid_text);
            }
            Expr::TypedString(typed) => {
                return string_value(&typed.value.value).is_some_and(is_nil_uuid_text);
            }
            Expr::Function(function) => return is_uuid_nil_call(function),
            _ => return false,
        }
    }
}

/// Whether the array `expression`, under casts and parentheses, holds the
/// nil UUID, written `ARRAY[...]` or as an array literal.
fn holds_nil(mut expression: &Expr) -> bool {
    loop {
        match expression {
            Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => expression = inner,
            Expr::Array(array) => {
                return array
                    .elem
                    .iter()
                    .any(|element| is_nil(element) || holds_nil(element));
            }
            Expr::Value(literal) => {
                return string_value(&literal.value).is_some_and(array_holds_nil);
            }
            _ => return false,
        }
    }
}

/// Whether `function` is a `NULLIF` whose second argument is the nil UUID.
fn is_nullif_of_nil(function: &Function) -> bool {
    matches!(split(&function.name), Some((None, name)) if name.eq_ignore_ascii_case("nullif"))
        && matches!(
            &function.args,
            FunctionArguments::List(list) if matches!(
                list.args.as_slice(),
                [_, FunctionArg::Unnamed(FunctionArgExpr::Expr(second))] if is_nil(second)
            )
        )
}

/// Whether `expression` tests a value against the nil UUID.
fn tests_nil(expression: &Expr) -> bool {
    match expression {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq | BinaryOperator::NotEq,
            right,
        }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => is_nil(left) || is_nil(right),
        Expr::In { expr, target, .. } => {
            is_nil(expr) || matches!(target, InTarget::List(list) if list.iter().any(is_nil))
        }
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq | BinaryOperator::NotEq,
            right,
            ..
        }
        | Expr::AllOp {
            left,
            compare_op: BinaryOperator::Eq | BinaryOperator::NotEq,
            right,
        } => is_nil(left) || holds_nil(right),
        Expr::Case {
            operand: Some(operand),
            conditions,
            ..
        } => is_nil(operand) || conditions.iter().any(|when| is_nil(&when.condition)),
        Expr::Function(function) => is_nullif_of_nil(function),
        _ => false,
    }
}

/// Whether `expression` rejects the nil UUID, written `x <> nil`,
/// `x IS DISTINCT FROM nil` or `x NOT IN (..., nil, ...)`.
fn rejects_nil(expression: &Expr) -> bool {
    match expression {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::NotEq,
            right,
        }
        | Expr::IsDistinctFrom(left, right) => is_nil(left) || is_nil(right),
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated: true,
            ..
        } => !is_nil(expr) && list.iter().any(is_nil),
        _ => false,
    }
}

/// Collects the tests against the nil UUID, skipping the `exempt` ones.
struct SentinelTests<'e> {
    exempt: Vec<&'e Expr>,
    found: Vec<String>,
}

impl Visitor for SentinelTests<'_> {
    type Break = Infallible;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Infallible> {
        if tests_nil(expression)
            && !self
                .exempt
                .iter()
                .any(|exempt| std::ptr::eq(*exempt, expression))
        {
            self.found.push(expression.to_string());
        }
        ControlFlow::Continue(())
    }
}

/// The tests against the nil UUID in `node` but the `exempt` ones, each
/// described and rendered as SQL.
fn sentinel_tests<V: Visit + ?Sized>(node: &V, exempt: Vec<&Expr>) -> Vec<(String, String)> {
    let mut tests = SentinelTests {
        exempt,
        found: Vec::new(),
    };
    let ControlFlow::Continue(()) = walk(node, &mut tests);
    tests
        .found
        .into_iter()
        .map(|test| (format!("`{test}`"), test))
        .collect()
}

/// Finds and explains tests against the nil UUID.
struct Finder(Engine);

impl ExpressionFinder for Finder {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        _database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        Ok(sentinel_tests(node, Vec::new()))
    }

    /// Skips the top-level conjuncts that reject the nil UUID, which keep
    /// the sentinel out of the stored rows.
    fn find_in_check<DB: DatabaseLike>(
        &self,
        _database: &DB,
        expression: &Expr,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let exempt = conjuncts(expression)
            .into_iter()
            .filter(|conjunct| rejects_nil(conjunct))
            .collect();
        Ok(sentinel_tests(expression, exempt))
    }

    fn problem(&self) -> &'static str {
        "which encodes absence as a magic value every writer must bind and every reader must know, where NULL states it directly"
    }

    fn resolution(&self) -> &'static str {
        match self.0 {
            Engine::PostgreSql => {
                "Leave a missing value NULL and test it with IS NULL or IS NOT NULL, reading an unset setting as NULL with NULLIF(current_setting(name, true), '')."
            }
            Engine::Sqlite => "Leave a missing value NULL and test it with IS NULL or IS NOT NULL.",
        }
    }
}

impl<DB: DatabaseLike> SchemaRule for NilUuidSentinel<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&Finder(Engine::of(database)), database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for NilUuidSentinel<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&Finder(Engine::of(database)), database, statement, reporter)
    }
}
