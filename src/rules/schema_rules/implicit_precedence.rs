//! Submodule providing the `ImplicitPrecedence` rule.

use std::{convert::Infallible, fmt, ops::ControlFlow};

use sql_traits::{errors::LookupError, traits::DatabaseLike};
use sqlparser::ast::{BinaryOperator, Expr, Statement, UnaryOperator, Visit, Visitor};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Struct defining a rule that reports two different operators meeting
/// without parentheses, so that operator precedence alone decides how they
/// group.
///
/// Engines rank operators differently. Measured on SQLite and PostgreSQL 18,
/// `'a' || 1 + 2` gave `2` and `a3`, `jsonb ->> 'a' + 1` gave `2` and an
/// error, and `3 = 1 < 2` gave `0` and a syntax error. Mixes both engines
/// group alike, such as `a AND b OR c` or `NOT a = b`, still leave a reader
/// in doubt. Three layers every engine and reader groups alike are exempt,
/// `*`, `/` and `%` inside `+` and `-`, arithmetic and signs inside a
/// comparison, and comparisons inside `AND` and `OR`. So are an operator
/// chained with itself, `+` with `-`, `*` with `/`, a sign inside
/// arithmetic, chains of the JSON access operators, a `NOT` over a plain
/// operand inside `AND` and `OR`, and every operand that syntax already
/// delimits, such as a call argument, an `IN` list element or a `CASE`
/// branch. Two comparisons, as in `a = b = c` or `a IS NULL = b`, are
/// reported. The grouping judged is the one the schema's parser produced.
/// The rule reads views, materialized views, policies, table check
/// constraints, SQL and PL/pgSQL function bodies and, as a query rule,
/// statements.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ImplicitPrecedence::default().into();
/// let implicit = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (a BOOL, b BOOL, c BOOL); CREATE VIEW v AS SELECT a AND b OR c FROM t;",
/// ).unwrap();
/// assert!(!constrainer.diagnostics(&implicit).is_empty());
/// let explicit = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (a BOOL, b BOOL, c BOOL); CREATE VIEW v AS SELECT (a AND b) OR c FROM t;",
/// ).unwrap();
/// assert!(constrainer.diagnostics(&explicit).is_empty());
/// ```
pub struct ImplicitPrecedence<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ImplicitPrecedence<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ImplicitPrecedence<DB>> for GenericConstrainer<DB> {
    fn from(rule: ImplicitPrecedence<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(ImplicitPrecedence::default()));
        constrainer
    }
}

impl<DB> Rule for ImplicitPrecedence<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(ImplicitPrecedence),
            group: LintGroup::Style,
            rationale: "Operator precedence differs between engines and leaves readers in doubt about how mixed operators group.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-PRECEDENCE",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE t (a BOOL, b BOOL, c BOOL);\nSELECT a AND b OR c FROM t;",
                good: "CREATE TABLE t (a BOOL, b BOOL, c BOOL);\nSELECT (a AND b) OR c FROM t;",
            },
        };
        &METADATA
    }
}

/// An operator's identity without allocating its spelling.
#[derive(Clone, Copy, PartialEq)]
enum Operator<'expression> {
    Binary(&'expression BinaryOperator),
    Unary(&'expression UnaryOperator),
    Comparison(&'static str),
    Quantified(&'expression BinaryOperator, &'static str),
    TimeZone,
}

impl fmt::Display for Operator<'_> {
    /// Writes the operator's SQL spelling.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binary(operator) => operator.fmt(formatter),
            Self::Unary(operator) => operator.fmt(formatter),
            Self::Comparison(name) => formatter.write_str(name),
            Self::Quantified(operator, quantifier) => write!(formatter, "{operator} {quantifier}"),
            Self::TimeZone => formatter.write_str("AT TIME ZONE"),
        }
    }
}

/// Identifies operators while leaving syntactic delimiters opaque.
fn operator(expression: &Expr) -> Option<Operator<'_>> {
    Some(match expression {
        Expr::BinaryOp { op: operator, .. } => Operator::Binary(operator),
        Expr::UnaryOp { op: operator, .. } => Operator::Unary(operator),
        Expr::IsNull(_) => Operator::Comparison("IS NULL"),
        Expr::IsNotNull(_) => Operator::Comparison("IS NOT NULL"),
        Expr::IsTrue(_) => Operator::Comparison("IS TRUE"),
        Expr::IsNotTrue(_) => Operator::Comparison("IS NOT TRUE"),
        Expr::IsFalse(_) => Operator::Comparison("IS FALSE"),
        Expr::IsNotFalse(_) => Operator::Comparison("IS NOT FALSE"),
        Expr::IsUnknown(_) => Operator::Comparison("IS UNKNOWN"),
        Expr::IsNotUnknown(_) => Operator::Comparison("IS NOT UNKNOWN"),
        Expr::IsDistinctFrom(..) => Operator::Comparison("IS DISTINCT FROM"),
        Expr::IsNotDistinctFrom(..) => Operator::Comparison("IS NOT DISTINCT FROM"),
        Expr::In { negated, .. } => Operator::Comparison(if *negated { "NOT IN" } else { "IN" }),
        Expr::Between { negated, .. } => {
            Operator::Comparison(if *negated { "NOT BETWEEN" } else { "BETWEEN" })
        }
        Expr::Like { negated, .. } => {
            Operator::Comparison(if *negated { "NOT LIKE" } else { "LIKE" })
        }
        Expr::ILike { negated, .. } => {
            Operator::Comparison(if *negated { "NOT ILIKE" } else { "ILIKE" })
        }
        Expr::SimilarTo { negated, .. } => Operator::Comparison(if *negated {
            "NOT SIMILAR TO"
        } else {
            "SIMILAR TO"
        }),
        Expr::RLike {
            negated, regexp, ..
        } => Operator::Comparison(match (*negated, *regexp) {
            (false, false) => "RLIKE",
            (true, false) => "NOT RLIKE",
            (false, true) => "REGEXP",
            (true, true) => "NOT REGEXP",
        }),
        Expr::AnyOp {
            compare_op,
            is_some,
            ..
        } => Operator::Quantified(compare_op, if *is_some { "SOME" } else { "ANY" }),
        Expr::AllOp { compare_op, .. } => Operator::Quantified(compare_op, "ALL"),
        Expr::AtTimeZone { .. } => Operator::TimeZone,
        _ => return None,
    })
}

impl Operator<'_> {
    /// Recognizes binary addition and subtraction.
    fn additive(self) -> bool {
        matches!(
            self,
            Self::Binary(BinaryOperator::Plus | BinaryOperator::Minus)
        )
    }

    /// Recognizes multiplication, division and remainder.
    fn multiplicative(self) -> bool {
        matches!(
            self,
            Self::Binary(
                BinaryOperator::Multiply | BinaryOperator::Divide | BinaryOperator::Modulo
            )
        )
    }

    /// Recognizes unary signs.
    fn sign(self) -> bool {
        matches!(
            self,
            Self::Unary(UnaryOperator::Minus | UnaryOperator::Plus)
        )
    }

    /// Recognizes arithmetic in the universally readable layers.
    fn arithmetic(self) -> bool {
        self.additive() || self.multiplicative() || self.sign()
    }

    /// Recognizes comparisons in the universally readable layers.
    fn comparison(self) -> bool {
        matches!(
            self,
            Self::Comparison(_)
                | Self::Quantified(..)
                | Self::Binary(
                    BinaryOperator::Eq
                        | BinaryOperator::NotEq
                        | BinaryOperator::Lt
                        | BinaryOperator::LtEq
                        | BinaryOperator::Gt
                        | BinaryOperator::GtEq
                        | BinaryOperator::Glob
                        | BinaryOperator::Regexp
                        | BinaryOperator::Match
                )
        )
    }

    /// Recognizes JSON field and path access chains.
    fn json_access(self) -> bool {
        matches!(
            self,
            Self::Binary(
                BinaryOperator::Arrow
                    | BinaryOperator::LongArrow
                    | BinaryOperator::HashArrow
                    | BinaryOperator::HashLongArrow
            )
        )
    }

    /// Tests whether an unparenthesized operand belongs to an exempt layer.
    fn accepts(self, child: Self, expression: &Expr) -> bool {
        if self.comparison() && child.comparison() {
            return false;
        }
        self == child
            || (self.additive() && (child.additive() || child.multiplicative()))
            || (self.multiplicative() && child.multiplicative())
            || (self.arithmetic() && child.sign())
            || (self.comparison() && child.arithmetic())
            || (self.json_access() && child.json_access())
            || (matches!(self, Self::Binary(BinaryOperator::And | BinaryOperator::Or))
                && (child.comparison()
                    || matches!(expression,
                    Expr::UnaryOp { op: UnaryOperator::Not, expr } if operator(expr).is_none())))
    }
}

/// Exposes only operands not delimited by SQL syntax.
fn operands(expression: &Expr) -> [Option<&Expr>; 3] {
    match expression {
        Expr::BinaryOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => [Some(left), Some(right), None],
        Expr::UnaryOp { expr, .. }
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsTrue(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotFalse(expr)
        | Expr::IsUnknown(expr)
        | Expr::IsNotUnknown(expr)
        | Expr::In { expr, .. } => [Some(expr), None, None],
        Expr::Between {
            expr, low, high, ..
        } => [Some(expr), Some(low), Some(high)],
        Expr::Like {
            expr,
            pattern,
            escape_char,
            ..
        }
        | Expr::ILike {
            expr,
            pattern,
            escape_char,
            ..
        }
        | Expr::SimilarTo {
            expr,
            pattern,
            escape_char,
            ..
        } => [Some(expr), Some(pattern), escape_char.as_ref()],
        Expr::RLike { expr, pattern, .. } => [Some(expr), Some(pattern), None],
        Expr::AnyOp { left, .. } | Expr::AllOp { left, .. } => [Some(left), None, None],
        Expr::AtTimeZone {
            timestamp,
            time_zone,
        } => [Some(timestamp), Some(time_zone), None],
        _ => [None, None, None],
    }
    .map(|operand| operand.map(Box::as_ref))
}

/// Collects mixed operators with their explicit grouping.
#[derive(Default)]
struct Groupings(Vec<(String, String)>);

impl Visitor for Groupings {
    type Break = Infallible;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Infallible> {
        if let Some(parent) = operator(expression) {
            for (index, operand) in operands(expression).into_iter().enumerate() {
                if let Some(operand) = operand
                    && let Some(child) = operator(operand)
                    && !parent.accepts(child, operand)
                {
                    let mut explicit = expression.clone();
                    wrap_operand(&mut explicit, index);
                    self.0.push((
                        format!(
                            "`{expression}`, which mixes `{parent}` and `{child}` and reads as `{explicit}`"
                        ),
                        expression.to_string(),
                    ));
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// Wraps the selected direct operand without changing its parsed grouping.
fn wrap_operand(expression: &mut Expr, index: usize) {
    let operand = match expression {
        Expr::BinaryOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => {
            if index == 0 {
                left
            } else {
                right
            }
        }
        Expr::UnaryOp { expr, .. }
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsTrue(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotFalse(expr)
        | Expr::IsUnknown(expr)
        | Expr::IsNotUnknown(expr)
        | Expr::In { expr, .. } => expr,
        Expr::Between {
            expr, low, high, ..
        } => match index {
            0 => expr,
            1 => low,
            _ => high,
        },
        Expr::Like {
            expr,
            pattern,
            escape_char,
            ..
        }
        | Expr::ILike {
            expr,
            pattern,
            escape_char,
            ..
        }
        | Expr::SimilarTo {
            expr,
            pattern,
            escape_char,
            ..
        } => match index {
            0 => expr,
            1 => pattern,
            _ => {
                let Some(escape) = escape_char else {
                    return;
                };
                escape
            }
        },
        Expr::RLike { expr, pattern, .. } => {
            if index == 0 {
                expr
            } else {
                pattern
            }
        }
        Expr::AnyOp { left, .. } | Expr::AllOp { left, .. } => left,
        Expr::AtTimeZone {
            timestamp,
            time_zone,
        } => {
            if index == 0 {
                timestamp
            } else {
                time_zone
            }
        }
        _ => return,
    };
    let original = std::mem::replace(
        operand.as_mut(),
        Expr::Value(sqlparser::ast::Value::Null.into()),
    );
    **operand = Expr::Nested(Box::new(original));
}

/// Finds mixed operator pairs in schema and query expressions.
struct Finder;

impl ExpressionFinder for Finder {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        _database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let mut groupings = Groupings::default();
        let ControlFlow::Continue(()) = walk(node, &mut groupings);
        Ok(groupings.0)
    }

    fn problem(&self) -> &'static str {
        "so its grouping rests on operator precedence, which engines rank differently and readers misremember"
    }

    fn resolution(&self) -> &'static str {
        "Add parentheses that state the intended grouping."
    }
}

impl<DB: DatabaseLike> SchemaRule for ImplicitPrecedence<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&Finder, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for ImplicitPrecedence<DB> {
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
