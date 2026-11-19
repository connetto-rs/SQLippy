//! Submodule providing the `NonterminatingRecursiveCte` rule.

use std::ops::ControlFlow;

use sql_traits::{errors::LookupError, traits::DatabaseLike};
use sqlparser::ast::{
    BinaryOperator, Cte, DataType, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments,
    Ident, ObjectNamePart, Query, Statement, Value, Visit, Visitor,
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::{RecursiveItem, same_name},
        expression_site_support::{ExpressionFinder, check_schema, check_statement},
        policy_support::{conjuncts, unnested},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Finds the recursive `WITH` items a cycle in the walked data keeps running.
struct UnendingItems;

/// Collects the unending items of every `WITH RECURSIVE` clause a node holds.
#[derive(Default)]
struct Unending {
    found: Vec<(String, String)>,
}

impl Visitor for Unending {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        if let Some(with) = &query.with
            && with.recursive
        {
            for item in &with.cte_tables {
                if let Some(described) = unending(item) {
                    self.found.push((described, item.to_string()));
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// Why a cycle keeps `item` producing rows, or `None` when it stops.
fn unending(item: &Cte) -> Option<String> {
    let recursive = RecursiveItem::split(item)?;
    if bounded(&recursive) || consumed(&recursive) {
        return None;
    }
    if recursive.keeps_duplicates {
        return Some(format!(
            "the recursive `WITH` item '{}' combined with `UNION ALL`, which keeps every repeated row",
            item.alias.name
        ));
    }
    let grown = recursive
        .outputs()?
        .into_iter()
        .find(|output| grows(&recursive, output))?;
    Some(format!(
        "the recursive `WITH` item '{}' projecting `{grown}` from its working table, so `UNION` never meets a repeated row",
        item.alias.name
    ))
}

/// Whether a condition of the recursive term caps a counter the term moves
/// by a constant toward the cap on each step, which stops the walk on any
/// data.
fn bounded(recursive: &RecursiveItem<'_>) -> bool {
    recursive.conditions().into_iter().any(|condition| {
        let Expr::BinaryOp { left, op, right } = unnested(condition) else {
            return false;
        };
        let (lower, upper) = match op {
            BinaryOperator::Lt | BinaryOperator::LtEq => (left, right),
            BinaryOperator::Gt | BinaryOperator::GtEq => (right, left),
            _ => return false,
        };
        let capped = |counter: &Expr, limit: &Expr, toward: Step| {
            recursive
                .working_column(counter)
                .is_some_and(|column| step(recursive, column) == Some(toward))
                && steady(recursive, limit)
        };
        capped(lower, upper, Step::Up) || capped(upper, lower, Step::Down)
    })
}

/// Whether a condition of the recursive term rejects a NULL in a working
/// table column the term replaces on each step by NULL or by its part past a
/// separator found in it, so the column's length falls until the walk stops.
fn consumed(recursive: &RecursiveItem<'_>) -> bool {
    recursive.conditions().into_iter().any(|condition| {
        let rejected = match unnested(condition) {
            Expr::IsNotNull(operand) => recursive.working_column(operand),
            Expr::BinaryOp {
                left,
                op:
                    BinaryOperator::Eq
                    | BinaryOperator::NotEq
                    | BinaryOperator::Lt
                    | BinaryOperator::LtEq
                    | BinaryOperator::Gt
                    | BinaryOperator::GtEq,
                right,
            } => recursive
                .working_column(left)
                .or_else(|| recursive.working_column(right)),
            _ => None,
        };
        rejected.is_some_and(|column| shrinks(recursive, column))
    })
}

/// Whether the recursive term puts in `column`'s place only NULL or a
/// `substr` of `column` starting past a position its `CASE` branch found.
fn shrinks(recursive: &RecursiveItem<'_>, column: &Ident) -> bool {
    let Some(output) = recursive.outputs().and_then(|outputs| {
        recursive
            .position(column)
            .and_then(|position| outputs.get(position).copied())
    }) else {
        return false;
    };
    match unnested(output) {
        Expr::Case {
            operand: None,
            conditions,
            else_result,
            ..
        } => {
            conditions.iter().all(|branch| {
                null(&branch.result) || cut(recursive, column, &branch.condition, &branch.result)
            }) && else_result.as_deref().is_none_or(null)
        }
        other => null(other),
    }
}

/// Whether `expression` is the NULL literal.
fn null(expression: &Expr) -> bool {
    matches!(unnested(expression), Expr::Value(value) if value.value == Value::Null)
}

/// Whether `result` is `substr(column, found + k)` with `k` a whole number
/// above zero and `found` a separator position that `guard` holds at least 1.
fn cut(recursive: &RecursiveItem<'_>, column: &Ident, guard: &Expr, result: &Expr) -> bool {
    let Expr::Substring {
        expr,
        substring_from: Some(start),
        substring_for: None,
        ..
    } = unnested(result)
    else {
        return false;
    };
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Plus,
        right,
    } = unnested(start)
    else {
        return false;
    };
    let past = |found: &Expr, offset: &Expr| {
        whole_at_least(offset, 1)
            && searches(recursive, column, found)
            && conjuncts(guard)
                .into_iter()
                .any(|condition| holds_found(condition, found))
    };
    recursive
        .working_column(expr)
        .is_some_and(|read| same_name(read, column))
        && (past(left, right) || past(right, left))
}

/// Whether `found` is `instr(column, separator)`, `strpos(column, separator)`
/// or `position(separator IN column)` with a string literal separator.
fn searches(recursive: &RecursiveItem<'_>, column: &Ident, found: &Expr) -> bool {
    let (text, separator) = match unnested(found) {
        Expr::Position { expr, r#in } => (r#in.as_ref(), expr.as_ref()),
        Expr::Function(function)
            if ["instr", "strpos"]
                .iter()
                .any(|known| called(function, known)) =>
        {
            let FunctionArguments::List(list) = &function.args else {
                return false;
            };
            let [
                FunctionArg::Unnamed(FunctionArgExpr::Expr(text)),
                FunctionArg::Unnamed(FunctionArgExpr::Expr(separator)),
            ] = list.args.as_slice()
            else {
                return false;
            };
            (text, separator)
        }
        _ => return false,
    };
    recursive
        .working_column(text)
        .is_some_and(|read| same_name(read, column))
        && matches!(
            unnested(separator),
            Expr::Value(value) if matches!(value.value, Value::SingleQuotedString(_))
        )
}

/// Whether `condition` holds `found` at least 1, as `found > 0` or
/// `found >= 1` does.
fn holds_found(condition: &Expr, found: &Expr) -> bool {
    let Expr::BinaryOp { left, op, right } = unnested(condition) else {
        return false;
    };
    let (position, bound, least) = match op {
        BinaryOperator::Gt => (left, right, 0),
        BinaryOperator::GtEq => (left, right, 1),
        BinaryOperator::Lt => (right, left, 0),
        BinaryOperator::LtEq => (right, left, 1),
        _ => return false,
    };
    unnested(position) == unnested(found) && whole_at_least(bound, least)
}

/// Whether `expression` is a whole number literal of at least `least`.
fn whole_at_least(expression: &Expr, least: u64) -> bool {
    matches!(
        unnested(expression),
        Expr::Value(value) if matches!(
            &value.value,
            Value::Number(number, _) if number.parse::<u64>().is_ok_and(|number| number >= least)
        )
    )
}

/// Whether an output of the recursive term computes a new value from the
/// working table on each step, as a counter or a path does.
fn grows(recursive: &RecursiveItem<'_>, output: &Expr) -> bool {
    match unnested(output) {
        Expr::BinaryOp {
            left,
            op:
                BinaryOperator::Plus
                | BinaryOperator::Minus
                | BinaryOperator::Multiply
                | BinaryOperator::StringConcat,
            right,
        } => recursive.reads_working(left) || recursive.reads_working(right),
        Expr::Function(function) => accumulates(function) && recursive.reads_working(output),
        _ => false,
    }
}

/// Whether `function` is a built-in that appends to an array or a string.
fn accumulates(function: &Function) -> bool {
    [
        "array_append",
        "array_prepend",
        "array_cat",
        "concat",
        "concat_ws",
    ]
    .iter()
    .any(|known| called(function, known))
}

/// Whether `function` calls the catalog function `known`, unqualified or in
/// `pg_catalog`.
fn called(function: &Function, known: &str) -> bool {
    let named = match function.name.0.as_slice() {
        [ObjectNamePart::Identifier(named)] => named,
        [
            ObjectNamePart::Identifier(schema),
            ObjectNamePart::Identifier(named),
        ] if spelled(schema, "pg_catalog") => named,
        _ => return false,
    };
    spelled(named, known)
}

/// Whether `identifier` names the lowercase catalog name `known`.
fn spelled(identifier: &Ident, known: &str) -> bool {
    if identifier.quote_style.is_none() {
        identifier.value.eq_ignore_ascii_case(known)
    } else {
        identifier.value == known
    }
}

/// Whether no working table column `limit` reads grows, so the cap cannot
/// move with the counter it caps.
fn steady(recursive: &RecursiveItem<'_>, limit: &Expr) -> bool {
    let outputs = recursive.outputs().unwrap_or_default();
    !recursive.reads_working_where(limit, |column| {
        recursive
            .position(column)
            .and_then(|position| outputs.get(position))
            .is_none_or(|output| grows(recursive, output))
    })
}

/// The way a counter moves on each step of the walk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Up,
    Down,
}

/// How the recursive term moves `column` by a positive constant in that
/// column's place, if it does.
fn step(recursive: &RecursiveItem<'_>, column: &Ident) -> Option<Step> {
    let outputs = recursive.outputs()?;
    let Expr::BinaryOp { left, op, right } = unnested(outputs.get(recursive.position(column)?)?)
    else {
        return None;
    };
    let moved = |operand: &Expr| {
        recursive
            .working_column(operand)
            .is_some_and(|read| same_name(read, column))
    };
    match op {
        BinaryOperator::Plus
            if (moved(left) && positive(right)) || (positive(left) && moved(right)) =>
        {
            Some(Step::Up)
        }
        BinaryOperator::Minus if moved(left) && positive(right) => Some(Step::Down),
        _ => None,
    }
}

/// Whether `expression` is a numeric literal above zero or an interval
/// literal that moves forward.
fn positive(expression: &Expr) -> bool {
    match unnested(expression) {
        Expr::Value(value) => {
            matches!(&value.value, Value::Number(number, _) if number.parse::<f64>().is_ok_and(|number| number > 0.0))
        }
        Expr::Interval(interval) => forward(&interval.value),
        Expr::Cast {
            expr,
            data_type: DataType::Interval { .. },
            ..
        } => forward(expr),
        _ => false,
    }
}

/// Whether `expression` is an interval string with a nonzero field and no
/// field that moves back.
fn forward(expression: &Expr) -> bool {
    matches!(
        unnested(expression),
        Expr::Value(value) if matches!(
            &value.value,
            Value::SingleQuotedString(text)
                if !text.contains('-')
                    && !text.as_bytes().windows(3).any(|word| word.eq_ignore_ascii_case(b"ago"))
                    && text.chars().any(|digit| matches!(digit, '1'..='9'))
        )
    )
}

impl ExpressionFinder for UnendingItems {
    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        _database: &DB,
        node: &V,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let mut unending = Unending::default();
        let _ = walk(node, &mut unending);
        Ok(unending.found)
    }

    fn problem(&self) -> &'static str {
        "so a cycle in the data it walks keeps it running until a timeout cancels it"
    }

    fn resolution(&self) -> &'static str {
        "Combine the terms with `UNION` and project only the walked key columns, or cap a counter the recursive term moves toward the cap, as `WHERE r.depth < 20` with `r.depth + 1`."
    }
}

/// Struct defining a rule that reports a `WITH RECURSIVE` item a cycle in
/// the data it walks keeps running.
///
/// PostgreSQL stops a recursive item once its recursive term yields no row
/// the working table lacks. Under `UNION ALL` every row is new, and under
/// `UNION` a column the term computes by arithmetic, concatenation or array
/// appending from the working table, such as a depth counter or a path
/// array, makes every row differ, so once the walked rows hold a cycle the
/// walk never ends. A condition in the term's `WHERE` or inner join `ON`
/// that caps a counter the term moves toward the cap by a positive constant
/// or interval on each step stops it on any data. So does one rejecting
/// NULL in a text column the term replaces by NULL or by its part past a
/// separator `instr`, `strpos` or `position` found in it, as splitting a
/// delimited string does. The rule reads views, materialized views,
/// policies, SQL and PL/pgSQL function bodies and, as a query rule,
/// statements.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NonterminatingRecursiveCte::default().into();
/// let schema = "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT);";
/// let unending = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW below AS WITH RECURSIVE r(id) AS (SELECT 1 \
///      UNION ALL SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&unending).is_err());
/// let ending = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE VIEW below AS WITH RECURSIVE r(id) AS (SELECT 1 \
///      UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&ending).is_ok());
/// ```
pub struct NonterminatingRecursiveCte<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NonterminatingRecursiveCte<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NonterminatingRecursiveCte<DB>> for GenericConstrainer<DB> {
    fn from(rule: NonterminatingRecursiveCte<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(NonterminatingRecursiveCte::default()));
        constrainer
    }
}

impl<DB> Rule for NonterminatingRecursiveCte<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NonterminatingRecursiveCte),
            group: LintGroup::Correctness,
            rationale: "A recursive WITH item stops only when its recursive term yields no new row, which UNION ALL, or UNION over a counter or path computed from the working table, never allows once the walked data holds a cycle, so one write closing a cycle makes every read through the item run until a timeout cancels it.",
            source: Some(
                "https://www.postgresql.org/docs/18/queries-with.html#QUERIES-WITH-RECURSIVE",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT REFERENCES groups (id));\n\
CREATE INDEX groups_parent ON groups (parent_id);\n\
CREATE VIEW below_one AS WITH RECURSIVE r(id) AS (SELECT 1 UNION ALL SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r;",
                good: "CREATE TABLE groups (id INT PRIMARY KEY, parent_id INT REFERENCES groups (id));\n\
CREATE INDEX groups_parent ON groups (parent_id);\n\
CREATE VIEW below_one AS WITH RECURSIVE r(id) AS (SELECT 1 UNION SELECT g.id FROM groups AS g JOIN r ON g.parent_id = r.id) SELECT id FROM r;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> SchemaRule for NonterminatingRecursiveCte<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_schema(&UnendingItems, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for NonterminatingRecursiveCte<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_statement(&UnendingItems, database, statement, reporter)
    }
}
