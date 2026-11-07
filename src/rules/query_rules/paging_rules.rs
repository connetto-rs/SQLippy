//! Submodule providing the rules on how a statement picks or pages rows.

use std::ops::ControlFlow;

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::{
    Expr, LimitClause, Offset, OrderByKind, Query, Statement, Value, ValueWithSpan, Visit, Visitor,
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// Collects one rendering per query of a statement that `pick` selects.
struct Queries<F> {
    pick: F,
    found: Vec<String>,
}

impl<F: FnMut(&Query) -> Option<String>> Visitor for Queries<F> {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        self.found.extend((self.pick)(query));
        ControlFlow::Continue(())
    }
}

/// Renderings of the queries of `statement` that `pick` selects.
fn queries(statement: &Statement, pick: impl FnMut(&Query) -> Option<String>) -> Vec<String> {
    let mut queries = Queries {
        pick,
        found: Vec::new(),
    };
    let _ = statement.visit(&mut queries);
    queries.found
}

/// Whether `expression` calls `random`.
fn is_random(expression: &Expr) -> bool {
    matches!(expression, Expr::Function(function) if function
        .name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .is_some_and(|name| name.value.eq_ignore_ascii_case("random")))
}

/// `ORDER BY` and the row cap of a query ordered by `random()` with a cap.
fn random_pick(query: &Query) -> Option<String> {
    let order_by = query.order_by.as_ref()?;
    if !matches!(&order_by.kind, OrderByKind::Expressions(keys) if keys.iter().any(|key| is_random(&key.expr)))
    {
        return None;
    }
    let cap = match (&query.limit_clause, &query.fetch) {
        (
            Some(
                LimitClause::LimitOffset {
                    limit: Some(limit), ..
                }
                | LimitClause::OffsetCommaLimit { limit, .. },
            ),
            _,
        ) => format!("LIMIT {limit}"),
        (_, Some(fetch)) => fetch.to_string(),
        _ => return None,
    };
    Some(format!("{order_by} {cap}"))
}

/// The `OFFSET` of a query, unless it is the literal `0`.
fn paging_offset(query: &Query) -> Option<String> {
    let (LimitClause::LimitOffset {
        offset: Some(Offset { value: offset, .. }),
        ..
    }
    | LimitClause::OffsetCommaLimit { offset, .. }) = query.limit_clause.as_ref()?
    else {
        return None;
    };
    // Expression evaluator: only the literal `0` counts as no offset. The
    // evaluator folds constant offsets such as `CAST(0 AS bigint)` too.
    if matches!(offset, Expr::Value(ValueWithSpan { value: Value::Number(number, _), .. }) if number == "0")
    {
        return None;
    }
    Some(format!("OFFSET {offset}"))
}

query_rule!(
    /// Struct defining a rule that reports `ORDER BY random()` with a `LIMIT`
    /// or `FETCH FIRST`, which picks a few random rows by sorting all of
    /// them.
    ///
    /// Measured on PostgreSQL 17.11 and 18.6 over 100,000 rows,
    /// `ORDER BY random() LIMIT 10` read every row in 9.5 to 9.9 ms.
    /// `TABLESAMPLE` is faster but not a fair sample, since `SYSTEM` picks
    /// whole pages and `BERNOULLI` with a `LIMIT` stops at the first rows it
    /// meets, so the rule explains the trade-off and is `pedantic`. A
    /// shuffle without a cap is not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = RandomOrderLimit::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT);").unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT id FROM t ORDER BY random() LIMIT 10").is_err());
    /// assert!(check("SELECT id FROM t ORDER BY random()").is_ok());
    /// ```
    RandomOrderLimit,
    LintGroup::Pedantic,
    "ORDER BY random() with a LIMIT sorts every row to keep a few, and the faster TABLESAMPLE methods do not draw a fair sample.",
    Some("https://www.postgresql.org/docs/current/sql-select.html")
);

impl<DB: DatabaseLike> QueryRule for RandomOrderLimit<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        _database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for found in queries(statement, random_pick) {
            reporter.statement(
                statement,
                found.clone(),
                format!("The statement uses `{found}`, which reads and sorts every row to keep a few."),
                "Keep it for small tables. For large ones, TABLESAMPLE SYSTEM reads a few pages but keeps whole pages, and TABLESAMPLE BERNOULLI with a LIMIT stops at the first sampled rows, which come from the start of the table, so neither is a fair sample.".to_owned(),
            )?;
        }
        Ok(())
    }
}

query_rule!(
    /// Struct defining a rule that reports `OFFSET` used for paging.
    ///
    /// The server computes and discards every skipped row, and a row
    /// inserted between pages shifts the next page. Measured on PostgreSQL
    /// 17.11 and 18.6, `OFFSET 90000` read 90,010 index entries in 7.0 to
    /// 7.2 ms where keyset paging read 10 in 0.02 to 0.04 ms. Small listings
    /// and jump-to-page navigation need `OFFSET`, so the rule is
    /// `pedantic`. The literal `OFFSET 0`, a planner fence that pages
    /// nothing, is not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = OffsetPaging::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT);").unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT id FROM t ORDER BY id LIMIT 10 OFFSET $1").is_err());
    /// assert!(check("SELECT id FROM t WHERE id > $1 ORDER BY id LIMIT 10").is_ok());
    /// ```
    OffsetPaging,
    LintGroup::Pedantic,
    "OFFSET makes the server compute and discard every skipped row, and a row inserted between pages shifts the next page.",
    Some("https://www.postgresql.org/docs/current/queries-limit.html")
);

impl<DB: DatabaseLike> QueryRule for OffsetPaging<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        _database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for found in queries(statement, paging_offset) {
            reporter.statement(
                statement,
                found.clone(),
                format!("The statement pages with `{found}`, which computes every skipped row."),
                "Page by key instead, keeping the last unique key of the page and asking for WHERE key > $1 ORDER BY key LIMIT n.".to_owned(),
            )?;
        }
        Ok(())
    }
}
