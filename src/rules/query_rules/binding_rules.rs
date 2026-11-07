//! Submodule providing the query rules that read which column a name binds
//! to.

use sql_traits::{
    errors::LookupError, traits::DatabaseLike, utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{
    BinaryOperator, Expr, GroupByExpr, Ident, NamedWindowExpr, Query, Select, SelectItem, SetExpr,
    Statement, WindowSpec, WindowType,
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::{
        key_support::named,
        policy_support::unnested,
        statement_support::{Finding, OwnLevel, check_select_expressions, check_selects, report},
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// Calls `each` with every bare name of a window specification and the
/// clause holding it.
fn window_names(
    spec: &WindowSpec,
    each: &mut impl FnMut(&'static str, &Ident) -> Result<(), LookupError>,
) -> Result<(), LookupError> {
    for expression in &spec.partition_by {
        if let Expr::Identifier(name) = unnested(expression) {
            each("PARTITION BY", name)?;
        }
    }
    for key in &spec.order_by {
        if let Expr::Identifier(name) = unnested(&key.expr) {
            each("window ORDER BY", name)?;
        }
    }
    Ok(())
}

/// Calls `each` with every bare name `select` groups by or its windows
/// partition or order by, and the clause holding it. PostgreSQL resolves
/// these names to an input column before a select-list alias.
fn input_first_names(
    query: &Query,
    select: &Select,
    mut each: impl FnMut(&'static str, &Ident) -> Result<(), LookupError>,
) -> Result<(), LookupError> {
    if let GroupByExpr::Expressions(keys, _) = &select.group_by {
        for key in keys {
            match unnested(key) {
                Expr::Identifier(name) => each("GROUP BY", name)?,
                Expr::Rollup(sets) | Expr::Cube(sets) | Expr::GroupingSets(sets) => {
                    for member in sets.iter().flatten() {
                        if let Expr::Identifier(name) = unnested(member) {
                            each("GROUP BY", name)?;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    for definition in &select.named_window {
        if let NamedWindowExpr::WindowSpec(spec) = &definition.1 {
            window_names(spec, &mut each)?;
        }
    }
    let mut own = OwnLevel::new(|expression: &Expr| match expression {
        Expr::Function(function) => match &function.over {
            Some(WindowType::WindowSpec(spec)) => window_names(spec, &mut each),
            _ => Ok(()),
        },
        _ => Ok(()),
    });
    own.over(&select.projection)?;
    if matches!(query.body.as_ref(), SetExpr::Select(_)) {
        own.over(&query.order_by)?;
    }
    Ok(())
}

query_rule!(
    /// Struct defining a rule that reports a bare name in `GROUP BY`, or in a
    /// window's `PARTITION BY` or `ORDER BY`, that is both a select-list
    /// alias and an input column the alias does not stand for.
    ///
    /// PostgreSQL binds such a name to the input column, so the grouping or
    /// the window ignores the alias, while a top-level `ORDER BY` binds the
    /// same name to the alias. Measured on PostgreSQL 17.11 and 18.6 with
    /// names `Ann`, `ann` and `NULL`, `SELECT lower(name) AS name, count(*)
    /// … GROUP BY name` returned two groups of 1 for `ann`, and `SELECT
    /// p.team AS id, row_number() OVER (PARTITION BY id …)` numbered every row
    /// 1. Names inside `ROLLUP`, `CUBE` and `GROUPING SETS` bind the same way.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = AliasShadowedByColumn::default().into();
    /// let database =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE people (id INT, name TEXT);").unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT lower(name) AS name, count(*) FROM people GROUP BY name").is_err());
    /// assert!(check("SELECT lower(name) AS low, count(*) FROM people GROUP BY low").is_ok());
    /// ```
    AliasShadowedByColumn,
    LintGroup::Suspicious,
    "PostgreSQL resolves a GROUP BY or window name to an input column before a select-list alias, so naming an alias after another column groups or orders by that column instead.",
    Some("https://www.postgresql.org/docs/current/sql-select.html")
);

impl<DB: DatabaseLike> QueryRule for AliasShadowedByColumn<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_selects(database, statement, |scope, query, select| {
                input_first_names(query, select, |clause, name| {
                    let folded = normalize_identifier(&name.value, name.quote_style.is_some());
                    let Some(aliased) = select.projection.iter().find_map(|item| match item {
                        SelectItem::ExprWithAlias { expr, alias }
                            if normalize_identifier(&alias.value, alias.quote_style.is_some())
                                == folded =>
                        {
                            Some(expr)
                        }
                        _ => None,
                    }) else {
                        return Ok(());
                    };
                    let reference = Expr::Identifier(name.clone());
                    let Some((relation, column)) = named(scope, &reference)? else {
                        return Ok(());
                    };
                    if named(scope, aliased)?
                        .is_some_and(|aliased| aliased == (relation.clone(), column.clone()))
                    {
                        return Ok(());
                    }
                    let finding = Finding {
                        object: name.to_string(),
                        message: format!(
                            "`{clause} {name}` uses the input column {relation}.{column}, not the select-list alias `{name}` for `{aliased}`, because PostgreSQL resolves that name to an input column first."
                        ),
                        resolution: "Write the expression itself, or qualify the column when the input column is meant, and rename the alias so it no longer matches an input column.".to_owned(),
                    };
                    if !found.contains(&finding) {
                        found.push(finding);
                    }
                    Ok(())
                })
            })
        })
    }
}

query_rule!(
    /// Struct defining a rule that reports a comparison of a column with
    /// itself, both sides resolving to the same column of the same `FROM`
    /// item.
    ///
    /// It reads as always true, but a comparison with `NULL` is never true.
    /// Measured on PostgreSQL 17.11 and 18.6 over three rows, one `name`
    /// `NULL`, `name = name`, `name <= name` and `name >= name` each kept 2
    /// rows and `name <> name`, `name < name` and `name > name` kept none.
    /// The usual cause is a mistyped column. A self-join comparing two
    /// instances of one table is not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = SelfComparison::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE people (id INT, name TEXT, team INT);",
    /// )
    /// .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT id FROM people WHERE name = name").is_err());
    /// assert!(check("SELECT a.id FROM people AS a JOIN people AS b ON a.team = b.team").is_ok());
    /// ```
    SelfComparison,
    LintGroup::Suspicious,
    "A column compared with itself reads as always true, but the comparison is never true for NULL.",
    Some("https://www.postgresql.org/docs/current/functions-comparison.html")
);

impl<DB: DatabaseLike> QueryRule for SelfComparison<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_select_expressions(database, statement, |scope, expression| {
                let Expr::BinaryOp { left, op, right } = expression else {
                    return Ok(());
                };
                let reflexive = match op {
                    BinaryOperator::Eq | BinaryOperator::LtEq | BinaryOperator::GtEq => true,
                    BinaryOperator::NotEq | BinaryOperator::Lt | BinaryOperator::Gt => false,
                    _ => return Ok(()),
                };
                let Some((relation, column)) = named(scope, unnested(left))? else {
                    return Ok(());
                };
                if named(scope, unnested(right))? != Some((relation.clone(), column.clone())) {
                    return Ok(());
                }
                found.push(if reflexive {
                    Finding {
                        object: expression.to_string(),
                        message: format!(
                            "`{expression}` compares {relation}.{column} with itself, which is never true where it is NULL, so it only says whether {column} is NULL."
                        ),
                        resolution: format!(
                            "Compare with the column meant, or write {column} IS NOT NULL when that is the intent."
                        ),
                    }
                } else {
                    Finding {
                        object: expression.to_string(),
                        message: format!(
                            "`{expression}` compares {relation}.{column} with itself and is never true."
                        ),
                        resolution: "Compare with the column meant.".to_owned(),
                    }
                });
                Ok(())
            })
        })
    }
}
