//! Submodule providing the query rules that read indexes.

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnDefinitionScope, ColumnScope, IdentifierCase},
    traits::{ColumnLike, DataTypeLike, DatabaseLike, TableLike},
};
use sqlparser::ast::{BinaryOperator, DataType, Expr, InTarget, SelectItem, SetExpr, Statement};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::{
        index_support::{Side, comparison_sides, expression_indexed, indexed, leading},
        key_support::{Instance, instances},
        policy_support::{conjuncts, is_column_reference},
        statement_support::{
            Finding, OwnLevel, check_queries, check_selects, reads_outer, report, selects,
        },
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// The column references of an expression, outside the queries it nests.
fn own_columns(expression: &Expr) -> Result<Vec<Expr>, LookupError> {
    let mut columns = Vec::new();
    OwnLevel::new(|node: &Expr| {
        if is_column_reference(node) {
            columns.push(node.clone());
        }
        Ok(())
    })
    .over(expression)?;
    Ok(columns)
}

/// The column, rendered as `table.column`, whose leading index an
/// expression around it defeats.
fn defeated<DB: DatabaseLike>(
    database: &DB,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    expression: &Expr,
) -> Result<Option<String>, LookupError> {
    let expression = leading(expression);
    if is_column_reference(expression) {
        return Ok(None);
    }
    let columns = own_columns(expression)?;
    let [reference] = columns.as_slice() else {
        return Ok(None);
    };
    let Some(ColumnDefinition::Base { table, column, .. }) =
        scope.resolve_column_definition(reference)?
    else {
        return Ok(None);
    };
    let coercible = match expression {
        Expr::Cast {
            expr,
            data_type: DataType::Text | DataType::Varchar(_) | DataType::String(_),
            ..
        } => is_column_reference(expr) && column.data_type(database).is_textual(database),
        _ => false,
    };
    if coercible
        || !indexed(database, table, column)?
        || expression_indexed(database, table, expression)?
    {
        return Ok(None);
    }
    Ok(Some(format!(
        "{}.{}",
        table.table_name(),
        column.column_name()
    )))
}

query_rule!(
    /// Struct defining a rule that reports a function, a type-changing cast
    /// or arithmetic around a column that leads an index, in a comparison of
    /// the `WHERE`, when no expression index matches it.
    ///
    /// PostgreSQL can only use an index for the expression it indexes.
    /// Measured on PostgreSQL 17.11 and 18.6, `lower(email) = …`,
    /// `coalesce(team_id, 0) = …`, `team_id + 0 = …` and
    /// `created_at::date = …` each ran a `Seq Scan` where the bare column
    /// used its index, and `CREATE INDEX ON users (lower(email))` turned the
    /// lookup into an index scan. A cast between `varchar` and `text` keeps
    /// the index and is not reported, and an expression index matches
    /// regardless of parentheses, qualifiers and the case of unquoted names.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ExpressionDefeatsIndex::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE t (email TEXT); CREATE INDEX t_email ON t (email);",
    /// )
    /// .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT 1 FROM t WHERE lower(email) = $1").is_err());
    /// assert!(check("SELECT 1 FROM t WHERE email = lower($1)").is_ok());
    /// ```
    ExpressionDefeatsIndex,
    LintGroup::Perf,
    "PostgreSQL can only use an index for the expression it indexes, so a function or cast around an indexed column makes it read the whole table.",
    Some("https://www.postgresql.org/docs/current/indexes-expressional.html")
);

impl<DB: DatabaseLike> QueryRule for ExpressionDefeatsIndex<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_selects(database, statement, |scope, _, select| {
                OwnLevel::new(|expression: &Expr| {
                    comparison_sides(expression, |column_side, _| {
                        if let Some(column) = defeated(database, scope, column_side)? {
                            let finding = Finding {
                                object: column_side.to_string(),
                                message: format!(
                                    "`{column_side}` wraps '{column}', which leads an index, so PostgreSQL cannot use that index for the comparison and reads the whole table."
                                ),
                                resolution: "Compare the bare column and move the computation to the other side, or create an index on the expression when it is immutable.".to_owned(),
                            };
                            if !found.contains(&finding) {
                                found.push(finding);
                            }
                        }
                        Ok(())
                    })
                })
                .over(&select.selection)
            })
        })
    }
}

/// Whether `expression` reads a column of `instance`, itself or through a
/// subquery it holds.
fn reads<DB: DatabaseLike>(
    database: &DB,
    full: &ColumnScope<'_, '_, DB>,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    instance: &Instance<'_, DB>,
    expression: &Expr,
) -> Result<bool, LookupError> {
    let mut read = false;
    OwnLevel::new(|node: &Expr| {
        read |= instance.names(scope, node)?;
        if let Expr::Subquery(query)
        | Expr::Exists {
            subquery: query, ..
        }
        | Expr::In {
            target: InTarget::Subquery(query),
            ..
        } = node
        {
            read |= reads_outer(database, full, query, &instance.name)?;
        }
        Ok(())
    })
    .over(expression)?;
    Ok(read)
}

/// Whether `column` is a column of `instance` that leads an index.
fn leads_index<DB: DatabaseLike>(
    database: &DB,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    instance: &Instance<'_, DB>,
    column: &Expr,
) -> Result<bool, LookupError> {
    if instance.names(scope, column)?
        && let Some(ColumnDefinition::Base { table, column, .. }) =
            scope.resolve_column_definition(column)?
    {
        return indexed(database, table, column);
    }
    Ok(false)
}

/// Whether an index of `instance` leads with `side`: a column that leads an
/// index, or an expression over the table's columns that an expression
/// index leads with.
fn serves<DB: DatabaseLike>(
    database: &DB,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    instance: &Instance<'_, DB>,
    side: &Expr,
) -> Result<bool, LookupError> {
    let side = leading(side);
    if is_column_reference(side) {
        return leads_index(database, scope, instance, side);
    }
    let columns = own_columns(side)?;
    let mut own = !columns.is_empty();
    for column in &columns {
        own &= instance.names(scope, column)?;
    }
    Ok(own && expression_indexed(database, instance.table, side)?)
}

/// Whether an index of `instance` can serve `condition`: one of its
/// conjuncts compares what an index leads with against a value free of the
/// table's own columns, bounds it with `BETWEEN`, tests it `IS NULL` or
/// `IS NOT NULL`, or is an `OR` whose every arm an index can serve.
fn servable<DB: DatabaseLike>(
    database: &DB,
    full: &ColumnScope<'_, '_, DB>,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    instance: &Instance<'_, DB>,
    condition: &Expr,
) -> Result<bool, LookupError> {
    // Expression evaluator: every expression free of the table's own columns
    // counts as a value, volatile calls included. The evaluator tells values
    // an index can look up from calls such as `random()`.
    let value =
        |other: &Expr| Ok::<_, LookupError>(!reads(database, full, scope, instance, other)?);
    for conjunct in conjuncts(condition) {
        let served = match conjunct {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
            } => {
                servable(database, full, scope, instance, left)?
                    && servable(database, full, scope, instance, right)?
            }
            Expr::IsNull(side) | Expr::IsNotNull(side) => serves(database, scope, instance, side)?,
            Expr::Between {
                expr,
                negated: false,
                low,
                high,
            } => value(low)? && value(high)? && serves(database, scope, instance, expr)?,
            _ => {
                let mut served = false;
                comparison_sides(conjunct, |side, other| {
                    let other = match other {
                        Side::Expr(other) => value(other)?,
                        Side::List(list) => {
                            let mut all = true;
                            for item in list {
                                all &= value(item)?;
                            }
                            all
                        }
                        Side::Query(query) => !reads_outer(database, full, query, &instance.name)?,
                    };
                    served |= other && serves(database, scope, instance, side)?;
                    Ok(())
                })?;
                served
            }
        };
        if served {
            return Ok(true);
        }
    }
    Ok(false)
}

query_rule!(
    /// Struct defining a rule that reports a `WHERE` over one table with no
    /// condition an index without a predicate can serve, so PostgreSQL reads
    /// the whole table.
    ///
    /// A condition counts when it compares a column, or an expression an
    /// expression index leads with, against a value free of the table's own
    /// columns, bounds it with `BETWEEN`, or tests it `IS NULL` or
    /// `IS NOT NULL`, and an `OR` counts when every arm does. A subquery that
    /// reads the table's own row is no value. Measured on PostgreSQL 17.11 and
    /// 18.6, `team_id = 7` without an index ran a `Seq Scan` over 100,000
    /// rows in 5.3 ms, and with one a bitmap index scan in 1.2 to 1.4 ms.
    /// The schema cannot tell a small lookup table from a large one, so the
    /// rule is `pedantic`. A statement without a `WHERE` and a `WHERE` over a
    /// join are not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnindexedFilter::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE t (id INT PRIMARY KEY, score INT);",
    /// )
    /// .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT id FROM t WHERE score = 1").is_err());
    /// assert!(check("SELECT id FROM t WHERE id = $1").is_ok());
    /// ```
    UnindexedFilter,
    LintGroup::Pedantic,
    "A WHERE that no index can serve makes PostgreSQL read every row of the table to find the ones it keeps.",
    Some("https://www.postgresql.org/docs/current/indexes-types.html")
);

impl<DB: DatabaseLike> QueryRule for UnindexedFilter<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_queries(database, statement, |full, query, _| {
                for select in selects(&query.body) {
                    if let (Some(scope), Some(selection), Some([instance])) = (
                        full.scope_for_select(select),
                        &select.selection,
                        instances(database, select).as_deref(),
                    ) && !servable(database, full, &scope, instance, selection)?
                    {
                        found.push(Finding {
                        object: selection.to_string(),
                        message: format!(
                            "The WHERE `{selection}` has no condition an index of '{}' without a predicate can serve, so PostgreSQL reads the whole table.",
                            instance.table.table_name()
                        ),
                        resolution: "Add an index on a column the WHERE compares with a value, or keep the scan for a small table.".to_owned(),
                    });
                    }
                }
                Ok(())
            })
        })
    }
}

/// The inner table and column a correlated subquery finds its rows through
/// when no index leads with that column.
fn unindexed_correlation<DB: DatabaseLike>(
    database: &DB,
    full: &ColumnScope<'_, '_, DB>,
    subquery: &sqlparser::ast::Query,
) -> Result<Option<(String, String)>, LookupError> {
    let SetExpr::Select(select) = subquery.body.as_ref() else {
        return Ok(None);
    };
    let local = ColumnScope::from_query(subquery, database, IdentifierCase::Folded)?;
    let scopes = local
        .scope_for_select(select)
        .zip(full.scope_for_select(select));
    let (Some((local, outer)), Some(selection)) = (scopes, &select.selection) else {
        return Ok(None);
    };
    for conjunct in conjuncts(selection) {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = conjunct
        else {
            continue;
        };
        for (inner, other) in [(left, right), (right, left)] {
            if let Some(ColumnDefinition::Base { table, column, .. }) =
                local.resolve_column_definition(inner)?
                && local.resolve_column_definition(other)?.is_none()
                && outer.resolve_column_definition(other)?.is_some()
                && !indexed(database, table, column)?
            {
                return Ok(Some((
                    table.table_name().to_owned(),
                    column.column_name().to_owned(),
                )));
            }
        }
    }
    Ok(None)
}

query_rule!(
    /// Struct defining a rule that reports a scalar subquery in the select
    /// list correlated with the outer row through an inner column that leads
    /// no index.
    ///
    /// The subquery runs once per outer row and reads its whole table each
    /// time. Measured on PostgreSQL 17.11 and 18.6, a per-team count over
    /// 100,000 users took 327.5 to 351.7 ms without an index on `team_id`,
    /// 15.7 to 17.6 ms as a `LEFT JOIN … GROUP BY`, and 4.3 to 5.0 ms as the
    /// same subquery with the index.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnindexedCorrelatedSelect::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE teams (id INT PRIMARY KEY); CREATE TABLE users (team_id INT);",
    /// )
    /// .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check(
    ///     "SELECT t.id, (SELECT count(*) FROM users AS u WHERE u.team_id = t.id) FROM teams AS t"
    /// )
    /// .is_err());
    /// assert!(check("SELECT t.id FROM teams AS t").is_ok());
    /// ```
    UnindexedCorrelatedSelect,
    LintGroup::Perf,
    "A scalar subquery in the select list runs once per outer row, and without an index on the column it correlates on each run reads the whole table.",
    None
);

impl<DB: DatabaseLike> QueryRule for UnindexedCorrelatedSelect<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_queries(database, statement, |full, query, _| {
                let SetExpr::Select(select) = query.body.as_ref() else {
                    return Ok(());
                };
                for item in &select.projection {
                    let (SelectItem::UnnamedExpr(Expr::Subquery(subquery))
                    | SelectItem::ExprWithAlias {
                        expr: Expr::Subquery(subquery),
                        ..
                    }) = item
                    else {
                        continue;
                    };
                    found.extend(unindexed_correlation(database, full, subquery)?.map(|(table, column)| Finding {
                    object: subquery.to_string(),
                    message: format!(
                        "`({subquery})` runs once per outer row and finds its rows through '{table}.{column}', which leads no index, so each run reads the whole table."
                    ),
                    resolution: format!("Create an index on {table} ({column}), or rewrite the subquery as a join."),
                }));
                }
                Ok(())
            })
        })
    }
}
