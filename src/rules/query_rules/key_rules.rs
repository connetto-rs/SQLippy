//! Submodule providing the query rules that read unique keys and foreign
//! keys.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinitionScope, ColumnScope},
    traits::{ColumnLike, DatabaseLike, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{
    BinaryOperator, Distinct, Expr, GroupByExpr, Join, JoinConstraint, JoinOperator, LimitClause,
    Query, Select, SelectItem, SelectItemQualifiedWildcardKind, SetExpr, Statement, Visit, Visitor,
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::{
        key_support::{
            Instance, determined, equalities, equality_keys, instances, named, order_of, references,
        },
        policy_support::conjuncts,
        statement_support::{
            Finding, OwnLevel, check_queries, check_scoped_selects, check_selects, is_random,
            report, row_limit,
        },
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// The row cap of a query: its `LIMIT`, else its `OFFSET`, else its
/// `FETCH`.
fn cap_of(query: &Query) -> Option<String> {
    row_limit(query)
        .or_else(|| match &query.limit_clause {
            Some(LimitClause::LimitOffset {
                offset: Some(offset),
                ..
            }) => Some(offset.to_string()),
            _ => None,
        })
        .or_else(|| query.fetch.as_ref().map(ToString::to_string))
}

/// Stops at the first aggregate call outside a window.
struct Aggregate;

impl Visitor for Aggregate {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        let aggregate = matches!(expression, Expr::Function(function) if function.over.is_none()
        && function.name.0.last().and_then(|part| part.as_ident()).is_some_and(|name| {
            matches!(
                name.value.to_ascii_lowercase().as_str(),
                "count" | "sum" | "avg" | "min" | "max" | "bool_and" | "bool_or" | "every"
                    | "array_agg" | "string_agg" | "json_agg" | "jsonb_agg"
                    | "json_object_agg" | "jsonb_object_agg"
            )
        }));
        if aggregate {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// Whether a `SELECT` returns one row however it is ordered: an aggregate
/// without `GROUP BY`, or a select list of constants.
fn single_answer(select: &Select) -> bool {
    let grouped = !matches!(&select.group_by, GroupByExpr::Expressions(keys, _) if keys.is_empty());
    // Expression evaluator: only literals and bind parameters count as
    // constants. The evaluator decides which select-list expressions are
    // constant, such as `lower($1)`.
    let constants = select.projection.iter().all(|item| {
        matches!(
            item,
            SelectItem::UnnamedExpr(Expr::Value(_))
                | SelectItem::ExprWithAlias {
                    expr: Expr::Value(_),
                    ..
                }
        )
    });
    constants || (!grouped && select.projection.visit(&mut Aggregate).is_break())
}

query_rule!(
    /// Struct defining a rule that reports a `LIMIT`, `OFFSET` or `FETCH`
    /// over rows the query does not order, or orders with ties.
    ///
    /// Without an `ORDER BY` that covers a unique key, PostgreSQL returns
    /// whichever rows it meets first. Measured on PostgreSQL 17.11 and 18.6,
    /// after an `UPDATE` of row 1, `LIMIT 1` returned row 2 instead of row 1,
    /// and with ties on `prio`, `ORDER BY prio LIMIT 2` returned `3,6` and
    /// then `9,3`. A unique key counts when it is unconditional, over plain
    /// columns, and cannot repeat through `NULL`s, and a joined table counts
    /// as ordered when its key is equal to ordered columns. A table the select
    /// list does not read needs no order, since rows that differ only there
    /// look the same. The rule does not report a `WHERE` that pins a whole
    /// unique key, a select list of constants, an aggregate without
    /// `GROUP BY`, or the body of an `EXISTS`. diesel's `.first()` is
    /// `.limit(1)`, so it is reported without `.order(…)` and not after
    /// `.find(id)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnorderedLimit::default().into();
    /// let database =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT PRIMARY KEY, prio INT);")
    ///         .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT id FROM t ORDER BY prio LIMIT 1").is_err());
    /// assert!(check("SELECT id FROM t ORDER BY prio, id LIMIT 1").is_ok());
    /// ```
    UnorderedLimit,
    LintGroup::Suspicious,
    "Without an ORDER BY that covers a unique key, LIMIT and OFFSET pick whichever rows PostgreSQL meets first, which can change between runs.",
    Some("https://www.postgresql.org/docs/current/queries-limit.html")
);

impl<DB: DatabaseLike> QueryRule for UnorderedLimit<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_queries(database, statement, |scope, query, existence| {
                let Some(cap) = cap_of(query).filter(|_| !existence) else {
                    return Ok(());
                };
                let order = order_of(query);
                if order.iter().any(|key| is_random(key)) {
                    return Ok(());
                }
                let verdict = match query.body.as_ref() {
                    SetExpr::Select(select) if single_answer(select) => Some(true),
                    SetExpr::Select(select) => scope
                        .scope_for_select(select)
                        .map(|local| determined(database, &local, select, &order))
                        .transpose()?
                        .flatten(),
                    _ => None,
                };
                if verdict == Some(false) || (verdict.is_none() && order.is_empty()) {
                    let message = if order.is_empty() {
                        format!(
                            "`{cap}` caps rows the query does not order, so PostgreSQL returns whichever rows it meets first."
                        )
                    } else {
                        format!(
                            "`{cap}` caps rows whose ORDER BY leaves ties, so rows with equal sort keys come back in any order."
                        )
                    };
                    found.push(Finding {
                        object: cap,
                        message,
                        resolution:
                            "Order by a unique key, adding the primary key as the last sort column."
                                .to_owned(),
                    });
                }
                Ok(())
            })
        })
    }
}

query_rule!(
    /// Struct defining a rule that reports `DISTINCT ON` whose `ORDER BY` is
    /// missing or leaves ties within a group.
    ///
    /// `DISTINCT ON` keeps the first row of each group, and only the
    /// `ORDER BY` decides which row is first. Measured on PostgreSQL 17.11
    /// and 18.6 with three rows per `prio`, no `ORDER BY` and `ORDER BY prio`
    /// both kept different rows before and after an `UPDATE`, and
    /// `ORDER BY prio, id DESC` kept the same rows both times. The rule uses
    /// the unique-key check of [`UnorderedLimit`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnorderedDistinctOn::default().into();
    /// let database =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT PRIMARY KEY, prio INT);")
    ///         .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT DISTINCT ON (prio) id FROM t ORDER BY prio").is_err());
    /// assert!(check("SELECT DISTINCT ON (prio) id FROM t ORDER BY prio, id").is_ok());
    /// ```
    UnorderedDistinctOn,
    LintGroup::Suspicious,
    "DISTINCT ON keeps the first row of each group, and an ORDER BY that leaves ties within the group lets that row change between runs.",
    Some("https://www.postgresql.org/docs/current/sql-select.html")
);

impl<DB: DatabaseLike> QueryRule for UnorderedDistinctOn<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_selects(database, statement, |scope, query, select| {
                let Some(distinct @ Distinct::On(_)) = &select.distinct else {
                    return Ok(());
                };
                let order = order_of(query);
                let verdict = determined(database, scope, select, &order)?;
                if verdict == Some(false) || (verdict.is_none() && order.is_empty()) {
                    found.push(Finding {
                    object: distinct.to_string(),
                    message: format!(
                        "`{distinct}` keeps the first row of each group, and the ORDER BY does not decide which row is first."
                    ),
                    resolution: "Continue the ORDER BY after the DISTINCT ON columns with columns that make each row unique, such as the primary key.".to_owned(),
                });
                }
                Ok(())
            })
        })
    }
}

/// The root of `item` in a union-find forest.
fn root(parents: &mut [usize], mut item: usize) -> usize {
    while parents[item] != item {
        parents[item] = parents[parents[item]];
        item = parents[item];
    }
    item
}

/// The condition a foreign key between `item`'s tables and the linked ones
/// gives, such as `o.customer_id = c.id`.
fn link<DB: DatabaseLike>(
    database: &DB,
    instances: &[Instance<'_, DB>],
    item: usize,
    linked: &[bool],
) -> Result<Option<String>, LookupError> {
    for unlinked in instances.iter().filter(|instance| instance.item == item) {
        for other in instances.iter().filter(|instance| linked[instance.item]) {
            for (child, parent) in [(unlinked, other), (other, unlinked)] {
                if let Some(pairs) = references(database, child.table, parent.table)?.first() {
                    let conditions: Vec<String> = pairs
                        .iter()
                        .map(|(host, referenced)| {
                            format!(
                                "{}.{} = {}.{}",
                                child.name,
                                host.column_name(),
                                parent.name,
                                referenced.column_name()
                            )
                        })
                        .collect();
                    return Ok(Some(conditions.join(" AND ")));
                }
            }
        }
    }
    Ok(None)
}

query_rule!(
    /// Struct defining a rule that reports a table in a comma-separated
    /// `FROM` that no `WHERE` condition links to the first one, directly or
    /// through other tables.
    ///
    /// Each of its rows pairs with every row of the rest. Measured on
    /// PostgreSQL 17.11 and 18.6, `FROM teams, members` returned 36,000 rows,
    /// 60 × 600, and `FROM teams t, members m, banned b WHERE m.team_id =
    /// t.id` returned 1,176 rows against 12 once `b` was linked. An explicit
    /// `CROSS JOIN` states the intent and is not reported, and the message
    /// names a foreign key that would link the table when one exists. Only
    /// `FROM` lists of plain tables are read.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnlinkedFromItem::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE a (id INT PRIMARY KEY); CREATE TABLE b (a_id INT REFERENCES a (id));",
    /// )
    /// .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT * FROM a, b").is_err());
    /// assert!(check("SELECT * FROM a, b WHERE b.a_id = a.id").is_ok());
    /// ```
    UnlinkedFromItem,
    LintGroup::Suspicious,
    "A table in a comma-separated FROM that no condition links to the others pairs each of its rows with every row of the rest.",
    None
);

impl<DB: DatabaseLike> QueryRule for UnlinkedFromItem<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_selects(database, statement, |scope, _, select| {
                if select.from.len() < 2 {
                    return Ok(());
                }
                let Some(instances) = instances(database, select) else {
                    return Ok(());
                };
                let mut parents: Vec<usize> = (0..select.from.len()).collect();
                for conjunct in select.selection.iter().flat_map(conjuncts) {
                    let mut items = Vec::new();
                    OwnLevel::new(|expression: &Expr| {
                        if let Some((relation, _)) = named(scope, expression)? {
                            items.extend(
                                instances
                                    .iter()
                                    .filter(|instance| instance.name == relation)
                                    .map(|instance| instance.item),
                            );
                        }
                        Ok(())
                    })
                    .over(conjunct)?;
                    for pair in items.windows(2) {
                        let (left, right) =
                            (root(&mut parents, pair[0]), root(&mut parents, pair[1]));
                        parents[left] = right;
                    }
                }
                let first = root(&mut parents, 0);
                let linked: Vec<bool> = (0..select.from.len())
                    .map(|item| root(&mut parents, item) == first)
                    .collect();
                for (item, from) in select.from.iter().enumerate() {
                    if !linked[item] {
                        let resolution = link(database, &instances, item, &linked)?.map_or_else(
                        || "Add the WHERE condition that links it, or write CROSS JOIN when every combination is meant.".to_owned(),
                        |condition| format!("Add {condition} to the WHERE, or write CROSS JOIN when every combination is meant."),
                    );
                        found.push(Finding {
                        object: from.to_string(),
                        message: format!(
                            "`{from}` is not linked to the first FROM item by any WHERE condition, so each of its rows pairs with every row of the rest."
                        ),
                        resolution,
                    });
                    }
                }
                Ok(())
            })
        })
    }
}

/// The relation a `SELECT DISTINCT` reads all its columns from and the one
/// it joins through a foreign key only to filter.
fn filtering_join<DB: DatabaseLike>(
    database: &DB,
    scope: &sql_traits::structs::ColumnDefinitionScope<'_, '_, '_, DB>,
    select: &Select,
) -> Result<Option<(String, String)>, LookupError> {
    let inner = select.from.iter().flat_map(|from| &from.joins).all(|join| {
        matches!(
            join.join_operator,
            JoinOperator::Join(_) | JoinOperator::Inner(_) | JoinOperator::CrossJoin(_)
        )
    });
    let (Some(Distinct::Distinct), Some(instances), true) =
        (&select.distinct, instances(database, select), inner)
    else {
        return Ok(None);
    };
    let mut selected = Vec::new();
    for item in &select.projection {
        let (SelectItem::UnnamedExpr(expression)
        | SelectItem::ExprWithAlias {
            expr: expression, ..
        }) = item
        else {
            return Ok(None);
        };
        let Some((relation, _)) = named(scope, expression)? else {
            return Ok(None);
        };
        selected.push(relation);
    }
    let Some(parent) = instances
        .iter()
        .find(|instance| selected.iter().all(|relation| *relation == instance.name))
    else {
        return Ok(None);
    };
    let pairs = equalities(scope, select)?.pairs;
    for child in instances
        .iter()
        .filter(|instance| instance.name != parent.name)
    {
        for key in references(database, child.table, parent.table)? {
            let joined = key.iter().all(|(host, referenced)| {
                let host = (child.name.clone(), host.stored_column_name().into_owned());
                let referenced = (
                    parent.name.clone(),
                    referenced.stored_column_name().into_owned(),
                );
                pairs.contains(&(host.clone(), referenced.clone()))
                    || pairs.contains(&(referenced, host))
            });
            if joined {
                return Ok(Some((
                    format!("{} AS {}", parent.table.table_name(), parent.name),
                    format!("{} AS {}", child.table.table_name(), child.name),
                )));
            }
        }
    }
    Ok(None)
}

query_rule!(
    /// Struct defining a rule that reports `SELECT DISTINCT` whose columns
    /// all come from the referenced side of a foreign-key join, so the
    /// child table only filters.
    ///
    /// The join builds every matching child row before `DISTINCT` collapses
    /// them. Measured on PostgreSQL 17.11 and 18.6 over 100,000 users, the
    /// `DISTINCT` join built 90,000 rows and collapsed them to 45 in 21.1 to
    /// 23.1 ms, while `WHERE EXISTS` took 10.5 to 11.1 ms. It is `pedantic`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = DistinctOverReferencedSide::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE a (id INT PRIMARY KEY); CREATE TABLE b (a_id INT REFERENCES a (id));",
    /// )
    /// .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT DISTINCT a.id FROM a JOIN b ON b.a_id = a.id").is_err());
    /// assert!(check("SELECT a.id FROM a WHERE EXISTS (SELECT 1 FROM b WHERE b.a_id = a.id)").is_ok());
    /// ```
    DistinctOverReferencedSide,
    LintGroup::Pedantic,
    "A DISTINCT over a foreign-key join that selects only the referenced side builds every matching child row before collapsing them, where EXISTS stops at the first.",
    None
);

impl<DB: DatabaseLike> QueryRule for DistinctOverReferencedSide<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_selects(database, statement, |scope, _, select| {
                found.extend(filtering_join(database, scope, select)?.map(|(parent, child)| Finding {
                    object: select.to_string(),
                    message: format!(
                        "`{select}` selects only columns of {parent} and joins {child} through its foreign key only to filter, so it builds every matching row before DISTINCT collapses them."
                    ),
                    resolution: format!("Select from {parent} WHERE EXISTS (SELECT 1 FROM {child} WHERE …) and drop DISTINCT."),
                }));
                Ok(())
            })
        })
    }
}

/// Whether anything in `select` outside the join `skip` reads a
/// column of `instance`: the select list, a wildcard over it, `WHERE`,
/// `GROUP BY`, `HAVING`, the windows, `DISTINCT ON`, another join's
/// condition, or the query's `ORDER BY`.
fn read_outside<DB: DatabaseLike>(
    database: &DB,
    full: &ColumnScope<'_, '_, DB>,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    query: &Query,
    select: &Select,
    instance: &Instance<'_, DB>,
    skip: &Join,
) -> Result<bool, LookupError> {
    for item in &select.projection {
        let read = match item {
            SelectItem::Wildcard(_) => true,
            SelectItem::QualifiedWildcard(SelectItemQualifiedWildcardKind::ObjectName(name), _) => {
                name.0
                    .last()
                    .and_then(|part| part.as_ident())
                    .is_some_and(|ident| {
                        normalize_identifier(&ident.value, ident.quote_style.is_some())
                            == instance.name
                    })
            }
            item => instance.read_in(database, full, scope, item)?,
        };
        if read {
            return Ok(true);
        }
    }
    let mut read = instance.read_in(database, full, scope, &select.selection)?
        || instance.read_in(database, full, scope, &select.group_by)?
        || instance.read_in(database, full, scope, &select.having)?
        || instance.read_in(database, full, scope, &select.named_window)?
        || instance.read_in(database, full, scope, &select.distinct)?;
    if matches!(query.body.as_ref(), SetExpr::Select(_)) {
        read |= instance.read_in(database, full, scope, &query.order_by)?;
    }
    for join in select.from.iter().flat_map(|from| &from.joins) {
        if !std::ptr::eq(join, skip) {
            read |= instance.read_in(database, full, scope, &join.join_operator)?;
        }
    }
    Ok(read)
}

/// Whether the equalities of `condition` pin a key of `instance` through
/// which each row matches at most one of its rows: every key column equal
/// to something that does not read `instance` itself.
fn matches_one<DB: DatabaseLike>(
    database: &DB,
    full: &ColumnScope<'_, '_, DB>,
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    instance: &Instance<'_, DB>,
    condition: &Expr,
) -> Result<bool, LookupError> {
    let mut pinned = Vec::new();
    for conjunct in conjuncts(condition) {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = conjunct
        else {
            continue;
        };
        for (side, other) in [(left, right), (right, left)] {
            if let Some((relation, column)) = named(scope, side)?
                && relation == instance.name
                && !instance.read_in(database, full, scope, other.as_ref())?
            {
                pinned.push(column);
            }
        }
    }
    Ok(equality_keys(database, instance.table)?.iter().any(|key| {
        key.iter().all(|column| {
            pinned
                .iter()
                .any(|pinned| *pinned == column.stored_column_name())
        })
    }))
}

query_rule!(
    /// Struct defining a rule that reports an outer join whose
    /// null-extended relation nothing outside the join condition reads,
    /// when the condition pins no unique key of it.
    ///
    /// Each row on the other side then repeats once per matching row and the
    /// join adds nothing else. Measured on PostgreSQL 17.11 and 18.6, three
    /// `people` rows `LEFT JOIN teams ON teams.id = people.team` returned 5
    /// rows when two `teams` rows had id 1, and 3 rows on a primary key, where
    /// `EXPLAIN` showed the join removed. The joined relation of a `LEFT` or
    /// `FULL` join is read, and so is the first relation of a `RIGHT` or
    /// `FULL` join. A unique key over nullable columns counts, since an
    /// equality never matches `NULL`, and a partial unique index does not.
    /// Only joins with an `ON` condition over plain tables are read.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnreadOuterJoin::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE a (id INT PRIMARY KEY); CREATE TABLE b (a_id INT);",
    /// )
    /// .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT a.id FROM a LEFT JOIN b ON b.a_id = a.id").is_err());
    /// assert!(check("SELECT b.a_id FROM b LEFT JOIN a ON a.id = b.a_id").is_ok());
    /// ```
    UnreadOuterJoin,
    LintGroup::Suspicious,
    "An outer join that nothing else reads and whose condition pins no unique key repeats each row once per match while adding nothing else.",
    None
);

impl<DB: DatabaseLike> QueryRule for UnreadOuterJoin<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        report(statement, reporter, |found| {
            check_scoped_selects(database, statement, |full, scope, query, select| {
                let Some(instances) = instances(database, select) else {
                    return Ok(());
                };
                let mut position = 0;
                for from in &select.from {
                    let first = position;
                    position += 1;
                    for (index, join) in from.joins.iter().enumerate() {
                        let joined = position;
                        position += 1;
                        let (extends_left, condition) = match &join.join_operator {
                            JoinOperator::Left(JoinConstraint::On(condition))
                            | JoinOperator::LeftOuter(JoinConstraint::On(condition)) => {
                                (None, condition)
                            }
                            JoinOperator::Right(JoinConstraint::On(condition))
                            | JoinOperator::RightOuter(JoinConstraint::On(condition)) => {
                                (Some(false), condition)
                            }
                            JoinOperator::FullOuter(JoinConstraint::On(condition)) => {
                                (Some(true), condition)
                            }
                            _ => continue,
                        };
                        let mut sides = Vec::new();
                        if extends_left != Some(false) {
                            sides.push((joined, &join.relation));
                        }
                        if extends_left.is_some() && index == 0 {
                            sides.push((first, &from.relation));
                        }
                        for (side, factor) in sides {
                            let instance = &instances[side];
                            if read_outside(database, full, scope, query, select, instance, join)?
                                || matches_one(database, full, scope, instance, condition)?
                            {
                                continue;
                            }
                            let table = instance.table.table_name();
                            found.push(Finding {
                                object: factor.to_string(),
                                message: format!(
                                    "`{factor}` is outer joined on `{condition}`, which pins no unique key of '{table}', and nothing else reads it, so each row repeats once per matching row of '{table}'."
                                ),
                                resolution: "Remove the join, or test for a matching row with EXISTS.".to_owned(),
                            });
                        }
                    }
                }
                Ok(())
            })
        })
    }
}
