//! Submodule providing the `RepeatedRecursionBound` rule.

use std::{collections::BTreeMap, convert::Infallible, ops::ControlFlow};

use sql_traits::traits::{DatabaseLike, FunctionLike, PolicyLike, TableLike, ViewLike};
use sqlparser::ast::{BinaryOperator, Expr, Ident, Query, TableFactor, Visit, Visitor};

use crate::{
    engine::Engine,
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::{RecursiveItem, same_name},
        expression_site_support::body_statements,
        literal_support::number_literal,
        policy_support::{conjuncts, unnested, walked_clauses},
        statement_support::selects,
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

schema_rule!(
    /// Struct defining a rule that reports the same numeric bound on
    /// recursive walks written at several sites of the schema.
    ///
    /// A bound is a number other than `0`, `1` and `-1` that the recursive
    /// term of a `WITH RECURSIVE` item compares with `<`, `<=`, `>` or `>=`
    /// against a column of its working table, such as `depth < 32`, or that
    /// the query reading the item compares with that column, such as
    /// `SELECT ... FROM walk WHERE depth >= 32`. A value bounding walks at two
    /// or more views, materialized views, policy clauses or SQL and PL/pgSQL
    /// function bodies is reported at each of them. A value repeated within
    /// one site is not.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = RepeatedRecursionBound::default().into();
    /// let walk = "WITH RECURSIVE walk(depth) AS (SELECT 0 UNION ALL SELECT depth + 1 FROM walk WHERE depth < 32) SELECT max(depth) FROM walk";
    /// let repeated = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "CREATE VIEW first_depth AS {walk}; CREATE VIEW second_depth AS {walk};"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&repeated).is_err());
    /// let named = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "CREATE FUNCTION depth_limit() RETURNS INT LANGUAGE sql IMMUTABLE AS $$ SELECT 32 $$;
    ///      CREATE VIEW first_depth AS {0}; CREATE VIEW second_depth AS {0};",
    ///     walk.replace("32", "depth_limit()")
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&named).is_ok());
    /// ```
    RepeatedRecursionBound,
    LintGroup::Pedantic,
    "Copies of one traversal limit written at several walks drift apart when one is changed.",
    Some("https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-RECURSIVE"),
    RuleExample {
        bad: "CREATE FUNCTION first_depth() RETURNS INT LANGUAGE sql IMMUTABLE AS $$ WITH RECURSIVE walk(depth) AS (SELECT 0 UNION ALL SELECT depth + 1 FROM walk WHERE depth < 32) SELECT max(depth) FROM walk $$;\n\
CREATE FUNCTION second_depth() RETURNS INT LANGUAGE sql IMMUTABLE AS $$ WITH RECURSIVE walk(depth) AS (SELECT 0 UNION ALL SELECT depth + 1 FROM walk WHERE depth < 32) SELECT max(depth) FROM walk $$;",
        good: "CREATE FUNCTION depth_limit() RETURNS INT LANGUAGE sql IMMUTABLE AS $$ SELECT 32 $$;\n\
CREATE FUNCTION first_depth() RETURNS INT LANGUAGE sql IMMUTABLE AS $$ WITH RECURSIVE walk(depth) AS (SELECT 0 UNION ALL SELECT depth + 1 FROM walk WHERE depth < depth_limit()) SELECT max(depth) FROM walk $$;\n\
CREATE FUNCTION second_depth() RETURNS INT LANGUAGE sql IMMUTABLE AS $$ WITH RECURSIVE walk(depth) AS (SELECT 0 UNION ALL SELECT depth + 1 FROM walk WHERE depth < depth_limit()) SELECT max(depth) FROM walk $$;",
    }
);

/// The number `expression` writes, when it is a bound rather than a
/// structural `0`, `1` or `-1`.
fn bound(expression: &Expr) -> Option<String> {
    let number = number_literal(expression)?;
    let trivial = number
        .parse::<f64>()
        .is_ok_and(|value| [0.0, 1.0].contains(&value.abs()));
    (!trivial).then(|| number.into_owned())
}

/// The bound a comparison `<`, `<=`, `>` or `>=` sets on an operand `is_walked`
/// holds for.
fn compared_bound<'e>(
    expression: &'e Expr,
    mut is_walked: impl FnMut(&'e Expr) -> bool,
) -> Option<String> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Lt | BinaryOperator::LtEq | BinaryOperator::Gt | BinaryOperator::GtEq,
        right,
    } = unnested(expression)
    else {
        return None;
    };
    if is_walked(left) {
        bound(right)
    } else if is_walked(right) {
        bound(left)
    } else {
        None
    }
}

/// Collects the recursion bounds of every `WITH RECURSIVE` clause a node
/// holds.
#[derive(Default)]
struct Bounds(Vec<String>);

impl Bounds {
    /// Records the bounds the query reading the recursive `item` puts on
    /// the `walked` columns of its working table.
    fn outer(&mut self, query: &Query, item: &Ident, walked: &[&Ident]) {
        for select in selects(&query.body) {
            let exposed = select
                .from
                .iter()
                .flat_map(|from| {
                    std::iter::once(&from.relation)
                        .chain(from.joins.iter().map(|join| &join.relation))
                })
                .find_map(|factor| match factor {
                    TableFactor::Table { name, alias, .. } => match name.0.as_slice() {
                        [part] => part
                            .as_ident()
                            .filter(|written| same_name(written, item))
                            .map(|written| alias.as_ref().map_or(written, |alias| &alias.name)),
                        _ => None,
                    },
                    _ => None,
                });
            let Some(exposed) = exposed else {
                continue;
            };
            let is_walked = |operand: &Expr| match unnested(operand) {
                Expr::Identifier(column) => walked.iter().any(|known| same_name(known, column)),
                Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                    [relation, column] => {
                        same_name(relation, exposed)
                            && walked.iter().any(|known| same_name(known, column))
                    }
                    _ => false,
                },
                _ => false,
            };
            for condition in select.selection.iter().flat_map(conjuncts) {
                self.0.extend(compared_bound(condition, is_walked));
            }
        }
    }
}

impl Visitor for Bounds {
    type Break = Infallible;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Infallible> {
        let Some(with) = query.with.as_ref().filter(|with| with.recursive) else {
            return ControlFlow::Continue(());
        };
        for item in &with.cte_tables {
            let Some(recursive) = RecursiveItem::split(item) else {
                continue;
            };
            let mut walked: Vec<&Ident> = Vec::new();
            for condition in recursive.conditions() {
                let mut column = None;
                let found = compared_bound(condition, |operand| {
                    column = recursive.working_column(operand);
                    column.is_some()
                });
                if let Some(found) = found {
                    self.0.push(found);
                    walked.extend(column);
                }
            }
            if !walked.is_empty() {
                self.outer(query, &item.alias.name, &walked);
            }
        }
        ControlFlow::Continue(())
    }
}

/// The recursion bounds a node holds, each once.
fn bounds_of<V: Visit + ?Sized>(node: &V) -> Vec<String> {
    let mut bounds = Bounds::default();
    let ControlFlow::Continue(()) = walk(node, &mut bounds);
    bounds.0.sort();
    bounds.0.dedup();
    bounds.0
}

/// A site whose recursive walks the rule reads.
enum Site<'db, DB: DatabaseLike> {
    /// A view.
    View(&'db DB::View),
    /// A materialized view.
    MaterializedView(&'db DB::MaterializedView),
    /// One clause of a policy on a table.
    Policy(&'db DB::Table, &'db DB::Policy, PolicyClause),
    /// A SQL or PL/pgSQL function body.
    Function(&'db DB::Function),
}

impl<DB: DatabaseLike> Site<'_, DB> {
    /// The site, described for a message.
    fn describe(&self, database: &DB) -> String {
        match self {
            Self::View(view) => format!("view '{}'", view.view_name()),
            Self::MaterializedView(view) => format!("materialized view '{}'", view.view_name()),
            Self::Policy(table, policy, clause) => format!(
                "the {clause} clause of policy '{}' on '{}'",
                policy.name(),
                table.table_name()
            ),
            Self::Function(function) => format!("function '{}'", signature(*function, database)),
        }
    }
}

/// A site and the recursion bounds it holds.
type SiteBounds<'db, DB> = (Site<'db, DB>, Vec<String>);

/// Every site of the schema with the recursion bounds it holds.
fn sites<DB: DatabaseLike>(database: &DB) -> Result<Vec<SiteBounds<'_, DB>>, Interruption> {
    let mut found = Vec::new();
    for view in database.views() {
        found.push((Site::View(view), bounds_of(view.definition())));
    }
    for view in database.materialized_views() {
        found.push((Site::MaterializedView(view), bounds_of(view.definition())));
    }
    for table in database.tables() {
        for policy in table.policies(database)? {
            for (clause, expression) in walked_clauses(database, policy)? {
                if let Some(expression) = expression {
                    found.push((Site::Policy(table, policy, clause), bounds_of(expression)));
                }
            }
        }
    }
    let functions = database.functions().filter(|function| {
        !matches!(
            function.target_name().schema(),
            Some("pg_catalog" | "information_schema")
        )
    });
    for function in functions {
        let mut bounds = bounds_of(&body_statements(function));
        if let Some(statements) = function.atomic_statements(database)? {
            for statement in statements.iter() {
                bounds.extend(bounds_of(statement));
            }
        }
        if let Some(body) = function.body_expression(database)? {
            bounds.extend(bounds_of(body.as_ref()));
        }
        bounds.sort();
        bounds.dedup();
        found.push((Site::Function(function), bounds));
    }
    found.retain(|(_, bounds)| !bounds.is_empty());
    Ok(found)
}

impl<DB: DatabaseLike> SchemaRule for RepeatedRecursionBound<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let sites = sites(database)?;
        let mut holders: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (index, (_, bounds)) in sites.iter().enumerate() {
            for value in bounds {
                holders.entry(value).or_default().push(index);
            }
        }
        for (index, (site, bounds)) in sites.iter().enumerate() {
            for value in bounds {
                let others: Vec<String> = holders[value.as_str()]
                    .iter()
                    .filter(|&&other| other != index)
                    .map(|&other| sites[other].0.describe(database))
                    .collect();
                if others.is_empty() {
                    continue;
                }
                let message = format!(
                    "{} bounds a recursive walk at {value}, as {} also does, so the copies drift apart when one changes.",
                    capitalized(&site.describe(database)),
                    others.join(" and ")
                );
                let resolution = match Engine::of(database) {
                    Engine::PostgreSql => format!(
                        "Name the bound once in an `IMMUTABLE` SQL function returning {value}, such as `depth_limit()`, and compare every walk with it."
                    ),
                    Engine::Sqlite => format!(
                        "Name the bound once with `CREATE VIEW depth_limit AS SELECT {value} AS value` and compare every walk with `(SELECT value FROM depth_limit)`."
                    ),
                };
                match site {
                    Site::View(view) => reporter.view(view, message, resolution)?,
                    Site::MaterializedView(view) => {
                        reporter.materialized_view(view, message, resolution)?;
                    }
                    Site::Policy(table, policy, clause) => reporter.policies(
                        vec![PolicySite {
                            table: Box::new((*table).clone()),
                            policy: Box::new((*policy).clone()),
                            clause: *clause,
                            expression: value.clone(),
                        }],
                        message,
                        resolution,
                    )?,
                    Site::Function(function) => reporter.function(function, message, resolution)?,
                }
            }
        }
        Ok(())
    }
}

/// `text` with its first letter in uppercase.
fn capitalized(text: &str) -> String {
    let mut characters = text.chars();
    characters.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(characters).collect()
    })
}
