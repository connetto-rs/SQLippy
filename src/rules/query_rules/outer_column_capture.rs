//! Submodule providing the `OuterColumnCapture` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ColumnDefinitionScope, ColumnScope, IdentifierCase},
    traits::DatabaseLike,
};
use sqlparser::ast::{
    Expr, Ident, InTarget, ObjectName, Query, Select, SetExpr, Statement, Visit, Visitor,
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::statement_support::{OwnLevel, root_query},
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter},
};

/// Collects, for every expression subquery of a query, the unqualified names
/// the subquery cannot resolve on its own and an enclosing query resolves.
struct Captures<'scope, 'query, 'db, DB: DatabaseLike> {
    database: &'db DB,
    scope: &'scope ColumnScope<'query, 'db, DB>,
    found: Vec<(String, String)>,
}

impl<DB: DatabaseLike> Captures<'_, '_, '_, DB> {
    fn check_body(
        &mut self,
        subquery: &Query,
        local: &ColumnScope<'_, '_, DB>,
        body: &SetExpr,
    ) -> Result<(), LookupError> {
        match body {
            SetExpr::Select(select) => self.check_select(subquery, local, select),
            SetExpr::SetOperation { left, right, .. } => {
                self.check_body(subquery, local, left)?;
                self.check_body(subquery, local, right)
            }
            SetExpr::Query(nested) => self.check_body(subquery, local, &nested.body),
            _ => Ok(()),
        }
    }

    fn check_select(
        &mut self,
        subquery: &Query,
        local: &ColumnScope<'_, '_, DB>,
        select: &Select,
    ) -> Result<(), LookupError> {
        let mut names: Vec<Ident> = Vec::new();
        let mut own = OwnLevel::new(|expression: &Expr| {
            if let Expr::Identifier(name) = expression
                && !names.iter().any(|seen| seen.value == name.value)
            {
                names.push(name.clone());
            }
            Ok(())
        });
        own.over(&select.projection)?;
        own.over(&select.selection)?;
        own.over(&select.having)?;
        let full = self.scope;
        local
            .scope_for_select(select)
            .zip(full.scope_for_select(select))
            .map_or(Ok(()), |(local, outer)| {
                self.check_names(subquery, &names, &local, &outer)
            })
    }

    /// Records each name that `local` cannot resolve and `outer`, which also
    /// sees the enclosing queries, resolves.
    fn check_names(
        &mut self,
        subquery: &Query,
        names: &[Ident],
        local: &ColumnDefinitionScope<'_, '_, '_, DB>,
        outer: &ColumnDefinitionScope<'_, '_, '_, DB>,
    ) -> Result<(), LookupError> {
        for name in names {
            let reference = Expr::Identifier(name.clone());
            let opaque = match local.resolve_column_definition(&reference)? {
                Some(ColumnDefinition::Opaque) => true,
                Some(_) => continue,
                None => false,
            };
            let Some((_, binding)) = outer.resolve_column_binding(&reference)? else {
                continue;
            };
            // A name an opaque relation of the subquery may expose, such as a
            // CTE whose columns the subquery alone cannot see, stays local
            // when the statement resolves it to a relation of the subquery's
            // own `FROM` or to no named relation.
            if opaque
                && binding.relation().is_none_or(|(relation, quoted)| {
                    local
                        .resolve_relation_binding(&ObjectName::from(vec![Ident {
                            quote_style: quoted.then_some('"'),
                            ..Ident::new(relation)
                        }]))
                        .is_some()
                })
            {
                continue;
            }
            let column = binding
                .exposed()
                .map_or(name.value.as_str(), |(column, _)| column);
            let outer = binding.relation().map_or_else(
                || column.to_owned(),
                |(relation, _)| format!("{relation}.{column}"),
            );
            self.found.push((
                subquery.to_string(),
                format!(
                    "`{name}` in `({subquery})` is not a column of the subquery's own tables and resolves to the outer '{outer}', so the subquery reads the outer row"
                ),
            ));
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for Captures<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        let (Expr::Subquery(subquery)
        | Expr::Exists { subquery, .. }
        | Expr::In {
            target: InTarget::Subquery(subquery),
            ..
        }) = expression
        else {
            return ControlFlow::Continue(());
        };
        ColumnScope::from_query(subquery, self.database, IdentifierCase::Folded)
            .and_then(|local| self.check_body(subquery, &local, &subquery.body))
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

query_rule!(
    /// Struct defining a rule that reports an unqualified name in a subquery
    /// that the subquery's own tables lack, so PostgreSQL resolves it to an
    /// enclosing query's table.
    ///
    /// Measured on PostgreSQL 17.11 and 18.6, with `banned` holding no `id`,
    /// `teams WHERE id IN (SELECT id FROM banned)` matched all 60 teams
    /// instead of 1, and the same filter in a `DELETE` deleted all 60. The
    /// rule reads the `IN`, `EXISTS`, `ANY` and scalar subqueries of
    /// `SELECT`, `INSERT … SELECT`, `UPDATE` and `DELETE` statements, and
    /// checks the select list, `WHERE` and `HAVING` of each. A qualified
    /// outer reference such as `teams.id` states the intent and is not
    /// reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = OuterColumnCapture::default().into();
    /// let database = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE teams (id INT); CREATE TABLE banned (team_id INT);",
    /// )
    /// .unwrap();
    /// let check = |sql: &str| {
    ///     let statement = &Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap()[0];
    ///     constrainer.validate_statement(&database, statement)
    /// };
    /// assert!(check("SELECT id FROM teams WHERE id IN (SELECT id FROM banned)").is_err());
    /// assert!(check("SELECT id FROM teams WHERE id IN (SELECT team_id FROM banned)").is_ok());
    /// ```
    OuterColumnCapture,
    LintGroup::Correctness,
    "A subquery may read the columns of the queries around it, so a name its own tables lack silently becomes the outer row's value.",
    Some("https://www.postgresql.org/docs/current/functions-subquery.html")
);

impl<DB: DatabaseLike> QueryRule for OuterColumnCapture<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let Some(root) = root_query(statement) else {
            return Ok(());
        };
        let scope = ColumnScope::from_query(&root, database, IdentifierCase::Folded)?;
        let mut captures = Captures {
            database,
            scope: &scope,
            found: Vec::new(),
        };
        root.visit(&mut captures)
            .break_value()
            .map_or(Ok(()), Err)?;
        for (subquery, message) in captures.found {
            reporter.statement(
                statement,
                subquery,
                format!("{message}."),
                "Qualify the name with the table it belongs to, such as banned.team_id, or with the outer table when the subquery is meant to read the outer row.".to_owned(),
            )?;
        }
        Ok(())
    }
}
