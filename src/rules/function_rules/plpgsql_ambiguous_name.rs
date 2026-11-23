//! PL/pgSQL column references a parameter or variable of the same name
//! makes ambiguous.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{
        ColumnDefinition, ExpressionContext, IdentifierCase, PlPgSqlScope, PlPgSqlVariable,
        VariableKind,
    },
    traits::{DatabaseLike, FunctionLike},
};
use sqlparser::ast::{
    ArgMode, ConflictTarget, Expr, Ident, ObjectNamePart, OnInsert, Query, SelectItem,
    SelectItemQualifiedWildcardKind, Statement, TableFactor, TableWithJoins, Visitor,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{function_rules::readable, walk_support::walk},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports an unqualified column reference
    /// in a PL/pgSQL body whose name also reaches a parameter or variable.
    ///
    /// Under the default `plpgsql.variable_conflict = error` PostgreSQL
    /// refuses the statement as ambiguous the first time it runs, which
    /// `CREATE FUNCTION` does not check. Under `use_column` or
    /// `use_variable` it binds the name to one of the two without a word.
    /// A `RETURNS TABLE` column is an output parameter, so it collides with
    /// a column of the same name in an `ON CONFLICT` target as well. A
    /// column named `new` or `old` collides only in a trigger function. A
    /// name that only a relation of unknown columns could hold, such as a
    /// function in `FROM` sql-traits cannot describe, is not reported.
    ///
    /// The rule does not run on SQLite, which has no stored functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = PlpgsqlAmbiguousName::default().into();
    /// let schema = |argument: &str, read: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE TABLE notes (id INT PRIMARY KEY);
    ///          CREATE FUNCTION find_note({argument} INT) RETURNS INT LANGUAGE plpgsql AS $$
    ///          DECLARE result INT;
    ///          BEGIN SELECT {read} INTO result FROM notes WHERE notes.id = {argument}; RETURN result; END $$;"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("id", "id")).is_err());
    /// assert!(constrainer.validate_schema(&schema("requested_id", "notes.id")).is_ok());
    /// ```
    PlpgsqlAmbiguousName,
    register_function_rule,
    LintGroup::Suspicious,
    "A PL/pgSQL statement that names a column the way it names a parameter or variable is refused as ambiguous the first time it runs, after CREATE FUNCTION has accepted it, and under a non-default plpgsql.variable_conflict it silently reads the wrong one.",
    Some("https://www.postgresql.org/docs/18/plpgsql-implementation.html#PLPGSQL-VAR-SUBST"),
    RuleExample {
        bad: "CREATE TABLE notes (id integer PRIMARY KEY);\n\
CREATE FUNCTION find_note(id integer) RETURNS integer LANGUAGE plpgsql AS $$ DECLARE result integer; BEGIN SELECT id INTO result FROM notes WHERE notes.id = find_note.id; RETURN result; END $$;",
        good: "CREATE TABLE notes (id integer PRIMARY KEY);\n\
CREATE FUNCTION find_note(requested_id integer) RETURNS integer LANGUAGE plpgsql AS $$ DECLARE result integer; BEGIN SELECT notes.id INTO result FROM notes WHERE notes.id = requested_id; RETURN result; END $$;",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

/// A name a column and a variable both answer to.
struct Collision {
    name: String,
    variable: String,
    kind: &'static str,
}

impl Collision {
    fn new(name: String, variable: &PlPgSqlVariable<'_>) -> Self {
        Self {
            name,
            variable: variable.name().to_owned(),
            kind: kind(variable),
        }
    }
}

/// What `variable` is, as a message names it.
fn kind(variable: &PlPgSqlVariable<'_>) -> &'static str {
    match variable.kind() {
        VariableKind::Parameter {
            mode: ArgMode::Out, ..
        } => "output parameter",
        VariableKind::Parameter { .. } => "parameter",
        VariableKind::Cursor => "cursor",
        VariableKind::CursorParameter => "cursor parameter",
        VariableKind::LoopIndex | VariableKind::LoopRecord => "loop variable",
        VariableKind::Handler => "exception variable",
        VariableKind::Trigger => "trigger variable",
        VariableKind::ReturnValue | VariableKind::Found | VariableKind::Declared { .. } => {
            "variable"
        }
    }
}

/// Whether a relation `item` joins, inside an unaliased parenthesized join
/// too, is named or aliased `qualifier`.
fn names_relation(item: &TableWithJoins, qualifier: &Ident) -> bool {
    std::iter::once(&item.relation)
        .chain(item.joins.iter().map(|join| &join.relation))
        .any(|factor| {
            let named = match factor {
                TableFactor::Table { name, alias, .. } => alias
                    .as_ref()
                    .map(|alias| &alias.name)
                    .or_else(|| name.0.last().and_then(ObjectNamePart::as_ident)),
                TableFactor::NestedJoin {
                    table_with_joins,
                    alias: None,
                } => return names_relation(table_with_joins, qualifier),
                TableFactor::NestedJoin { alias, .. }
                | TableFactor::Derived { alias, .. }
                | TableFactor::TableFunction { alias, .. }
                | TableFactor::Function { alias, .. }
                | TableFactor::UNNEST { alias, .. }
                | TableFactor::JsonTable { alias, .. }
                | TableFactor::OpenJsonTable { alias, .. }
                | TableFactor::Pivot { alias, .. }
                | TableFactor::Unpivot { alias, .. }
                | TableFactor::MatchRecognize { alias, .. }
                | TableFactor::XmlTable { alias, .. }
                | TableFactor::SemanticView { alias, .. } => {
                    alias.as_ref().map(|alias| &alias.name)
                }
                TableFactor::UnpivotExpr { .. } => None,
            };
            named.is_some_and(|named| {
                IdentifierCase::Folded.identifiers_match(
                    &named.value,
                    named.quote_style.is_some(),
                    &qualifier.value,
                    qualifier.quote_style.is_some(),
                )
            })
        })
}

/// Finds the first name of one site that a column and a variable share.
struct Collisions<'c, 'b, 'db, DB: DatabaseLike> {
    context: &'c ExpressionContext<'c, 'db, DB>,
    scope: &'c PlPgSqlScope<'b, 'db, DB>,
}

impl<DB: DatabaseLike> Collisions<'_, '_, '_, DB> {
    /// The collision of a column reference that also names a variable. A
    /// binding that exposes no column name reached a relation whose columns
    /// are unknown, which may not hold the name at all, so it collides with
    /// nothing.
    fn reference(&self, expression: &Expr) -> Result<Option<Collision>, LookupError> {
        if !matches!(
            expression,
            Expr::Identifier(_) | Expr::CompoundIdentifier(_)
        ) {
            return Ok(None);
        }
        let column = self
            .context
            .reference(expression)?
            .is_some_and(|(definition, binding)| {
                binding.exposed().is_some()
                    && !matches!(
                        definition,
                        ColumnDefinition::Variable(_)
                            | ColumnDefinition::VariableField(_)
                            | ColumnDefinition::Parameter { .. }
                    )
            });
        if !column {
            return Ok(None);
        }
        Ok(self
            .context
            .variable(expression)?
            .map(|variable| Collision::new(expression.to_string(), &variable)))
    }
}

/// Stops the walk at `collision`, a lookup failure included.
fn stop(
    collision: Result<Option<Collision>, LookupError>,
) -> ControlFlow<Result<Collision, LookupError>> {
    match collision.transpose() {
        Some(found) => ControlFlow::Break(found),
        None => ControlFlow::Continue(()),
    }
}

impl<DB: DatabaseLike> Visitor for Collisions<'_, '_, '_, DB> {
    type Break = Result<Collision, LookupError>;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        stop(self.reference(expression))
    }

    /// An `alias.*` whose alias names both a relation of the `FROM` and a
    /// variable.
    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        let Some(select) = query.body.as_select() else {
            return ControlFlow::Continue(());
        };
        let found =
            select.projection.iter().find_map(|item| {
                let SelectItem::QualifiedWildcard(
                    SelectItemQualifiedWildcardKind::ObjectName(name),
                    _,
                ) = item
                else {
                    return None;
                };
                let [part] = name.0.as_slice() else {
                    return None;
                };
                let relation = part.as_ident()?;
                if !select
                    .from
                    .iter()
                    .any(|item| names_relation(item, relation))
                {
                    return None;
                }
                self.scope
                    .wildcard_variable(std::slice::from_ref(relation))
                    .map(|variable| Collision::new(format!("{name}.*"), &variable))
            });
        stop(Ok(found))
    }

    /// An `ON CONFLICT` column that also names a variable.
    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        if let Statement::Insert(insert) = statement
            && let Some(OnInsert::OnConflict(conflict)) = &insert.on
            && let Some(ConflictTarget::Columns { columns, .. }) = &conflict.conflict_target
        {
            return stop(Ok(columns.iter().find_map(|column| {
                self.scope
                    .variable(std::slice::from_ref(column))
                    .map(|variable| Collision::new(column.to_string(), &variable))
            })));
        }
        ControlFlow::Continue(())
    }
}

/// The first name of `function`'s body a column and a variable share.
fn collision<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
) -> Result<Option<Collision>, LookupError> {
    let Some(body) = readable(function.plpgsql_sites(database).map(Some))? else {
        return Ok(None);
    };
    let sites = readable(body.sites())?;
    for site in &sites {
        let context = site.context(IdentifierCase::Folded)?;
        let mut collisions = Collisions {
            context: &context,
            scope: site.plpgsql_scope(),
        };
        if let ControlFlow::Break(found) = walk(&site.sql(), &mut collisions) {
            return found.map(Some);
        }
    }
    Ok(None)
}

impl<DB: DatabaseLike> FunctionRule for PlpgsqlAmbiguousName<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if function.target_name().schema() == Some("pg_catalog") {
            return Ok(());
        }
        let Some(Collision {
            name,
            variable,
            kind,
        }) = collision(database, function)?
        else {
            return Ok(());
        };
        reporter.function(
            function,
            format!(
                "In function '{}', `{name}` names both a column and the {kind} '{variable}', so PostgreSQL refuses the statement as ambiguous the first time it runs.",
                signature(function, database)
            ),
            format!(
                "Qualify the column with its table or alias, or rename the {kind} '{variable}'."
            ),
        )?;
        Ok(())
    }
}
