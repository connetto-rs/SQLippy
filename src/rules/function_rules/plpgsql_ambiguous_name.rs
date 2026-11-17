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
    ArgMode, ConflictTarget, Expr, Ident, OnInsert, Query, SelectItem,
    SelectItemQualifiedWildcardKind, SetExpr, Statement, TableFactor, Visitor,
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{function_rules::unreadable_body, walk_support::walk},
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
    /// column named `new` or `old` collides only in a trigger function.
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
    }
);

/// A name a column and a variable both answer to.
struct Collision {
    name: String,
    variable: String,
    kind: &'static str,
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

/// Whether a relation of `select`'s `FROM` is named or aliased `qualifier`.
fn names_relation(from: &[sqlparser::ast::TableWithJoins], qualifier: &Ident) -> bool {
    from.iter()
        .flat_map(|item| {
            std::iter::once(&item.relation).chain(item.joins.iter().map(|join| &join.relation))
        })
        .any(|factor| {
            let named = match factor {
                TableFactor::Table { name, alias, .. } => alias
                    .as_ref()
                    .map(|alias| &alias.name)
                    .or_else(|| name.0.last().and_then(|part| part.as_ident())),
                TableFactor::Derived { alias, .. } | TableFactor::Function { alias, .. } => {
                    alias.as_ref().map(|alias| &alias.name)
                }
                _ => None,
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
    fn found(
        name: String,
        variable: &PlPgSqlVariable<'_>,
    ) -> ControlFlow<Result<Collision, LookupError>> {
        ControlFlow::Break(Ok(Collision {
            name,
            variable: variable.name().to_owned(),
            kind: kind(variable),
        }))
    }
}

impl<DB: DatabaseLike> Visitor for Collisions<'_, '_, '_, DB> {
    type Break = Result<Collision, LookupError>;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if !matches!(
            expression,
            Expr::Identifier(_) | Expr::CompoundIdentifier(_)
        ) {
            return ControlFlow::Continue(());
        }
        let column = match self.context.reference(expression) {
            Ok(found) => found.is_some_and(|(definition, _)| {
                !matches!(
                    definition,
                    ColumnDefinition::Variable(_)
                        | ColumnDefinition::VariableField(_)
                        | ColumnDefinition::Parameter { .. }
                )
            }),
            Err(error) => return ControlFlow::Break(Err(error)),
        };
        if !column {
            return ControlFlow::Continue(());
        }
        match self.context.variable(expression) {
            Ok(Some(variable)) => Self::found(expression.to_string(), &variable),
            Ok(None) => ControlFlow::Continue(()),
            Err(error) => ControlFlow::Break(Err(error)),
        }
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        let SetExpr::Select(select) = query.body.as_ref() else {
            return ControlFlow::Continue(());
        };
        for item in &select.projection {
            let SelectItem::QualifiedWildcard(SelectItemQualifiedWildcardKind::ObjectName(name), _) =
                item
            else {
                continue;
            };
            let Some(qualifier) = name
                .0
                .iter()
                .map(|part| part.as_ident().cloned())
                .collect::<Option<Vec<Ident>>>()
            else {
                continue;
            };
            if let [relation] = qualifier.as_slice()
                && names_relation(&select.from, relation)
                && let Some(variable) = self.scope.wildcard_variable(&qualifier)
            {
                return Self::found(format!("{name}.*"), &variable);
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        if let Statement::Insert(insert) = statement
            && let Some(OnInsert::OnConflict(conflict)) = &insert.on
            && let Some(ConflictTarget::Columns { columns, .. }) = &conflict.conflict_target
        {
            for column in columns {
                if let Some(variable) = self.scope.variable(std::slice::from_ref(column)) {
                    return Self::found(column.to_string(), &variable);
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// The first name of `function`'s body a column and a variable share.
fn collision<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
) -> Result<Option<Collision>, LookupError> {
    let body = match function.plpgsql_sites(database) {
        Ok(body) => body,
        Err(error) if unreadable_body(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let sites = match body.sites() {
        Ok(sites) => sites,
        Err(error) if unreadable_body(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
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
