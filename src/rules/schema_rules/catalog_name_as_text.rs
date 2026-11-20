//! Submodule providing the `CatalogNameAsText` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ExpressionContext},
    traits::{ColumnLike, DataTypeLike, DatabaseLike, TableLike, ViewLike},
};
use sqlparser::ast::{BinaryOperator, Expr, InTarget, Visit, Visitor};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        literal_support::text_literal,
        policy_support::unnested,
        type_support::underlying_type,
        typed_site_support::{TypedFinder, TypedFinding, check_typed_sites},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

schema_rule!(
    /// Struct defining a rule that reports a text column compared with the
    /// name of a relation of the schema, or with the name of the table a
    /// trigger fires on.
    ///
    /// The comparisons read are `=`, `<>`, `IS [NOT] DISTINCT FROM`,
    /// `[NOT] IN`, `= ANY` and `<> ALL` over `ARRAY[...]`, and a simple
    /// `CASE`, whose one side is a stored column of a text type, through
    /// domains, and whose other side is a string literal naming a table,
    /// view or materialized view, bare or schema-qualified, or
    /// `TG_TABLE_NAME` or `TG_RELNAME`. A literal naming no relation is not
    /// reported, and a category that happens to share a table's name is,
    /// which is why the rule is pedantic. Storing a name, as an audit log
    /// does, is not reported. The rule reads views, materialized views,
    /// policies, table check constraints and SQL and PL/pgSQL function
    /// bodies.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = CatalogNameAsText::default().into();
    /// let text = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE documents (id INT PRIMARY KEY);
    ///      CREATE TABLE grants (id INT PRIMARY KEY, relation_name TEXT NOT NULL);
    ///      CREATE VIEW document_grants AS SELECT id FROM grants WHERE relation_name = 'documents';",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&text).is_err());
    /// let identity = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE documents (id INT PRIMARY KEY);
    ///      CREATE TABLE grants (id INT PRIMARY KEY, relation_name REGCLASS NOT NULL);
    ///      CREATE VIEW document_grants AS SELECT id FROM grants WHERE relation_name = 'public.documents'::regclass;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&identity).is_ok());
    /// ```
    CatalogNameAsText,
    LintGroup::Pedantic,
    "A relation named by text has no stable identity, so a rename or a drop can leave stored names pointing at nothing.",
    Some("https://www.postgresql.org/docs/current/datatype-oid.html"),
    RuleExample {
        bad: "CREATE TABLE documents (id INT PRIMARY KEY);\n\
CREATE TABLE grants (id INT PRIMARY KEY, relation_name TEXT NOT NULL);\n\
CREATE FUNCTION document_grants() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT id FROM grants WHERE relation_name = 'documents' $$;",
        good: "CREATE TABLE documents (id INT PRIMARY KEY);\n\
CREATE TABLE grants (id INT PRIMARY KEY, relation_name REGCLASS NOT NULL);\n\
CREATE FUNCTION document_grants() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT id FROM grants WHERE relation_name = 'public.documents'::regclass $$;",
    }
);

/// The operand pairs a comparison tests, each in both orders.
fn compared(expression: &Expr) -> Vec<(&Expr, &Expr)> {
    let pairs: Vec<(&Expr, &Expr)> = match expression {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq | BinaryOperator::NotEq,
            right,
        }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => vec![(left, right)],
        Expr::In {
            expr,
            target: InTarget::List(list),
            ..
        } => list.iter().map(|item| (expr.as_ref(), item)).collect(),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq | BinaryOperator::NotEq,
            right,
            ..
        }
        | Expr::AllOp {
            left,
            compare_op: BinaryOperator::Eq | BinaryOperator::NotEq,
            right,
        } => match unnested(right) {
            Expr::Array(array) => array
                .elem
                .iter()
                .map(|item| (left.as_ref(), item))
                .collect(),
            _ => Vec::new(),
        },
        Expr::Case {
            operand: Some(operand),
            conditions,
            ..
        } => conditions
            .iter()
            .map(|when| (operand.as_ref(), &when.condition))
            .collect(),
        _ => Vec::new(),
    };
    pairs
        .into_iter()
        .flat_map(|(left, right)| [(left, right), (right, left)])
        .collect()
}

/// The `table.column` name of the stored text column `expression` reads.
fn text_column<DB: DatabaseLike>(
    context: &ExpressionContext<'_, '_, DB>,
    expression: &Expr,
) -> Result<Option<String>, LookupError> {
    let expression = unnested(expression);
    if !matches!(
        expression,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
    ) {
        return Ok(None);
    }
    Ok(match context.reference(expression)? {
        Some((
            ColumnDefinition::Base {
                table,
                column,
                database,
            },
            _,
        )) if underlying_type(database, column.data_type(database)).is_textual(database) => {
            Some(format!("{}.{}", table.table_name(), column.column_name()))
        }
        _ => None,
    })
}

/// Whether a relation stored as `schema` and `name` is the one `written`
/// names, bare or as `schema.name`, a relation stored without a schema
/// standing in `public`.
fn written_as(written: &str, schema: Option<&str>, name: &str) -> bool {
    match written.split_once('.') {
        Some((written_schema, written_name)) => {
            written_name == name && written_schema == schema.unwrap_or("public")
        }
        None => written == name,
    }
}

/// What the relation `expression` names is, described, when it is a string
/// literal naming a relation of the schema or the trigger's table name.
fn relation_named<DB: DatabaseLike>(database: &DB, expression: &Expr) -> Option<String> {
    if let Expr::Identifier(name) = unnested(expression)
        && name.quote_style.is_none()
        && ["tg_table_name", "tg_relname"]
            .iter()
            .any(|variable| name.value.eq_ignore_ascii_case(variable))
    {
        return Some(format!("the trigger's table name `{}`", name.value));
    }
    let written = text_literal(expression)?;
    if let Some(table) = database.tables().find(|table| {
        written_as(
            written,
            table.stored_table_schema().as_deref(),
            &table.stored_table_name(),
        )
    }) {
        return Some(format!("the name of table '{}'", table.table_name()));
    }
    if let Some(view) = database.views().find(|view| {
        written_as(
            written,
            view.stored_view_schema().as_deref(),
            &view.stored_view_name(),
        )
    }) {
        return Some(format!("the name of view '{}'", view.view_name()));
    }
    database
        .materialized_views()
        .find(|view| {
            written_as(
                written,
                view.stored_view_schema().as_deref(),
                &view.stored_view_name(),
            )
        })
        .map(|view| format!("the name of materialized view '{}'", view.view_name()))
}

/// Collects the comparisons of text columns with relation names.
struct Comparisons<'c, 'q, 'db, DB: DatabaseLike> {
    database: &'db DB,
    context: &'c ExpressionContext<'q, 'db, DB>,
    found: Vec<TypedFinding>,
}

impl<DB: DatabaseLike> Visitor for Comparisons<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        for (column_side, name_side) in compared(expression) {
            let Some(relation) = relation_named(self.database, name_side) else {
                continue;
            };
            let column = match text_column(self.context, column_side) {
                Ok(Some(column)) => column,
                Ok(None) => continue,
                Err(error) => return ControlFlow::Break(error),
            };
            self.found.push(TypedFinding {
                found: format!(
                    "`{expression}`, comparing text column '{column}' with {relation}"
                ),
                resolution: match Engine::of(self.database) {
                    Engine::PostgreSql => "Type the column `regclass`, which keeps the relation's identity through renames and refuses a dropped one, and compare it with `'schema.relation'::regclass` under a controlled `search_path`, or declare an enum when the values are categories rather than relations.",
                    Engine::Sqlite => "Maintain stored relation names explicitly in every rename or drop migration, or use stable application categories rather than relation names.",
                }.to_owned(),
            });
            break;
        }
        ControlFlow::Continue(())
    }
}

/// Finds and explains comparisons of text columns with relation names.
struct Finder;

impl TypedFinder for Finder {
    fn reads_checks(&self) -> bool {
        true
    }

    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        context: &ExpressionContext<'_, '_, DB>,
        node: &V,
        _clause: bool,
    ) -> Result<Vec<TypedFinding>, LookupError> {
        let mut comparisons = Comparisons {
            database,
            context,
            found: Vec::new(),
        };
        if let ControlFlow::Break(error) = walk(node, &mut comparisons) {
            return Err(error);
        }
        Ok(comparisons.found)
    }

    fn problem(&self) -> &'static str {
        "so the row names a relation by text, which a rename or a drop leaves pointing at nothing"
    }
}

impl<DB: DatabaseLike> SchemaRule for CatalogNameAsText<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        check_typed_sites(&Finder, database, reporter)
    }
}
