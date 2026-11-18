//! Submodule providing the `UnqualifiedNameUnderUnsafeSearchPath` rule.

use std::ops::ControlFlow;

use sql_traits::traits::DatabaseLike;
use sqlparser::ast::{
    BinaryOperator, DataType, Expr, FunctionArguments, ObjectName, ObjectNamePart, Query,
    Statement, TableFactor, UnaryOperator, Value, Visitor,
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        cte_support::WithScopes,
        script_support::{Untrusted, untrusted},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, ScriptRule},
};

rule_definition!(
    /// Struct defining a rule that reports unqualified functions, operators,
    /// relations and cast types resolved under a `search_path` the script
    /// has not established as trusted.
    ///
    /// A path is trusted when it lists `pg_catalog`, then only schemas this
    /// script created earlier without `IF NOT EXISTS`, and ends with
    /// `pg_temp`. The session starts untrusted. `SET`, `SET LOCAL` until the
    /// transaction ends, `RESET` and `set_config('search_path', ...)` change
    /// it. A string function body is resolved at each call, under the
    /// function's own `SET search_path` when that is trusted and under its
    /// caller's otherwise. Names bound to a `WITH` item, operators written
    /// `OPERATOR(schema.op)`, `AND`, `OR`, `NOT`, negative literals and types
    /// the grammar qualifies itself, such as `integer`, are not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     UnqualifiedNameUnderUnsafeSearchPath::default().into();
    /// for (sql, findings) in [
    ///     ("SET search_path = public; SELECT lower('A');", 1),
    ///     ("SET search_path = pg_catalog, pg_temp; SELECT lower('A');", 0),
    ///     ("SET search_path = public; SELECT pg_catalog.lower('A');", 0),
    /// ] {
    ///     let database = ParserDB::parse::<PostgreSqlDialect>(sql).unwrap();
    ///     let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap();
    ///     assert_eq!(constrainer.script_diagnostics(&database, &statements).len(), findings);
    /// }
    /// ```
    UnqualifiedNameUnderUnsafeSearchPath,
    register_script_rule,
    LintGroup::Restriction,
    "A role able to create objects in a schema the search_path lists, or a temporary relation, can supply its own function, operator, relation or type in place of an unqualified name.",
    Some("https://github.com/timescale/pgspot/blob/main/src/pgspot/visitors.py"),
    RuleExample {
        bad: "CREATE TABLE public.documents (identifier INT PRIMARY KEY);\n\
SET search_path = public;\n\
SELECT lower('HELLO'), 1 + 2, identifier::text FROM documents;",
        good: "CREATE TABLE public.documents (identifier INT PRIMARY KEY);\n\
SET search_path = pg_catalog, pg_temp;\n\
SELECT pg_catalog.lower('HELLO'), 1 OPERATOR(pg_catalog.+) 2,\n\
identifier::pg_catalog.text FROM public.documents;",
    }
);

/// Type names PostgreSQL's grammar maps to `pg_catalog` types itself, so no
/// path lookup resolves them.
const GRAMMAR_TYPES: &[&str] = &[
    "bigint",
    "bit",
    "boolean",
    "char",
    "character",
    "dec",
    "decimal",
    "double",
    "float",
    "int",
    "integer",
    "interval",
    "json",
    "national",
    "nchar",
    "numeric",
    "real",
    "smallint",
    "time",
    "timestamp",
    "varchar",
];

/// The name of `data_type` when a path lookup resolves it.
fn unqualified_type(data_type: &DataType) -> Option<String> {
    let written = data_type.to_string();
    let base: String = written
        .chars()
        .take_while(|character| character.is_alphanumeric() || matches!(character, '_' | '"' | '.'))
        .collect();
    let folded = base.to_lowercase();
    (!base.is_empty() && !base.contains('.') && !GRAMMAR_TYPES.contains(&folded.as_str()))
        .then_some(written)
}

/// Whether `name` has a single part.
fn is_unqualified(name: &ObjectName) -> bool {
    matches!(name.0.as_slice(), [ObjectNamePart::Identifier(_)])
}

/// Keyword expressions sqlparser reads as function calls that PostgreSQL
/// evaluates without looking up a function: conditional expressions, array
/// and row constructors, `GROUPING` and the XML constructors.
const KEYWORD_FUNCTIONS: &[&str] = &[
    "coalesce",
    "greatest",
    "least",
    "array",
    "row",
    "grouping",
    "xmlconcat",
    "xmlelement",
    "xmlexists",
    "xmlforest",
    "xmlparse",
    "xmlpi",
    "xmlroot",
    "xmlserialize",
];

/// Collects the unqualified names a statement resolves through the path.
#[derive(Default)]
struct UnqualifiedNames {
    scopes: WithScopes,
    names: Vec<String>,
    /// Set by a table function, whose name the next relation visit repeats.
    table_function: bool,
}

impl UnqualifiedNames {
    fn push(&mut self, name: String) {
        if !self.names.contains(&name) {
            self.names.push(name);
        }
    }
}

impl Visitor for UnqualifiedNames {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        self.scopes.enter(query);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        self.scopes.leave(query);
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<()> {
        if let TableFactor::Table {
            name,
            args: Some(_),
            ..
        } = factor
        {
            self.table_function = true;
            if is_unqualified(name) {
                self.push(name.to_string());
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<()> {
        if std::mem::take(&mut self.table_function) {
            return ControlFlow::Continue(());
        }
        if is_unqualified(relation) && self.scopes.binding(relation).is_none() {
            self.push(relation.to_string());
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        let created = match statement {
            Statement::CreateFunction(function) => Some(&function.name),
            Statement::CreateAggregate(aggregate) => Some(&aggregate.name),
            Statement::CreateType { name, .. } => Some(name),
            Statement::CreateDomain(domain) => Some(&domain.name),
            _ => None,
        };
        if let Some(name) = created.filter(|name| is_unqualified(name)) {
            self.push(name.to_string());
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        let name = match expression {
            Expr::Function(function) if is_unqualified(&function.name) => {
                let name = function.name.to_string();
                let folded = name.to_lowercase();
                if matches!(function.args, FunctionArguments::None)
                    || KEYWORD_FUNCTIONS.contains(&folded.as_str())
                {
                    None
                } else if folded == "nullif" {
                    Some("= in NULLIF".to_owned())
                } else {
                    Some(name)
                }
            }
            Expr::BinaryOp { op, .. } => match op {
                BinaryOperator::And | BinaryOperator::Or => None,
                BinaryOperator::PGCustomBinaryOperator(parts) if parts.len() > 1 => None,
                op => Some(op.to_string()),
            },
            Expr::UnaryOp { op, expr } => match (op, expr.as_ref()) {
                (UnaryOperator::Not, _) => None,
                (UnaryOperator::Minus, Expr::Value(literal))
                    if matches!(literal.value, Value::Number(..)) =>
                {
                    None
                }
                (op, _) => Some(op.to_string()),
            },
            Expr::In { .. } => Some("= in IN".to_owned()),
            Expr::Between { .. } => Some(">= and <= in BETWEEN".to_owned()),
            Expr::Like { .. } => Some("LIKE".to_owned()),
            Expr::ILike { .. } => Some("ILIKE".to_owned()),
            Expr::SimilarTo { .. } => Some("SIMILAR TO".to_owned()),
            Expr::IsDistinctFrom(..) | Expr::IsNotDistinctFrom(..) => {
                Some("= in IS DISTINCT FROM".to_owned())
            }
            Expr::AnyOp { compare_op, .. } | Expr::AllOp { compare_op, .. } => match compare_op {
                BinaryOperator::PGCustomBinaryOperator(parts) if parts.len() > 1 => None,
                op => Some(op.to_string()),
            },
            Expr::Cast { data_type, .. } => unqualified_type(data_type),
            _ => None,
        };
        if let Some(name) = name {
            self.push(name);
        }
        ControlFlow::Continue(())
    }
}

/// The unqualified names `statements` resolve through the path.
fn unqualified_names(statements: &[Statement]) -> Vec<String> {
    let mut visitor = UnqualifiedNames::default();
    for statement in statements {
        let _ = walk(statement, &mut visitor);
    }
    visitor.names
}

impl<DB: DatabaseLike> ScriptRule for UnqualifiedNameUnderUnsafeSearchPath<DB> {
    type Database = DB;

    fn check_script(
        &self,
        _database: &Self::Database,
        statements: &[Statement],
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        untrusted(statements, |site| {
            let (statement, names, message, resolution) = match site {
                Untrusted::Session(statement) => {
                    let names = unqualified_names(std::slice::from_ref(statement));
                    let listed = names.join(", ");
                    (
                        statement,
                        names,
                        format!(
                            "The statement resolves {listed} through a search_path this script has not set to pg_catalog, schemas it created and pg_temp last, so a role creating in a searched schema or a temporary relation can stand in for them."
                        ),
                        "Qualify each name with its schema, operators as OPERATOR(pg_catalog.=), or first SET search_path = pg_catalog, <schemas this script creates>, pg_temp.".to_owned(),
                    )
                }
                Untrusted::Body {
                    statement,
                    kind,
                    name,
                    body,
                } => {
                    let names = unqualified_names(&body);
                    let listed = names.join(", ");
                    (
                        statement,
                        names,
                        format!(
                            "The {kind} '{name}' resolves {listed} in its body through its caller's search_path or one naming schemas this script has not created, so a caller or a role creating in a searched schema can stand in for them."
                        ),
                        format!(
                            "Give '{name}' SET search_path = pg_catalog, pg_temp, or qualify each name in its body."
                        ),
                    )
                }
            };
            if names.is_empty() {
                return Ok(());
            }
            reporter.statement(statement, names.join(", "), message, resolution)
        })
    }
}
