//! Trigger functions choosing their behaviour by the spelling of the table
//! that fired them.

use std::{collections::HashSet, ops::ControlFlow};

use sql_traits::traits::{DatabaseLike, FunctionLike};
use sqlparser::ast::{BinaryOperator, Expr, Ident, InTarget, Query, Visitor};
use sqlparser_plpgsql::{
    embedded::{Block, Node, NodeKind},
    namespace::{FunctionKind, NameKind, Namespace, Signature, Sql, TriggerVariable},
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        literal_support::text_literal, plpgsql_flow_support::plpgsql_block,
        trigger_support::evaluated, walk_support::walk,
    },
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports a trigger function comparing
    /// `TG_TABLE_NAME` or `TG_RELNAME` with a table name to choose what it
    /// does.
    ///
    /// The rule does not run on SQLite, which has no trigger functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = TableNameDispatch::default().into();
    /// let schema = |body: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE TABLE events (kind TEXT);
    ///          CREATE FUNCTION record() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {body} RETURN NEW; END $$;"
    ///     ))
    ///     .unwrap()
    /// };
    /// let dispatching = schema(
    ///     "IF TG_TABLE_NAME = 'notes' THEN INSERT INTO events VALUES ('note'); END IF;",
    /// );
    /// assert!(constrainer.validate_schema(&dispatching).is_err());
    /// let argument = schema("INSERT INTO events VALUES (TG_ARGV[0]);");
    /// assert!(constrainer.validate_schema(&argument).is_ok());
    /// ```
    TableNameDispatch,
    register_function_rule,
    LintGroup::Pedantic,
    "A trigger function that branches on TG_TABLE_NAME runs the wrong branch once a table is renamed or the function is attached to another table, while one function per behaviour, or a trigger argument read from TG_ARGV, states the behaviour where the trigger is created.",
    Some("https://www.postgresql.org/docs/18/plpgsql-trigger.html"),
    RuleExample {
        bad: "CREATE TABLE notes (id integer PRIMARY KEY);\n\
CREATE TABLE folders (id integer PRIMARY KEY);\n\
CREATE TABLE events (object_id integer NOT NULL, kind text NOT NULL);\n\
CREATE FUNCTION record_object() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_TABLE_NAME = 'notes' THEN INSERT INTO events VALUES (NEW.id, 'note'); ELSE INSERT INTO events VALUES (NEW.id, 'folder'); END IF; RETURN NEW; END $$;\n\
CREATE TRIGGER record_note AFTER INSERT ON notes FOR EACH ROW EXECUTE FUNCTION record_object();\n\
CREATE TRIGGER record_folder AFTER INSERT ON folders FOR EACH ROW EXECUTE FUNCTION record_object();",
        good: "CREATE TABLE notes (id integer PRIMARY KEY);\n\
CREATE TABLE folders (id integer PRIMARY KEY);\n\
CREATE TABLE events (object_id integer NOT NULL, kind text NOT NULL);\n\
CREATE FUNCTION record_note() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO events VALUES (NEW.id, 'note'); RETURN NEW; END $$;\n\
CREATE FUNCTION record_folder() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO events VALUES (NEW.id, 'folder'); RETURN NEW; END $$;\n\
CREATE TRIGGER record_note AFTER INSERT ON notes FOR EACH ROW EXECUTE FUNCTION record_note();\n\
CREATE TRIGGER record_folder AFTER INSERT ON folders FOR EACH ROW EXECUTE FUNCTION record_folder();",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

/// Whether `ident` reaches `TG_TABLE_NAME` or `TG_RELNAME` in `namespace`.
fn names_table(namespace: &Namespace, ident: &Ident) -> bool {
    let stored = if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_lowercase()
    };
    matches!(
        namespace.lookup(&[stored], |_| false),
        Some((name, 1)) if matches!(
            name.kind(),
            NameKind::Trigger(TriggerVariable::TgTableName | TriggerVariable::TgRelname)
        )
    )
}

/// Whether `expression` is a bare name reaching the firing table's name.
fn is_table_name(namespace: &Namespace, expression: &Expr) -> bool {
    match expression {
        Expr::Identifier(ident) => names_table(namespace, ident),
        Expr::Nested(inner) => is_table_name(namespace, inner),
        _ => false,
    }
}

/// Finds the first comparison of the firing table's name with a literal.
struct Comparison<'n> {
    namespace: &'n Namespace,
}

impl Visitor for Comparison<'_> {
    type Break = String;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<String> {
        let compared = |left: &Expr, right: &Expr| {
            (is_table_name(self.namespace, left) && text_literal(right).is_some())
                || (is_table_name(self.namespace, right) && text_literal(left).is_some())
        };
        let found = match expression {
            Expr::BinaryOp { left, op, right } => {
                matches!(op, BinaryOperator::Eq | BinaryOperator::NotEq) && compared(left, right)
            }
            Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => {
                compared(left, right)
            }
            Expr::In {
                expr,
                target: InTarget::List(list),
                ..
            } => {
                is_table_name(self.namespace, expr)
                    && list.iter().any(|item| text_literal(item).is_some())
            }
            Expr::Case {
                operand: Some(operand),
                conditions,
                ..
            } => {
                is_table_name(self.namespace, operand)
                    && conditions
                        .iter()
                        .any(|when| text_literal(&when.condition).is_some())
            }
            _ => false,
        };
        if found {
            ControlFlow::Break(expression.to_string())
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// Collects the subject of every `CASE` statement in `nodes`.
fn case_subjects(nodes: &[Node], subjects: &mut HashSet<*const Query>) {
    for node in nodes {
        match &node.kind {
            NodeKind::Case(case) => {
                subjects.extend(case.subject.as_deref().map(std::ptr::from_ref));
                for branch in &case.branches {
                    case_subjects(&branch.statements, subjects);
                }
                case_subjects(case.otherwise.as_deref().unwrap_or_default(), subjects);
            }
            NodeKind::If(conditional) => {
                for branch in &conditional.branches {
                    case_subjects(&branch.statements, subjects);
                }
                case_subjects(&conditional.otherwise, subjects);
            }
            NodeKind::Loop(repeated) => case_subjects(&repeated.statements, subjects),
            NodeKind::Block(block) => block_case_subjects(block, subjects),
            _ => {}
        }
    }
}

/// Collects the subject of every `CASE` statement in `block`.
fn block_case_subjects(block: &Block, subjects: &mut HashSet<*const Query>) {
    case_subjects(&block.statements, subjects);
    for handler in &block.handlers {
        case_subjects(&handler.statements, subjects);
    }
}

/// The first place `block` compares the firing table's name with a literal.
fn dispatch(block: &Block, signature: &Signature) -> Option<String> {
    let mut subjects = HashSet::new();
    block_case_subjects(block, &mut subjects);
    let sites = block.sites(signature, |_| false).ok()?;
    sites.iter().find_map(|site| {
        let mut comparison = Comparison {
            namespace: &site.namespace,
        };
        match site.sql {
            Sql::Statement(statement) => walk(statement, &mut comparison).break_value(),
            Sql::Expression(query) => {
                if subjects.contains(&std::ptr::from_ref(query))
                    && evaluated(query)
                        .is_some_and(|subject| is_table_name(&site.namespace, subject))
                {
                    return Some(format!("CASE {query}"));
                }
                walk(query, &mut comparison).break_value()
            }
            Sql::Dynamic(_) => None,
        }
    })
}

impl<DB: DatabaseLike> FunctionRule for TableNameDispatch<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let returns_trigger = function
            .normalized_return_type_name(database)
            .is_some_and(|name| {
                name.rsplit('.')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("trigger"))
            });
        if !returns_trigger {
            return Ok(());
        }
        let Some(block) = plpgsql_block(function) else {
            return Ok(());
        };
        // PostgreSQL refuses a trigger function that declares parameters.
        let trigger_signature = Signature {
            name: function.stored_name().into_owned(),
            parameters: Vec::new(),
            kind: FunctionKind::Trigger,
        };
        if let Some(found) = dispatch(&block, &trigger_signature) {
            reporter.function(
                function,
                format!(
                    "Function '{}' compares the firing table's name with a table name in `{found}`, so a renamed table or a new trigger on another table runs the wrong branch.",
                    signature(function, database)
                ),
                "Give each behaviour its own trigger function, or pass the behaviour as an argument in each CREATE TRIGGER and read it from TG_ARGV."
                    .to_owned(),
            )?;
        }
        Ok(())
    }
}
