//! Submodule providing the `DeferredCheckDeletedRow` rule.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{ConstraintDeferral, IdentifierCase},
    traits::{ColumnLike, DatabaseLike, FunctionLike, Relation, TableLike, TriggerLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, Query,
    SetExpr, Statement, TriggerPeriod, UnaryOperator, Visitor,
};
use sqlparser_plpgsql::embedded::{Node, NodeKind, RaiseLevel};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        function_body_support::parameter,
        guarded_parent_support::sole_relation,
        key_support::equality_keys,
        plpgsql_flow_support::{FlowState, FlowVisitor, plpgsql_block, walk_block},
        policy_support::{conjuncts, sql_query_body, unnested},
        trigger_support::{
            evaluated, fires_on_insert, fires_on_update, new_field, row_trigger, stored,
            triggers_with_functions,
        },
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

rule_definition!(
    /// Struct defining a rule that reports a deferrable row-level constraint
    /// trigger whose function raises when a row related to `NEW` is missing,
    /// on a path where it has not checked that `NEW`'s own row still exists.
    ///
    /// PostgreSQL queues the event of a deferred constraint trigger and runs
    /// the function at commit even when the transaction deleted the row that
    /// fired it, so a completeness check refuses a transaction that creates
    /// and deletes the row. A rejection counts when its condition is a `NOT
    /// EXISTS` subquery reading `NEW`, or a negated call to a `LANGUAGE sql`
    /// function whose whole body is `SELECT EXISTS (...)` called with `NEW`.
    /// The existence check counts when it is an `EXISTS` subquery over the
    /// trigger's table, or such a function over it, that matches every
    /// column of one of the table's unique keys to the same field of `NEW`,
    /// and the rejection runs only on the paths where it holds. It reads
    /// the table through `ONLY` unless the table has no child table, whose
    /// rows the key does not keep apart from its own. A trigger `WHEN`
    /// clause does not count, since PostgreSQL tests it when the row
    /// changes. A check that deliberately refuses the deletion, such as one
    /// requiring a historical event, is excused with an allowance on the
    /// table.
    ///
    /// The rule does not run on SQLite, which has no trigger functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = DeferredCheckDeletedRow::default().into();
    /// let schema = |guard: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE TABLE parents (id INT PRIMARY KEY);
    ///          CREATE TABLE children (parent_id INT PRIMARY KEY REFERENCES parents (id));
    ///          CREATE FUNCTION require_child() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {guard}
    ///          IF NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id) THEN
    ///            RAISE EXCEPTION 'parent % requires a child', NEW.id;
    ///          END IF; RETURN NULL; END $$;
    ///          CREATE CONSTRAINT TRIGGER parent_requires_child AFTER INSERT ON parents
    ///          DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_child();"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("")).is_err());
    /// let guarded = "IF NOT EXISTS (SELECT FROM parents WHERE id = NEW.id) THEN RETURN NULL; END IF;";
    /// assert!(constrainer.validate_schema(&schema(guarded)).is_ok());
    /// ```
    DeferredCheckDeletedRow,
    register_schema_rule,
    LintGroup::Suspicious,
    "PostgreSQL runs a deferred constraint trigger at commit for every row event it queued, including a row the same transaction has since deleted, so a function requiring a related row of NEW refuses a transaction whose final state has neither row.",
    Some("https://www.postgresql.org/docs/18/sql-createtrigger.html"),
    RuleExample {
        bad: "CREATE TABLE parents (id integer PRIMARY KEY);\n\
CREATE TABLE children (parent_id integer PRIMARY KEY REFERENCES parents (id));\n\
CREATE FUNCTION require_child() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id) THEN RAISE EXCEPTION 'parent % requires a child', NEW.id; END IF; RETURN NULL; END $$;\n\
CREATE CONSTRAINT TRIGGER parent_requires_child AFTER INSERT ON parents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_child();",
        good: "CREATE TABLE parents (id integer PRIMARY KEY);\n\
CREATE TABLE children (parent_id integer PRIMARY KEY REFERENCES parents (id));\n\
CREATE FUNCTION require_child() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NOT EXISTS (SELECT FROM parents WHERE id = NEW.id) THEN RETURN NULL; END IF; IF NOT EXISTS (SELECT FROM children WHERE parent_id = NEW.id) THEN RAISE EXCEPTION 'parent % requires a child', NEW.id; END IF; RETURN NULL; END $$;\n\
CREATE CONSTRAINT TRIGGER parent_requires_child AFTER INSERT ON parents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_child();",
    },
    Basis::Declared,
    &[Engine::PostgreSql]
);

/// What an existence test asks about.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Subject {
    /// The trigger's own row, matched on every column of a unique key.
    Own,
    /// Another row, found through a field of `NEW`.
    Related,
}

/// What every path reaching a point has established.
#[derive(Clone, Copy, Default)]
struct Established {
    /// The trigger's own row exists.
    present: bool,
    /// A row related to `NEW` is missing.
    missing: bool,
}

impl FlowState for Established {
    fn join(&mut self, other: Self) {
        self.present &= other.present;
        self.missing &= other.missing;
    }
}

/// Whether `node` reads a field of `NEW`.
fn reads_new<N: sqlparser::ast::Visit>(node: &N) -> bool {
    struct ReadsNew;
    impl Visitor for ReadsNew {
        type Break = ();
        fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            if new_field(expression).is_some() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }
    }
    walk(node, &mut ReadsNew).is_break()
}

/// How the expressions of an existence subquery reach `NEW`, written in the
/// trigger function or passed to a helper as its arguments, each at the
/// position of the parameter it binds.
enum Scope<'c, 'db, DB: DatabaseLike> {
    Trigger,
    Helper {
        helper: &'db DB::Function,
        arguments: &'c [Option<&'c Expr>],
    },
}

impl<DB: DatabaseLike> Scope<'_, '_, DB> {
    /// The field of `NEW` `expression` stands for in this scope.
    fn field(&self, database: &DB, expression: &Expr) -> Option<String> {
        match self {
            Self::Trigger => new_field(expression).map(Cow::into_owned),
            Self::Helper { helper, arguments } => parameter(database, helper, expression)
                .and_then(|position| arguments.get(position).copied().flatten())
                .and_then(new_field)
                .map(Cow::into_owned),
        }
    }

    /// Whether the subquery reads `NEW` in this scope.
    fn reads_new(&self, subquery: &Query) -> bool {
        match self {
            Self::Trigger => reads_new(subquery),
            Self::Helper { arguments, .. } => arguments
                .iter()
                .flatten()
                .any(|argument| reads_new(*argument)),
        }
    }
}

/// Reads the existence tests of a trigger function's conditions for one
/// trigger's table.
struct Tests<'db, DB: DatabaseLike> {
    database: &'db DB,
    table: &'db DB::Table,
    /// The folded column names of each unique key of `table`.
    keys: Vec<Vec<String>>,
}

impl<'db, DB: DatabaseLike> Tests<'db, DB> {
    /// What the `EXISTS` subquery `subquery` asks about in `scope`, `None`
    /// when it reads nothing of `NEW`.
    fn subquery(&self, scope: &Scope<'_, 'db, DB>, subquery: &Query) -> Option<Subject> {
        if self.own_row(scope, subquery) {
            return Some(Subject::Own);
        }
        scope.reads_new(subquery).then_some(Subject::Related)
    }

    /// Whether `subquery` selects from the trigger's table alone the row
    /// whose every column of one unique key equals the same field of `NEW`.
    fn own_row(&self, scope: &Scope<'_, 'db, DB>, subquery: &Query) -> bool {
        let SetExpr::Select(select) = subquery.body.as_ref() else {
            return false;
        };
        let ([from], Some(selection)) = (select.from.as_slice(), &select.selection) else {
            return false;
        };
        if !from.joins.is_empty() {
            return false;
        }
        let Some(exposed) = sole_relation(self.database, &from.relation, self.table) else {
            return false;
        };
        let column = |expression: &Expr| match unnested(expression) {
            Expr::Identifier(column) => Some(stored(column).into_owned()),
            Expr::CompoundIdentifier(parts) if parts.len() == 2 && stored(&parts[0]) == exposed => {
                Some(stored(&parts[1]).into_owned())
            }
            _ => None,
        };
        let mut matched = Vec::new();
        for conjunct in conjuncts(selection) {
            let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = unnested(conjunct)
            else {
                continue;
            };
            for (side, value) in [(left, right), (right, left)] {
                if let Some(named) = column(side)
                    && scope.field(self.database, value).as_ref() == Some(&named)
                {
                    matched.push(named);
                }
            }
        }
        self.keys
            .iter()
            .any(|key| key.iter().all(|column| matched.contains(column)))
    }

    /// What a call to a `LANGUAGE sql` function whose whole body is `SELECT
    /// EXISTS (...)` asks about, `None` for any other call.
    fn helper(&self, call: &Function) -> Result<Option<Subject>, LookupError> {
        let FunctionArguments::List(list) = &call.args else {
            return Ok(None);
        };
        // A name PostgreSQL cannot call, such as one with three parts, calls no helper.
        let Ok(mut reached) = self
            .database
            .functions_reached_by(call, IdentifierCase::Folded)
        else {
            return Ok(None);
        };
        let (Some(helper), None) = (reached.next(), reached.next()) else {
            return Ok(None);
        };
        let names = helper
            .stored_argument_names(self.database)
            .collect::<Vec<_>>();
        let mut arguments = vec![None; names.len()];
        for (position, argument) in list.args.iter().enumerate() {
            let (position, value) = match argument {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(value)) => (Some(position), value),
                FunctionArg::Named {
                    name,
                    arg: FunctionArgExpr::Expr(value),
                    ..
                }
                | FunctionArg::ExprNamed {
                    name: Expr::Identifier(name),
                    arg: FunctionArgExpr::Expr(value),
                    ..
                } => (
                    names
                        .iter()
                        .position(|parameter| parameter.as_deref() == Some(&*stored(name))),
                    value,
                ),
                _ => return Ok(None),
            };
            let Some(slot) = position.and_then(|position| arguments.get_mut(position)) else {
                return Ok(None);
            };
            *slot = Some(value);
        }
        let Some(body) = sql_query_body(self.database, helper)? else {
            return Ok(None);
        };
        let Some(Expr::Exists {
            subquery,
            negated: false,
        }) = evaluated(&body)
        else {
            return Ok(None);
        };
        Ok(self.subquery(
            &Scope::Helper {
                helper,
                arguments: &arguments,
            },
            subquery,
        ))
    }

    /// Calls `found` with what each existence test of `condition` asks
    /// about and whether its row exists when `condition` evaluates to
    /// `holds`.
    fn implied(
        &self,
        condition: &Expr,
        holds: bool,
        found: &mut impl FnMut(Subject, bool),
    ) -> Result<(), LookupError> {
        match condition {
            Expr::Nested(inner) => self.implied(inner, holds, found)?,
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr,
            } => self.implied(expr, !holds, found)?,
            Expr::BinaryOp { left, op, right }
                if (holds && *op == BinaryOperator::And)
                    || (!holds && *op == BinaryOperator::Or) =>
            {
                self.implied(left, holds, found)?;
                self.implied(right, holds, found)?;
            }
            Expr::Exists { subquery, negated } => {
                if let Some(subject) = self.subquery(&Scope::Trigger, subquery) {
                    found(subject, holds != *negated);
                }
            }
            Expr::Function(call) => {
                if let Some(subject) = self.helper(call)? {
                    found(subject, holds);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Walks a trigger function, finding a rejection on a related row that is
/// missing, on a path that has not established the trigger's own row.
struct Rejections<'t, 'db, DB: DatabaseLike> {
    tests: &'t Tests<'db, DB>,
    rejects: bool,
    error: Option<LookupError>,
}

impl<DB: DatabaseLike> Rejections<'_, '_, DB> {
    /// Calls `found` on the existence tests `condition` implies when it
    /// evaluates to `holds`, keeping the first lookup error.
    fn implied(&mut self, condition: &Query, holds: bool, found: &mut impl FnMut(Subject, bool)) {
        let Some(condition) = evaluated(condition) else {
            return;
        };
        if let Err(error) = self.tests.implied(condition, holds, found) {
            self.error.get_or_insert(error);
        }
    }
}

impl<DB: DatabaseLike> FlowVisitor for Rejections<'_, '_, DB> {
    type State = Established;

    fn query(&mut self, _query: &Query, _state: &mut Established) {}

    fn statement(&mut self, _statement: &Statement, _state: &mut Established) {}

    fn step(&mut self, node: &Node, state: &mut Established) {
        if state.present {
            return;
        }
        match &node.kind {
            NodeKind::Raise(raise) if raise.level == RaiseLevel::Exception => {
                self.rejects |= state.missing;
            }
            // A failing `ASSERT` raises.
            NodeKind::Assert(assert) => {
                let mut rejects = false;
                self.implied(&assert.condition, false, &mut |subject, exists| {
                    rejects |= subject == Subject::Related && !exists;
                });
                self.rejects |= rejects;
            }
            _ => {}
        }
    }

    fn assume(&mut self, condition: &Query, holds: bool, state: &mut Established) {
        self.implied(condition, holds, &mut |subject, exists| match subject {
            Subject::Own => state.present |= exists,
            Subject::Related => state.missing |= !exists,
        });
    }
}

impl<DB: DatabaseLike> SchemaRule for DeferredCheckDeletedRow<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for (function, trigger) in triggers_with_functions(database) {
            let deferrable = trigger
                .deferral()
                .is_some_and(ConstraintDeferral::is_deferrable);
            let fires_with_new = fires_on_insert(trigger) || fires_on_update(trigger);
            if !deferrable || !fires_with_new || !row_trigger(trigger, TriggerPeriod::After) {
                continue;
            }
            let Some(block) = plpgsql_block(function) else {
                continue;
            };
            let Relation::Table(table) = trigger.relation(database)? else {
                continue;
            };
            let mut keys = Vec::new();
            for key in equality_keys(database, table)? {
                keys.push(
                    key.iter()
                        .map(|column| {
                            normalize_identifier(
                                column.column_name(),
                                column.column_name_is_quoted(),
                            )
                            .into_owned()
                        })
                        .collect::<Vec<_>>(),
                );
            }
            let tests = Tests {
                database,
                table,
                keys,
            };
            let mut rejections = Rejections {
                tests: &tests,
                rejects: false,
                error: None,
            };
            walk_block(&mut rejections, &block, Established::default());
            if let Some(error) = rejections.error {
                return Err(error.into());
            }
            if !rejections.rejects {
                continue;
            }
            let (name, relation) = (trigger.name(), table.table_name());
            let called = signature(function, database);
            let message = format!(
                "Deferrable constraint trigger '{name}' on '{relation}' calls '{called}', which raises when a row related to NEW is missing on a path that does not first check that NEW's row still exists in '{relation}', so a transaction that inserts and deletes the row fails at commit."
            );
            let resolution = match tests.keys.first() {
                Some(key) => {
                    let key = key
                        .iter()
                        .map(|column| format!("{column} = NEW.{column}"))
                        .collect::<Vec<_>>()
                        .join(" AND ");
                    format!(
                        "Return at the start of '{called}' when `NOT EXISTS (SELECT FROM {relation} WHERE {key})`, or excuse '{relation}' when the check must refuse deleting the row."
                    )
                }
                None => format!(
                    "Give '{relation}' a primary key and return at the start of '{called}' when no row of '{relation}' has NEW's key, or excuse '{relation}' when the check must refuse deleting the row."
                ),
            };
            reporter.table(table, message, resolution)?;
        }
        Ok(())
    }
}
