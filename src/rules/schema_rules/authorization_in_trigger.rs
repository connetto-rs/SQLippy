//! Submodule providing the `AuthorizationInTrigger` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::IdentifierCase,
    traits::{DatabaseLike, FunctionLike, PolicyLike, TableLike, TriggerLike},
};
use sqlparser::ast::{Expr, TriggerEvent, Visitor};
use sqlparser_plpgsql::{
    condition::errcode,
    embedded::{Block, Condition, Node, Raise, RaiseOptionKind},
};
use sqlstate::pg::INSUFFICIENT_PRIVILEGE;

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        function_reach_support::reaches_function,
        literal_support::text_literal,
        plpgsql_flow_support::plpgsql_block,
        policy_support::{Command, applied},
        trigger_support::evaluated,
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

schema_rule!(
    /// Struct defining a rule that reports a trigger on a table with row
    /// level security that repeats the authorization a policy for the same
    /// command makes, by calling a helper the policy calls or by raising
    /// `insufficient_privilege`.
    ///
    /// The policy already decides who may run the command on which rows,
    /// so the trigger repeats the decision on a second path, which can
    /// drift from the policy that tools and readers consult.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = AuthorizationInTrigger::default().into();
    /// let schema = |check: &str| {
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///         "CREATE TABLE notes (id INT PRIMARY KEY, owner_id UUID NOT NULL, body TEXT NOT NULL);
    ///          ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
    ///          CREATE FUNCTION owns_note(subject UUID) RETURNS BOOLEAN LANGUAGE sql STABLE AS
    ///            $$ SELECT subject = current_setting('app.user_id')::uuid $$;
    ///          CREATE POLICY own_insert ON notes FOR INSERT WITH CHECK (owns_note(owner_id));
    ///          CREATE FUNCTION check_note() RETURNS trigger LANGUAGE plpgsql AS
    ///            $$ BEGIN IF NOT {check} THEN RAISE EXCEPTION 'rejected'; END IF; RETURN NEW; END $$;
    ///          CREATE TRIGGER check_note BEFORE INSERT ON notes FOR EACH ROW EXECUTE FUNCTION check_note();"
    ///     ))
    ///     .unwrap()
    /// };
    /// assert!(constrainer.validate_schema(&schema("owns_note(NEW.owner_id)")).is_err());
    /// assert!(constrainer.validate_schema(&schema("length(NEW.body) > 0")).is_ok());
    /// ```
    AuthorizationInTrigger,
    LintGroup::Pedantic,
    "A trigger that repeats the authorization check a row level security policy already makes for the same command is a second authorization path, which can drift from the policy that tools and readers consult and makes the effective access rule harder to read.",
    Some("https://www.postgresql.org/docs/18/ddl-rowsecurity.html"),
    RuleExample {
        bad: "CREATE ROLE app;\n\
CREATE TABLE notes (id integer PRIMARY KEY, owner_id uuid NOT NULL);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE FUNCTION owns_note(subject_id uuid) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT subject_id = NULLIF(current_setting('app.user_id', true), '')::uuid $$;\n\
CREATE POLICY own_insert ON notes FOR INSERT TO app WITH CHECK (owns_note(owner_id));\n\
GRANT INSERT ON notes TO app;\n\
CREATE FUNCTION check_owner() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NOT owns_note(NEW.owner_id) THEN RAISE insufficient_privilege; END IF; RETURN NEW; END $$;\n\
CREATE TRIGGER check_owner BEFORE INSERT ON notes FOR EACH ROW EXECUTE FUNCTION check_owner();",
        good: "CREATE ROLE app;\n\
CREATE TABLE notes (id integer PRIMARY KEY, owner_id uuid NOT NULL);\n\
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
CREATE FUNCTION owns_note(subject_id uuid) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT subject_id = NULLIF(current_setting('app.user_id', true), '')::uuid $$;\n\
CREATE POLICY own_insert ON notes FOR INSERT TO app WITH CHECK (owns_note(owner_id));\n\
GRANT INSERT ON notes TO app;",
    }
);

/// The commands a trigger event runs under.
fn command(event: &TriggerEvent) -> Option<Command> {
    match event {
        TriggerEvent::Insert => Some(Command::Insert),
        TriggerEvent::Update(_) => Some(Command::Update),
        TriggerEvent::Delete => Some(Command::Delete),
        TriggerEvent::Truncate => None,
    }
}

/// The user functions the calls in a policy expression reach.
struct Helpers<'db, DB: DatabaseLike> {
    database: &'db DB,
    found: Vec<&'db DB::Function>,
}

impl<DB: DatabaseLike> Visitor for Helpers<'_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        let Expr::Function(call) = expression else {
            return ControlFlow::Continue(());
        };
        match self
            .database
            .functions_reached_by(call, IdentifierCase::Folded)
        {
            Ok(reached) => {
                for function in reached {
                    if function.target_name().schema() != Some("pg_catalog")
                        && !self.found.contains(&function)
                    {
                        self.found.push(function);
                    }
                }
                ControlFlow::Continue(())
            }
            Err(error) => ControlFlow::Break(error),
        }
    }
}

/// Whether `raise` raises `insufficient_privilege`, as its condition or
/// through `USING ERRCODE`.
fn raises_insufficient_privilege(raise: &Raise) -> bool {
    let named = match &raise.condition {
        Some(Condition::Name(name)) => name.sqlstate() == INSUFFICIENT_PRIVILEGE,
        Some(Condition::Sqlstate(code)) => *code == INSUFFICIENT_PRIVILEGE,
        Some(Condition::Others) | None => false,
    };
    named
        || raise.options.iter().any(|option| {
            option.kind == RaiseOptionKind::Errcode
                && evaluated(&option.value)
                    .and_then(text_literal)
                    .is_some_and(|code| errcode(code) == Ok(Some(INSUFFICIENT_PRIVILEGE)))
        })
}

/// Whether any statement of `nodes`, at any depth, raises
/// `insufficient_privilege`.
fn nodes_raise(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| match node {
        Node::Raise(raise) => raises_insufficient_privilege(raise),
        Node::Block(block) => block_raises(block),
        Node::If(conditional) => {
            conditional
                .branches
                .iter()
                .any(|branch| nodes_raise(&branch.statements))
                || nodes_raise(&conditional.otherwise)
        }
        Node::Case(case) => {
            case.branches
                .iter()
                .any(|branch| nodes_raise(&branch.statements))
                || nodes_raise(&case.otherwise)
        }
        Node::Loop(repeated) => nodes_raise(&repeated.statements),
        _ => false,
    })
}

/// Whether `block` or one of its handlers raises `insufficient_privilege`.
fn block_raises(block: &Block) -> bool {
    nodes_raise(&block.statements)
        || block
            .handlers
            .iter()
            .any(|handler| nodes_raise(&handler.statements))
}

/// How a trigger repeats a policy's authorization.
enum Repeat<'db, DB: DatabaseLike> {
    /// The trigger calls a helper the policy calls.
    Helper(&'db DB::Function),
    /// The trigger raises `insufficient_privilege`.
    Raise,
}

impl<DB: DatabaseLike> SchemaRule for AuthorizationInTrigger<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for trigger in database.triggers() {
            let Some(function) = trigger.function(database) else {
                continue;
            };
            let table = trigger.table(database)?;
            if !table.has_row_level_security(database)? {
                continue;
            }
            let commands: Vec<Command> = trigger.events().iter().filter_map(command).collect();
            let raises = plpgsql_block(function).is_some_and(|block| block_raises(&block));
            let mut found = None;
            'policies: for policy in table.policies(database)? {
                for &command in &commands {
                    if !command.covered_by(policy.command()) {
                        continue;
                    }
                    let mut helpers = Helpers {
                        database,
                        found: Vec::new(),
                    };
                    for applied in applied(database, policy, command)? {
                        if let ControlFlow::Break(error) = walk(applied.expression, &mut helpers) {
                            return Err(error.into());
                        }
                    }
                    for helper in helpers.found {
                        if reaches_function(database, function, helper)? {
                            found = Some((policy, Repeat::<DB>::Helper(helper)));
                            break 'policies;
                        }
                    }
                    if raises && found.is_none() {
                        found = Some((policy, Repeat::Raise));
                    }
                }
            }
            let Some((policy, repeat)) = found else {
                continue;
            };
            let (name, relation, policy) = (trigger.name(), table.table_name(), policy.name());
            let called = signature(function, database);
            let message = match repeat {
                Repeat::Helper(helper) => format!(
                    "Trigger '{name}' on '{relation}' runs '{called}', which calls '{}' as policy '{policy}' does, so the trigger repeats an authorization check the policy already makes.",
                    signature(helper, database)
                ),
                Repeat::Raise => format!(
                    "Trigger '{name}' on '{relation}' runs '{called}', which raises insufficient_privilege for a command policy '{policy}' already authorizes, so the trigger is a second authorization path."
                ),
            };
            reporter.table(
                table,
                message,
                format!(
                    "Drop the check from the trigger and let policy '{policy}' decide, or move any rule the policy lacks into a policy."
                ),
            )?;
        }
        Ok(())
    }
}
