//! Submodule providing the `AuthorizationInTrigger` rule.

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashSet},
    ops::ControlFlow,
};

use sql_traits::{
    errors::LookupError,
    structs::IdentifierCase,
    traits::{DatabaseLike, FunctionLike, PolicyLike, TableLike, TriggerLike},
};
use sqlparser::ast::{
    Expr, FromTable, JoinConstraint, JoinOperator, ObjectName, Query, Select, SetExpr, Statement,
    TableFactor, TableWithJoins, TriggerEvent, UpdateTableFromKind, Visitor,
};
use sqlparser_plpgsql::{
    condition::errcode,
    embedded::{
        Block, Condition, DeclarationKind, LoopControl, Node, NodeKind, Open, Raise,
        RaiseOptionKind, ReturnQuery, expression,
    },
};
use sqlstate::pg::INSUFFICIENT_PRIVILEGE;

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        function_reach_support::reachable_functions,
        literal_support::text_literal,
        plpgsql_flow_support::plpgsql_block,
        policy_support::{Command, applied, sql_query_body},
        trigger_support::{evaluated, triggers_with_functions},
        walk_support::{stopped, walk},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

schema_rule!(
    /// Struct defining a rule that reports a trigger on a table with row
    /// level security that repeats the authorization a policy for the same
    /// command makes, by deciding with the result of a helper the policy
    /// calls or by raising `insufficient_privilege`.
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
    nodes.iter().any(|node| match &node.kind {
        NodeKind::Raise(raise) => raises_insufficient_privilege(raise),
        NodeKind::Block(block) => block_raises(block),
        NodeKind::If(conditional) => {
            conditional
                .branches
                .iter()
                .any(|branch| nodes_raise(&branch.statements))
                || nodes_raise(&conditional.otherwise)
        }
        NodeKind::Case(case) => {
            case.branches
                .iter()
                .any(|branch| nodes_raise(&branch.statements))
                || nodes_raise(case.otherwise.as_deref().unwrap_or_default())
        }
        NodeKind::Loop(repeated) => nodes_raise(&repeated.statements),
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

/// The conditions of a PL/pgSQL body, the queries it evaluates as tests,
/// the SQL it runs, the variables it assigns and the values it returns,
/// each at every depth.
#[derive(Default)]
struct Readings<'b> {
    /// The queries a condition evaluates: an `IF` or `ELSIF`, `CASE`,
    /// `WHILE`, `EXIT WHEN` or `ASSERT` condition, and the array a
    /// `FOREACH` loop iterates.
    conditions: Vec<&'b Query>,
    /// The SQL the body runs, whose `WHERE`, `HAVING` and join `ON`
    /// conditions decide its rows.
    statements: Vec<&'b Statement>,
    /// The variables the body assigns, with the query that evaluates the
    /// value, a declared variable's default included.
    assignments: Vec<(String, &'b Query)>,
    /// The queries that evaluate the values the body returns.
    returns: Vec<&'b Query>,
}

/// Fills `readings` with the conditions, statements, assignments and
/// returns of `block`.
fn block_readings<'b>(block: &'b Block, readings: &mut Readings<'b>) {
    for declaration in &block.declarations {
        if let DeclarationKind::Variable(variable) = &declaration.kind
            && let Some(default) = &variable.default
        {
            readings
                .assignments
                .push((declaration.name.clone(), default));
        }
    }
    for node in &block.statements {
        node_readings(node, readings);
    }
    for handler in &block.handlers {
        for node in &handler.statements {
            node_readings(node, readings);
        }
    }
}

/// Fills `readings` with the conditions, statements, assignments and
/// returns of `node`.
fn node_readings<'b>(node: &'b Node, readings: &mut Readings<'b>) {
    match &node.kind {
        NodeKind::Block(block) => block_readings(block, readings),
        NodeKind::If(conditional) => {
            for branch in &conditional.branches {
                readings.conditions.push(&branch.condition);
                for node in &branch.statements {
                    node_readings(node, readings);
                }
            }
            for node in &conditional.otherwise {
                node_readings(node, readings);
            }
        }
        NodeKind::Case(case) => {
            if let Some(subject) = &case.subject {
                readings.conditions.push(subject);
            }
            for branch in &case.branches {
                readings.conditions.push(&branch.condition);
                for node in &branch.statements {
                    node_readings(node, readings);
                }
            }
            if let Some(otherwise) = &case.otherwise {
                for node in otherwise {
                    node_readings(node, readings);
                }
            }
        }
        NodeKind::Loop(repeated) => {
            match &repeated.control {
                LoopControl::While(condition)
                | LoopControl::Array {
                    array: condition, ..
                } => {
                    readings.conditions.push(condition);
                }
                LoopControl::Query { query, .. } => readings.statements.push(query),
                LoopControl::Cursor { cursor, .. } => readings.statements.push(&cursor.query),
                LoopControl::Unconditional
                | LoopControl::Range { .. }
                | LoopControl::Dynamic { .. } => {}
            }
            for node in &repeated.statements {
                node_readings(node, readings);
            }
        }
        NodeKind::Exit(exit) => {
            if let Some(condition) = &exit.condition {
                readings.conditions.push(condition);
            }
        }
        NodeKind::Assert(assert) => readings.conditions.push(&assert.condition),
        NodeKind::Statement { statement, .. } => readings.statements.push(statement),
        NodeKind::Perform { query } | NodeKind::Open(Open::Query { query, .. }) => {
            readings.statements.push(query);
        }
        NodeKind::Open(Open::Bound(cursor)) => readings.statements.push(&cursor.query),
        NodeKind::ReturnQuery(ReturnQuery::Query(statement)) => {
            readings.statements.push(statement);
        }
        NodeKind::Assignment(assignment) => {
            if assignment.target.indirection.is_empty()
                && let Some(name) = target_name(&assignment.target.name)
            {
                readings.assignments.push((name, &assignment.value));
            }
        }
        NodeKind::Return { value: Some(value) } | NodeKind::ReturnNext { value: Some(value) } => {
            readings.returns.push(value);
        }
        NodeKind::Return { value: None }
        | NodeKind::ReturnNext { value: None }
        | NodeKind::ReturnQuery(ReturnQuery::Dynamic(_))
        | NodeKind::Dynamic { .. }
        | NodeKind::Open(Open::Dynamic { .. })
        | NodeKind::Raise(_)
        | NodeKind::Fetch(_)
        | NodeKind::Move { .. }
        | NodeKind::Close { .. }
        | NodeKind::Commit { .. }
        | NodeKind::Rollback { .. }
        | NodeKind::Diagnostics(_) => {}
    }
}

/// The name an assignment target writes, folded the way PostgreSQL reads
/// it, `None` for a qualifier or a part built at run time.
fn target_name(target: &ObjectName) -> Option<String> {
    if target.0.len() != 1 {
        return None;
    }
    let ident = target.0.first()?.as_ident()?;
    Some(if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_ascii_lowercase()
    })
}

/// The `WHERE`, `HAVING` and join `ON` conditions of `statement`, the
/// queries it reads included.
fn statement_conditions(statement: &Statement) -> Vec<&Expr> {
    let mut conditions = Vec::new();
    match statement {
        Statement::Query(query) => conditions.extend(query_conditions(query)),
        Statement::Update(update) => {
            conditions.extend(from_conditions(&update.table));
            if let Some(from) = &update.from {
                for table in match from {
                    UpdateTableFromKind::BeforeSet(tables)
                    | UpdateTableFromKind::AfterSet(tables) => tables,
                } {
                    conditions.extend(from_conditions(table));
                }
            }
            if let Some(selection) = &update.selection {
                conditions.push(selection);
            }
        }
        Statement::Delete(delete) => {
            for table in match &delete.from {
                FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => tables,
            } {
                conditions.extend(from_conditions(table));
            }
            if let Some(selection) = &delete.selection {
                conditions.push(selection);
            }
        }
        Statement::Insert(insert) => {
            if let Some(source) = &insert.source {
                conditions.extend(query_conditions(source));
            }
        }
        Statement::Merge(merge) => {
            conditions.extend(factor_conditions(&merge.source));
            conditions.push(&merge.on);
            for clause in &merge.clauses {
                if let Some(predicate) = &clause.predicate {
                    conditions.push(predicate);
                }
            }
        }
        _ => {}
    }
    conditions
}

/// The `WHERE`, `HAVING` and join `ON` conditions of `query`, the queries
/// it reads included.
fn query_conditions(query: &Query) -> Vec<&Expr> {
    let mut conditions = query.with.as_ref().map_or_else(Vec::new, |with| {
        with.cte_tables
            .iter()
            .flat_map(|cte| query_conditions(&cte.query))
            .collect()
    });
    conditions.extend(set_conditions(&query.body));
    conditions
}

/// The `WHERE`, `HAVING` and join `ON` conditions of `body`, the queries it
/// reads included.
fn set_conditions(body: &SetExpr) -> Vec<&Expr> {
    match body {
        SetExpr::Select(select) => select_conditions(select),
        SetExpr::Query(query) => query_conditions(query),
        SetExpr::SetOperation { left, right, .. } => {
            let mut conditions = set_conditions(left);
            conditions.extend(set_conditions(right));
            conditions
        }
        SetExpr::Values(_) | SetExpr::Table(_) => Vec::new(),
        SetExpr::Insert(statement)
        | SetExpr::Update(statement)
        | SetExpr::Delete(statement)
        | SetExpr::Merge(statement) => statement_conditions(statement),
    }
}

/// The `WHERE`, `HAVING` and join `ON` conditions of `select`, the queries
/// it reads included.
fn select_conditions(select: &Select) -> Vec<&Expr> {
    let mut conditions: Vec<&Expr> = select
        .from
        .iter()
        .flat_map(|from| from_conditions(from))
        .collect();
    if let Some(selection) = &select.selection {
        conditions.push(selection);
    }
    if let Some(having) = &select.having {
        conditions.push(having);
    }
    conditions
}

/// The conditions of the relation and the joins of `joined`.
fn from_conditions(joined: &TableWithJoins) -> Vec<&Expr> {
    let mut conditions = factor_conditions(&joined.relation);
    for join in &joined.joins {
        if let Some(condition) = join_condition(&join.join_operator) {
            conditions.push(condition);
        }
        conditions.extend(factor_conditions(&join.relation));
    }
    conditions
}

/// The conditions of the query `factor` reads, when it reads one.
fn factor_conditions(factor: &TableFactor) -> Vec<&Expr> {
    match factor {
        TableFactor::Derived { subquery, .. } => query_conditions(subquery),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => from_conditions(table_with_joins),
        _ => Vec::new(),
    }
}

/// The `ON` condition `operator` joins on, when it joins on one.
fn join_condition(operator: &JoinOperator) -> Option<&Expr> {
    let (JoinOperator::Join(constraint)
    | JoinOperator::Inner(constraint)
    | JoinOperator::Left(constraint)
    | JoinOperator::LeftOuter(constraint)
    | JoinOperator::Right(constraint)
    | JoinOperator::RightOuter(constraint)
    | JoinOperator::FullOuter(constraint)
    | JoinOperator::CrossJoin(constraint)
    | JoinOperator::Semi(constraint)
    | JoinOperator::LeftSemi(constraint)
    | JoinOperator::RightSemi(constraint)
    | JoinOperator::Anti(constraint)
    | JoinOperator::LeftAnti(constraint)
    | JoinOperator::RightAnti(constraint)
    | JoinOperator::StraightJoin(constraint)
    | JoinOperator::AsOf { constraint, .. }) = operator
    else {
        return None;
    };
    match constraint {
        JoinConstraint::On(condition) => Some(condition),
        _ => None,
    }
}

/// The function calls an expression makes, resolved the way the body writes
/// them, and the values those calls return.
struct ReachingCalls<'db, 'w, DB: DatabaseLike> {
    database: &'db DB,
    helper: &'db DB::Function,
    /// The functions whose returned value the search already weighed.
    carrying: &'w mut HashSet<&'db DB::Function>,
}

impl<DB: DatabaseLike> Visitor for ReachingCalls<'_, '_, DB> {
    type Break = Option<LookupError>;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        let Expr::Function(call) = expression else {
            return ControlFlow::Continue(());
        };
        let reached = match self
            .database
            .functions_reached_by(call, IdentifierCase::Folded)
        {
            Ok(reached) => reached,
            Err(error) => return ControlFlow::Break(Some(error)),
        };
        for function in reached {
            if function == self.helper {
                return ControlFlow::Break(None);
            }
            if function.target_name().schema() == Some("pg_catalog") {
                continue;
            }
            if !self.carrying.insert(function) {
                continue;
            }
            let carries =
                match function_carries(self.database, function, self.helper, self.carrying) {
                    Ok(carries) => carries,
                    Err(error) => return ControlFlow::Break(Some(error)),
                };
            if carries {
                return ControlFlow::Break(None);
            }
        }
        ControlFlow::Continue(())
    }
}

/// Whether the value `expression` evaluates depends on the result of
/// `helper`, through the calls it makes and the values those calls return.
fn value_reaches<'db, DB: DatabaseLike>(
    database: &'db DB,
    expression: &Expr,
    helper: &'db DB::Function,
    carrying: &mut HashSet<&'db DB::Function>,
) -> Result<bool, LookupError> {
    let mut calls = ReachingCalls {
        database,
        helper,
        carrying,
    };
    stopped(walk(expression, &mut calls))
}

/// Whether the value `function` returns may carry the result of `helper`,
/// through the values the body returns and the variables they assign.
fn function_carries<'db, DB: DatabaseLike>(
    database: &'db DB,
    function: &'db DB::Function,
    helper: &'db DB::Function,
    carrying: &mut HashSet<&'db DB::Function>,
) -> Result<bool, LookupError> {
    let Some(block) = plpgsql_block(function) else {
        return sql_carries(database, function, helper, carrying);
    };
    let mut readings = Readings::default();
    block_readings(&block, &mut readings);
    if readings.returns.is_empty() {
        return Ok(false);
    }
    let carrying_names = if readings.assignments.is_empty() {
        BTreeSet::new()
    } else {
        carrying_names(database, &readings.assignments, helper, carrying)?
    };
    for value in &readings.returns {
        let returned = expression(value);
        if value_reaches(database, &returned, helper, carrying)?
            || reads_carrying_name(&returned, &carrying_names)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the value a SQL body returns may carry the result of `helper`.
///
/// The body's query is the value the function returns, so every call it
/// makes carries.
fn sql_carries<'db, DB: DatabaseLike>(
    database: &'db DB,
    function: &'db DB::Function,
    helper: &'db DB::Function,
    carrying: &mut HashSet<&'db DB::Function>,
) -> Result<bool, LookupError> {
    let body = sql_query_body(database, function)?;
    let atomic = if body.is_some() {
        None
    } else {
        function.atomic_statements(database)?
    };
    let mut queries: Vec<&Query> = Vec::new();
    if let Some(query) = &body {
        queries.push(query);
    } else if let Some(statements) = &atomic {
        let statements: &[Statement] = statements;
        if let Some(statement) = statements
            .iter()
            .rev()
            .find(|statement| matches!(statement, Statement::Query(_)))
            && let Statement::Query(query) = statement
        {
            queries.push(query);
        }
    }
    for query in queries {
        let mut calls = ReachingCalls {
            database,
            helper,
            carrying,
        };
        if stopped(walk(query, &mut calls))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The variables a body's assignments may hold the result of `helper` in,
/// following the value each assigned expression derives.
fn carrying_names<'db, DB: DatabaseLike>(
    database: &'db DB,
    assignments: &[(String, &Query)],
    helper: &'db DB::Function,
    carrying: &mut HashSet<&'db DB::Function>,
) -> Result<BTreeSet<String>, LookupError> {
    let mut names = BTreeSet::new();
    loop {
        let grown = names.len();
        for (name, value) in assignments {
            if names.contains(name.as_str()) {
                continue;
            }
            let assigned = expression(value);
            if value_reaches(database, &assigned, helper, carrying)?
                || reads_carrying_name(&assigned, &names)
            {
                names.insert(name.clone());
            }
        }
        if names.len() == grown {
            break;
        }
    }
    Ok(names)
}

/// Whether `expression` reads any of the variables named in `names`,
/// unqualified.
fn reads_carrying_name(expression: &Expr, names: &BTreeSet<String>) -> bool {
    struct Readers<'n> {
        names: &'n BTreeSet<String>,
    }

    impl Visitor for Readers<'_> {
        type Break = ();

        fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
            if let Expr::Identifier(ident) = expression {
                let reads = if ident.quote_style.is_some() {
                    self.names.contains(&ident.value)
                } else {
                    self.names
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(&ident.value))
                };
                if reads {
                    return ControlFlow::Break(());
                }
            }
            ControlFlow::Continue(())
        }
    }

    let mut readers = Readers { names };
    walk(expression, &mut readers).is_break()
}

/// Whether a condition of `function`'s body decides with the result of
/// `helper`.
fn function_decides<'db, DB: DatabaseLike>(
    database: &'db DB,
    function: &'db DB::Function,
    helper: &'db DB::Function,
    carrying: &mut HashSet<&'db DB::Function>,
) -> Result<bool, LookupError> {
    if let Some(block) = plpgsql_block(function) {
        let mut readings = Readings::default();
        block_readings(&block, &mut readings);
        let mut conditions: Vec<Cow<'_, Expr>> = Vec::new();
        for condition in &readings.conditions {
            let condition = expression(condition);
            if value_reaches(database, &condition, helper, carrying)? {
                return Ok(true);
            }
            conditions.push(condition);
        }
        for statement in &readings.statements {
            for condition in statement_conditions(statement) {
                if value_reaches(database, condition, helper, carrying)? {
                    return Ok(true);
                }
                conditions.push(Cow::Borrowed(condition));
            }
        }
        if conditions.is_empty() || readings.assignments.is_empty() {
            return Ok(false);
        }
        let carrying_names = carrying_names(database, &readings.assignments, helper, carrying)?;
        if carrying_names.is_empty() {
            return Ok(false);
        }
        for condition in &conditions {
            if reads_carrying_name(condition, &carrying_names) {
                return Ok(true);
            }
        }
        Ok(false)
    } else {
        let Some(query) = sql_query_body(database, function)? else {
            return Ok(false);
        };
        for condition in query_conditions(&query) {
            if value_reaches(database, condition, helper, carrying)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Whether the trigger decides with the result of `helper`: the trigger's
/// `WHEN` clause, or a condition of the function it runs or of the functions
/// it calls, decides with it.
fn decides_with<'db, DB: DatabaseLike>(
    database: &'db DB,
    function: &'db DB::Function,
    helper: &'db DB::Function,
    when: Option<&'db Expr>,
) -> Result<bool, LookupError> {
    let mut carrying: HashSet<&'db DB::Function> = HashSet::new();
    if let Some(condition) = when
        && value_reaches(database, condition, helper, &mut carrying)?
    {
        return Ok(true);
    }
    for function in reachable_functions(database, function)? {
        if function_decides(database, function, helper, &mut carrying)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// How a trigger repeats a policy's authorization.
enum Repeat<'db, DB: DatabaseLike> {
    /// The trigger decides with the result of a helper the policy calls.
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
        for (function, trigger) in triggers_with_functions(database) {
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
                        if decides_with(database, function, helper, trigger.condition())? {
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
