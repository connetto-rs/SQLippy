//! Walks a PL/pgSQL body in the order it can run, carrying what a rule tracks
//! along every path through branches, loops, exits and handlers.

use std::{convert::Infallible, ops::ControlFlow};

use sql_traits::{traits::FunctionLike, utils::identifier_resolution::normalize_identifier};
use sqlparser::ast::{
    Expr, Query, SetExpr, SetOperator, SetQuantifier, Statement, VisitMut, visit_expressions_mut,
};
use sqlparser_plpgsql::{
    embedded::{
        Block, BoundCursor, Branch, Case, DeclarationKind, Dynamic, Exit, ExitKind, Fetch, If,
        Indirection, Loop, LoopControl, Node, NodeKind, Open, Raise, RaiseLevel, ReturnQuery,
        Variable,
    },
    embedded_sql,
};

use crate::rules::inline_support::selected_expression;

/// The body of a PL/pgSQL function, `None` for another language or a body
/// that does not parse.
pub(crate) fn plpgsql_block<F: FunctionLike>(function: &F) -> Option<Block> {
    if function.stored_language().as_deref() != Some("plpgsql") {
        return None;
    }
    embedded_sql(function.body()?).ok()
}

/// The one statement a PL/pgSQL body runs, the query whose rows it returns,
/// a `DELETE` or an `UPDATE`, and the conditions of the guards it passes
/// first.
pub(crate) struct Ran {
    /// The statement the body runs.
    pub(crate) statement: Statement,
    /// The condition of each guard, under which the body raises an exception
    /// or returns before the statement runs.
    pub(crate) guards: Vec<Expr>,
}

/// What `block` runs when it does nothing else. Its statements are guards
/// `IF condition THEN RAISE EXCEPTION ...; END IF;` or `IF condition THEN
/// RETURN; END IF;`, the exception carrying no argument, then one `DELETE`
/// or `UPDATE`, bare or as a `RETURN QUERY`, or `RETURN QUERY` statements,
/// either maybe followed by a bare `RETURN`, the queries read as the `UNION
/// ALL` of them, a `RETURN` of one scalar subquery, or a `SELECT ... INTO`
/// the one variable declared without a default followed by a `RETURN` of a
/// name. Every other variable is declared with a default and, as no
/// statement but these assigns it, reads as that default.
pub(crate) fn ran_statement(block: Block) -> Option<Ran> {
    let Block {
        declarations,
        statements,
        handlers,
        ..
    } = block;
    if !handlers.is_empty() {
        return None;
    }
    let mut defaults: Vec<(String, Expr)> = Vec::new();
    let mut target = None;
    for declaration in declarations {
        let DeclarationKind::Variable(Variable { default, .. }) = declaration.kind else {
            return None;
        };
        match default {
            Some(default) => {
                let mut value = selected_expression(&default)?.clone();
                substitute(&mut value, &defaults);
                defaults.push((declaration.name, value));
            }
            None if target.is_none() => target = Some(declaration.name),
            None => return None,
        }
    }
    let mut statements = statements.into_iter().peekable();
    let mut guards = Vec::new();
    while let Some(condition) = statements.peek().and_then(guard) {
        guards.push(condition);
        statements.next();
    }
    let statements: Vec<Node> = statements.collect();
    let mut statement = match target {
        None => ran_by(statements)?,
        Some(_) => Statement::Query(Box::new(selected_into(&statements)?)),
    };
    substitute(&mut statement, &defaults);
    for guard in &mut guards {
        substitute(guard, &defaults);
    }
    Some(Ran { statement, guards })
}

/// The statement run by a write, possibly returned by `RETURN QUERY`, or a returned query.
fn ran_by(mut statements: Vec<Node>) -> Option<Statement> {
    if matches!(
        statements.as_slice(),
        [_] | [
            _,
            Node {
                kind: NodeKind::Return { value: None },
                ..
            }
        ]
    ) {
        match statements.remove(0) {
            Node {
                kind:
                    NodeKind::Statement {
                        statement,
                        into: None,
                    }
                    | NodeKind::ReturnQuery(ReturnQuery::Query(statement)),
                ..
            } if matches!(
                statement.as_ref(),
                Statement::Delete(_) | Statement::Update(_)
            ) =>
            {
                return Some(*statement);
            }
            node => statements.insert(0, node),
        }
    }
    returned_by(statements).map(|query| Statement::Query(Box::new(query)))
}

/// The condition of `node`, when it is an `IF` whose one branch raises an
/// exception carrying no argument or returns, without `ELSE`.
fn guard(node: &Node) -> Option<Expr> {
    let NodeKind::If(If {
        branches,
        otherwise,
    }) = &node.kind
    else {
        return None;
    };
    let [
        Branch {
            condition,
            statements,
        },
    ] = branches.as_slice()
    else {
        return None;
    };
    let leaves = match statements.as_slice() {
        [
            Node {
                kind: NodeKind::Return { value: None },
                ..
            },
        ] => true,
        [
            Node {
                kind:
                    NodeKind::Raise(Raise {
                        level: RaiseLevel::Exception,
                        arguments,
                        options,
                        ..
                    }),
                ..
            },
        ] => {
            arguments.is_empty()
                && options.iter().all(|option| {
                    matches!(selected_expression(&option.value), Some(Expr::Value(_)))
                })
        }
        _ => false,
    };
    (leaves && otherwise.is_empty())
        .then(|| selected_expression(condition).cloned())
        .flatten()
}

/// The query whose rows `statements` return, `RETURN QUERY` statements
/// maybe followed by a bare `RETURN` or a `RETURN` of one scalar subquery.
fn returned_by(mut statements: Vec<Node>) -> Option<Query> {
    if let [
        Node {
            kind: NodeKind::Return { value: Some(value) },
            ..
        },
    ] = statements.as_slice()
    {
        let Expr::Subquery(query) = selected_expression(value)? else {
            return None;
        };
        return Some(query.as_ref().clone());
    }
    if let Some(Node {
        kind: NodeKind::Return { value: None },
        ..
    }) = statements.last()
    {
        statements.pop();
    }
    statements
        .into_iter()
        .map(|node| match node.kind {
            NodeKind::ReturnQuery(ReturnQuery::Query(statement)) => match *statement {
                Statement::Query(query) => Some(query),
                _ => None,
            },
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .reduce(|left, right| {
            Box::new(Query {
                with: None,
                body: Box::new(SetExpr::SetOperation {
                    op: SetOperator::Union,
                    set_quantifier: SetQuantifier::All,
                    left: Box::new(SetExpr::Query(left)),
                    right: Box::new(SetExpr::Query(right)),
                }),
                order_by: None,
                limit_clause: None,
                fetch: None,
                locks: Vec::new(),
                for_clause: None,
                settings: None,
                format_clause: None,
                pipe_operators: Vec::new(),
            })
        })
        .map(|query| *query)
}

/// The query of `statements` when they are a `SELECT ... INTO` followed by
/// a `RETURN` of a name, which reads nothing.
fn selected_into(statements: &[Node]) -> Option<Query> {
    let [
        Node {
            kind:
                NodeKind::Statement {
                    statement,
                    into: Some(_),
                },
            ..
        },
        Node {
            kind: NodeKind::Return { value: Some(value) },
            ..
        },
    ] = statements
    else {
        return None;
    };
    match (statement.as_ref(), selected_expression(value)) {
        (Statement::Query(query), Some(Expr::Identifier(_))) => Some(query.as_ref().clone()),
        _ => None,
    }
}

/// `node` with every name of a variable in `defaults` replaced by that
/// variable's default.
fn substitute<N: VisitMut>(node: &mut N, defaults: &[(String, Expr)]) {
    let ControlFlow::Continue(()) = visit_expressions_mut(node, |expression| {
        if let Expr::Identifier(name) = expression
            && let Some((_, default)) = defaults.iter().find(|(variable, _)| {
                *variable == normalize_identifier(&name.value, name.quote_style.is_some())
            })
        {
            *expression = Expr::Nested(Box::new(default.clone()));
        }
        ControlFlow::<Infallible>::Continue(())
    });
}

/// What a rule knows at one point of a body, merged where paths meet.
pub(crate) trait FlowState: Clone {
    /// Merges what another path reaching the same point knows.
    fn join(&mut self, other: Self);
}

/// The steps a rule reads, each seen with the state of a path reaching it.
pub(crate) trait FlowVisitor {
    /// What the rule carries along each path.
    type State: FlowState;

    /// Reads a block as a path enters it, before its declarations.
    fn enter(&mut self, _block: &Block, _state: &mut Self::State) {}

    /// Reads a loop as a path reaches it, before the SQL its control runs
    /// and the targets each iteration assigns.
    fn repeat(&mut self, _repeated: &Loop, _state: &mut Self::State) {}

    /// Reads a query the body evaluates, such as a condition, a loop bound,
    /// a declaration default or an assigned value.
    fn query(&mut self, query: &Query, state: &mut Self::State);

    /// Reads an SQL statement the body runs, the query of a `PERFORM`, an
    /// `OPEN`, a `RETURN QUERY` or a `FOR` loop and the query a cursor is
    /// bound to included.
    fn statement(&mut self, statement: &Statement, state: &mut Self::State);

    /// Reads a step that holds no other step, after the SQL it evaluates
    /// and runs.
    fn step(&mut self, _node: &Node, _state: &mut Self::State) {}

    /// Narrows a path that goes on only when `condition` evaluated to
    /// `holds`, as a branch taken or passed over, a loop entered or left
    /// and a passing `ASSERT` do.
    fn assume(&mut self, _condition: &Query, _holds: bool, _state: &mut Self::State) {}
}

/// Walks `block` from `state`, answering the state of the paths that run off
/// its end, `None` when every path leaves through a `RETURN` or an error.
///
/// A loop body is walked twice, so a step sees what an earlier iteration
/// left behind.
pub(crate) fn walk_block<V: FlowVisitor>(
    visitor: &mut V,
    block: &Block,
    state: V::State,
) -> Option<V::State> {
    Walker {
        visitor,
        frames: Vec::new(),
    }
    .block(block, state)
}

/// A block or loop enclosing the step being walked, and the paths an `EXIT`
/// or a `CONTINUE` hands it.
struct Frame<'b, S> {
    /// The `<<label>>` an `EXIT` or a `CONTINUE` names it by.
    label: Option<&'b str>,
    /// Whether it is a loop, which an `EXIT` without a label reaches.
    repeats: bool,
    /// The state of every path an `EXIT` takes past its end.
    exits: Option<S>,
    /// The state of every path a `CONTINUE` takes to the next iteration.
    continues: Option<S>,
}

impl<'b, S> Frame<'b, S> {
    const fn new(label: Option<&'b str>, repeats: bool) -> Self {
        Self {
            label,
            repeats,
            exits: None,
            continues: None,
        }
    }
}

struct Walker<'v, 'b, V: FlowVisitor> {
    visitor: &'v mut V,
    frames: Vec<Frame<'b, V::State>>,
}

/// Merges two optional path states, `None` standing for no path.
fn joined<S: FlowState>(left: Option<S>, right: Option<S>) -> Option<S> {
    match (left, right) {
        (Some(mut left), Some(right)) => {
            left.join(right);
            Some(left)
        }
        (left, right) => left.or(right),
    }
}

impl<'b, V: FlowVisitor> Walker<'_, 'b, V> {
    fn block(&mut self, block: &'b Block, mut state: V::State) -> Option<V::State> {
        self.frames.push(Frame::new(block.label.as_deref(), false));
        self.visitor.enter(block, &mut state);
        for declaration in &block.declarations {
            if let DeclarationKind::Variable(variable) = &declaration.kind
                && let Some(default) = &variable.default
            {
                self.visitor.query(default, &mut state);
            }
        }
        let entry = state.clone();
        let mut out = self.nodes(&block.statements, Some(state));
        // A handler starts once the block's own changes are rolled back.
        for handler in &block.handlers {
            out = joined(out, self.nodes(&handler.statements, Some(entry.clone())));
        }
        let frame = self.frames.pop().expect("pushed above");
        joined(out, frame.exits)
    }

    fn nodes(&mut self, nodes: &'b [Node], mut state: Option<V::State>) -> Option<V::State> {
        for node in nodes {
            state = self.node(node, state?);
        }
        state
    }

    fn node(&mut self, node: &'b Node, mut state: V::State) -> Option<V::State> {
        match &node.kind {
            NodeKind::Block(block) => return self.block(block, state),
            NodeKind::If(conditional) => return self.conditional(conditional, state),
            NodeKind::Case(case) => return self.case(case, state),
            NodeKind::Loop(repeated) => return self.repeated(repeated, state),
            NodeKind::Exit(exit) => return self.exit(exit, state),
            NodeKind::Return { value: Some(value) }
            | NodeKind::ReturnNext { value: Some(value) } => {
                self.visitor.query(value, &mut state);
            }
            NodeKind::Raise(raise) => {
                let options = raise.options.iter().map(|option| &option.value);
                for query in raise.arguments.iter().chain(options) {
                    self.visitor.query(query, &mut state);
                }
            }
            NodeKind::Assert(assert) => self.visitor.query(&assert.condition, &mut state),
            NodeKind::Assignment(assignment) => {
                for indirection in &assignment.target.indirection {
                    match indirection {
                        Indirection::Field(_) => {}
                        Indirection::Index(index) => self.visitor.query(index, &mut state),
                        Indirection::Slice { lower, upper } => {
                            for bound in [lower, upper].into_iter().flatten() {
                                self.visitor.query(bound, &mut state);
                            }
                        }
                    }
                }
                self.visitor.query(&assignment.value, &mut state);
            }
            NodeKind::Dynamic { dynamic, .. }
            | NodeKind::Open(Open::Dynamic { dynamic, .. })
            | NodeKind::ReturnQuery(ReturnQuery::Dynamic(dynamic)) => {
                self.dynamic(dynamic, &mut state);
            }
            NodeKind::Open(Open::Bound(cursor)) => self.cursor(cursor, &mut state),
            NodeKind::Statement { statement, .. }
            | NodeKind::Perform { query: statement }
            | NodeKind::Open(Open::Query {
                query: statement, ..
            })
            | NodeKind::ReturnQuery(ReturnQuery::Query(statement)) => {
                self.visitor.statement(statement, &mut state);
            }
            NodeKind::Fetch(Fetch { direction, .. }) | NodeKind::Move { direction, .. } => {
                if let Some(count) = direction.expression() {
                    self.visitor.query(count, &mut state);
                }
            }
            NodeKind::Return { value: None }
            | NodeKind::ReturnNext { value: None }
            | NodeKind::Close { .. }
            | NodeKind::Commit { .. }
            | NodeKind::Rollback { .. }
            | NodeKind::Diagnostics(_) => {}
        }
        self.visitor.step(node, &mut state);
        match &node.kind {
            NodeKind::Return { .. } => None,
            NodeKind::Raise(raise) if raise.level == RaiseLevel::Exception => None,
            NodeKind::Assert(assert) => {
                self.visitor.assume(&assert.condition, true, &mut state);
                Some(state)
            }
            _ => Some(state),
        }
    }

    /// Walks each branch an `IF` can take, a later branch on the paths every
    /// earlier condition failed.
    fn conditional(&mut self, conditional: &'b If, mut state: V::State) -> Option<V::State> {
        let mut out = None;
        for branch in &conditional.branches {
            self.visitor.query(&branch.condition, &mut state);
            let mut taken = state.clone();
            self.visitor.assume(&branch.condition, true, &mut taken);
            out = joined(out, self.nodes(&branch.statements, Some(taken)));
            self.visitor.assume(&branch.condition, false, &mut state);
        }
        joined(out, self.nodes(&conditional.otherwise, Some(state)))
    }

    /// Walks each branch a `CASE` can take, narrowing only a searched
    /// `CASE`, which tests each condition as a boolean. Without an `ELSE`, a
    /// value no branch matches raises `case_not_found`.
    fn case(&mut self, case: &'b Case, mut state: V::State) -> Option<V::State> {
        if let Some(subject) = &case.subject {
            self.visitor.query(subject, &mut state);
        }
        let mut out = None;
        for branch in &case.branches {
            self.visitor.query(&branch.condition, &mut state);
            let mut taken = state.clone();
            if case.subject.is_none() {
                self.visitor.assume(&branch.condition, true, &mut taken);
                self.visitor.assume(&branch.condition, false, &mut state);
            }
            out = joined(out, self.nodes(&branch.statements, Some(taken)));
        }
        let Some(otherwise) = &case.otherwise else {
            return out;
        };
        joined(out, self.nodes(otherwise, Some(state)))
    }

    /// Walks a loop body twice, so the second pass sees what the first
    /// carried around the loop.
    fn repeated(&mut self, repeated: &'b Loop, mut head: V::State) -> Option<V::State> {
        self.visitor.repeat(repeated, &mut head);
        self.control(&repeated.control, &mut head);
        let condition = match &repeated.control {
            LoopControl::While(condition) => Some(condition.as_ref()),
            _ => None,
        };
        let mut exits = None;
        for _ in 0..2 {
            let mut entry = head.clone();
            if let Some(condition) = condition {
                self.visitor.query(condition, &mut entry);
                self.visitor.assume(condition, true, &mut entry);
            }
            self.frames
                .push(Frame::new(repeated.label.as_deref(), true));
            let body = self.nodes(&repeated.statements, Some(entry));
            let frame = self.frames.pop().expect("pushed above");
            exits = joined(exits, frame.exits);
            if let Some(again) = joined(body, frame.continues) {
                head.join(again);
            }
        }
        let ended = match &repeated.control {
            LoopControl::Unconditional => None,
            LoopControl::While(condition) => {
                self.visitor.query(condition, &mut head);
                self.visitor.assume(condition, false, &mut head);
                Some(head)
            }
            _ => Some(head),
        };
        joined(ended, exits)
    }

    /// Hands the path to the block or loop the `EXIT` or `CONTINUE` reaches,
    /// answering the path that goes on past it.
    fn exit(&mut self, exit: &Exit, mut state: V::State) -> Option<V::State> {
        let (leaving, staying) = if let Some(condition) = &exit.condition {
            self.visitor.query(condition, &mut state);
            let mut leaving = state.clone();
            self.visitor.assume(condition, true, &mut leaving);
            self.visitor.assume(condition, false, &mut state);
            (leaving, Some(state))
        } else {
            (state, None)
        };
        let reached = match &exit.label {
            None => self.frames.iter().rposition(|frame| frame.repeats),
            Some(label) => self
                .frames
                .iter()
                .rposition(|frame| frame.label == Some(label.as_str())),
        };
        // A label no enclosing block or loop carries is the function's name,
        // which labels the level holding the whole body. An `EXIT` without a
        // label outside every loop, which PostgreSQL refuses, reaches it too.
        let frame = &mut self.frames[reached.unwrap_or(0)];
        let paths = match exit.kind {
            ExitKind::Exit => &mut frame.exits,
            ExitKind::Continue => &mut frame.continues,
        };
        *paths = joined(paths.take(), Some(leaving));
        staying
    }

    /// Reads the SQL a loop runs once, before its first iteration.
    fn control(&mut self, control: &LoopControl, state: &mut V::State) {
        match control {
            LoopControl::Unconditional | LoopControl::While(_) => {}
            LoopControl::Query { query, .. } => self.visitor.statement(query, state),
            LoopControl::Array { array, .. } => self.visitor.query(array, state),
            LoopControl::Range {
                lower, upper, step, ..
            } => {
                for bound in [Some(lower), Some(upper), step.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    self.visitor.query(bound, state);
                }
            }
            LoopControl::Cursor { cursor, .. } => self.cursor(cursor, state),
            LoopControl::Dynamic { dynamic, .. } => self.dynamic(dynamic, state),
        }
    }

    /// Reads the arguments a bound cursor opens with and the query it runs.
    fn cursor(&mut self, cursor: &BoundCursor, state: &mut V::State) {
        for argument in &cursor.arguments {
            self.visitor.query(argument, state);
        }
        self.visitor.statement(&cursor.query, state);
    }

    /// Reads the command text and the `USING` arguments of a dynamic command.
    fn dynamic(&mut self, dynamic: &Dynamic, state: &mut V::State) {
        self.visitor.query(&dynamic.command, state);
        for argument in &dynamic.arguments {
            self.visitor.query(argument, state);
        }
    }
}
