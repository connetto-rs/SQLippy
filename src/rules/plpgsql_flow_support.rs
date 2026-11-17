//! Walks a PL/pgSQL body in the order it can run, carrying what a rule tracks
//! along every path through branches, loops, exits and handlers.

use sql_traits::traits::FunctionLike;
use sqlparser::ast::{Query, Statement};
use sqlparser_plpgsql::{
    embedded::{Block, Exit, ExitKind, Loop, LoopControl, Node, Open, RaiseLevel, ReturnQuery},
    embedded_sql,
};

/// The body of a PL/pgSQL function, `None` for another language or a body
/// that does not parse.
pub(crate) fn plpgsql_block<F: FunctionLike>(function: &F) -> Option<Block> {
    if function.stored_language().as_deref() != Some("plpgsql") {
        return None;
    }
    embedded_sql(function.body()?).ok()
}

/// The SQL statement `node` runs as written, the query of a `PERFORM`, an
/// `OPEN` or a `RETURN QUERY` included.
pub(crate) fn ran_statement(node: &Node) -> Option<&Statement> {
    match node {
        Node::Statement { statement, .. }
        | Node::Perform { query: statement }
        | Node::Open(Open::Query {
            query: statement, ..
        })
        | Node::ReturnQuery(ReturnQuery::Query(statement)) => Some(statement),
        _ => None,
    }
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

    /// Reads a query the body evaluates, such as a condition, a loop bound,
    /// a declaration default or an assigned value.
    fn query(&mut self, query: &Query, state: &mut Self::State);

    /// Reads a step that holds no other step, after the queries it
    /// evaluates.
    fn step(&mut self, node: &Node, state: &mut Self::State);

    /// Narrows a path that goes on only when `condition` evaluated to
    /// `holds`, as a branch taken or passed over and a passing `ASSERT` do.
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
        loops: Vec::new(),
    }
    .block(block, Some(state))
}

/// Where the paths leaving a loop early go.
struct LoopExits<S> {
    /// The state of every path an `EXIT` takes out of the loop.
    exits: Option<S>,
    /// The state of every path a `CONTINUE` takes to the next iteration.
    continues: Option<S>,
}

struct Walker<'v, V: FlowVisitor> {
    visitor: &'v mut V,
    loops: Vec<LoopExits<V::State>>,
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

impl<V: FlowVisitor> Walker<'_, V> {
    fn query(&mut self, query: &Query, state: &mut Option<V::State>) {
        if let Some(state) = state {
            self.visitor.query(query, state);
        }
    }

    fn block(&mut self, block: &Block, mut state: Option<V::State>) -> Option<V::State> {
        for declaration in &block.declarations {
            if let sqlparser_plpgsql::embedded::DeclarationKind::Variable(variable) =
                &declaration.kind
                && let Some(default) = &variable.default
            {
                self.query(default, &mut state);
            }
        }
        let entry = state.clone();
        let mut out = self.nodes(&block.statements, state);
        // A handler starts once the block's own changes are rolled back.
        for handler in &block.handlers {
            out = joined(out, self.nodes(&handler.statements, entry.clone()));
        }
        out
    }

    fn nodes(&mut self, nodes: &[Node], mut state: Option<V::State>) -> Option<V::State> {
        for node in nodes {
            state = self.node(node, state);
        }
        state
    }

    fn node(&mut self, node: &Node, mut state: Option<V::State>) -> Option<V::State> {
        state.as_ref()?;
        match node {
            Node::Block(block) => self.block(block, state),
            Node::If(conditional) => {
                let mut out = None;
                for branch in &conditional.branches {
                    self.query(&branch.condition, &mut state);
                    let mut taken = state.clone();
                    self.assume(&branch.condition, true, &mut taken);
                    out = joined(out, self.nodes(&branch.statements, taken));
                    self.assume(&branch.condition, false, &mut state);
                }
                joined(out, self.nodes(&conditional.otherwise, state))
            }
            Node::Case(case) => {
                if let Some(subject) = &case.subject {
                    self.query(subject, &mut state);
                }
                let mut out = None;
                for branch in &case.branches {
                    self.query(&branch.condition, &mut state);
                    let mut taken = state.clone();
                    // A searched CASE tests each condition as a boolean.
                    if case.subject.is_none() {
                        self.assume(&branch.condition, true, &mut taken);
                    }
                    out = joined(out, self.nodes(&branch.statements, taken));
                    if case.subject.is_none() {
                        self.assume(&branch.condition, false, &mut state);
                    }
                }
                joined(out, self.nodes(&case.otherwise, state))
            }
            Node::Loop(repeated) => self.repeated(repeated, state),
            Node::Exit(exit) => self.exit(exit, state),
            Node::Return { value } => {
                if let Some(value) = value {
                    self.query(value, &mut state);
                }
                self.step(node, &mut state);
                None
            }
            Node::Raise(raise) => {
                let options = raise.options.iter().map(|option| &option.value);
                for query in raise.arguments.iter().chain(options) {
                    self.query(query, &mut state);
                }
                self.step(node, &mut state);
                (raise.level != RaiseLevel::Exception)
                    .then_some(state)
                    .flatten()
            }
            Node::Assert(assert) => {
                self.query(&assert.condition, &mut state);
                self.step(node, &mut state);
                self.assume(&assert.condition, true, &mut state);
                state
            }
            Node::Assignment(assignment) => {
                self.query(&assignment.value, &mut state);
                self.step(node, &mut state);
                state
            }
            Node::Dynamic { dynamic, .. }
            | Node::Open(Open::Dynamic { dynamic, .. })
            | Node::ReturnQuery(ReturnQuery::Dynamic(dynamic)) => {
                self.query(&dynamic.command, &mut state);
                for argument in &dynamic.arguments {
                    self.query(argument, &mut state);
                }
                self.step(node, &mut state);
                state
            }
            Node::Open(Open::Bound(cursor)) => {
                for argument in &cursor.arguments {
                    self.query(argument, &mut state);
                }
                self.step(node, &mut state);
                state
            }
            Node::ReturnNext { value } => {
                if let Some(value) = value {
                    self.query(value, &mut state);
                }
                self.step(node, &mut state);
                state
            }
            Node::Statement { .. }
            | Node::Perform { .. }
            | Node::Open(Open::Query { .. })
            | Node::ReturnQuery(ReturnQuery::Query(_))
            | Node::Fetch(_)
            | Node::Move { .. }
            | Node::Close { .. }
            | Node::Commit { .. }
            | Node::Rollback { .. }
            | Node::Diagnostics(_) => {
                self.step(node, &mut state);
                state
            }
        }
    }

    /// Walks a loop body twice, so the second pass sees what the first
    /// carried around the loop.
    fn repeated(&mut self, repeated: &Loop, mut state: Option<V::State>) -> Option<V::State> {
        let ends_by_itself = !matches!(repeated.control, LoopControl::Unconditional);
        self.control(&repeated.control, &mut state);
        let mut entry = state;
        let mut exits = None;
        for _ in 0..2 {
            self.loops.push(LoopExits {
                exits: None,
                continues: None,
            });
            let body = self.nodes(&repeated.statements, entry.clone());
            let frame = self.loops.pop().expect("pushed above");
            exits = joined(exits, frame.exits);
            entry = joined(entry, joined(body, frame.continues));
        }
        if ends_by_itself {
            joined(entry, exits)
        } else {
            exits
        }
    }

    /// Hands the path to the innermost loop's exit or next iteration.
    fn exit(&mut self, exit: &Exit, mut state: Option<V::State>) -> Option<V::State> {
        if let Some(condition) = &exit.condition {
            self.query(condition, &mut state);
        }
        if let Some(frame) = self.loops.last_mut() {
            let target = match exit.kind {
                ExitKind::Exit => &mut frame.exits,
                ExitKind::Continue => &mut frame.continues,
            };
            *target = joined(target.take(), state.clone());
        }
        exit.condition.is_some().then_some(state).flatten()
    }

    /// Reads the queries a loop runs before its first iteration.
    fn control(&mut self, control: &LoopControl, state: &mut Option<V::State>) {
        match control {
            LoopControl::Unconditional | LoopControl::Query { .. } => {}
            LoopControl::While(query) | LoopControl::Array { array: query, .. } => {
                self.query(query, state);
            }
            LoopControl::Range {
                lower, upper, step, ..
            } => {
                self.query(lower, state);
                self.query(upper, state);
                if let Some(step) = step {
                    self.query(step, state);
                }
            }
            LoopControl::Cursor { cursor, .. } => {
                for argument in &cursor.arguments {
                    self.query(argument, state);
                }
            }
            LoopControl::Dynamic { dynamic, .. } => {
                self.query(&dynamic.command, state);
                for argument in &dynamic.arguments {
                    self.query(argument, state);
                }
            }
        }
    }

    fn step(&mut self, node: &Node, state: &mut Option<V::State>) {
        if let Some(state) = state {
            self.visitor.step(node, state);
        }
    }

    fn assume(&mut self, condition: &Query, holds: bool, state: &mut Option<V::State>) {
        if let Some(state) = state {
            self.visitor.assume(condition, holds, state);
        }
    }
}
