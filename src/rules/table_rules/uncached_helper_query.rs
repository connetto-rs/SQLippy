//! Submodule providing the `UncachedHelperQuery` rule.

use std::{collections::HashMap, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{
        CallApplication, CallResolution, ColumnDefinition, Definition, DefinitionId,
        DefinitionSource, EmbeddedSql, ExpressionContext, ExpressionScope, IdentifierCase,
        Reaching, VariableRead,
    },
    traits::{DataStatementLike, DatabaseLike, FunctionLike, PolicyLike, TableLike},
};
use sqlparser::ast::{Expr, Query, SelectItem, SetExpr, TableFactor, Value, Visit, Visitor};

use crate::{
    error::{Interruption, PolicySite},
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        function_body_support::{BodyNode, function_body},
        function_rules::unreadable_body,
        inline_support::{inlined_in_expression, inlined_in_from},
        policy_support::{reads_row, walked_clauses},
        walk_support::{stop_on, stopped, walk},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule, reporter::signature},
};

const CASE: IdentifierCase = IdentifierCase::Folded;

/// The function PostgreSQL runs for a call it resolved as `resolution`, none
/// for a call it refuses or reads as a cast.
fn called<'db, DB: DatabaseLike>(
    resolution: &CallResolution<'db, DB>,
) -> Option<&'db DB::Function> {
    match resolution {
        CallResolution::Selected(selected) => Some(selected.function()),
        _ => None,
    }
}

/// `result`, or the default value for a body that is not SQL, is missing or
/// does not parse.
fn readable<T: Default>(result: Result<T, LookupError>) -> Result<T, LookupError> {
    result.or_else(|error| unreadable_body(&error).then(T::default).ok_or(error))
}

/// Whether a value the definition gives its variable may come from the
/// function's arguments: an argument itself, a value the body does not spell
/// out, or SQL reading a variable holding one. `followed` holds the
/// definitions already met.
fn tainted<DB: DatabaseLike>(
    definition: &Definition<'_, '_, DB>,
    followed: &mut Vec<DefinitionId>,
) -> Result<bool, LookupError> {
    if followed.contains(&definition.id()) {
        return Ok(false);
    }
    followed.push(definition.id());
    match definition.source() {
        DefinitionSource::Null | DefinitionSource::CursorName | DefinitionSource::PortalName => {
            Ok(false)
        }
        DefinitionSource::Value(_)
        | DefinitionSource::QueryOutput { .. }
        | DefinitionSource::ArrayElement { .. }
        | DefinitionSource::LoopIndex { .. } => {
            for read in definition.reads(CASE)? {
                if read_tainted(&read, followed)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        DefinitionSource::Incoming
        | DefinitionSource::Unknown
        | DefinitionSource::Diagnostics(_)
        | DefinitionSource::CallOutput { .. }
        | DefinitionSource::CursorOutput { .. }
        | DefinitionSource::DynamicOutput { .. } => Ok(true),
    }
}

/// Whether a definition reaching `read` may come from the function's
/// arguments. A read no definition reaches sits where the body never runs,
/// so it counts as dependent and is not reported.
fn read_tainted<DB: DatabaseLike>(
    read: &VariableRead<'_, '_, DB>,
    followed: &mut Vec<DefinitionId>,
) -> Result<bool, LookupError> {
    match read.reaching() {
        Reaching::Unreachable => Ok(true),
        Reaching::Definitions(definitions) => {
            for definition in definitions {
                if tainted(definition, followed)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// One statement or expression of a helper's body: the context binding its
/// names, the PL/pgSQL variables it reads, and the `SELECT` PostgreSQL wraps
/// a PL/pgSQL expression in.
struct Root<'c, 'q, 'r, 'db, DB: DatabaseLike> {
    context: &'c ExpressionContext<'q, 'db, DB>,
    reads: &'c [VariableRead<'r, 'db, DB>],
    wrapper: Option<&'c Query>,
}

impl<'db, DB: DatabaseLike> Root<'_, '_, '_, 'db, DB> {
    /// Whether the column reference `expression`, which `local` does not
    /// bind, may read the function's arguments: an argument, a variable
    /// holding one, a column of an enclosing query, a name nothing binds or
    /// one an opaque relation may hold.
    fn dependent_reference(&self, expression: &Expr) -> Result<bool, LookupError> {
        match self.context.reference(expression)? {
            Some((
                ColumnDefinition::Variable(variable) | ColumnDefinition::VariableField(variable),
                _,
            )) => self
                .reads
                .iter()
                .find(|read| read.variable().id() == variable.id())
                .map_or(Ok(true), |read| read_tainted(read, &mut Vec::new())),
            _ => Ok(true),
        }
    }

    /// Whether `node` reads nothing that may come from the function's
    /// arguments, its column references bound first by `local`, the context
    /// of `node` alone, and the rest by the body. A name an opaque relation of
    /// `node`, such as a function in `FROM`, may hold is bound by neither.
    fn independent<N: Visit + ?Sized>(
        &self,
        node: &N,
        local: Option<&ExpressionContext<'_, 'db, DB>>,
    ) -> Result<bool, LookupError> {
        struct References<'a, 'c, 'q, 'r, 'l, 'db, DB: DatabaseLike> {
            root: &'a Root<'c, 'q, 'r, 'db, DB>,
            local: Option<&'a ExpressionContext<'l, 'db, DB>>,
        }
        impl<DB: DatabaseLike> Visitor for References<'_, '_, '_, '_, '_, '_, DB> {
            type Break = Option<LookupError>;
            fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Option<LookupError>> {
                match expression {
                    Expr::Value(value) if matches!(value.value, Value::Placeholder(_)) => {
                        ControlFlow::Break(None)
                    }
                    Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
                        if self.local.is_some_and(|local| {
                            matches!(
                                local.reference(expression),
                                Ok(Some((definition, _)))
                                    if !matches!(definition, ColumnDefinition::Opaque)
                            )
                        }) {
                            return ControlFlow::Continue(());
                        }
                        stop_on(self.root.dependent_reference(expression))
                    }
                    _ => ControlFlow::Continue(()),
                }
            }
        }
        Ok(!stopped(walk(node, &mut References { root: self, local }))?)
    }

    /// The text naming a part: the expression of the `SELECT` PostgreSQL
    /// wraps a PL/pgSQL expression in, or the query.
    fn render(&self, query: &Query) -> String {
        if self
            .wrapper
            .is_some_and(|wrapper| std::ptr::eq(wrapper, query))
            && let SetExpr::Select(select) = query.body.as_ref()
            && let [SelectItem::UnnamedExpr(expression)] = select.projection.as_slice()
        {
            return expression.to_string();
        }
        query.to_string()
    }
}

/// Whether functions read a relation, directly or through the functions
/// they call, remembered by function.
struct Relations<'db, DB: DatabaseLike> {
    database: &'db DB,
    known: HashMap<&'db DB::Function, bool>,
}

impl<'db, DB: DatabaseLike> Relations<'db, DB> {
    fn function(&mut self, function: &'db DB::Function) -> Result<bool, LookupError> {
        if let Some(reads) = self.known.get(function) {
            return Ok(*reads);
        }
        self.known.insert(function, false);
        if function.target_name().schema() == Some("pg_catalog") {
            return Ok(false);
        }
        let mut reads = !readable(function.referenced_relations(self.database))?.is_empty();
        for called in readable(function.referenced_functions(self.database))? {
            if reads {
                break;
            }
            reads = self.function(called)?;
        }
        self.known.insert(function, reads);
        Ok(reads)
    }

    /// Whether the calls `node` makes, resolved in `context`, reach a
    /// function reading a relation.
    fn calls<N: Visit + ?Sized>(
        &mut self,
        context: &ExpressionContext<'_, 'db, DB>,
        node: &N,
    ) -> Result<bool, LookupError> {
        struct Calls<'a, 'c, 'q, 'db, DB: DatabaseLike> {
            relations: &'a mut Relations<'db, DB>,
            context: &'c ExpressionContext<'q, 'db, DB>,
        }
        impl<'db, DB: DatabaseLike> Calls<'_, '_, '_, 'db, DB> {
            fn reaches(
                &mut self,
                application: Result<Option<CallApplication<'_, 'db, DB>>, LookupError>,
            ) -> ControlFlow<Option<LookupError>> {
                stop_on(application.and_then(|application| {
                    application
                        .and_then(|application| called(application.resolution()))
                        .map_or(Ok(false), |function| self.relations.function(function))
                }))
            }
        }
        impl<DB: DatabaseLike> Visitor for Calls<'_, '_, '_, '_, DB> {
            type Break = Option<LookupError>;
            fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Option<LookupError>> {
                let application = self.context.call(expression);
                self.reaches(application)
            }
            fn pre_visit_table_factor(
                &mut self,
                factor: &TableFactor,
            ) -> ControlFlow<Option<LookupError>> {
                let application = self.context.relation_call(factor);
                self.reaches(application)
            }
        }
        stopped(walk(
            node,
            &mut Calls {
                relations: self,
                context,
            },
        ))
    }
}

/// Collects the outermost parts of a helper's body that do not depend on
/// its arguments and read a relation: a query, a set-returning call, or a
/// set-returning function in `FROM` that PostgreSQL does not inline.
struct Parts<'a, 'c, 'q, 'r, 'db, DB: DatabaseLike> {
    database: &'db DB,
    root: &'a Root<'c, 'q, 'r, 'db, DB>,
    relations: &'a mut Relations<'db, DB>,
    within: Option<*const ()>,
    found: Vec<String>,
}

impl<DB: DatabaseLike> Parts<'_, '_, '_, '_, '_, DB> {
    fn query(&mut self, query: &Query) -> Result<(), LookupError> {
        let local = ExpressionContext::new(query, self.database, CASE).ok();
        if !self.root.independent(query, local.as_ref())? {
            return Ok(());
        }
        self.within = Some(std::ptr::from_ref(query).cast());
        if !DataStatementLike::<DB>::referenced_relations(query, self.database)?.is_empty()
            || self.relations.calls(self.root.context, query)?
        {
            self.found.push(self.root.render(query));
        }
        Ok(())
    }

    fn expression(&mut self, expression: &Expr) -> Result<(), LookupError> {
        if !self
            .root
            .context
            .call(expression)?
            .and_then(|application| called(application.resolution()))
            .is_some_and(FunctionLike::returns_set)
        {
            return Ok(());
        }
        let empty = ExpressionScope::Empty;
        let local = ExpressionContext::for_expression(expression, &empty, self.database, CASE).ok();
        if !self.root.independent(expression, local.as_ref())? {
            return Ok(());
        }
        self.within = Some(std::ptr::from_ref(expression).cast());
        if self.relations.calls(self.root.context, expression)? {
            self.found.push(expression.to_string());
        }
        Ok(())
    }

    fn table_factor(&mut self, factor: &TableFactor) -> Result<(), LookupError> {
        let Some((application, function)) =
            self.root
                .context
                .relation_call(factor)?
                .and_then(|application| {
                    called(application.resolution()).map(|function| (application, function))
                })
        else {
            return Ok(());
        };
        if inlined_in_from(self.database, function)? {
            return Ok(());
        }
        let empty = ExpressionScope::Empty;
        let mut reads = self.relations.function(function)?;
        for argument in application.arguments() {
            let local =
                ExpressionContext::for_expression(argument, &empty, self.database, CASE).ok();
            if !self.root.independent(*argument, local.as_ref())? {
                return Ok(());
            }
            reads = reads || self.relations.calls(self.root.context, *argument)?;
        }
        self.within = Some(std::ptr::from_ref(factor).cast());
        if reads {
            let arguments: Vec<String> = application
                .arguments()
                .iter()
                .map(ToString::to_string)
                .collect();
            self.found
                .push(format!("{}({})", application.name(), arguments.join(", ")));
        }
        Ok(())
    }

    fn leave(&mut self, node: *const ()) {
        if self.within == Some(node) {
            self.within = None;
        }
    }
}

impl<DB: DatabaseLike> Visitor for Parts<'_, '_, '_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        if self.within.is_some() {
            return ControlFlow::Continue(());
        }
        self.query(query)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.leave(std::ptr::from_ref(query).cast());
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if self.within.is_some() {
            return ControlFlow::Continue(());
        }
        self.expression(expression)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        self.leave(std::ptr::from_ref(expression).cast());
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<LookupError> {
        if self.within.is_some() {
            return ControlFlow::Continue(());
        }
        self.table_factor(factor)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<LookupError> {
        self.leave(std::ptr::from_ref(factor).cast());
        ControlFlow::Continue(())
    }
}

/// Appends to `found` the parts [`Parts`] collects in `node`, a statement or
/// expression of the body `root` describes.
fn collect<'db, DB: DatabaseLike, N: Visit + ?Sized>(
    database: &'db DB,
    root: &Root<'_, '_, '_, 'db, DB>,
    relations: &mut Relations<'db, DB>,
    node: &N,
    found: &mut Vec<String>,
) -> Result<(), LookupError> {
    let mut parts = Parts {
        database,
        root,
        relations,
        within: None,
        found: Vec::new(),
    };
    walk(node, &mut parts).break_value().map_or(Ok(()), Err)?;
    found.append(&mut parts.found);
    Ok(())
}

/// The parts of `function`'s body that do not depend on its arguments and
/// read a relation, in body order.
fn independent_parts<'db, DB: DatabaseLike>(
    database: &'db DB,
    function: &'db DB::Function,
    relations: &mut Relations<'db, DB>,
) -> Result<Vec<String>, LookupError> {
    let mut found = Vec::new();
    match function.stored_language().as_deref() {
        Some("plpgsql") => {
            let Some(body) = readable(function.plpgsql_sites(database).map(Some))? else {
                return Ok(found);
            };
            for site in &readable(body.sites())? {
                let context = site.context(CASE)?;
                let reads = site.reads(CASE)?;
                let sql = site.sql();
                let wrapper = match sql {
                    EmbeddedSql::Expression(query) => Some(query),
                    EmbeddedSql::Statement(_) => None,
                };
                let root = Root {
                    context: &context,
                    reads: &reads,
                    wrapper,
                };
                collect(database, &root, relations, &sql, &mut found)?;
            }
        }
        None | Some("sql") => {
            let scope = ExpressionScope::FunctionBody(function);
            function_body(database, function, |node| -> Result<(), LookupError> {
                match node {
                    BodyNode::Statement(statement) => {
                        let context =
                            ExpressionContext::for_statement(statement, &scope, database, CASE)?;
                        let root = Root {
                            context: &context,
                            reads: &[],
                            wrapper: None,
                        };
                        collect(database, &root, relations, statement, &mut found)
                    }
                    BodyNode::Expression(expression) => {
                        let context =
                            ExpressionContext::for_expression(expression, &scope, database, CASE)?;
                        let root = Root {
                            context: &context,
                            reads: &[],
                            wrapper: None,
                        };
                        collect(database, &root, relations, expression, &mut found)
                    }
                }
            })?;
        }
        Some(_) => {}
    }
    Ok(found)
}

/// One call the rule reports.
struct Finding {
    call: String,
    function: String,
    part: String,
}

/// Collects the calls outside sublinks whose arguments read the row, to
/// functions PostgreSQL does not inline whose bodies hold a part that does
/// not depend on the arguments and reads a relation.
struct PerRowCalls<'a, 'c, 'q, 'db, DB: DatabaseLike> {
    database: &'db DB,
    table: &'db DB::Table,
    context: &'c ExpressionContext<'q, 'db, DB>,
    relations: &'a mut Relations<'db, DB>,
    depth: usize,
    findings: Vec<Finding>,
}

impl<DB: DatabaseLike> PerRowCalls<'_, '_, '_, '_, DB> {
    fn call(&mut self, expression: &Expr) -> Result<(), LookupError> {
        let Some(function) = self
            .context
            .call(expression)?
            .and_then(|application| called(application.resolution()))
        else {
            return Ok(());
        };
        if !reads_row(self.database, self.table, None, expression)?
            || inlined_in_expression(self.database, function)?
        {
            return Ok(());
        }
        for part in independent_parts(self.database, function, self.relations)? {
            self.findings.push(Finding {
                call: expression.to_string(),
                function: signature(function, self.database),
                part,
            });
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for PerRowCalls<'_, '_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        if self.depth > 0 {
            return ControlFlow::Continue(());
        }
        self.call(expression)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Struct defining a rule that reports a call in a policy whose arguments
/// read the row, to a function PostgreSQL does not inline, whose body
/// computes something that does not depend on those arguments and reads a
/// relation.
///
/// PostgreSQL runs such a function once for every row the policy checks, so
/// the independent part, such as the caller's teams, is rebuilt for every
/// row. Written in the policy as a sublink compared with the row, PostgreSQL
/// builds it once per statement. Dependence follows the body's references
/// to its parameters, through PL/pgSQL variables and the definitions
/// reaching them. A set-returning function in `FROM` that PostgreSQL inlines
/// into the query calling it does not count.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = UncachedHelperQuery::default().into();
/// let schema = "CREATE TABLE members (team INT, member TEXT);
///     CREATE TABLE docs (team INT);
///     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///     CREATE FUNCTION my_teams() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER
///       AS $$ SELECT team FROM members WHERE member = current_setting('app.user_id') $$;
///     CREATE FUNCTION can_read(doc_team INT) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
///       AS $$ SELECT doc_team IN (SELECT my_teams()) $$;";
///
/// let per_row = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY p ON docs USING (can_read(team));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&per_row).is_err());
///
/// let once = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE POLICY p ON docs USING (team IN (SELECT my_teams()));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&once).is_ok());
/// ```
pub struct UncachedHelperQuery<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for UncachedHelperQuery<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<UncachedHelperQuery<DB>> for GenericConstrainer<DB> {
    fn from(rule: UncachedHelperQuery<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for UncachedHelperQuery<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(UncachedHelperQuery),
            group: LintGroup::Perf,
            rationale: "PostgreSQL runs a function it does not inline once for every row a policy checks, so a set its body builds from anything but its arguments, such as the caller's teams, is rebuilt for every row, while the same set written in the policy as a sublink is built once per statement.",
            source: Some("https://wiki.postgresql.org/wiki/Inlining_of_SQL_functions"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE members (team INT, member TEXT);\n\
CREATE TABLE docs (id INT PRIMARY KEY, team INT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE FUNCTION my_teams() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER\n  AS $$ SELECT team FROM members WHERE member = current_setting('app.user_id') $$;\n\
CREATE FUNCTION can_read(doc_team INT) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER\n  AS $$ SELECT doc_team IN (SELECT my_teams()) $$;\n\
CREATE POLICY team_read ON docs USING (can_read(team));",
                good: "CREATE TABLE members (team INT, member TEXT);\n\
CREATE TABLE docs (id INT PRIMARY KEY, team INT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE FUNCTION my_teams() RETURNS SETOF INT LANGUAGE sql STABLE SECURITY DEFINER\n  AS $$ SELECT team FROM members WHERE member = current_setting('app.user_id') $$;\n\
CREATE POLICY team_read ON docs USING (team IN (SELECT my_teams()));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for UncachedHelperQuery<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut relations = Relations {
            database,
            known: HashMap::new(),
        };
        let scope = ExpressionScope::Table(table);
        for policy in table.policies(database)? {
            for (clause, expression) in walked_clauses(database, policy)? {
                let Some(expression) = expression else {
                    continue;
                };
                let context =
                    ExpressionContext::for_expression(expression, &scope, database, CASE)?;
                let mut calls = PerRowCalls {
                    database,
                    table,
                    context: &context,
                    relations: &mut relations,
                    depth: 0,
                    findings: Vec::new(),
                };
                walk(expression, &mut calls)
                    .break_value()
                    .map_or(Ok(()), Err)?;
                for Finding {
                    call,
                    function,
                    part,
                } in calls.findings
                {
                    let (name, table_name) = (policy.name(), table.table_name());
                    reporter.policies(
                        vec![PolicySite {
                            table: Box::new(table.clone()),
                            policy: Box::new(policy.clone()),
                            clause,
                            expression: call.clone(),
                        }],
                        format!(
                            "Policy '{name}' on '{table_name}' calls `{call}` in its {clause} clause, and PostgreSQL runs '{function}' for each row it checks, recomputing `{part}` although it does not depend on the arguments."
                        ),
                        format!(
                            "Compute `{part}` in the policy as a sublink compared with the row, which PostgreSQL evaluates once per statement, or have a set-returning helper return the keys '{function}' tests."
                        ),
                    )?;
                }
            }
        }
        Ok(())
    }
}
