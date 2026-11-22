//! Submodule providing the `ExposedDefinerOverProtectedTable` rule.

use std::{borrow::Cow, iter, mem, ops::ControlFlow, ptr, slice};

use sql_traits::{
    errors::{LookupError, RowSecurityError},
    structs::{
        ColumnDefinition, ExpressionContext, ExpressionScope, IdentifierCase, OperandType,
        RowStatement, WrittenCall,
    },
    traits::{DatabaseLike, FunctionLike, Relation, TableLike, UserDefinedTypeLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::{
    ast::{
        ArgMode, BinaryOperator, Distinct, Expr, Function, FunctionBehavior, FunctionCalledOnNull,
        FunctionSecurity, GroupByExpr, Ident, InTarget, JoinConstraint, JoinOperator,
        ObjectNamePart, Query, Select, SelectFlavor, SelectItem, SetExpr, SetOperator,
        SetQuantifier, Statement, TableFactor, TableWithJoins, Value, Visitor, With,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::{
    deployment::Deployment,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::stored_name,
        cte_support::{WithScopes, same_name, stored_relation},
        grant_support::{function_callers, granted_callers},
        implication_support::{
            Columns, ParameterValues, Term, admits, clause_implies, parameter, renamed,
        },
        policy_support::{acting, client_roles, conjuncts, is_role_read, sql_query_body},
        type_support::user_type_named,
        walk_support::walk,
    },
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// Struct defining a rule that reports a `SECURITY DEFINER` function that
/// `PUBLIC` or a declared anonymous or app role can execute while its body
/// reads or writes a table with row-level security.
///
/// Every such caller reads and writes those tables as the function's owner,
/// so a helper returning identifiers, counts or yes-or-no answers discloses
/// rows the caller's own policies hide. A helper a policy calls is reported
/// too, since a caller holding `EXECUTE` can also call it directly.
/// PostgreSQL grants `PUBLIC` `EXECUTE` on every new function, and default
/// privileges such as Supabase's grant it to anonymous roles, so the rule reads
/// the privileges the schema leaves after both, with those a role inherits.
/// A declared role that neither the schema nor its cluster bootstrap creates
/// is not checked. SQL and PL/pgSQL bodies are read for the tables they
/// touch. A body whose tables cannot be known, such as C code or one running
/// dynamic SQL through `EXECUTE`, is reported as well, since nothing shows it
/// stays away from protected tables.
///
/// A function is not reported when every caller already reads what it
/// returns. Its body is then one `LANGUAGE sql` query that writes nothing and
/// sets no parameter besides `search_path`, and every read of a table with
/// row-level security in it is filtered, by its `WHERE` and the `ON` of the
/// joins that drop its rows, to rows each caller's own `SELECT` policies on
/// that table admit, while each caller may select every column of the table.
/// The filter has to imply every restrictive policy and one permissive one,
/// stating each condition as written, where a scalar subquery reading no
/// relation such as `(SELECT auth.uid())` stands for its value, or testing
/// the same column against a set within the policy's, as written or declared
/// with [`Deployment::with_set_within`]. A set read through an input
/// parameter of an enum type, such as `resources_with(min_role)`, has to lie
/// within the policy's for every label of the enum. It has to for `NULL`
/// too, which holds only when the function is `STRICT` or the call returns
/// `NULL` for a `NULL` argument, since no declaration states it. A column of
/// the same name hides the parameter, as in PostgreSQL. Only filter terms
/// that read alike for the caller and the owner count, those reading no
/// relation, no role, no privilege, no search path and no function running
/// as its caller, and a table read under an alias renaming its columns
/// confines nothing.
/// Every function of the schema the body calls is held to the same test,
/// except a `SECURITY DEFINER` function every caller may execute directly,
/// which this rule judges on its own. Functions in `pg_catalog` are trusted.
///
/// A read whose column reaches, unchanged, the result of a function that is
/// not `VOLATILE` and returns a set, through `UNION` arms and `WITH` items
/// read whole with nothing grouping, filtering or limiting it on the way,
/// also tests that column against the function's own call, written
/// schema-qualified with its arguments. A policy testing the column against
/// that call, or against a set declared to hold it, is then implied.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ExposedDefinerOverProtectedTable::default().into();
///
/// let exposed = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT, owner TEXT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
///        SET search_path = pg_catalog, pg_temp AS 'SELECT count(*) FROM public.docs';",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&exposed).is_err());
///
/// let revoked = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE docs (id INT, owner TEXT);
///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
///      CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER
///        SET search_path = pg_catalog, pg_temp AS 'SELECT count(*) FROM public.docs';
///      REVOKE EXECUTE ON FUNCTION doc_count() FROM PUBLIC;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&revoked).is_ok());
/// ```
pub struct ExposedDefinerOverProtectedTable<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ExposedDefinerOverProtectedTable<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ExposedDefinerOverProtectedTable<DB>>
    for GenericConstrainer<DB>
{
    fn from(rule: ExposedDefinerOverProtectedTable<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for ExposedDefinerOverProtectedTable<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(ExposedDefinerOverProtectedTable),
            group: LintGroup::Suspicious,
            rationale: "A `SECURITY DEFINER` function reads and writes with its owner's rights, so letting `PUBLIC` or an anonymous or app role execute it hands every such caller the owner's view of the row-level-security tables its body touches.",
            source: Some("https://supabase.com/docs/guides/database/database-advisors"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE docs (id INT, owner TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS 'SELECT count(*) FROM public.docs';",
                good: "CREATE TABLE docs (id INT, owner TEXT);\n\
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
CREATE FUNCTION doc_count() RETURNS BIGINT LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS 'SELECT count(*) FROM public.docs';\n\
REVOKE EXECUTE ON FUNCTION doc_count() FROM PUBLIC;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> FunctionRule for ExposedDefinerOverProtectedTable<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if function.security_mode() != FunctionSecurity::Definer {
            return Ok(());
        }
        let callers = function_callers(database, reporter.deployment(), function)?;
        if callers.is_empty() {
            return Ok(());
        }
        let touched = match function.referenced_tables(database) {
            Ok(tables) => {
                let mut protected = Vec::new();
                for table in tables {
                    if table.has_row_level_security(database)? {
                        protected.push(format!("'{}'", table.table_name()));
                    }
                }
                if protected.is_empty()
                    || Confinement::new(database, reporter.deployment(), function)?
                        .confines(function)?
                {
                    return Ok(());
                }
                format!(
                    "reads or writes {}, which has row-level security,",
                    protected.join(", ")
                )
            }
            Err(error) if super::unreadable_body(&error) => format!(
                "has a body whose tables cannot be checked ({error}), so it may read or write tables with row-level security"
            ),
            Err(error) => return Err(error.into()),
        };
        let signature = signature(function, database);
        let callers = callers.join(", ");
        reporter.function_privilege(
            function,
            format!(
                "`SECURITY DEFINER` function '{signature}' {touched} as its owner, and {callers} can execute it."
            ),
            format!(
                "REVOKE EXECUTE ON FUNCTION {signature} FROM {}; and grant it only to the roles that need it, or have its body limit each caller to the rows that caller may see.",
                callers.replace('\'', "")
            ),
        )
    }
}

/// Decides whether a function shows its callers only rows of tables with
/// row-level security that their own `SELECT` policies show them.
struct Confinement<'a, DB: DatabaseLike> {
    database: &'a DB,
    deployment: &'a Deployment,
    /// The roles the function runs for, `None` standing for `PUBLIC`.
    callers: Vec<Option<&'a DB::Role>>,
    /// The functions whose proof is under way, so a cycle proves nothing.
    proving: Vec<*const DB::Function>,
    /// The functions proved.
    proved: Vec<*const DB::Function>,
}

impl<'a, DB: DatabaseLike> Confinement<'a, DB> {
    /// The proof for the callers of `function`, which are every client role
    /// and `PUBLIC` while `PUBLIC` may execute it, else the declared roles
    /// granted `EXECUTE`.
    fn new(
        database: &'a DB,
        deployment: &'a Deployment,
        function: &DB::Function,
    ) -> Result<Self, LookupError> {
        let callers = if function.is_executable_by_public(database)? {
            client_roles(database, deployment)
                .into_iter()
                .map(|(_, role)| role)
                .collect()
        } else {
            granted_callers(database, deployment, function)?
                .into_iter()
                .map(Some)
                .collect()
        };
        Ok(Self {
            database,
            deployment,
            callers,
            proving: Vec::new(),
            proved: Vec::new(),
        })
    }

    /// Whether every row of a table with row-level security that `function`
    /// reads, itself or through the functions it calls, is one each caller's
    /// `SELECT` policies admit.
    fn confines(&mut self, function: &'a DB::Function) -> Result<bool, LookupError> {
        let address = ptr::from_ref(function);
        if self.proved.contains(&address) {
            return Ok(true);
        }
        if self.proving.contains(&address) {
            return Ok(false);
        }
        self.proving.push(address);
        let confined = self.confines_body(function);
        self.proving.pop();
        if matches!(confined, Ok(true)) {
            self.proved.push(address);
        }
        confined
    }

    /// Whether the functions `function` calls confine their reads, and its
    /// own body reads no table with row-level security or confines each read.
    fn confines_body(&mut self, function: &'a DB::Function) -> Result<bool, LookupError> {
        let (tables, callees) = match function
            .referenced_tables(self.database)
            .and_then(|tables| Ok((tables, function.referenced_functions(self.database)?)))
        {
            Ok(found) => found,
            Err(error) if super::unreadable_body(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        for callee in callees {
            if callee.target_name().schema() != Some("pg_catalog")
                && !self.runs_for_every_caller(callee)?
                && !self.confines(callee)?
            {
                return Ok(false);
            }
        }
        let mut protected = false;
        for table in tables {
            protected |= table.has_row_level_security(self.database)?;
        }
        if !protected {
            return Ok(true);
        }
        if function.configuration_parameters().iter().any(|parameter| {
            !parameter
                .name
                .to_string()
                .eq_ignore_ascii_case("search_path")
        }) {
            return Ok(false);
        }
        let Some(query) = sql_query_body(self.database, function)? else {
            return Ok(false);
        };
        let statement = Statement::Query(Box::new(query.into_owned()));
        let Statement::Query(query) = &statement else {
            unreachable!("the statement was built from a query");
        };
        let scope = ExpressionScope::FunctionBody(function);
        let Ok(context) = ExpressionContext::for_statement(
            &statement,
            &scope,
            self.database,
            IdentifierCase::AsWritten,
        ) else {
            return Ok(false);
        };
        let path = function.search_path(self.database)?;
        let lineage = Lineage::of(function, query);
        let mut reads = Reads {
            body: Body {
                parameters: self.parameter_values(function)?,
                confinement: self,
            },
            context: &context,
            path: path.as_deref(),
            items: WithScopes::default(),
            lineage: &lineage,
        };
        match walk(query.as_ref(), &mut reads) {
            ControlFlow::Continue(()) => Ok(true),
            ControlFlow::Break(None) => Ok(false),
            ControlFlow::Break(Some(error)) => Err(error),
        }
    }

    /// The values each input parameter of `function` may hold, in the order
    /// `$n` counts them. A parameter of an enum type holds its labels, and
    /// `NULL` unless the function is `STRICT`, and one of another type `None`.
    fn parameter_values(
        &self,
        function: &'a DB::Function,
    ) -> Result<Vec<Option<ParameterValues>>, LookupError> {
        let null = !matches!(
            function.null_input_behavior(),
            FunctionCalledOnNull::Strict | FunctionCalledOnNull::ReturnsNullOnNullInput
        );
        let scope = ExpressionScope::FunctionBody(function);
        let inputs = function
            .argument_modes()
            .filter(|mode| !matches!(mode, ArgMode::Out))
            .count();
        let mut values = Vec::with_capacity(inputs);
        for ordinal in 0..inputs {
            let placeholder = parameter(ordinal);
            let context = ExpressionContext::for_expression(
                &placeholder,
                &scope,
                self.database,
                IdentifierCase::AsWritten,
            )?;
            let OperandType::Known { type_name, .. } = context.type_of(&placeholder)? else {
                values.push(None);
                continue;
            };
            values.push(
                user_type_named(self.database, &type_name)
                    .and_then(UserDefinedTypeLike::enumeration)
                    .map(|enumeration| ParameterValues {
                        labels: enumeration
                            .into_members()
                            .map(|member| {
                                Expr::Value(
                                    Value::SingleQuotedString(member.label().to_owned()).into(),
                                )
                            })
                            .collect(),
                        null,
                    }),
            );
        }
        Ok(values)
    }

    /// Whether `callee` runs as its owner and every caller may execute it
    /// directly, so calling it discloses nothing a direct call does not.
    fn runs_for_every_caller(&self, callee: &DB::Function) -> Result<bool, LookupError> {
        if callee.security_mode() != FunctionSecurity::Definer {
            return Ok(false);
        }
        for caller in &self.callers {
            let executes = match *caller {
                Some(role) => callee.can_execute(role, self.database)?,
                None => callee.is_executable_by_public(self.database)?,
            };
            if !executes {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether `expression` evaluates alike for a caller and for the owner,
    /// reading no relation, no role, no privilege and no search path, and
    /// calling no function of the schema that runs as its caller.
    fn reads_alike(&self, expression: &Expr) -> Result<bool, LookupError> {
        match walk(expression, &mut CallerBound(self.database)) {
            ControlFlow::Continue(()) => Ok(true),
            ControlFlow::Break(None) => Ok(false),
            ControlFlow::Break(Some(error)) => Err(error),
        }
    }
}

/// The proof of one function body, whose filters name its input parameters
/// as `$n`.
struct Body<'c, 'a, DB: DatabaseLike> {
    confinement: &'c Confinement<'a, DB>,
    /// The values each input parameter may hold, in the order `$n` counts
    /// them.
    parameters: Vec<Option<ParameterValues>>,
}

impl<DB: DatabaseLike> Body<'_, '_, DB> {
    /// Whether `filter`, stating conditions of the columns of `table` by
    /// their stored names, admits only rows every caller's `SELECT` policies
    /// admit, of which every caller may select every column.
    fn admits_every_caller(&self, table: &DB::Table, filter: &Expr) -> Result<bool, LookupError> {
        let database = self.confinement.database;
        for caller in &self.confinement.callers {
            let security = match table.row_security(RowStatement::Select, acting(*caller), database)
            {
                Ok(security) => security,
                Err(RowSecurityError::Lookup(error)) => return Err(error),
                Err(_) => return Ok(false),
            };
            let admitted = match security.gates() {
                Some(gates) => admits(database, table, gates, self, |condition| {
                    clause_implies(self, filter, condition)
                })?,
                None => security.exemption().is_some(),
            };
            if !admitted {
                return Ok(false);
            }
            let held = table.privileges(acting(*caller), database)?;
            for column in table.columns(database)? {
                if !held.select.on_column(column) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

/// A policy condition states the columns of its table by their stored names,
/// as a confined filter does once renamed.
impl<DB: DatabaseLike> Columns for Body<'_, '_, DB> {
    type Tested = String;

    fn deployment(&self) -> &Deployment {
        self.confinement.deployment
    }

    fn rename(&self, column: Cow<'_, str>) -> Option<String> {
        Some(column.into_owned())
    }

    fn tested(&self, column: &Expr) -> Option<String> {
        stored_name(column).map(Cow::into_owned)
    }

    fn tests(&self, column: &Expr, tested: &String) -> bool {
        stored_name(column).is_some_and(|name| name == *tested)
    }

    fn parameter_values(&self, ordinal: usize) -> Option<&ParameterValues> {
        self.parameters.get(ordinal)?.as_ref()
    }

    fn returns_null_on_null_argument(&self, call: &Function, index: usize) -> bool {
        let database = self.confinement.database;
        let Ok(reached) = database.functions_reached_by(call, IdentifierCase::Folded) else {
            return false;
        };
        let mut any = false;
        for function in reached {
            if !function.returns_null_on_null_argument(database, index) {
                return false;
            }
            any = true;
        }
        any
    }
}

/// Finds a term that may evaluate otherwise for the caller than for the
/// owner, breaking with `None`, or with the error resolving a call.
struct CallerBound<'a, DB: DatabaseLike>(&'a DB);

impl<DB: DatabaseLike> CallerBound<'_, DB> {
    /// Whether `call` may reach a function of the schema running as its
    /// caller.
    fn runs_as_caller<'c>(&self, call: impl Into<WrittenCall<'c>>) -> Result<bool, LookupError> {
        Ok(self
            .0
            .functions_reached_by(call, IdentifierCase::Folded)?
            .any(|function| {
                function.target_name().schema() != Some("pg_catalog")
                    && function.security_mode() != FunctionSecurity::Definer
            }))
    }

    /// The walk's step for whether a term runs as its caller.
    fn verdict(outcome: Result<bool, LookupError>) -> ControlFlow<Option<LookupError>> {
        match outcome {
            Ok(false) => ControlFlow::Continue(()),
            Ok(true) => ControlFlow::Break(None),
            Err(error) => ControlFlow::Break(Some(error)),
        }
    }
}

impl<DB: DatabaseLike> Visitor for CallerBound<'_, DB> {
    type Break = Option<LookupError>;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        let Expr::Function(call) = expression else {
            return ControlFlow::Continue(());
        };
        if is_role_read(expression) || reads_session_state(call) {
            return ControlFlow::Break(None);
        }
        Self::verdict(self.runs_as_caller(call))
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table { args: None, .. } = factor {
            return ControlFlow::Break(None);
        }
        WrittenCall::relation(factor).map_or(ControlFlow::Continue(()), |call| {
            Self::verdict(self.runs_as_caller(call))
        })
    }
}

/// Whether `call` asks what privileges or roles the current role holds, such
/// as `has_table_privilege` or `pg_has_role`, or which schemas the search
/// path names, which the function's own `SET search_path` changes.
fn reads_session_state(call: &Function) -> bool {
    call.name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .is_some_and(|name| {
            let name = name.value.to_lowercase();
            (name.starts_with("has_") && name.ends_with("_privilege"))
                || matches!(
                    name.as_str(),
                    "pg_has_role" | "row_security_active" | "current_schema" | "current_schemas"
                )
        })
}

/// What a relation of a `FROM` item reads.
enum Read<'a, DB: DatabaseLike> {
    /// No table with row-level security.
    Open,
    /// The table with row-level security, by the name the query gives it.
    Protected(&'a DB::Table, String),
    /// Something no filter confines, such as a view.
    Unconfined,
}

/// Walks a body, breaking with `None` at a read the filters around it leave
/// unconfined, or with a lookup error.
struct Reads<'c, 'q, 'a, DB: DatabaseLike> {
    body: Body<'c, 'a, DB>,
    context: &'c ExpressionContext<'q, 'a, DB>,
    path: Option<&'c [(Cow<'c, str>, bool)]>,
    items: WithScopes,
    lineage: &'c Lineage,
}

impl<'a, DB: DatabaseLike> Reads<'_, '_, 'a, DB> {
    /// Whether every `SELECT` of `body`, outside nested queries, confines its
    /// reads, a body that writes or reads `TABLE` never.
    fn confines(&self, body: &SetExpr) -> Result<bool, LookupError> {
        match body {
            SetExpr::Select(select) => self.confines_select(select),
            SetExpr::SetOperation { left, right, .. } => {
                Ok(self.confines(left)? && self.confines(right)?)
            }
            SetExpr::Query(_) | SetExpr::Values(_) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Whether each relation with row-level security a `SELECT` reads is
    /// confined by the filters that drop its rows.
    fn confines_select(&self, select: &Select) -> Result<bool, LookupError> {
        let filter: Vec<&Expr> = select.selection.iter().flat_map(conjuncts).collect();
        for from in &select.from {
            let relations =
                iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation));
            for (position, relation) in relations.enumerate() {
                let (table, name) = match self.read(relation)? {
                    Read::Open => continue,
                    Read::Unconfined => return Ok(false),
                    Read::Protected(table, name) => (table, name),
                };
                let mut kept = Vec::new();
                for conjunct in filter.iter().copied().chain(joined_filter(from, position)) {
                    if let Some(stated) =
                        renamed(conjunct, |reference| term(self.context, reference, &name))
                        && self.body.confinement.reads_alike(conjunct)?
                    {
                        kept.push(stated);
                    }
                }
                if let Some(membership) = self.lineage.membership(select, |column| {
                    match term(self.context, column, &name)? {
                        Term::Column(column) => Some(column),
                        Term::Parameter(_) => None,
                    }
                }) {
                    kept.push(membership);
                }
                if !self.body.admits_every_caller(table, &conjunction(kept))? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// What `relation` reads, a `WITH` item and a call nothing.
    fn read(&self, relation: &TableFactor) -> Result<Read<'a, DB>, LookupError> {
        let database = self.body.confinement.database;
        match relation {
            TableFactor::Table {
                name,
                alias,
                args: None,
                ..
            } => {
                if self.items.binding(name).is_some() {
                    return Ok(Read::Open);
                }
                Ok(match stored_relation(database, name, self.path)? {
                    Some(Relation::Table(table)) if table.has_row_level_security(database)? => {
                        if alias
                            .as_ref()
                            .is_some_and(|alias| !alias.columns.is_empty())
                        {
                            return Ok(Read::Unconfined);
                        }
                        let exposed = alias
                            .as_ref()
                            .map(|alias| &alias.name)
                            .or_else(|| name.0.last().and_then(|part| part.as_ident()));
                        match exposed {
                            Some(exposed) => Read::Protected(
                                table,
                                normalize_identifier(&exposed.value, exposed.quote_style.is_some())
                                    .into_owned(),
                            ),
                            None => Read::Unconfined,
                        }
                    }
                    Some(Relation::View(_)) => Read::Unconfined,
                    _ => Read::Open,
                })
            }
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => self.read_nested(table_with_joins),
            _ => Ok(Read::Open),
        }
    }

    /// What a parenthesized join reads, which is nothing when none of its
    /// relations reads a table with row-level security and else something
    /// left unconfined.
    fn read_nested(&self, joined: &TableWithJoins) -> Result<Read<'a, DB>, LookupError> {
        for relation in
            iter::once(&joined.relation).chain(joined.joins.iter().map(|join| &join.relation))
        {
            if !matches!(self.read(relation)?, Read::Open) {
                return Ok(Read::Unconfined);
            }
        }
        Ok(Read::Open)
    }
}

impl<DB: DatabaseLike> Visitor for Reads<'_, '_, '_, DB> {
    type Break = Option<LookupError>;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.items.enter(query);
        if query.locks.is_empty() {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(None)
        }
    }

    /// Judges the query once its `WITH` items are in reach.
    fn post_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        let confined = self.confines(&query.body);
        self.items.leave(query);
        match confined {
            Ok(true) => ControlFlow::Continue(()),
            Ok(false) => ControlFlow::Break(None),
            Err(error) => ControlFlow::Break(Some(error)),
        }
    }
}

/// The `SELECT`s of a function body each of whose rows reaches the
/// function's result holding the one column it projects, unchanged.
struct Lineage {
    /// `SELECT f($1, …)` calling the function with its own arguments, `None`
    /// when calls need not agree on the set it returns.
    member: Option<Box<Query>>,
    selects: Vec<*const Select>,
}

impl Lineage {
    /// The lineage of `query`, the body of `function`. A `SECURITY DEFINER`
    /// function that is not `VOLATILE` returns the same set to a caller as to
    /// a policy calling it with the same arguments.
    fn of<F: FunctionLike>(function: &F, query: &Query) -> Self {
        let member = (function.security_mode() == FunctionSecurity::Definer
            && function.volatility() != FunctionBehavior::Volatile
            && function.returns_set())
        .then(|| member(function))
        .flatten();
        let mut carried = Carried::default();
        if member.is_some() {
            carried.query(query);
        }
        Self {
            member,
            selects: carried.selects,
        }
    }

    /// `"column" IN (SELECT f($1, …))` when `select` belongs to the lineage
    /// and `own` names the stored column of the projection.
    fn membership(
        &self,
        select: &Select,
        own: impl FnOnce(&Expr) -> Option<String>,
    ) -> Option<Expr> {
        let template = self.member.as_ref()?;
        if !self.selects.iter().any(|carried| ptr::eq(*carried, select)) {
            return None;
        }
        let (projected, _) = carried_column(select)?;
        let column = own(projected)?;
        Some(Expr::In {
            expr: Box::new(Expr::Identifier(Ident::with_quote('"', column))),
            target: InTarget::Subquery(template.clone()),
            negated: false,
            global: false,
        })
    }
}

/// `SELECT schema.name($1, …)` calling `function`, its schema `public` when
/// its name has none, or `None` when an argument is not an input.
fn member<F: FunctionLike>(function: &F) -> Option<Box<Query>> {
    let mut arguments = Vec::new();
    for (position, mode) in function.argument_modes().enumerate() {
        if mode != ArgMode::In {
            return None;
        }
        arguments.push(parameter(position).to_string());
    }
    let written = |name: &str, quoted: bool| {
        let stored = normalize_identifier(name, quoted).into_owned();
        if quoted {
            Ident::with_quote('"', stored)
        } else {
            Ident::new(stored)
        }
    };
    let target = function.target_name();
    let schema = target.schema().map_or_else(
        || Ident::new("public"),
        |schema| written(schema, target.schema_is_quoted()),
    );
    let name = written(target.name(), target.name_is_quoted());
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(&format!("SELECT {schema}.{name}({})", arguments.join(", ")))
        .and_then(|mut parser| parser.parse_query())
        .ok()
}

/// Walks down from a result to the `SELECT`s every row of which reaches it.
#[derive(Default)]
struct Carried<'q> {
    selects: Vec<*const Select>,
    /// The `WITH` clauses in reach, each with how many of its items, from
    /// the first, it shows.
    frames: Vec<(&'q With, usize)>,
    /// The `WITH` item bodies already followed, so a recursive item is
    /// followed once.
    followed: Vec<*const Query>,
}

impl<'q> Carried<'q> {
    /// Follows `query` unless a limit, an offset or a lock may leave some of
    /// its rows behind.
    fn query(&mut self, query: &'q Query) {
        if query.limit_clause.is_some()
            || query.fetch.is_some()
            || !query.pipe_operators.is_empty()
            || !query.locks.is_empty()
        {
            return;
        }
        let depth = self.frames.len();
        if let Some(with) = &query.with {
            self.frames.push((with, with.cte_tables.len()));
        }
        self.body(&query.body);
        self.frames.truncate(depth);
    }

    /// Follows every arm of a `UNION`, which keeps each row of each arm.
    fn body(&mut self, body: &'q SetExpr) {
        match body {
            SetExpr::Select(select) => self.select(select),
            SetExpr::Query(query) => self.query(query),
            SetExpr::SetOperation {
                op: SetOperator::Union,
                set_quantifier: SetQuantifier::All | SetQuantifier::Distinct | SetQuantifier::None,
                left,
                right,
            } => {
                self.body(left);
                self.body(right);
            }
            _ => {}
        }
    }

    /// Records `select` when its rows each hold its one projected column,
    /// and follows the `WITH` item it projects whole.
    fn select(&mut self, select: &'q Select) {
        let Some((_, projected)) = carried_column(select) else {
            return;
        };
        self.selects.push(select);
        let ([from], None) = (select.from.as_slice(), &select.selection) else {
            return;
        };
        let TableFactor::Table {
            name,
            alias,
            args: None,
            ..
        } = &from.relation
        else {
            return;
        };
        let ([ObjectNamePart::Identifier(written)], []) =
            (name.0.as_slice(), from.joins.as_slice())
        else {
            return;
        };
        let Some((frame, item)) = self.item(written) else {
            return;
        };
        let (with, _) = self.frames[frame];
        let cte = &with.cte_tables[item];
        let renamed = alias
            .as_ref()
            .map_or(&[][..], |alias| alias.columns.as_slice());
        let column = match (renamed, cte.alias.columns.as_slice()) {
            ([column], _) | ([], [column]) => &column.name,
            ([], []) => match output_name(&cte.query) {
                Some(name) => name,
                None => return,
            },
            _ => return,
        };
        let relation = alias.as_ref().map_or(written, |alias| &alias.name);
        let body = ptr::from_ref(cte.query.as_ref());
        if !names(projected, relation, column) || self.followed.contains(&body) {
            return;
        }
        self.followed.push(body);
        let outer = mem::take(&mut self.frames);
        self.frames.extend_from_slice(&outer[..frame]);
        self.frames.push((
            with,
            if with.recursive {
                with.cte_tables.len()
            } else {
                item
            },
        ));
        self.query(&cte.query);
        self.frames = outer;
    }

    /// The frame and position of the visible `WITH` item `written` names.
    fn item(&self, written: &Ident) -> Option<(usize, usize)> {
        self.frames
            .iter()
            .enumerate()
            .rev()
            .find_map(|(frame, (with, visible))| {
                with.cte_tables[..*visible]
                    .iter()
                    .position(|item| same_name(&item.alias.name, written))
                    .map(|item| (frame, item))
            })
    }
}

/// The column reference a `SELECT` projects alone, with the parts of its
/// name, when each row its `FROM` and filters leave yields one row holding
/// it, with no grouping, aggregate or `DISTINCT ON` choosing among them.
fn carried_column(select: &Select) -> Option<(&Expr, &[Ident])> {
    let [
        SelectItem::UnnamedExpr(projected)
        | SelectItem::ExprWithAlias {
            expr: projected, ..
        },
    ] = select.projection.as_slice()
    else {
        return None;
    };
    let plain = matches!(
        select.distinct,
        None | Some(Distinct::All | Distinct::Distinct)
    ) && select.select_modifiers.is_none()
        && select.top.is_none()
        && select.exclude.is_none()
        && select.into.is_none()
        && select.lateral_views.is_empty()
        && select.prewhere.is_none()
        && select.connect_by.is_empty()
        && matches!(&select.group_by, GroupByExpr::Expressions(grouped, modifiers) if grouped.is_empty() && modifiers.is_empty())
        && select.cluster_by.is_empty()
        && select.distribute_by.is_empty()
        && select.sort_by.is_empty()
        && select.having.is_none()
        && select.named_window.is_empty()
        && select.qualify.is_none()
        && select.value_table_mode.is_none()
        && select.flavor == SelectFlavor::Standard;
    let parts = match projected {
        Expr::Identifier(name) => slice::from_ref(name),
        Expr::CompoundIdentifier(parts) => parts.as_slice(),
        _ => return None,
    };
    plain.then_some((projected, parts))
}

/// The name of the one column `query` yields, given by its leftmost
/// `SELECT`.
fn output_name(query: &Query) -> Option<&Ident> {
    let mut body = query.body.as_ref();
    loop {
        match body {
            SetExpr::SetOperation { left, .. } => body = left,
            SetExpr::Query(query) => body = query.body.as_ref(),
            SetExpr::Select(select) => {
                return match select.projection.as_slice() {
                    [SelectItem::ExprWithAlias { alias, .. }] => Some(alias),
                    [SelectItem::UnnamedExpr(Expr::Identifier(name))] => Some(name),
                    [SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts))] => parts.last(),
                    _ => None,
                };
            }
            _ => return None,
        }
    }
}

/// Whether the column reference named by `parts` names `column` of the
/// relation a query names `relation`.
fn names(parts: &[Ident], relation: &Ident, column: &Ident) -> bool {
    matches!(parts, [name] if same_name(name, column))
        || matches!(parts, [qualifier, name] if same_name(qualifier, relation) && same_name(name, column))
}

/// The conjuncts of the `ON` conditions of `from` that drop rows of its
/// relation at `position`, counted from zero. An inner join's drop rows of
/// the relations up to the one it joins, a left join's of the one it joins
/// and a right join's of those before it.
fn joined_filter(from: &TableWithJoins, position: usize) -> impl Iterator<Item = &Expr> {
    from.joins
        .iter()
        .enumerate()
        .filter_map(move |(index, join)| {
            let joined = index + 1;
            match &join.join_operator {
                JoinOperator::Join(JoinConstraint::On(condition))
                | JoinOperator::Inner(JoinConstraint::On(condition))
                    if position <= joined =>
                {
                    Some(condition)
                }
                JoinOperator::Left(JoinConstraint::On(condition))
                | JoinOperator::LeftOuter(JoinConstraint::On(condition))
                    if position == joined =>
                {
                    Some(condition)
                }
                JoinOperator::Right(JoinConstraint::On(condition))
                | JoinOperator::RightOuter(JoinConstraint::On(condition))
                    if position < joined =>
                {
                    Some(condition)
                }
                _ => None,
            }
        })
        .flat_map(conjuncts)
}

/// The input parameter of the function whose body holds `reference` that
/// it names where no column of the same name is in reach, or else the stored
/// name of the column of the relation the query names `relation` it names.
fn term<DB: DatabaseLike>(
    context: &ExpressionContext<'_, '_, DB>,
    reference: &Expr,
    relation: &str,
) -> Option<Term> {
    match context.reference(reference).ok()?? {
        (ColumnDefinition::Parameter { ordinal, .. }, _) => Some(Term::Parameter(ordinal)),
        (_, binding) => {
            let ((named_relation, relation_quoted), (column, column_quoted)) =
                binding.relation().zip(binding.exposed())?;
            (normalize_identifier(named_relation, relation_quoted) == relation)
                .then(|| Term::Column(normalize_identifier(column, column_quoted).into_owned()))
        }
    }
}

/// The `AND` of `conjuncts`, `TRUE` for none.
fn conjunction(conjuncts: Vec<Expr>) -> Expr {
    conjuncts
        .into_iter()
        .reduce(|left, right| Expr::BinaryOp {
            left: Box::new(left),
            op: BinaryOperator::And,
            right: Box::new(right),
        })
        .unwrap_or(Expr::Value(Value::Boolean(true).into()))
}
