//! Submodule providing the `ExposedDefinerOverProtectedTable` rule.

use std::{borrow::Cow, iter, ops::ControlFlow, ptr};

use sql_traits::{
    errors::{LookupError, RowSecurityError},
    structs::{ColumnDefinitionScope, ColumnScope, IdentifierCase, RowStatement, WrittenCall},
    traits::{DatabaseLike, FunctionLike, Relation, TableLike},
    utils::identifier_resolution::normalize_identifier,
};
use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionSecurity, JoinConstraint, JoinOperator, Query, Select,
    SetExpr, TableFactor, TableWithJoins, Value, Visitor,
};

use crate::{
    deployment::Deployment,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::stored_name,
        cte_support::{WithScopes, stored_relation},
        grant_support::{function_callers, granted_callers},
        implication_support::{Columns, admits, clause_implies, renamed},
        key_support::named,
        policy_support::{acting, client_roles, conjuncts, is_role_read, sql_query_body},
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
/// with [`Deployment::with_set_within`]. Only filter terms that read alike
/// for the caller and the owner count, those reading no relation, no role,
/// no privilege, no search path and no function running as its caller, and
/// a table read under an alias renaming its columns confines nothing.
/// Every function of the schema the body calls is held to the same test,
/// except a `SECURITY DEFINER` function every caller may execute directly,
/// which this rule judges on its own. Functions in `pg_catalog` are trusted.
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
    fn confines(&mut self, function: &DB::Function) -> Result<bool, LookupError> {
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
    fn confines_body(&mut self, function: &DB::Function) -> Result<bool, LookupError> {
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
        let Ok(scope) = ColumnScope::from_query(&query, self.database, IdentifierCase::AsWritten)
        else {
            return Ok(false);
        };
        let path = function.search_path(self.database)?;
        let mut reads = Reads {
            confinement: self,
            scope: &scope,
            path: path.as_deref(),
            items: WithScopes::default(),
        };
        match walk(query.as_ref(), &mut reads) {
            ControlFlow::Continue(()) => Ok(true),
            ControlFlow::Break(None) => Ok(false),
            ControlFlow::Break(Some(error)) => Err(error),
        }
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

    /// Whether `filter`, stating conditions of the columns of `table` by
    /// their stored names, admits only rows every caller's `SELECT` policies
    /// admit, of which every caller may select every column.
    fn admits_every_caller(&self, table: &DB::Table, filter: &Expr) -> Result<bool, LookupError> {
        for caller in &self.callers {
            let security =
                match table.row_security(RowStatement::Select, acting(*caller), self.database) {
                    Ok(security) => security,
                    Err(RowSecurityError::Lookup(error)) => return Err(error),
                    Err(_) => return Ok(false),
                };
            let admitted = match security.gates() {
                Some(gates) => admits(self.database, table, gates, self, |condition| {
                    clause_implies(self, filter, condition)
                })?,
                None => security.exemption().is_some(),
            };
            if !admitted {
                return Ok(false);
            }
            let held = table.privileges(acting(*caller), self.database)?;
            for column in table.columns(self.database)? {
                if !held.select.on_column(column) {
                    return Ok(false);
                }
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

/// A policy condition states the columns of its table by their stored names,
/// as a confined filter does once renamed.
impl<DB: DatabaseLike> Columns for Confinement<'_, DB> {
    type Tested = String;

    fn deployment(&self) -> &Deployment {
        self.deployment
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
    confinement: &'c Confinement<'a, DB>,
    scope: &'c ColumnScope<'q, 'a, DB>,
    path: Option<&'c [(Cow<'c, str>, bool)]>,
    items: WithScopes,
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
        let Some(scope) = self.scope.scope_for_select(select) else {
            return Ok(false);
        };
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
                        renamed(conjunct, |column| own_column(&scope, column, &name))
                        && self.confinement.reads_alike(conjunct)?
                    {
                        kept.push(stated);
                    }
                }
                if !self
                    .confinement
                    .admits_every_caller(table, &conjunction(kept))?
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// What `relation` reads, a `WITH` item and a call nothing.
    fn read(&self, relation: &TableFactor) -> Result<Read<'a, DB>, LookupError> {
        let database = self.confinement.database;
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

/// The stored name of the column `column` names when it resolves in `scope`
/// to the relation the query names `relation`.
fn own_column<DB: DatabaseLike>(
    scope: &ColumnDefinitionScope<'_, '_, '_, DB>,
    column: &Expr,
    relation: &str,
) -> Option<String> {
    named(scope, column)
        .ok()
        .flatten()
        .and_then(|(named_relation, column)| (named_relation == relation).then_some(column))
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
