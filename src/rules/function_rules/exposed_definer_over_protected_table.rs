//! Submodule providing the `ExposedDefinerOverProtectedTable` rule.

use std::{borrow::Cow, cell::RefCell, iter, mem, ops::ControlFlow, ptr, rc::Rc, slice};

use sql_traits::{
    errors::{LookupError, RowSecurityError},
    structs::{
        ColumnBinding, ColumnDefinition, ConstraintDeferral, ExpressionContext, ExpressionScope,
        IdentifierCase, OperandType, RowStatement, WrittenCall,
    },
    traits::{
        ColumnCollation, ColumnLike, DataTypeLike, DatabaseLike, EnumerationKind, ForeignKeyLike,
        FunctionLike, PolicyLike, Relation, TableLike, UserDefinedTypeLike,
    },
    utils::{identifier_resolution::normalize_identifier, scalar_family::ScalarFamily},
};
use sqlparser::{
    ast::{
        ArgMode, BinaryOperator, DataType, Distinct, Expr, Function, FunctionArg, FunctionArgExpr,
        FunctionArguments, FunctionBehavior, FunctionCalledOnNull, FunctionSecurity, GroupByExpr,
        Ident, InTarget, JoinConstraint, JoinOperator, ObjectNamePart, Query, Select, SelectFlavor,
        SelectItem, SetExpr, SetOperator, SetQuantifier, Statement, TableAliasColumnDef,
        TableFactor, TableInheritance, TableWithJoins, Value, Visit, Visitor, With,
        visit_expressions,
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
        cte_support::{
            WithScopes, join_constraint, same_name, stored_column, stored_relation, stored_table,
        },
        grant_support::{function_callers, granted_callers},
        implication_support::{
            Columns, Condition, ParameterValues, Term, admits, clause_implies, membership,
            parameter, renamed,
        },
        key_support::{checked_whenever_set, equality_keys, key_pairs},
        literal_support::{literal, string_value},
        null_support::rejects_null,
        policy_support::{
            acting, client_roles, conjuncts, is_role_read, sets_only_search_path, sql_query_body,
            unnested, unwrapped,
        },
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
/// A condition on a column also counts for a column the same filters hold
/// equal to it with `=`, when both are columns of stored tables whose types
/// hold `=` only between identical values. These are integers, `uuid`,
/// `boolean`, dates, timestamps, one enum type, and `text` or `varchar` with
/// no collation. A `USING` join holds the column it merges equal to that
/// column of each table it merges whose row is present, and the first join
/// merging a name holds its two sides equal wherever an `ON` with that
/// equality would. An `EXISTS` or `IN` of a `WHERE` over a query that
/// neither aggregates nor combines rows adds that query's `WHERE` to the
/// outer filters, since a row passing it exists, and `x IN (SELECT y …)`
/// holds `x` equal to `y`. A query nested in a condition of a `WHERE` is
/// filtered by the other conditions of that `WHERE` too, since its outcome
/// reaches the result only for outer rows passing them.
///
/// A read whose column reaches, unchanged, the result of a function that is
/// not `VOLATILE` and returns a set, through `UNION` arms and `WITH` items
/// read whole with nothing grouping, filtering or limiting it on the way,
/// also tests that column against the function's own call, written
/// schema-qualified with its arguments. A policy testing the column against
/// that call, or against a set declared to hold it, is then implied.
///
/// A column tested with `IN` or `= ANY` against the set of a function that
/// is not `VOLATILE`, sets no parameter besides `search_path` and returns
/// one column of rows of stored tables, through `UNION` arms, `WITH` items
/// and calls of such functions, also meets what the function's filters
/// state of the row it draws the value from. A condition on the returned
/// column holds of the tested column when `=` compares both by the same
/// identity. A condition on another column holds of the tested row when a
/// foreign key that is `NOT DEFERRABLE`, validated and checking every row
/// holding a value maps the returned column onto the tested one, unique in
/// its table, and maps that column onto one compared by the same identity.
/// A row the keys keep apart from the tested one is left out first.
/// Following such keys from a column, each table on which the value is
/// unique pins its columns generated as one value, the columns a key fills
/// from a column pinned before and those the filter pins, and a value whose
/// row pins a column to none of the values the tested value's row may hold
/// is never the tested value. Keys of a table another table inherits from
/// count for nothing, since that table's rows escape them.
///
/// A column also lies in the set of a `SECURITY DEFINER` function a policy
/// of the table tests a column against, when that function runs as the
/// owner the body runs as and, if `STRICT`, the policy passes a literal
/// other than `NULL` for every parameter. An arm of it has to read one table alone,
/// every row and with no sample, and return the column of every row of it
/// meeting its filter. A row the body reads of that table, not filled with
/// `NULL`s by an outer join, has to meet every condition of the filter, and
/// the body's filters hold the column the arm returns of that row equal to
/// the column.
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
    /// The rows each function read so far draws the values it returns from,
    /// by the function's address.
    arms: RefCell<Vec<ReadArms<'a, DB>>>,
    /// The functions whose rows are being read, so a cycle reads none.
    drawing: RefCell<Vec<*const DB::Function>>,
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
            arms: RefCell::default(),
            drawing: RefCell::default(),
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
        if !sets_only_search_path(function) {
            return Ok(false);
        }
        self.read_body(
            function,
            |query| Lineage::of(function, query),
            |reads, query| reads.confines_query(query, &[], &[]),
        )
        .map(|confined| confined == Some(true))
    }

    /// What `walk` finds reading the body of `function`, one `LANGUAGE sql`
    /// query, with the lineage `lineage` gives it, or `None` when the body is
    /// no such query or its names do not resolve.
    fn read_body<T>(
        &self,
        function: &'a DB::Function,
        lineage: impl FnOnce(&Query) -> Lineage,
        walk: impl FnOnce(&mut Reads<'_, '_, 'a, DB>, &Query) -> Result<T, LookupError>,
    ) -> Result<Option<T>, LookupError> {
        let Some(query) = sql_query_body(self.database, function)? else {
            return Ok(None);
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
            return Ok(None);
        };
        let path = function.search_path(self.database)?;
        let lineage = lineage(query);
        let mut reads = Reads {
            body: Body {
                parameters: self.parameter_values(function)?,
                confinement: self,
                function,
            },
            context: &context,
            path: path.as_deref(),
            items: WithScopes::default(),
            lineage: &lineage,
        };
        walk(&mut reads, query).map(Some)
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

    /// The rows `function` draws the values it returns from, read once.
    fn arms(&self, function: &'a DB::Function) -> Result<Rc<Arms<'a, DB>>, LookupError> {
        let address = ptr::from_ref(function);
        if let Some((_, arms)) = self.arms.borrow().iter().find(|(read, _)| *read == address) {
            return Ok(Rc::clone(arms));
        }
        if self.drawing.borrow().contains(&address) {
            return Ok(Rc::new(Arms::default()));
        }
        self.drawing.borrow_mut().push(address);
        let arms = self.read_arms(function);
        self.drawing.borrow_mut().pop();
        let arms = Rc::new(arms?);
        self.arms.borrow_mut().push((address, Rc::clone(&arms)));
        Ok(arms)
    }

    /// [`Self::arms`] read from the body of `function`. A `VOLATILE` function
    /// may read rows of a later snapshot, and a parameter it sets may change
    /// what its filters compute, so either draws from rows the rule cannot
    /// tell.
    fn read_arms(&self, function: &'a DB::Function) -> Result<Arms<'a, DB>, LookupError> {
        if function.volatility() == FunctionBehavior::Volatile
            || !function.returns_set()
            || !sets_only_search_path(function)
        {
            return Ok(Arms::default());
        }
        self.read_body(
            function,
            |_| Lineage::default(),
            |reads, query| {
                let mut carried = Carried::new();
                carried.query(query);
                let mut drawing = Drawing {
                    leaves: carried.leaves(),
                    arms: Arms {
                        arms: Vec::new(),
                        complete: carried.complete,
                    },
                };
                reads.draw_query(query, &mut drawing)?;
                drawing.arms.complete &= drawing.leaves.is_empty();
                Ok(drawing.arms)
            },
        )
        .map(Option::unwrap_or_default)
    }
}

/// The rows the values a set-returning function returns are drawn from.
struct Arms<'a, DB: DatabaseLike> {
    arms: Vec<Arm<'a, DB>>,
    /// Whether every value the function returns is the column of a row of
    /// `arms`.
    complete: bool,
}

impl<DB: DatabaseLike> Default for Arms<'_, DB> {
    fn default() -> Self {
        Self {
            arms: Vec::new(),
            complete: false,
        }
    }
}

/// One way a function draws a value it returns from a row.
struct Arm<'a, DB: DatabaseLike> {
    drawn: Rc<Drawn<'a, DB>>,
    /// Whether the function returns the column of every row of the table
    /// meeting the conditions.
    exhaustive: bool,
}

/// A row of a stored table that a function returns one column of.
struct Drawn<'a, DB: DatabaseLike> {
    table: &'a DB::Table,
    /// The column returned.
    column: &'a DB::Column,
    /// Conditions the row meets, over the stored names of the columns of
    /// `table`, each evaluating alike for every role.
    conditions: Vec<Expr>,
}

/// The leaf `SELECT`s of a function body not read yet, and the rows read.
struct Drawing<'a, DB: DatabaseLike> {
    /// Each leaf not read yet. Every row of a leaf reaches the result.
    leaves: Vec<*const Select>,
    arms: Arms<'a, DB>,
}

/// The proof of one function body, whose filters name its input parameters
/// as `$n`.
struct Body<'c, 'a, DB: DatabaseLike> {
    confinement: &'c Confinement<'a, DB>,
    /// The values each input parameter may hold, in the order `$n` counts
    /// them.
    parameters: Vec<Option<ParameterValues>>,
    function: &'a DB::Function,
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
                    clause_implies(self, filter, condition, &[])
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

/// What a relation of a `FROM` item holds under a column name.
enum Side<'c, DB: DatabaseLike> {
    /// Something other than a stored table or a source projecting a stored
    /// column under the name, whose columns are not read.
    Unknown,
    /// A stored table with no column of the name.
    Absent,
    /// The stored column the name reaches.
    Column(&'c DB::Column),
}

/// A relation reading a `WITH` item or a subquery whose body yields each
/// of its rows from a row passing the body's `WHERE`.
#[derive(Clone, Copy)]
struct Source<'s> {
    relation: &'s TableFactor,
    body: &'s Select,
    /// The names the alias of the relation gives its columns.
    aliased: &'s [TableAliasColumnDef],
    /// The names the `WITH` item gives its columns, which `aliased`
    /// overrides.
    renamed: &'s [TableAliasColumnDef],
}

impl Source<'_> {
    /// The position of the first output column named `name`, normalized,
    /// unless the body projects a `*`, which may shift or hold it.
    /// PostgreSQL refuses a `USING` name a side holds twice.
    fn ordinal(&self, name: &str) -> Option<usize> {
        let mut found = None;
        for (ordinal, item) in self.body.projection.iter().enumerate() {
            let projected = match item {
                SelectItem::ExprWithAlias { alias, .. } => Some(alias),
                SelectItem::UnnamedExpr(Expr::Identifier(name)) => Some(name),
                SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => parts.last(),
                SelectItem::UnnamedExpr(_) => None,
                _ => return None,
            };
            let output = self
                .aliased
                .get(ordinal)
                .or_else(|| self.renamed.get(ordinal))
                .map(|column| &column.name)
                .or(projected);
            if found.is_none()
                && output.is_some_and(|output| {
                    normalize_identifier(&output.value, output.quote_style.is_some()) == name
                })
            {
                found = Some(ordinal);
            }
        }
        found
    }

    /// The definition and binding of the column the body projects as its
    /// output column named `name`, normalized.
    fn column<'c, 'q, 'a, DB: DatabaseLike>(
        &self,
        context: &'c ExpressionContext<'q, 'a, DB>,
        name: &str,
    ) -> Option<(ColumnDefinition<'c, 'q, 'a, DB>, ColumnBinding<'c>)> {
        let projected = projection_at(self.body, self.ordinal(name)?)?;
        context.reference(projected).ok().flatten()
    }
}

/// What a relation of a `FROM` item reads.
enum Read<'a, DB: DatabaseLike> {
    /// No table with row-level security.
    Open,
    /// The table with row-level security.
    Protected(&'a DB::Table),
    /// Something no filter confines, such as a view.
    Unconfined,
}

/// Walks a body for a read the filters around it leave unconfined.
struct Reads<'c, 'q, 'a, DB: DatabaseLike> {
    body: Body<'c, 'a, DB>,
    context: &'c ExpressionContext<'q, 'a, DB>,
    path: Option<&'c [(Cow<'c, str>, bool)]>,
    items: WithScopes,
    lineage: &'c Lineage,
}

impl<'c, 'q, 'a, DB: DatabaseLike> Reads<'c, 'q, 'a, DB> {
    /// Whether `query` and every query nested in it confine their reads,
    /// where `held` holds for every outer row the result of `query` reaches
    /// the function's result through and `owners` are the queries around it
    /// whose `WITH` holds items in reach.
    fn confines_query(
        &mut self,
        query: &Query,
        held: &[&Expr],
        owners: &[&Query],
    ) -> Result<bool, LookupError> {
        if !query.locks.is_empty() {
            return Ok(false);
        }
        let mut owners = owners.to_vec();
        if query.with.is_some() {
            owners.push(query);
        }
        self.items.enter(query);
        let confined = match self.confines_nested(query, held, &owners) {
            Ok(true) => self.confines(&query.body, held, &owners),
            other => other,
        };
        self.items.leave(query);
        confined
    }

    /// Whether each query nested directly in `query` confines its reads. One
    /// in a condition of a `WHERE` also holds the other conditions of that
    /// `WHERE`, since the outer row passes them whenever its outcome counts.
    fn confines_nested(
        &mut self,
        query: &Query,
        held: &[&Expr],
        owners: &[&Query],
    ) -> Result<bool, LookupError> {
        let mut beside = Vec::new();
        conditions_beside(&query.body, &mut beside);
        let outcome = nested_queries(query, 1, |nested| {
            let mut within = held.to_vec();
            if let Some((_, others)) = beside.iter().find(|(at, _)| ptr::eq(*at, nested)) {
                within.extend_from_slice(others);
            }
            match self.confines_query(nested, &within, owners) {
                Ok(true) => ControlFlow::Continue(()),
                Ok(false) => ControlFlow::Break(None),
                Err(error) => ControlFlow::Break(Some(error)),
            }
        });
        match outcome {
            ControlFlow::Continue(()) => Ok(true),
            ControlFlow::Break(None) => Ok(false),
            ControlFlow::Break(Some(error)) => Err(error),
        }
    }

    /// Whether every `SELECT` of `body`, outside nested queries, confines its
    /// reads, a body that writes or reads `TABLE` never.
    fn confines(
        &self,
        body: &SetExpr,
        held: &[&Expr],
        owners: &[&Query],
    ) -> Result<bool, LookupError> {
        match body {
            SetExpr::Select(select) => self.confines_select(select, held, owners),
            SetExpr::SetOperation { left, right, .. } => {
                Ok(self.confines(left, held, owners)? && self.confines(right, held, owners)?)
            }
            SetExpr::Query(_) | SetExpr::Values(_) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Whether each relation with row-level security a `SELECT` reads is
    /// confined by the filters that drop its rows, the conditions `held` of
    /// the outer rows, and what the sets they test its columns against tell.
    fn confines_select(
        &self,
        select: &Select,
        held: &[&Expr],
        owners: &[&Query],
    ) -> Result<bool, LookupError> {
        let filters = self.filters(select, held, owners)?;
        for from in &select.from {
            for (position, relation) in relations(from).enumerate() {
                let table = match self.read(relation)? {
                    Read::Open => continue,
                    Read::Unconfined => return Ok(false),
                    Read::Protected(table) => table,
                };
                let Stated {
                    resolver,
                    equalities,
                    mut conditions,
                    ..
                } = self.stated(&filters, from, position)?;
                let mut drawn = Vec::new();
                for condition in &conditions {
                    drawn.extend(self.drawn_condition(table, condition, &conditions)?);
                }
                conditions.extend(drawn);
                let witnessed = self.witnessed_sets(
                    select,
                    &filters,
                    table,
                    relation,
                    &equalities,
                    &conditions,
                )?;
                conditions.extend(witnessed);
                if let Some(membership) = self.lineage.membership(select, |column| {
                    match term(&resolver, column, relation, &equalities)? {
                        Term::Column(column) => Some(column),
                        Term::Parameter(_) => None,
                    }
                }) {
                    conditions.push(membership);
                }
                if !self
                    .body
                    .admits_every_caller(table, &conjunction(conditions))?
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// The filters of `select`, with the conditions `held` of the outer rows
    /// and the queries `owners` around it whose `WITH` holds items in reach.
    fn filters<'e>(
        &self,
        select: &'e Select,
        held: &'e [&'e Expr],
        owners: &[&'e Query],
    ) -> Result<Filters<'e>, LookupError> {
        let filter: Vec<&Expr> = select.selection.iter().flat_map(conjuncts).collect();
        let sources = self.sources(select, owners);
        let witnessed = filter
            .iter()
            .copied()
            .filter_map(semi_join)
            .chain(sources.iter().map(|source| source.body))
            .flat_map(|found| found.selection.iter().flat_map(conjuncts))
            .collect();
        let mut rejected = Vec::with_capacity(select.from.len());
        for from in &select.from {
            rejected.push(self.rejected(from, &filter)?);
        }
        let merges = self.merges(select, &sources)?;
        Ok(Filters {
            held,
            filter,
            witnessed,
            sources,
            from: &select.from,
            rejected,
            merges,
        })
    }

    /// What the filters of the relation at `position` of `from` state of it.
    fn stated<'r>(
        &'r self,
        filters: &'r Filters<'_>,
        from: &'r TableWithJoins,
        position: usize,
    ) -> Result<Stated<'r, 'q, 'a, DB>, LookupError> {
        let relation = relation_at(from, position);
        let item = filters
            .from
            .iter()
            .position(|item| ptr::eq(item, from))
            .expect("the relation is of a `FROM` item of the filtered `SELECT`");
        let resolver = Resolver {
            context: self.context,
            merges: &filters.merges,
            from,
            rejected: &filters.rejected[item],
            sources: &filters.sources,
        };
        let dropping = filters.dropping(&resolver, position);
        let equalities = Equalities::of(&resolver, &dropping, position)?;
        let mut conditions = Vec::new();
        let mut whole = true;
        for &(clause, conjunct) in &dropping {
            match renamed(conjunct, |reference| {
                term(&resolver, reference, relation, &equalities)
            }) {
                Some(stated) if self.body.confinement.reads_alike(conjunct)? => {
                    conditions.push(stated);
                }
                _ => whole &= !matches!(clause, Clause::Where),
            }
        }
        Ok(Stated {
            resolver,
            equalities,
            conditions,
            whole,
        })
    }

    /// The stored table `relation` reads every row of under its own column
    /// names, which a `WITH` item, a call, `ONLY` and a sample never are.
    fn stored(&self, relation: &TableFactor) -> Result<Option<&'a DB::Table>, LookupError> {
        let TableFactor::Table {
            name,
            alias,
            args: None,
            sample: None,
            inheritance: None | Some(TableInheritance::IncludeDescendants),
            ..
        } = relation
        else {
            return Ok(None);
        };
        if self.items.binding(name).is_some()
            || alias
                .as_ref()
                .is_some_and(|alias| !alias.columns.is_empty())
        {
            return Ok(None);
        }
        stored_table(self.body.confinement.database, name, self.path)
    }

    /// What `condition`, stated of the columns of `table`, tells of its row
    /// when it tests a column against the set of a function, besides the
    /// `conditions` of the row: one of the rows the function may draw the
    /// value from that the keys do not keep apart from the row meets its
    /// conditions that carry over to the row.
    fn drawn_condition(
        &self,
        table: &'a DB::Table,
        condition: &Expr,
        conditions: &[Expr],
    ) -> Result<Option<Expr>, LookupError> {
        let confinement = self.body.confinement;
        let database = confinement.database;
        let Some(([tested], members)) = membership(condition) else {
            return Ok(None);
        };
        let (Some(name), Expr::Function(call)) = (stored_name(tested), members.as_ref()) else {
            return Ok(None);
        };
        let (Some(column), Some(function)) = (
            column_named(database, table, &name)?,
            called(database, call)?,
        ) else {
            return Ok(None);
        };
        let arms = confinement.arms(function)?;
        if !arms.complete {
            return Ok(None);
        }
        let tested_kinds = discriminators(database, table, column, conditions)?;
        let mut alternatives = Vec::new();
        for arm in &arms.arms {
            let drawn = arm.drawn.as_ref();
            let source = drawn.column;
            let kinds = discriminators(database, drawn.table, source, &drawn.conditions)?;
            if apart(&tested_kinds, &kinds) {
                continue;
            }
            let carried = carried_conditions(database, drawn, source, table, column)?;
            if carried.is_empty() {
                return Ok(None);
            }
            alternatives.push(conjunction(carried));
        }
        Ok(alternatives
            .into_iter()
            .reduce(|left, right| Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOperator::Or,
                right: Box::new(right),
            }))
    }

    /// `column IN (SELECT helper())` for `relation`, a read of `table` its
    /// filters state `conditions` of, for each helper a policy of the table
    /// tests a column against, when a row of a table `select` reads meets
    /// every condition of an exhaustive arm of the helper over that table
    /// and the filters hold the column the arm returns equal to `column`.
    fn witnessed_sets(
        &self,
        select: &Select,
        filters: &Filters<'_>,
        table: &'a DB::Table,
        relation: &TableFactor,
        equalities: &Equalities<'_>,
        conditions: &[Expr],
    ) -> Result<Vec<Expr>, LookupError> {
        let sets = self.policy_sets(table)?;
        let mut witnessed = Vec::new();
        if sets.is_empty() {
            return Ok(witnessed);
        }
        for from in &select.from {
            for (position, joined) in relations(from).enumerate() {
                let same = ptr::eq(joined, relation);
                let Some(joined_table) = self.stored(joined)? else {
                    continue;
                };
                if !same && !present(from, position) {
                    continue;
                }
                let arms: Vec<(&Expr, &Drawn<'a, DB>)> = sets
                    .iter()
                    .flat_map(|(members, arms)| {
                        arms.arms
                            .iter()
                            .filter(|arm| arm.exhaustive && arm.drawn.table == joined_table)
                            .map(move |arm| (members, arm.drawn.as_ref()))
                    })
                    .collect();
                if arms.is_empty() {
                    continue;
                }
                let stated;
                let row = if same {
                    conditions
                } else {
                    stated = self.stated(filters, from, position)?;
                    stated.conditions.as_slice()
                };
                let clause = conjunction(row.to_vec());
                for (members, drawn) in arms {
                    if !self.implies_every(&clause, &drawn.conditions)? {
                        continue;
                    }
                    let column = if same {
                        Some(drawn.column.column_name())
                    } else {
                        equalities.of_relation(
                            &Node::Column {
                                factor: joined,
                                name: Cow::Borrowed(drawn.column.column_name()),
                            },
                            relation,
                        )
                    };
                    if let Some(column) = column
                        && let Some(membership) = set_membership(column, members)
                        && !witnessed.contains(&membership)
                    {
                        witnessed.push(membership);
                    }
                }
            }
        }
        Ok(witnessed)
    }

    /// Whether `clause` implies each of `conditions`.
    fn implies_every(&self, clause: &Expr, conditions: &[Expr]) -> Result<bool, LookupError> {
        for condition in conditions {
            if !clause_implies(
                &self.body,
                clause,
                &Condition::new(&self.body, condition),
                &[],
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The calls of `SECURITY DEFINER` functions the policies of `table` test
    /// a column against, as written, each with the rows it draws from, when
    /// the function runs as the owner this body runs as, so that it sees the
    /// rows the body reads, some arm of it is exhaustive, and a `STRICT`
    /// function gets no argument that may be `NULL`.
    fn policy_sets(&self, table: &'a DB::Table) -> Result<Vec<SetCall<'a, DB>>, LookupError> {
        let confinement = self.body.confinement;
        let database = confinement.database;
        let function = self.body.function;
        let mut sets = Vec::new();
        if function.security_mode() != FunctionSecurity::Definer {
            return Ok(sets);
        }
        let owner = function.owner(database)?;
        let mut calls: Vec<Function> = Vec::new();
        for policy in table.policies(database)? {
            let Some(using) = policy.using_clause(database)? else {
                continue;
            };
            let _ = visit_expressions(using.expression(), |expression| {
                if let Some((_, members)) = membership(expression)
                    && matches!(members.as_ref(), Expr::Function(written) if !calls.contains(written))
                    && let Expr::Function(written) = members.into_owned()
                {
                    calls.push(written);
                }
                ControlFlow::<()>::Continue(())
            });
        }
        for written in calls {
            let Some(helper) = called(database, &written)? else {
                continue;
            };
            if helper.security_mode() != FunctionSecurity::Definer
                || helper.owner(database)? != owner
                || (matches!(
                    helper.null_input_behavior(),
                    FunctionCalledOnNull::Strict | FunctionCalledOnNull::ReturnsNullOnNullInput
                ) && !arguments_set(&written, helper))
            {
                continue;
            }
            let arms = confinement.arms(helper)?;
            if arms.arms.iter().any(|arm| arm.exhaustive) {
                sets.push((Expr::Function(written), arms));
            }
        }
        Ok(sets)
    }

    /// Reads, standing in the `WITH` scopes of each, the rows each leaf of
    /// `drawing` in `query` draws its value from.
    fn draw_query(
        &mut self,
        query: &Query,
        drawing: &mut Drawing<'a, DB>,
    ) -> Result<(), LookupError> {
        self.items.enter(query);
        let drawn = query
            .with
            .iter()
            .flat_map(|with| &with.cte_tables)
            .try_for_each(|item| self.draw_query(&item.query, drawing))
            .and_then(|()| self.draw_body(&query.body, drawing));
        self.items.leave(query);
        drawn
    }

    /// [`Self::draw_query`] over the arms of `body`.
    fn draw_body(
        &mut self,
        body: &SetExpr,
        drawing: &mut Drawing<'a, DB>,
    ) -> Result<(), LookupError> {
        match body {
            SetExpr::Select(select) => {
                let address = ptr::from_ref(select.as_ref());
                if let Some(position) = drawing.leaves.iter().position(|leaf| *leaf == address) {
                    drawing.leaves.swap_remove(position);
                    self.draw_select(select, &mut drawing.arms)?;
                }
                Ok(())
            }
            SetExpr::SetOperation { left, right, .. } => {
                self.draw_body(left, drawing)?;
                self.draw_body(right, drawing)
            }
            SetExpr::Query(query) => self.draw_query(query, drawing),
            _ => Ok(()),
        }
    }

    /// Adds to `arms` the row of a stored table whose column the leaf
    /// `select` returns, with what its filters state of the row, or the rows
    /// of the function whose call it returns the value of, and marks `arms`
    /// incomplete for any other leaf.
    fn draw_select(&self, select: &Select, arms: &mut Arms<'a, DB>) -> Result<(), LookupError> {
        let projected = carried_column(select).map(|(projected, _)| projected);
        let factor = projected
            .and_then(|projected| self.context.reference(projected).ok().flatten())
            .and_then(|(_, binding)| binding.entry())
            .map(|entry| ptr::from_ref(entry.factor()));
        let found = factor.and_then(|factor| {
            select.from.iter().find_map(|from| {
                relations(from)
                    .position(|relation| ptr::eq(relation, factor))
                    .map(|position| (from, position))
            })
        });
        if let (Some(projected), Some((from, position))) = (projected, found) {
            let relation = relation_at(from, position);
            if let Some(table) = self.stored(relation)? {
                let filters = self.filters(select, &[], &[])?;
                let Stated {
                    resolver,
                    equalities,
                    mut conditions,
                    whole: stated,
                } = self.stated(&filters, from, position)?;
                if let Some(Term::Column(name)) = term(&resolver, projected, relation, &equalities)
                    && let Some(column) =
                        column_named(self.body.confinement.database, table, &name)?
                {
                    let written = conditions.len();
                    conditions.retain(|condition| !reads_parameter(condition));
                    arms.arms.push(Arm {
                        exhaustive: stated
                            && conditions.len() == written
                            && select.from.len() == 1
                            && from.joins.is_empty(),
                        drawn: Rc::new(Drawn {
                            table,
                            column,
                            conditions,
                        }),
                    });
                    return Ok(());
                }
            } else if let Some(call) = whole_call(relation)
                && let Some(function) = called(self.body.confinement.database, call)?
            {
                let called = self.body.confinement.arms(function)?;
                arms.complete &= called.complete;
                arms.arms.extend(called.arms.iter().map(|arm| Arm {
                    drawn: Rc::clone(&arm.drawn),
                    exhaustive: false,
                }));
                return Ok(());
            }
        }
        arms.complete = false;
        Ok(())
    }

    /// The columns the `USING` joins of `select` merge.
    fn merges(&self, select: &Select, sources: &[Source<'_>]) -> Result<Vec<Merge>, LookupError> {
        let mut merges: Vec<Merge> = Vec::new();
        for from in &select.from {
            let natural = from.joins.iter().any(|join| {
                matches!(
                    join_constraint(&join.join_operator),
                    Some(JoinConstraint::Natural)
                )
            });
            for (index, join) in from.joins.iter().enumerate() {
                let Some(JoinConstraint::Using(names) | JoinConstraint::UsingAlias(names, _)) =
                    join_constraint(&join.join_operator)
                else {
                    continue;
                };
                for name in names
                    .iter()
                    .filter_map(|name| name.0.last().and_then(ObjectNamePart::as_ident))
                {
                    let right = self.identity_at(from, index + 1, name, sources)?;
                    let normalized = normalize_identifier(&name.value, name.quote_style.is_some());
                    if let Some(merge) = merges
                        .iter_mut()
                        .find(|merge| ptr::eq(merge.from, from) && merge.name == normalized)
                    {
                        merge.last = index;
                        merge.sides.push(index + 1);
                        if merge.identity != right {
                            merge.identity = None;
                        }
                    } else {
                        let left = self.left_side(from, index, name, sources)?;
                        merges.push(Merge {
                            from,
                            name: normalized.into_owned(),
                            last: index,
                            sides: left
                                .iter()
                                .map(|(side, _)| *side)
                                .chain([index + 1])
                                .collect(),
                            identity: left.and_then(|(_, identity)| {
                                (!natural && right.as_ref() == Some(&identity)).then_some(identity)
                            }),
                        });
                    }
                }
            }
        }
        Ok(merges)
    }

    /// For each join of `from`, whether a condition of `filter` cannot be
    /// true on a row it extends with nulls, so that it drops the rows of its
    /// outer join that find no match.
    fn rejected(&self, from: &TableWithJoins, filter: &[&Expr]) -> Result<Vec<bool>, LookupError> {
        let database = self.body.confinement.database;
        let mut rejected = Vec::with_capacity(from.joins.len());
        for (index, join) in from.joins.iter().enumerate() {
            let extended = match join.join_operator {
                JoinOperator::Left(_) | JoinOperator::LeftOuter(_) => index + 1..index + 2,
                JoinOperator::Right(_) | JoinOperator::RightOuter(_) => 0..index + 1,
                _ => {
                    rejected.push(false);
                    continue;
                }
            };
            let bound = |expression: &Expr| {
                Ok(self
                    .context
                    .reference(expression)?
                    .and_then(|(_, binding)| binding.entry())
                    .is_some_and(|entry| {
                        extended
                            .clone()
                            .any(|position| ptr::eq(entry.factor(), relation_at(from, position)))
                    }))
            };
            let mut found = false;
            for condition in filter {
                if rejects_null(condition, &bound, database, self.context)? {
                    found = true;
                    break;
                }
            }
            rejected.push(found);
        }
        Ok(rejected)
    }

    /// The relations of the `FROM` items of `select` that read a `WITH` item
    /// or a subquery whose body yields each of its rows from a row passing
    /// its `WHERE`. A body two of them read is left out, since their rows
    /// come from different rows of it.
    fn sources<'s>(&self, select: &'s Select, owners: &[&'s Query]) -> Vec<Source<'s>> {
        let mut sources: Vec<Source<'_>> = Vec::new();
        for from in &select.from {
            for relation in relations(from) {
                let read = match relation {
                    TableFactor::Derived {
                        subquery, alias, ..
                    } => Some((subquery.as_ref(), &[][..], alias)),
                    TableFactor::Table {
                        name,
                        alias,
                        args: None,
                        ..
                    } => self
                        .items
                        .binding(name)
                        .filter(|binding| !binding.in_own_body)
                        .and_then(|binding| {
                            let owner = owners
                                .iter()
                                .find(|owner| ptr::eq(**owner, binding.owner))?;
                            let item = &owner.with.as_ref()?.cte_tables[binding.item];
                            Some((item.query.as_ref(), item.alias.columns.as_slice(), alias))
                        }),
                    _ => None,
                };
                if let Some((query, renamed, alias)) = read
                    && let Some(body) = witnessed(query)
                {
                    sources.push(Source {
                        relation,
                        body,
                        aliased: alias.as_ref().map_or(&[], |alias| alias.columns.as_slice()),
                        renamed,
                    });
                }
            }
        }
        sources
            .iter()
            .filter(|source| {
                sources
                    .iter()
                    .filter(|other| ptr::eq(other.body, source.body))
                    .count()
                    == 1
            })
            .copied()
            .collect()
    }

    /// The position of the first relation of `from`, up to the one at
    /// `index`, with a column named `name`, with what `=` compares its values
    /// by, `None` when any of those relations is no stored table. PostgreSQL
    /// refuses a `USING` name more than one relation before the join holds.
    fn left_side(
        &self,
        from: &TableWithJoins,
        index: usize,
        name: &Ident,
        sources: &[Source<'_>],
    ) -> Result<Option<(usize, Identity)>, LookupError> {
        let mut found = None;
        for position in 0..=index {
            match self.column_at(from, position, name, sources)? {
                Side::Unknown => return Ok(None),
                Side::Column(column) if found.is_none() => found = Some((position, column)),
                Side::Column(_) | Side::Absent => {}
            }
        }
        found.map_or(Ok(None), |(position, column)| {
            Ok(identity(column, self.body.confinement.database)?
                .map(|identity| (position, identity)))
        })
    }

    /// What `=` compares the values of the column named `name` of the
    /// relation at `position` of `from` by, when it reaches a stored column.
    fn identity_at(
        &self,
        from: &TableWithJoins,
        position: usize,
        name: &Ident,
        sources: &[Source<'_>],
    ) -> Result<Option<Identity>, LookupError> {
        match self.column_at(from, position, name, sources)? {
            Side::Column(column) => identity(column, self.body.confinement.database),
            Side::Unknown | Side::Absent => Ok(None),
        }
    }

    /// The column named `name` of the relation at `position` of `from`, for
    /// a source the stored column its body projects under the name.
    fn column_at(
        &self,
        from: &TableWithJoins,
        position: usize,
        name: &Ident,
        sources: &[Source<'_>],
    ) -> Result<Side<'c, DB>, LookupError> {
        let database = self.body.confinement.database;
        let factor = relation_at(from, position);
        if let Some(source) = sources
            .iter()
            .find(|source| ptr::eq(source.relation, factor))
        {
            let normalized = normalize_identifier(&name.value, name.quote_style.is_some());
            return Ok(match source.column(self.context, &normalized) {
                Some((ColumnDefinition::Base { column, .. }, _)) => Side::Column(column),
                _ => Side::Unknown,
            });
        }
        let TableFactor::Table {
            name: relation,
            alias,
            args: None,
            ..
        } = factor
        else {
            return Ok(Side::Unknown);
        };
        let stored = if self.items.binding(relation).is_none() {
            stored_table(database, relation, self.path)?
        } else {
            None
        };
        let Some(table) = stored else {
            return Ok(Side::Unknown);
        };
        Ok(
            stored_column(database, table, alias.as_ref(), name)?
                .map_or(Side::Absent, Side::Column),
        )
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
                            Read::Unconfined
                        } else {
                            Read::Protected(table)
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
        for relation in relations(joined) {
            if !matches!(self.read(relation)?, Read::Open) {
                return Ok(Read::Unconfined);
            }
        }
        Ok(Read::Open)
    }
}

/// Records, for each query nested in a condition of a `WHERE` of a `SELECT`
/// of `body`, outside nested queries, the other conditions of that `WHERE`.
fn conditions_beside<'q>(body: &'q SetExpr, beside: &mut Vec<(*const Query, Vec<&'q Expr>)>) {
    match body {
        SetExpr::Select(select) => {
            let filter: Vec<&Expr> = select.selection.iter().flat_map(conjuncts).collect();
            for (index, condition) in filter.iter().enumerate() {
                let _ = nested_queries(*condition, 0, |nested| {
                    let others = filter
                        .iter()
                        .enumerate()
                        .filter(|(other, _)| *other != index)
                        .map(|(_, other)| *other);
                    beside.push((ptr::from_ref(nested), others.collect()));
                    ControlFlow::<()>::Continue(())
                });
            }
        }
        SetExpr::SetOperation { left, right, .. } => {
            conditions_beside(left, beside);
            conditions_beside(right, beside);
        }
        _ => {}
    }
}

/// Hands `each` every query of `node` that `depth` of its queries enclose,
/// until `each` breaks.
fn nested_queries<N: Visit + ?Sized, B>(
    node: &N,
    depth: usize,
    each: impl FnMut(&Query) -> ControlFlow<B>,
) -> ControlFlow<B> {
    /// The walk's state, `entered` counting the queries it is inside.
    struct Nested<F> {
        depth: usize,
        entered: usize,
        each: F,
    }

    impl<B, F: FnMut(&Query) -> ControlFlow<B>> Visitor for Nested<F> {
        type Break = B;

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<B> {
            let outcome = if self.entered == self.depth {
                (self.each)(query)
            } else {
                ControlFlow::Continue(())
            };
            self.entered += 1;
            outcome
        }

        fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<B> {
            self.entered -= 1;
            ControlFlow::Continue(())
        }
    }

    walk(
        node,
        &mut Nested {
            depth,
            entered: 0,
            each,
        },
    )
}

/// The columns the column equalities among some filters hold equal, where
/// `=` holds only between identical values.
#[derive(Default)]
struct Equalities<'r> {
    /// Each column an equality names.
    columns: Vec<Node<'r>>,
    /// For each column, the index of one of its class nearer the column
    /// heading the class, or its own for the head.
    parents: Vec<usize>,
}

/// A column an equality names.
#[derive(PartialEq, Eq)]
enum Node<'r> {
    /// The column of this name of a `FROM` item.
    Column {
        factor: *const TableFactor,
        name: Cow<'r, str>,
    },
    /// The column of this name the `USING` joins of a `FROM` item merge.
    Merged {
        from: *const TableWithJoins,
        name: &'r str,
    },
}

impl<'r> Node<'r> {
    /// The column named `name` of the relation at `position` of `from`.
    fn at(from: &TableWithJoins, position: usize, name: &'r str) -> Self {
        Self::Column {
            factor: relation_at(from, position),
            name: Cow::Borrowed(name),
        }
    }
}

impl<'r> Equalities<'r> {
    /// The classes the conditions `a.x = b.y` and `a.x IN (SELECT b.y …)`
    /// among `filters` form, with those the `USING` joins `resolver` reads
    /// form for the relation at `position` of its `FROM` item. A `USING`
    /// join holds the merged column equal to the column of each relation it
    /// merges whose row is present, and the column of its first join equal
    /// on both sides wherever that join drops rows of the relation.
    fn of<DB: DatabaseLike>(
        resolver: &Resolver<'r, '_, '_, DB>,
        filters: &[(Clause, &Expr)],
        position: usize,
    ) -> Result<Self, LookupError> {
        let mut equalities = Self::default();
        for &(_, filter) in filters {
            let (left, right) = match unnested(filter) {
                Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Eq,
                    right,
                } => (left.as_ref(), right.as_ref()),
                Expr::In { expr, .. } => match semi_join(filter).and_then(carried_column) {
                    Some((projected, _)) => (expr.as_ref(), projected),
                    None => continue,
                },
                _ => continue,
            };
            if let (Some((left, kind)), Some((right, other))) =
                (resolver.equated(left)?, resolver.equated(right)?)
                && kind == other
            {
                equalities.link(left, right);
            }
        }
        let from = resolver.from;
        for merge in resolver
            .merges
            .iter()
            .filter(|merge| ptr::eq(merge.from, from) && merge.identity.is_some())
        {
            if merge.sides.contains(&position) {
                equalities.link(merge.node(), Node::at(from, position, &merge.name));
            }
            for (index, &side) in merge.sides.iter().enumerate().skip(1) {
                if resolver.dropping(side - 1, position).is_some()
                    && merge.sides[1..index]
                        .iter()
                        .all(|earlier| resolver.keeps_left(earlier - 1))
                {
                    equalities.link(
                        resolver.column_node(merge.sides[0], &merge.name),
                        resolver.column_node(side, &merge.name),
                    );
                }
            }
        }
        Ok(equalities)
    }

    /// Joins the classes of `left` and `right`.
    fn link(&mut self, left: Node<'r>, right: Node<'r>) {
        let left = self.joined(left);
        let right = self.joined(right);
        self.parents[left] = right;
    }

    /// The head of the class of `column`, which forms a class of its own
    /// when no equality named it yet.
    fn joined(&mut self, column: Node<'r>) -> usize {
        let index = self.position(&column).unwrap_or_else(|| {
            self.parents.push(self.columns.len());
            self.columns.push(column);
            self.columns.len() - 1
        });
        self.head(index)
    }

    /// The index of `column`.
    fn position(&self, column: &Node<'_>) -> Option<usize> {
        self.columns.iter().position(|named| named == column)
    }

    /// The head of the class of the column at `index`.
    fn head(&self, mut index: usize) -> usize {
        while self.parents[index] != index {
            index = self.parents[index];
        }
        index
    }

    /// The name of a column of `relation` held equal to `column`.
    fn of_relation(&self, column: &Node<'_>, relation: &TableFactor) -> Option<&str> {
        let class = self.head(self.position(column)?);
        self.columns
            .iter()
            .enumerate()
            .find_map(|(index, named)| match named {
                Node::Column { factor, name }
                    if ptr::eq(*factor, relation) && self.head(index) == class =>
                {
                    Some(name.as_ref())
                }
                _ => None,
            })
    }
}

/// A column the `USING` joins of one `FROM` item merge.
struct Merge {
    from: *const TableWithJoins,
    /// The name the joins merge.
    name: String,
    /// The index of the last join merging the name.
    last: usize,
    /// The positions of the relations the joins merge the column of, the
    /// one before the first join leading.
    sides: Vec<usize>,
    /// What `=` compares the merged values by, when every relation the
    /// joins merge is a stored table whose column compares by it and no
    /// `NATURAL` join merges more.
    identity: Option<Identity>,
}

impl Merge {
    /// The merged column.
    fn node(&self) -> Node<'_> {
        Node::Merged {
            from: self.from,
            name: &self.name,
        }
    }
}

/// Where a filter of a read stands.
#[derive(Clone, Copy)]
enum Clause {
    /// A condition of the outer rows.
    Held,
    /// The `WHERE` of the `SELECT`.
    Where,
    /// The `WHERE` of a query an `EXISTS` or `IN` of that `WHERE` finds a
    /// row of, or of the body of a `WITH` item or subquery of its `FROM`.
    Witness,
    /// An `ON` condition of the `FROM` item.
    On,
}

/// The filters of a `SELECT`, with the conditions held of its outer rows.
struct Filters<'e> {
    held: &'e [&'e Expr],
    /// The conjuncts of the `WHERE`.
    filter: Vec<&'e Expr>,
    /// The conjuncts of the `WHERE` of each query an `EXISTS` or `IN` of
    /// the `WHERE` finds a row of, and of the body each relation of
    /// `sources` reads.
    witnessed: Vec<&'e Expr>,
    /// The relations of the `SELECT` reading a `WITH` item or subquery
    /// every row of which comes from a row of its body.
    sources: Vec<Source<'e>>,
    /// The `FROM` items of the `SELECT`.
    from: &'e [TableWithJoins],
    /// For each join of each item of `from`, whether the `WHERE` drops the
    /// rows it extends with nulls.
    rejected: Vec<Vec<bool>>,
    /// The columns the `USING` joins of the `SELECT` merge.
    merges: Vec<Merge>,
}

impl Filters<'_> {
    /// The filters that drop rows of the relation at `position` of the
    /// `FROM` item `resolver` resolves, each with where it stands.
    fn dropping<'f, DB: DatabaseLike>(
        &'f self,
        resolver: &Resolver<'f, '_, '_, DB>,
        position: usize,
    ) -> Vec<(Clause, &'f Expr)> {
        self.held
            .iter()
            .map(|condition| (Clause::Held, *condition))
            .chain(
                self.filter
                    .iter()
                    .map(|condition| (Clause::Where, *condition)),
            )
            .chain(
                self.witnessed
                    .iter()
                    .map(|condition| (Clause::Witness, *condition)),
            )
            .chain(
                resolver
                    .joined_filter(position)
                    .map(|condition| (Clause::On, condition)),
            )
            .collect()
    }
}

/// What the filters of one relation of a `FROM` item state of its row.
struct Stated<'r, 'q, 'a, DB: DatabaseLike> {
    resolver: Resolver<'r, 'q, 'a, DB>,
    equalities: Equalities<'r>,
    /// The filters, over the stored names of the relation's columns, that
    /// evaluate alike for every role.
    conditions: Vec<Expr>,
    /// Whether `conditions` states every conjunct of the `WHERE`.
    whole: bool,
}

/// The call of a function a policy tests a column against, as written,
/// with the rows the function draws from.
type SetCall<'a, DB> = (Expr, Rc<Arms<'a, DB>>);

/// A function, by its address, with the rows it draws from.
type ReadArms<'a, DB> = (*const <DB as DatabaseLike>::Function, Rc<Arms<'a, DB>>);

/// Resolves the columns the filters of the relations of one `FROM` item
/// name.
struct Resolver<'r, 'q, 'a, DB: DatabaseLike> {
    context: &'r ExpressionContext<'q, 'a, DB>,
    /// The columns the `USING` joins of the `SELECT` merge.
    merges: &'r [Merge],
    from: &'r TableWithJoins,
    /// For each join of `from`, whether the `WHERE` drops the rows it
    /// extends with nulls.
    rejected: &'r [bool],
    /// The relations of the `SELECT` reading a `WITH` item or subquery
    /// every row of which comes from a row of its body.
    sources: &'r [Source<'r>],
}

impl<'r, 'q, 'a, DB: DatabaseLike> Resolver<'r, 'q, 'a, DB> {
    /// The definition and binding of the column `reference` names. A column
    /// a source projects from a column reference is that column of the row
    /// its `SELECT` yields it from.
    fn reference(
        &self,
        reference: &Expr,
    ) -> Option<(ColumnDefinition<'r, 'q, 'a, DB>, ColumnBinding<'r>)> {
        let (definition, binding) = self.context.reference(reference).ok()??;
        if let Some(entry) = binding.entry()
            && let Some(source) = self
                .sources
                .iter()
                .find(|source| ptr::eq(source.relation, entry.factor()))
            && let Some(projected) = projection_at(source.body, entry.ordinal())
            && let Some(resolved) = self.context.reference(projected).ok().flatten()
        {
            return Some(resolved);
        }
        Some((definition, binding))
    }

    /// The conjuncts of the `ON` conditions of the `FROM` item that drop
    /// rows of its relation at `position`, counted from zero.
    fn joined_filter(&self, position: usize) -> impl Iterator<Item = &'r Expr> + '_ {
        (0..self.from.joins.len())
            .filter_map(move |index| match self.dropping(index, position) {
                Some(JoinConstraint::On(condition)) => Some(condition),
                _ => None,
            })
            .flat_map(conjuncts)
    }

    /// The constraint of the join at `index` of the `FROM` item when it
    /// drops rows of its relation at `position`. An inner join drops rows of
    /// the relations up to the one it joins, a left join of the one it joins
    /// and a right join of those before it. An outer join whose rows
    /// extended with nulls the `WHERE` drops acts as an inner join.
    fn dropping(&self, index: usize, position: usize) -> Option<&'r JoinConstraint> {
        let joined = index + 1;
        match &self.from.joins[index].join_operator {
            JoinOperator::Join(constraint) | JoinOperator::Inner(constraint)
                if position <= joined =>
            {
                Some(constraint)
            }
            JoinOperator::Left(constraint)
            | JoinOperator::LeftOuter(constraint)
            | JoinOperator::Right(constraint)
            | JoinOperator::RightOuter(constraint)
                if self.rejected[index] && position <= joined =>
            {
                Some(constraint)
            }
            JoinOperator::Left(constraint) | JoinOperator::LeftOuter(constraint)
                if position == joined =>
            {
                Some(constraint)
            }
            JoinOperator::Right(constraint) | JoinOperator::RightOuter(constraint)
                if position < joined =>
            {
                Some(constraint)
            }
            _ => None,
        }
    }

    /// Whether the join at `index` of the `FROM` item yields, on each row,
    /// the value its left side holds in a column a `USING` merges.
    fn keeps_left(&self, index: usize) -> bool {
        match self.from.joins[index].join_operator {
            JoinOperator::Join(_)
            | JoinOperator::Inner(_)
            | JoinOperator::Left(_)
            | JoinOperator::LeftOuter(_) => true,
            JoinOperator::Right(_) | JoinOperator::RightOuter(_) => self.rejected[index],
            _ => false,
        }
    }

    /// The column named `name` of the relation at `position` of the `FROM`
    /// item, for a source the column of the row of its body it comes from.
    fn column_node(&self, position: usize, name: &'r str) -> Node<'r> {
        let relation = relation_at(self.from, position);
        self.sources
            .iter()
            .find(|source| ptr::eq(source.relation, relation))
            .and_then(|source| source.column(self.context, name))
            .and_then(|(_, binding)| self.node(&binding))
            .unwrap_or_else(|| Node::at(self.from, position, name))
    }

    /// The column a `USING` join of the `SELECT` merged that `binding`
    /// reached.
    fn merge(&self, binding: &ColumnBinding<'_>) -> Option<&'r Merge> {
        let found = binding.merge()?;
        let (name, quoted) = binding.exposed()?;
        let name = normalize_identifier(name, quoted);
        self.merges.iter().find(|merge| {
            ptr::eq(merge.from, found.from()) && merge.last == found.join() && merge.name == name
        })
    }

    /// The column `binding` reached.
    fn node(&self, binding: &ColumnBinding<'r>) -> Option<Node<'r>> {
        if let Some(merge) = self.merge(binding) {
            return Some(merge.node());
        }
        let (entry, (name, quoted)) = (binding.entry()?, binding.exposed()?);
        Some(Node::Column {
            factor: entry.factor(),
            name: normalize_identifier(name, quoted),
        })
    }

    /// The column `side` names, with what `=` compares its values by, or
    /// `None` when two equal values of it may differ.
    fn equated(&self, side: &Expr) -> Result<Option<(Node<'r>, Cow<'r, Identity>)>, LookupError> {
        let Some((definition, binding)) = self.reference(unnested(side)) else {
            return Ok(None);
        };
        let identity = match (self.merge(&binding), definition) {
            (Some(merge), _) => merge.identity.as_ref().map(Cow::Borrowed),
            (
                None,
                ColumnDefinition::Base {
                    column, database, ..
                },
            ) => identity(column, database)?.map(Cow::Owned),
            _ => None,
        };
        Ok(identity
            .zip(self.node(&binding))
            .map(|(identity, node)| (node, identity)))
    }
}

/// What `=` compares the values of a column by, when two values it holds
/// equal are the same value.
#[derive(Clone, PartialEq, Eq)]
enum Identity {
    /// A builtin type of this family.
    Family(ScalarFamily),
    /// The enum type of this name.
    Enumeration(String),
}

/// What `=` compares the values of `column` by, or `None` when two equal
/// values of it may differ.
fn identity<DB: DatabaseLike>(
    column: &DB::Column,
    database: &DB,
) -> Result<Option<Identity>, LookupError> {
    let declared = column.data_type(database);
    let data_type = declared.base_type(database).unwrap_or(declared);
    Ok(if data_type.array_element(database).is_some() {
        None
    } else if let Some(enumeration) = data_type.enumeration(database) {
        (enumeration.kind() == EnumerationKind::Enum)
            .then(|| Identity::Enumeration(data_type.name(database).into_owned()))
    } else {
        match data_type.scalar_family(database) {
            Some(
                family @ (ScalarFamily::Bool
                | ScalarFamily::Int
                | ScalarFamily::Uuid
                | ScalarFamily::Date
                | ScalarFamily::Timestamp
                | ScalarFamily::TimestampTz),
            ) => Some(Identity::Family(family)),
            Some(ScalarFamily::String)
                if declared.domain(database).is_none()
                    && !data_type.normalized_name(database).starts_with("CHAR")
                    && matches!(
                        column.collation(database)?,
                        ColumnCollation::DatabaseDefault
                    ) =>
            {
                Some(Identity::Family(ScalarFamily::String))
            }
            _ => None,
        }
    })
}

/// The `SELECT`s of a function body each of whose rows reaches the
/// function's result holding the one column it projects, unchanged.
#[derive(Default)]
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
        Some(in_set(&own(projected)?, template.clone()))
    }
}

/// `"column" IN query`.
fn in_set(column: &str, query: Box<Query>) -> Expr {
    Expr::In {
        expr: Box::new(Expr::Identifier(Ident::with_quote('"', column))),
        target: InTarget::Subquery(query),
        negated: false,
        global: false,
    }
}

/// `"column" IN (SELECT members)`, testing `column` against the set
/// `members` yields.
fn set_membership(column: &str, members: &Expr) -> Option<Expr> {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(&format!("SELECT {members}"))
        .and_then(|mut parser| parser.parse_query())
        .ok()
        .map(|query| in_set(column, query))
}

/// The one function of the schema `call` reaches.
fn called<'db, 'c, DB: DatabaseLike>(
    database: &'db DB,
    call: impl Into<WrittenCall<'c>>,
) -> Result<Option<&'db DB::Function>, LookupError> {
    let mut reached = database.functions_reached_by(call, IdentifierCase::Folded)?;
    Ok(match (reached.next(), reached.next()) {
        (Some(function), None) => Some(function),
        _ => None,
    })
}

/// The column of `table` whose stored name is `name`.
fn column_named<'db, DB: DatabaseLike>(
    database: &'db DB,
    table: &'db DB::Table,
    name: &str,
) -> Result<Option<&'db DB::Column>, LookupError> {
    table.column(name, database, IdentifierCase::AsWritten)
}

/// Whether `condition` reads an input parameter, written `$n`.
fn reads_parameter(condition: &Expr) -> bool {
    visit_expressions(condition, |expression| {
        if let Expr::Value(value) = expression
            && matches!(value.value, Value::Placeholder(_))
        {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .is_break()
}

/// Whether `=` holds between `left` and `right` only for identical values,
/// compared alike for both.
fn same_identity<DB: DatabaseLike>(
    database: &DB,
    left: &DB::Column,
    right: &DB::Column,
) -> Result<bool, LookupError> {
    let left = identity(left, database)?;
    Ok(left.is_some() && left == identity(right, database)?)
}

/// Whether every row of the table holding `foreign_key` with a value in
/// `column` references a row at the end of every statement.
fn binds<DB: DatabaseLike>(
    database: &DB,
    foreign_key: &DB::ForeignKey,
    column: &DB::Column,
) -> Result<bool, LookupError> {
    Ok(
        foreign_key.deferral(database) == ConstraintDeferral::NotDeferrable
            && foreign_key.is_validated(database)?
            && checked_whenever_set(database, foreign_key, column)?
            && no_inheritors(database, foreign_key.host_table(database))?,
    )
}

/// Whether `column` alone is a unique key of `table`.
fn unique_alone<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    column: &DB::Column,
) -> Result<bool, LookupError> {
    Ok(no_inheritors(database, table)?
        && equality_keys(database, table)?
            .iter()
            .any(|key| matches!(key.as_slice(), [only] if *only == column)))
}

/// Whether no table inherits from `table`, whose keys and constraints would
/// leave the rows of such a table unchecked although a read of `table`
/// yields them.
fn no_inheritors<DB: DatabaseLike>(database: &DB, table: &DB::Table) -> Result<bool, LookupError> {
    Ok(table.inheritors(database)?.next().is_none())
}

/// The conditions of `drawn` that hold of the row of `table` whose `column`
/// equals the `source` column of the row drawn, over the columns of `table`.
/// The value drawn carries the conditions on `source` when `=` compares both
/// columns by the same identity. When `column` is unique in `table`, a
/// foreign key of the drawn row that binds it maps `source` onto `column`
/// carries those on each column it maps onto one compared alike.
fn carried_conditions<DB: DatabaseLike>(
    database: &DB,
    drawn: &Drawn<'_, DB>,
    source: &DB::Column,
    table: &DB::Table,
    column: &DB::Column,
) -> Result<Vec<Expr>, LookupError> {
    let mut renames: Vec<(&str, &str)> = Vec::new();
    if same_identity(database, source, column)? {
        renames.push((source.column_name(), column.column_name()));
    }
    if unique_alone(database, table, column)? {
        for foreign_key in drawn.table.foreign_keys(database)? {
            if !ptr::eq(foreign_key.referenced_table(database)?, table)
                || !binds(database, foreign_key, source)?
            {
                continue;
            }
            let pairs = key_pairs(database, foreign_key)?;
            if !pairs
                .iter()
                .any(|(host, referenced)| *host == source && *referenced == column)
            {
                continue;
            }
            for (host, referenced) in pairs {
                if same_identity(database, host, referenced)? {
                    renames.push((host.column_name(), referenced.column_name()));
                }
            }
        }
    }
    Ok(drawn
        .conditions
        .iter()
        .filter_map(|condition| {
            renamed(condition, |reference| {
                let name = stored_name(reference)?;
                renames
                    .iter()
                    .find(|(from, _)| *from == name)
                    .map(|(_, to)| Term::Column((*to).to_owned()))
            })
        })
        .collect())
}

/// The values a column of a row is pinned to, on a table whose column
/// holding the value followed is unique, so that every row of the table
/// holding that value pins them.
struct Pinned<'a, DB: DatabaseLike> {
    table: &'a DB::Table,
    /// The stored name of the column holding the value followed.
    keyed: String,
    /// The stored name of the pinned column.
    column: String,
    values: Vec<String>,
}

/// What pins the row holding the value of `column` of a row of `table`
/// meeting `conditions`. Following each foreign key that binds the column
/// holding the value, it reaches the one row each key references. Each row
/// reached pins its columns generated as one literal and the columns a key
/// fills from a column pinned before, the first also those `conditions`
/// fix, counting only enum and text columns compared by identity.
fn discriminators<'a, DB: DatabaseLike>(
    database: &'a DB,
    table: &'a DB::Table,
    column: &'a DB::Column,
    conditions: &[Expr],
) -> Result<Vec<Pinned<'a, DB>>, LookupError> {
    let mut fixed = Vec::new();
    for (name, values) in conditions.iter().filter_map(fixed_by) {
        if let Some(column) = column_named(database, table, &name)?
            && let Some(pinned) = pin(database, column, &values)?
        {
            fixed.push(pinned);
        }
    }
    let mut pending = vec![(table, column, fixed)];
    let mut visited: Vec<&DB::Column> = Vec::new();
    let mut pinned = Vec::new();
    while let Some((table, column, mut fixed)) = pending.pop() {
        if visited.contains(&column) {
            continue;
        }
        visited.push(column);
        for generated in table.columns(database)? {
            if let Some(expression) = generated.generation_expression() {
                fixed.extend(pin(database, generated, &[expression])?);
            }
        }
        if unique_alone(database, table, column)? {
            pinned.extend(fixed.iter().map(|(fixed_column, values)| Pinned {
                table,
                keyed: column.column_name().to_owned(),
                column: fixed_column.column_name().to_owned(),
                values: values.clone(),
            }));
        }
        for foreign_key in column.foreign_keys(database)? {
            if !binds(database, foreign_key, column)? {
                continue;
            }
            let pairs = key_pairs(database, foreign_key)?;
            let mut next = None;
            let mut carried = Vec::new();
            for &(host, referenced) in &pairs {
                if host == column {
                    next = Some(referenced);
                }
                if let Some((_, values)) = fixed.iter().find(|(fixed, _)| *fixed == host)
                    && same_identity(database, host, referenced)?
                {
                    carried.push((referenced, values.clone()));
                }
            }
            let referenced_table = foreign_key.referenced_table(database)?;
            pending.extend(next.map(|next| (referenced_table, next, carried)));
        }
    }
    Ok(pinned)
}

/// A column with the texts its row may hold in it.
type Fixed<'a, DB> = (&'a <DB as DatabaseLike>::Column, Vec<String>);

/// `column` with the texts of `values`, when it is an enum or a text column
/// `=` compares by identity and each value a string literal it holds as
/// written.
fn pin<'a, DB: DatabaseLike>(
    database: &DB,
    column: &'a DB::Column,
    values: &[&Expr],
) -> Result<Option<Fixed<'a, DB>>, LookupError> {
    let enumeration = match identity(column, database)? {
        Some(Identity::Enumeration(_)) => true,
        Some(Identity::Family(ScalarFamily::String)) => false,
        _ => return Ok(None),
    };
    Ok(values
        .iter()
        .map(|value| kept_literal(value, enumeration).map(str::to_owned))
        .collect::<Option<Vec<String>>>()
        .map(|values| (column, values)))
}

/// The string literal `expression` writes under parentheses and casts that
/// keep its text: to `text`, to `varchar` of no length, and, for an enum
/// column, to a type of no modifiers, which `=` accepts only as the enum.
fn kept_literal(mut expression: &Expr, enumeration: bool) -> Option<&str> {
    loop {
        match expression {
            Expr::Nested(inner) => expression = inner,
            Expr::Cast {
                expr, data_type, ..
            } if matches!(
                data_type,
                DataType::Text | DataType::Varchar(None) | DataType::CharacterVarying(None)
            ) || (enumeration
                && matches!(data_type, DataType::Custom(_, modifiers) if modifiers.is_empty())) =>
            {
                expression = expr;
            }
            Expr::Value(value) => return string_value(&value.value),
            _ => return None,
        }
    }
}

/// The column `condition` fixes with `=` or `IN` to values reading no
/// column, with the values.
fn fixed_by(condition: &Expr) -> Option<(Cow<'_, str>, Vec<&Expr>)> {
    match unwrapped(condition) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => [(left, right), (right, left)]
            .into_iter()
            .find_map(|(column, value)| Some((stored_name(column)?, vec![value.as_ref()]))),
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated: false,
            ..
        } => Some((stored_name(expr)?, list.iter().collect())),
        _ => None,
    }
}

/// Whether `call` passes `function` a literal other than `NULL` for each of
/// its input parameters, leaving none to a default.
fn arguments_set<F: FunctionLike>(call: &Function, function: &F) -> bool {
    let inputs = function
        .argument_modes()
        .filter(|mode| !matches!(mode, ArgMode::Out))
        .count();
    matches!(&call.args, FunctionArguments::List(list) if list.args.len() == inputs
    && list.args.iter().all(|argument| {
        let (FunctionArg::Unnamed(argument)
        | FunctionArg::Named { arg: argument, .. }
        | FunctionArg::ExprNamed { arg: argument, .. }) = argument;
        matches!(argument, FunctionArgExpr::Expr(value)
            if literal(value).is_some_and(|value| !matches!(value, Value::Null)))
    }))
}

/// The call `relation` reads every row of, numbering none.
fn whole_call(relation: &TableFactor) -> Option<WrittenCall<'_>> {
    match relation {
        TableFactor::Table {
            with_ordinality: false,
            sample: None,
            ..
        }
        | TableFactor::Function {
            with_ordinality: false,
            ..
        } => WrittenCall::relation(relation),
        _ => None,
    }
}

/// Whether some table on which `left` and `right` each pin a column of the
/// row holding their value, keyed by the same column, pins it to values
/// none of which both allow, so the two values differ.
fn apart<DB: DatabaseLike>(left: &[Pinned<'_, DB>], right: &[Pinned<'_, DB>]) -> bool {
    left.iter().any(|left| {
        right.iter().any(|right| {
            ptr::eq(left.table, right.table)
                && left.keyed == right.keyed
                && left.column == right.column
                && !left.values.iter().any(|value| right.values.contains(value))
        })
    })
}

/// The relations of `from`, in order.
fn relations(from: &TableWithJoins) -> impl Iterator<Item = &TableFactor> {
    iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
}

/// Whether each row `from` yields holds a row of the relation at
/// `position`, which no outer join fills with `NULL`s.
fn present(from: &TableWithJoins, position: usize) -> bool {
    from.joins
        .iter()
        .enumerate()
        .all(|(index, join)| match &join.join_operator {
            JoinOperator::Join(_) | JoinOperator::Inner(_) | JoinOperator::CrossJoin(_) => true,
            JoinOperator::Left(_) | JoinOperator::LeftOuter(_) => position != index + 1,
            JoinOperator::Right(_) | JoinOperator::RightOuter(_) => position > index,
            _ => false,
        })
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
    /// The `SELECT`s of `selects` that project a `WITH` item followed.
    through: Vec<*const Select>,
    /// Whether every row of the result comes from a `SELECT` of `selects`.
    complete: bool,
    /// The `WITH` clauses in reach, each with how many of its items, from
    /// the first, it shows.
    frames: Vec<(&'q With, usize)>,
    /// The `WITH` item bodies already followed, so a recursive item is
    /// followed once.
    followed: Vec<*const Query>,
}

impl<'q> Carried<'q> {
    /// A walk that has met no query yet.
    fn new() -> Self {
        Self {
            complete: true,
            ..Self::default()
        }
    }

    /// The `SELECT`s of `selects` drawing their rows from no `WITH` item
    /// followed.
    fn leaves(&self) -> Vec<*const Select> {
        self.selects
            .iter()
            .copied()
            .filter(|select| !self.through.contains(select))
            .collect()
    }

    /// Follows `query` unless a limit, an offset or a lock may leave some of
    /// its rows behind.
    fn query(&mut self, query: &'q Query) {
        if query.limit_clause.is_some()
            || query.fetch.is_some()
            || !query.pipe_operators.is_empty()
            || !query.locks.is_empty()
        {
            self.complete = false;
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
            _ => self.complete = false,
        }
    }

    /// Records `select` when its rows each hold its one projected column,
    /// and follows the `WITH` item it projects whole.
    fn select(&mut self, select: &'q Select) {
        let Some((_, projected)) = carried_column(select) else {
            self.complete = false;
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
        self.through.push(select);
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
    let parts = match projected {
        Expr::Identifier(name) => slice::from_ref(name),
        Expr::CompoundIdentifier(parts) => parts.as_slice(),
        _ => return None,
    };
    plain(select).then_some((projected, parts))
}

/// Whether each row the `FROM` and filters of `select` leave yields at
/// most one row, with no grouping or `DISTINCT ON` choosing among them.
fn plain(select: &Select) -> bool {
    matches!(
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
        && select.flavor == SelectFlavor::Standard
}

/// The `SELECT` that `condition`, an `EXISTS` or `IN` over a query, finds
/// a row of that passes its `WHERE` whenever `condition` holds.
fn semi_join(condition: &Expr) -> Option<&Select> {
    let (Expr::Exists {
        subquery,
        negated: false,
    }
    | Expr::In {
        target: InTarget::Subquery(subquery),
        negated: false,
        ..
    }) = unnested(condition)
    else {
        return None;
    };
    witnessed(subquery)
}

/// The expression `select` projects as its output column at `ordinal`,
/// counted from zero, when no `*` comes before it.
fn projection_at(select: &Select, ordinal: usize) -> Option<&Expr> {
    let mut projected = None;
    for item in select.projection.get(..=ordinal)? {
        match item {
            SelectItem::UnnamedExpr(expression)
            | SelectItem::ExprWithAlias {
                expr: expression, ..
            } => projected = Some(expression),
            _ => return None,
        }
    }
    projected
}

/// The `SELECT` of `query` each row of which comes from a row of its `FROM`
/// passing its `WHERE`, with no row when none passes, projecting columns,
/// constants or `*`.
fn witnessed(query: &Query) -> Option<&Select> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let projected = select.projection.iter().all(|item| match item {
        SelectItem::UnnamedExpr(projected)
        | SelectItem::ExprWithAlias {
            expr: projected, ..
        } => matches!(
            projected,
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_)
        ),
        _ => matches!(
            item,
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..)
        ),
    });
    (query.order_by.is_none() && plain(select) && projected).then_some(select)
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

/// The relation at `position` of `from`, counted from zero.
fn relation_at(from: &TableWithJoins, position: usize) -> &TableFactor {
    match position.checked_sub(1) {
        Some(join) => &from.joins[join].relation,
        None => &from.relation,
    }
}

/// The input parameter of the function whose body holds `reference` that
/// it names where no column of the same name is in reach, or else the stored
/// name of the column of `relation` it names or `equalities` hold equal to
/// the column it names.
fn term<'r, DB: DatabaseLike>(
    resolver: &Resolver<'r, '_, '_, DB>,
    reference: &Expr,
    relation: &TableFactor,
    equalities: &Equalities<'r>,
) -> Option<Term> {
    match resolver.reference(reference)? {
        (ColumnDefinition::Parameter { ordinal, .. }, _) => Some(Term::Parameter(ordinal)),
        (_, binding) => match resolver.node(&binding)? {
            Node::Column { factor, name } if ptr::eq(factor, relation) => {
                Some(Term::Column(name.into_owned()))
            }
            node => equalities
                .of_relation(&node, relation)
                .map(|column| Term::Column(column.to_owned())),
        },
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
