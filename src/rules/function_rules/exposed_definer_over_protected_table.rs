//! Submodule providing the `ExposedDefinerOverProtectedTable` rule.

use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    convert::Infallible,
    iter, mem,
    ops::ControlFlow,
    ptr,
    rc::Rc,
    slice,
};

use sql_traits::{
    errors::{LookupError, RowSecurityError},
    structs::{
        ColumnBinding, ColumnDefinition, ExpressionContext, ExpressionScope, FunctionResultType,
        IdentifierCase, OperandType, RowStatement, RowVersion, TriggerEnablement, WrittenCall,
    },
    traits::{
        ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, PolicyLike, Relation, TableLike,
        TriggerLike, UserDefinedTypeLike,
    },
    utils::{identifier_resolution::normalize_identifier, normalize_postgres_type},
};
use sqlparser::{
    ast::{
        ArgMode, Assignment, AssignmentTarget, BinaryOperator, CaseWhen, CastKind, DataType,
        Delete, Expr, FromTable, Function, FunctionArg, FunctionArgExpr, FunctionArguments,
        FunctionBehavior, FunctionCalledOnNull, FunctionSecurity, Ident, InTarget, Insert,
        JoinConstraint, JoinOperator, LockClause, ObjectName, ObjectNamePart, Query, Select,
        SelectItem, SelectItemQualifiedWildcardKind, SetExpr, SetOperator, SetQuantifier,
        Statement, TableAliasColumnDef, TableFactor, TableInheritance, TableObject, TableWithJoins,
        TriggerEvent, TriggerObject, TriggerObjectKind, TriggerPeriod, Update, UpdateTableFromKind,
        Value, Values, Visit, VisitMut, Visitor, VisitorMut, With,
        helpers::attached_token::AttachedToken, visit_expressions, visit_expressions_mut,
        visit_relations,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};
use sqlparser_plpgsql::embedded::Block;

use crate::{
    deployment::Deployment,
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::{
            Identity, fixed_by, held_values, identity, pin, same_identity, stored_name,
        },
        cte_support::{
            WithScopes, join_constraint, same_name, stored_column, stored_relation, stored_table,
        },
        grant_support::{function_callers, granted_callers, schema_of},
        implication_support::{
            Columns, Condition, ParameterValues, StoredRelation, Term, admits, clause_implies,
            keeps_existence, left_to_prove, membership, parameter, parameter_ordinal, renamed,
            witnessed,
        },
        inline_support::selected_expression,
        key_support::{binds, equality_keys, key_pairs, no_inheritors},
        ladder_support::{
            Ladders, called, listed_arguments, plain, positional_arguments, relation_arguments,
        },
        literal_support::literal,
        null_support::rejects_null,
        plpgsql_flow_support::{Ran, plpgsql_block, ran_statements},
        policy_support::{
            acting, client_roles, conjuncts, is_column_reference, is_role_read,
            sets_only_search_path, sql_query_body, sql_statement_body, unnested, unwrapped,
        },
        type_support::user_type_named,
        walk_support::{holds_subquery, walk},
    },
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

use super::plpgsql_ambiguous_name::collision;

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
/// returns. Its body is then one `LANGUAGE sql` query, or a PL/pgSQL block
/// that only returns queries, through `RETURN QUERY`, a `RETURN` of a scalar
/// subquery or a `SELECT ... INTO` of the variable it returns, maybe past
/// guards `IF condition THEN RAISE EXCEPTION ...` or `IF condition THEN
/// RETURN`, and names no column a variable also answers to. Every other
/// variable it declares holds the default it is declared with or the value
/// one assignment among the guards gives it. A guard's
/// condition evaluates alike for a caller and the owner, each query it holds
/// confining its reads by the test below, so the owner finds there the rows
/// a caller finds, and each argument and `USING` option of its exception
/// evaluates alike and reads no subquery, so whether it raises and what it
/// says tell nothing of what the owner reads. That query writes nothing, the
/// function sets no parameter besides `search_path` and neither it nor a
/// function it calls runs `set_config`, and every read
/// of a table with row-level security in it is filtered, by its `WHERE` and
/// the `ON` of the joins that drop its rows, to rows each caller's own
/// `SELECT` policies on that table admit, while each caller may select every
/// column of the table. A read locking its rows with `FOR UPDATE`, `FOR
/// SHARE` or their key forms locks stored tables only, and the rows it locks
/// of a table with row-level security are those each caller's `UPDATE`
/// policies admit too, each caller holding `UPDATE` on a column of the
/// table, as PostgreSQL requires of a caller locking them directly.
/// The filter has to imply every restrictive policy and one permissive one,
/// stating each condition as written, where a scalar subquery reading no
/// relation such as `(SELECT auth.uid())` stands for its value, or testing
/// the same column against a set within the policy's, as written, declared
/// with [`Deployment::with_set_within`] or read off a ladder of the schema.
/// A non-negated `EXISTS` or `IN` over stored tables, such as one over a
/// membership table, implies the policy's when its names resolve to the same
/// tables and columns and it finds a row only where the policy's does,
/// reading each of the policy's tables as one of its own and stating every
/// condition of the policy's `ON` and `WHERE` and, for an `IN`, the tested
/// value. Its projection and a positive `LIMIT` of an `EXISTS` find nothing
/// else.
/// A filter whose `OR` arms each imply another permissive policy counts too,
/// since PostgreSQL admits a row any permissive policy admits.
/// A set read through an input parameter of an enum type, such as
/// `resources_with(min_role)`, has to lie within the policy's for every
/// label of the enum. It has to for `NULL`
/// too, which holds only when the function is `STRICT` or the call returns
/// `NULL` for a `NULL` argument, since no declaration states it. A column of
/// the same name hides the parameter, as in PostgreSQL. Only filter terms
/// that read alike for the caller and the owner count. Such a term reads no
/// role, no privilege and no search path, calls no `VOLATILE` built-in such
/// as `random()`, which the policy evaluates anew, reads only stored tables
/// of which every caller may select every column, and calls a function
/// running as its caller only when that function is one `LANGUAGE sql`
/// query, not `VOLATILE`, setting its own `search_path` and no other
/// parameter, that every caller may execute and whose body reads alike in
/// turn. A stored table with row-level security reads alike only in a
/// subquery the term holds true for finding a row in, a non-negated `EXISTS`
/// or `IN` reached through `AND` and `OR` over a query inner-joining its
/// relations, which an `IN` does not limit, since its own read is confined,
/// so each caller finds every row the owner finds. A table read under an
/// alias renaming its columns confines nothing.
/// Every function of the schema the body calls is held to the same test,
/// except a `SECURITY DEFINER` function every caller may execute directly,
/// which this rule judges on its own. Functions in `pg_catalog` besides
/// `set_config` are trusted.
/// A `SECURITY DEFINER` function the callers may not execute counts too
/// when neither it nor a function it reaches is `VOLATILE`, so none writes,
/// and the function the callers execute is one whose every value is the
/// column of a row each caller's `SELECT` policies admit for lying in that
/// function's own set. The callers then learn of the rows the helper reads
/// only which of the rows they read the function returns.
///
/// A function is not reported either when each caller could run what it
/// writes and change the same rows the same way. Its body is then one
/// `DELETE`, `UPDATE` or `INSERT` of one table, in `LANGUAGE sql` or in a
/// PL/pgSQL block past such guards, bare or as its `RETURN QUERY`. A block
/// may run several such writes, returned queries and queries it `PERFORM`s
/// or selects `INTO` its variable in turn, each held to its own test, since
/// a caller running them in the same order meets the same rows at each. A
/// write, a `PERFORM` or a `SELECT ... INTO` may be followed by a guard `IF
/// NOT FOUND THEN ...`, which raises where the caller's own statement would
/// find no row too,
/// and one write may assign its `RETURNING` `INTO`, or its row count through
/// `GET DIAGNOSTICS ... = ROW_COUNT`, the variable declared without a
/// default, which the block's last `RETURN` returns and no statement reads.
/// A `DELETE` or an `UPDATE` is read as the `SELECT` of the
/// rows it writes joined to the tables its `USING` or `FROM` names,
/// projecting what its `RETURNING` returns. That `SELECT` is held to the
/// test above, the written table to each caller's policies for the command
/// besides the `SELECT` ones, as PostgreSQL holds a write reading a column
/// of its table. An `UPDATE` sets each column, named alone, to a value that
/// evaluates alike for a caller and the owner and names no column of another
/// relation it joins, and the policies judging the updated row, its `WITH
/// CHECK` and the `SELECT` ones, have to hold of the row the filter admits
/// with those values in place. Its `RETURNING` reads each set column as its
/// value. A policy or a `RETURNING` naming a set column inside a subquery
/// fails that. Every caller holds `DELETE` on the table, or `UPDATE` on each
/// column set.
///
/// An `INSERT` of one table naming each column it writes, with no `ON
/// CONFLICT`, is read as the `SELECT` of the values each row of its `VALUES`
/// list or of its one `SELECT` writes, held to the test above and reading at
/// most one table. Each value evaluates alike for a caller and the owner, as
/// a `SET` value does, and every caller holds `INSERT` on each column named.
/// Each other column holds its default, which has to name alike anywhere and
/// call no `VOLATILE` function, or `NULL` without one. The value of an
/// identity or generated column is not followed, so a policy naming one
/// fails. The `WITH CHECK` of each caller's `INSERT` policies, and the
/// `SELECT` ones with a `RETURNING`, have to hold of the new row with those
/// values in place, for each row the read rows admit.
///
/// A policy comparing a value a write writes with that same value holds when
/// the value cannot be `NULL`, as for a literal, a `current_setting` without
/// `missing_ok`, or a value of a `NOT NULL` column, whose write of `NULL`
/// fails for the owner too.
///
/// A trigger runs as the owner inside the function, so each one that may
/// fire on the write, enabled and declared for its command, and for an
/// `UPDATE OF` naming a column the `SET` names, has to act alike for a
/// caller. An `AFTER` trigger whose function is `SECURITY DEFINER` runs as
/// its owner either way. A `BEFORE ROW` trigger of an `UPDATE` or an
/// `INSERT` whose PL/pgSQL body only assigns fields of `NEW` and returns it
/// writes those columns too, in the order of the trigger names, and its
/// values are held to the written values' test, the row the policies judge
/// holding them. A column it writes needs no `UPDATE` or `INSERT` grant. Any
/// other trigger keeps the function reported.
///
/// A call `f(a)` passing a label of an enum lies within `f(b)` passing a
/// lower label of the same enum, all other arguments alike, when `f` is a
/// `LANGUAGE sql` function that is not `VOLATILE`, sets no parameter besides
/// `search_path` and returns a set whose rows only drop as the parameter
/// grows. Its body passes that when every use of the parameter compares a
/// column of the enum's type with `>=` or `>` to it, or passes it as it
/// stands to such a function, from `WITH` items, `UNION` and `INTERSECT`
/// arms, the left arm of `EXCEPT`, inner and cross joins, and `AND`, `OR`,
/// `IN`, `= ANY (ARRAY(…))` and `EXISTS` conditions that are not negated,
/// with nothing grouping or limiting rows. Such a ladder holds for the
/// existence oracle rules too, and composes with declared sets.
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
/// reaches the result only for outer rows passing them. A column the
/// filters fix with `=` to a literal stands for that literal in a row
/// tested with `IN` against a set, and the literal for the column.
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
/// state of the row it draws the value from. A filter of the function
/// reading one of its parameters states it of the argument the tested call
/// passes, when that call passes each positionally as a literal or as a
/// parameter of the calling function. A filter of a function the body
/// reads whole in its `FROM` states the same of the argument that call
/// passes, and states nothing otherwise. The value drawn through a
/// `SECURITY DEFINER` function also lies in the set of its own call, with
/// the arguments the call passes. A column held equal with `=` to the only
/// column a call of such a function returns in a `FROM` item lies in the
/// set of that call, written schema-qualified, when the call passes each
/// argument positionally as a literal or a parameter. Of an `OR` of such
/// tests and other conditions, what every arm states holds.
/// When the function draws the value from the tested column itself, unique
/// in its table, the row drawn is the tested row and every condition holds
/// of it. Otherwise a condition on the returned column holds of the tested
/// column when `=` compares both by the same identity. A condition on
/// another column holds of the tested row when a
/// foreign key that is `NOT DEFERRABLE`, validated and checking every row
/// holding a value maps the returned column onto the tested one, unique in
/// its table, and maps that column onto one compared by the same identity.
/// A row the keys keep apart from the tested one is left out first.
/// Following such keys from a column, each table on which the value is
/// unique pins its columns generated as one value, its `NOT NULL` columns a
/// validated check holds `=` one value or `IN` a list of values as a
/// top-level conjunct, the columns a key fills from a column pinned before
/// and those the filter pins, and a value whose row pins a column to none of
/// the values the tested value's row may hold is never the tested value.
/// Keys of a table another table inherits from count for nothing, since
/// that table's rows escape them.
///
/// A column also lies in the set of a `SECURITY DEFINER` function a policy
/// of the table tests a column against, when that function runs as the
/// owner the body runs as and, if `STRICT`, the policy passes a literal
/// other than `NULL` for every parameter. An arm of it has to read one table alone,
/// every row and with no sample, and return the column of every row of it
/// meeting its filter, where a condition reading a parameter states it of
/// the literal the policy passes, and of no other argument. A row of that
/// table the `SELECT` reads, or a query an `EXISTS` or `IN` of its `WHERE`
/// finds, not filled with `NULL`s by an outer join, has to meet every
/// condition of the filter, and the body's filters hold the column the arm
/// returns of that row equal to the column.
///
/// The rule does not run on SQLite, which has no stored functions.
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

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
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
    ladders: Ladders<'a, DB>,
    /// The function the callers execute.
    exposed: &'a DB::Function,
    /// Whether every value `exposed` returns lies in a set a `SELECT` policy
    /// of the table it is drawn from tests, once read.
    released: Cell<Option<bool>>,
}

impl<'a, DB: DatabaseLike> Confinement<'a, DB> {
    /// The proof for the callers of `function`, which are every client role
    /// and `PUBLIC` while `PUBLIC` may execute it, else the declared roles
    /// granted `EXECUTE`.
    fn new(
        database: &'a DB,
        deployment: &'a Deployment,
        function: &'a DB::Function,
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
            ladders: Ladders::new(database),
            exposed: function,
            released: Cell::new(None),
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

    /// Whether the functions `function` calls confine their reads, call no
    /// `set_config`, whose setting a filter may then read in place of the
    /// caller's, and its own body reads no table with row-level security or
    /// confines each read.
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
            let confined = if callee.target_name().schema() == Some("pg_catalog") {
                callee.target_name().name() != "set_config"
            } else {
                self.runs_for_every_caller(callee)?
                    || self.confines(callee)?
                    || self.releases_through_policy_sets(callee)?
            };
            if !confined {
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
        .map(|confined| confined.is_some_and(|confined| confined.iter().all(|read| *read)))
    }

    /// Whether `callee`, a `SECURITY DEFINER` function that neither writes
    /// nor calls a function that may, reaches the callers only through the
    /// values the exposed function returns, each of which a `SELECT` policy
    /// of the table it is drawn from admits through the exposed function's
    /// own set. The callers then learn which of the rows they read it
    /// returns, and nothing of a row they cannot read.
    fn releases_through_policy_sets(&self, callee: &'a DB::Function) -> Result<bool, LookupError> {
        if callee.security_mode() != FunctionSecurity::Definer
            || !self.reads_only(callee, &mut Vec::new())?
        {
            return Ok(false);
        }
        if let Some(released) = self.released.get() {
            return Ok(released);
        }
        let released = self.releases_policy_sets()?;
        self.released.set(Some(released));
        Ok(released)
    }

    /// Whether neither `function` nor a function it reaches is `VOLATILE`,
    /// so none writes, with `seen` holding the functions already read.
    fn reads_only(
        &self,
        function: &'a DB::Function,
        seen: &mut Vec<*const DB::Function>,
    ) -> Result<bool, LookupError> {
        let address = ptr::from_ref(function);
        if seen.contains(&address) {
            return Ok(true);
        }
        seen.push(address);
        if function.volatility() == FunctionBehavior::Volatile {
            return Ok(false);
        }
        if function.target_name().schema() == Some("pg_catalog") {
            return Ok(true);
        }
        let callees = match function.referenced_functions(self.database) {
            Ok(callees) => callees,
            Err(error) if super::unreadable_body(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        for callee in callees {
            if !self.reads_only(callee, seen)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether every value the exposed function returns is the column of a
    /// row each caller's `SELECT` policies admit by testing that column
    /// against the function's own set.
    fn releases_policy_sets(&self) -> Result<bool, LookupError> {
        let function = self.exposed;
        let Some(member) = member(function) else {
            return Ok(false);
        };
        let arms = self.arms(function)?;
        if !arms.complete || arms.arms.is_empty() {
            return Ok(false);
        }
        let body = Body {
            parameters: self.parameter_values(function)?,
            confinement: self,
            function,
        };
        for arm in &arms.arms {
            let tested = in_set(arm.drawn.column.column_name(), member.clone());
            if !body.admits_every_caller(arm.drawn.table, &tested, RowStatement::Select, &[])? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// What `walk` finds reading each statement of the body of `function`,
    /// in order, one `LANGUAGE sql` statement or those [`Self::block_statements`]
    /// reads, each read as [`Self::read_statement`] does with the lineage
    /// `lineage` gives it. `None` when the body is no such statement or a
    /// statement reads as `None`.
    fn read_body<T>(
        &self,
        function: &'a DB::Function,
        lineage: impl Fn(&Query) -> Lineage,
        mut walk: impl FnMut(&mut Reads<'_, '_, 'a, DB>, &Query) -> Result<T, LookupError>,
    ) -> Result<Option<Vec<T>>, LookupError> {
        let path = function.search_path(self.database)?;
        let statements = match plpgsql_block(function) {
            Some(block) => match self.block_statements(function, block, path.as_deref())? {
                Some(statements) => statements,
                None => return Ok(None),
            },
            None => match sql_statement_body(self.database, function)? {
                Some(statement) => vec![statement.into_owned()],
                None => return Ok(None),
            },
        };
        let mut found = Vec::with_capacity(statements.len());
        for statement in statements {
            let Some(read) =
                self.read_statement(function, statement, path.as_deref(), &lineage, &mut walk)?
            else {
                return Ok(None);
            };
            found.push(read);
        }
        Ok(Some(found))
    }

    /// The statements the `plpgsql` block `block` of `function` runs, as
    /// [`ran_statements`] reads them, its names resolving on `path`. `None`
    /// when it runs others, a name of the block may read a variable where a
    /// statement reads a column, a guard of the block may evaluate otherwise
    /// for a caller than for the owner, as [`Self::guard_reads_alike`] tells,
    /// so that whether it raises tells what the owner reads, or a value an
    /// exception carries reads a subquery or may evaluate otherwise.
    fn block_statements(
        &self,
        function: &'a DB::Function,
        block: Block,
        path: Option<&[(Cow<'_, str>, bool)]>,
    ) -> Result<Option<Vec<Statement>>, LookupError> {
        let Some(Ran {
            statements,
            guards,
            raised,
        }) = ran_statements(block)
        else {
            return Ok(None);
        };
        if collision(self.database, function)?.is_some() {
            return Ok(None);
        }
        for guard in &guards {
            if !self.guard_reads_alike(function, guard, path)? {
                return Ok(None);
            }
        }
        for value in &raised {
            if holds_subquery(value) || !CallerBound::new(self, path, None).reads_alike(value)? {
                return Ok(None);
            }
        }
        Ok(Some(statements))
    }

    /// Whether the guard condition `guard` of `function` evaluates alike for
    /// a caller and for the owner, its names resolving on `path`. Each query
    /// it holds has to confine its reads, as [`Reads::confines_query`] reads
    /// them, so the owner finds the very rows a caller finds there, and its
    /// terms have to read alike otherwise.
    fn guard_reads_alike(
        &self,
        function: &'a DB::Function,
        guard: &Expr,
        path: Option<&[(Cow<'_, str>, bool)]>,
    ) -> Result<bool, LookupError> {
        let mut bound = CallerBound::new(self, path, None);
        if holds_subquery(guard) {
            let query = rows_query(
                vec![SelectItem::UnnamedExpr(guard.clone())],
                Vec::new(),
                None,
            );
            let confined = self.read_statement(
                function,
                Statement::Query(Box::new(query)),
                path,
                &|_| Lineage::default(),
                &mut |reads, query| reads.confines_query(query, &[], &[]),
            )?;
            if confined != Some(true) {
                return Ok(false);
            }
            relations_within(guard, &mut bound.positive);
        }
        bound.reads_alike(guard)
    }

    /// What `walk` finds reading `statement` of the body of `function`, its
    /// names resolving on `path`, with the lineage `lineage` gives it, read as
    /// [`Self::queried`] reads it. `None` when its names do not resolve.
    fn read_statement<T>(
        &self,
        function: &'a DB::Function,
        statement: Statement,
        path: Option<&[(Cow<'_, str>, bool)]>,
        lineage: &impl Fn(&Query) -> Lineage,
        walk: &mut impl FnMut(&mut Reads<'_, '_, 'a, DB>, &Query) -> Result<T, LookupError>,
    ) -> Result<Option<T>, LookupError> {
        let Some((statement, write, insertion)) = self.queried(statement, path)? else {
            return Ok(None);
        };
        let scope = ExpressionScope::FunctionBody(function);
        let (Statement::Query(query), Ok(context)) = (
            &statement,
            ExpressionContext::for_statement(
                &statement,
                &scope,
                self.database,
                IdentifierCase::AsWritten,
            ),
        ) else {
            return Ok(None);
        };
        let written = match write {
            Some(write) => {
                let select = query.body.as_select().expect("writes select their target");
                let from = select.from.first().expect("writes have a target");
                Some((ptr::from_ref(&from.relation), write))
            }
            None => None,
        };
        let inserted = insertion.map(|mut insertion| {
            selects(&query.body, &mut insertion.rows);
            insertion
        });
        let lineage = lineage(query);
        let mut reads = Reads {
            body: Body {
                parameters: self.parameter_values(function)?,
                confinement: self,
                function,
            },
            context: &context,
            path,
            items: WithScopes::default(),
            lineage: &lineage,
            written,
            inserted,
        };
        walk(&mut reads, query).map(Some)
    }

    /// `statement`, a query as it stands, a `DELETE` as [`deleted_rows`]
    /// gives it, an `UPDATE` as [`Updated::rows`] and an `INSERT` as
    /// [`Inserted::rows`] do, with how it writes the rows its query yields,
    /// its names resolving on `path`. `None` for another statement or a
    /// write whose triggers may act otherwise for a caller.
    fn queried(
        &self,
        statement: Statement,
        path: Option<&[(Cow<'_, str>, bool)]>,
    ) -> Result<Option<Queried<'a, DB>>, LookupError> {
        Ok(Some(match statement {
            query @ Statement::Query(_) => (query, None, None),
            Statement::Delete(delete) => {
                let Some((query, target)) = deleted_rows(delete) else {
                    return Ok(None);
                };
                if self.triggered(&target, path, Fired::Delete)?.is_none() {
                    return Ok(None);
                }
                (Statement::Query(Box::new(query)), Some(Write::Delete), None)
            }
            Statement::Update(update) => {
                let Some(mut updated) = Updated::new(update) else {
                    return Ok(None);
                };
                let Some(maintained) =
                    self.triggered(&updated.target, path, Fired::Update(updated.set()))?
                else {
                    return Ok(None);
                };
                for maintenance in &maintained {
                    if updated.maintain(maintenance).is_none() {
                        return Ok(None);
                    }
                }
                let Some((query, write)) = updated.rows() else {
                    return Ok(None);
                };
                (Statement::Query(Box::new(query)), Some(write), None)
            }
            Statement::Insert(insert) => {
                let Some(inserted) = Inserted::new(insert) else {
                    return Ok(None);
                };
                let (Some(table), Some(maintained)) = (
                    stored_table(self.database, &inserted.target, path)?,
                    self.triggered(&inserted.target, path, Fired::Insert)?,
                ) else {
                    return Ok(None);
                };
                let Some((query, insertion)) =
                    inserted.rows(table, self.filled(table)?, &maintained)
                else {
                    return Ok(None);
                };
                (Statement::Query(Box::new(query)), None, Some(insertion))
            }
            _ => return Ok(None),
        }))
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
        Ok(callee.security_mode() == FunctionSecurity::Definer
            && self.executable_by_every_caller(callee)?)
    }

    /// Whether every caller may execute `function`.
    fn executable_by_every_caller(&self, function: &DB::Function) -> Result<bool, LookupError> {
        for caller in &self.callers {
            let executes = match *caller {
                Some(role) => function.can_execute(role, self.database)?,
                None => function.is_executable_by_public(self.database)?,
            };
            if !executes {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether every caller may select every column of `table`.
    fn selectable_by_every_caller(&self, table: &DB::Table) -> Result<bool, LookupError> {
        for caller in &self.callers {
            let held = table.privileges(acting(*caller), self.database)?;
            for column in table.columns(self.database)? {
                if !held.select.on_column(column) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// The `BEFORE ROW` maintenance triggers, as `sql-traits` reads one, the
    /// write `fired` of the table `name` names runs, in the order they fire,
    /// when every other trigger that may fire on it is an `AFTER` trigger
    /// whose function runs as its owner, as it does called from the caller
    /// too. `None` when `name` names no table or another trigger may fire,
    /// since a trigger runs as the owner inside the function and one running
    /// `BEFORE` may change the row past the caller's policies.
    fn triggered(
        &self,
        name: &ObjectName,
        path: Option<&[(Cow<'_, str>, bool)]>,
        fired: Fired<'_>,
    ) -> Result<Option<Vec<Maintenance>>, LookupError> {
        let database = self.database;
        let Some(table) = stored_table(database, name, path)? else {
            return Ok(None);
        };
        let mut triggers: Vec<&DB::Trigger> = table.triggers(database)?.collect();
        triggers.sort_by(|left, right| left.name().cmp(right.name()));
        let mut maintained = Vec::new();
        for trigger in triggers {
            if trigger.enablement(database)? == TriggerEnablement::Disabled
                || !trigger.events().iter().any(|event| fires_on(event, fired))
            {
                continue;
            }
            let row = matches!(
                trigger.orientation(),
                Some(
                    TriggerObjectKind::For(TriggerObject::Row)
                        | TriggerObjectKind::ForEach(TriggerObject::Row)
                )
            );
            match trigger.timing() {
                Some(TriggerPeriod::After)
                    if trigger.function(database).is_some_and(|function| {
                        function.security_mode() == FunctionSecurity::Definer
                    }) => {}
                Some(TriggerPeriod::Before)
                    if row
                        && !matches!(fired, Fired::Delete)
                        && trigger.is_maintenance_trigger(database)? =>
                {
                    maintained.push(Maintenance {
                        assignments: trigger
                            .maintenance_assignments(database)?
                            .map(|(column, value)| (column.column_name().to_owned(), value))
                            .collect(),
                        condition: trigger.condition().cloned(),
                    });
                }
                _ => return Ok(None),
            }
        }
        Ok(Some(maintained))
    }

    /// Whether every caller holds the privilege `write` needs on `table`.
    fn writable_by_every_caller(
        &self,
        table: &DB::Table,
        write: &Write,
    ) -> Result<bool, LookupError> {
        for caller in &self.callers {
            let held = table.privileges(acting(*caller), self.database)?;
            match write {
                Write::Delete => {
                    if !held.delete {
                        return Ok(false);
                    }
                }
                Write::Update { columns, set } => {
                    for name in &columns[..*set] {
                        let Some(column) = column_named(self.database, table, name)? else {
                            return Ok(false);
                        };
                        if !held.update.on_column(column) {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    /// Whether every caller holds `INSERT` on each column of `table` whose
    /// stored name `named` holds.
    fn insertable_by_every_caller(
        &self,
        table: &DB::Table,
        named: &[String],
    ) -> Result<bool, LookupError> {
        for caller in &self.callers {
            let held = table.privileges(acting(*caller), self.database)?;
            for name in named {
                let column = column_named(self.database, table, name)?
                    .expect("inserted columns belong to their table");
                if !held.insert.on_column(column) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Whether every caller holds `UPDATE` on a column of `table`, which
    /// PostgreSQL requires of a caller locking its rows.
    fn lockable_by_every_caller(&self, table: &DB::Table) -> Result<bool, LookupError> {
        for caller in &self.callers {
            if !table
                .privileges(acting(*caller), self.database)?
                .update
                .on_any_column()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// What an `INSERT` into `table` not naming a column writes it, for each
    /// column by its stored name.
    fn filled(&self, table: &DB::Table) -> Result<Vec<(String, Fill)>, LookupError> {
        let database = self.database;
        let mut filled = Vec::new();
        for column in table.columns(database)? {
            let fill = if column.identity_generation(database).is_some()
                || column.is_generated(database)
            {
                Fill::Opaque
            } else {
                match column.default_expression() {
                    None => Fill::Value(Box::new(Expr::Value(Value::Null.into()))),
                    Some(default)
                        if reads_alike_anywhere(database, default)
                            && !calls_volatile(database, default) =>
                    {
                        Fill::Value(Box::new(default.clone()))
                    }
                    Some(_) => Fill::Otherwise,
                }
            };
            filled.push((column.stored_column_name().into_owned(), fill));
        }
        Ok(filled)
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

    /// [`Self::arms`] read from the body of `function`, which runs one
    /// statement. A `VOLATILE` function may read rows of a later snapshot,
    /// and a parameter it sets may change what its filters compute, so
    /// either draws from rows the rule cannot tell.
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
                    member: (function.security_mode() == FunctionSecurity::Definer)
                        .then(|| member(function))
                        .flatten(),
                };
                reads.draw_query(query, &mut drawing)?;
                drawing.arms.complete &= drawing.leaves.is_empty();
                Ok(drawing.arms)
            },
        )
        .map(|arms| match arms.map(<[_; 1]>::try_from) {
            Some(Ok([arms])) => arms,
            _ => Arms::default(),
        })
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
    /// meeting the conditions, those reading a parameter for the values the
    /// call passes.
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
    /// Further such conditions reading the function's input parameters as
    /// `$n`, which the row meets for the values a call passes.
    bound: Vec<Expr>,
    /// `"column" IN (SELECT f($1, …))`, the column in the set of the
    /// function, a `SECURITY DEFINER` one, that returns it. The row meets it
    /// once drawn, though the function need not return the column of a row
    /// only for meeting it.
    member: Option<Expr>,
}

impl<DB: DatabaseLike> Drawn<'_, DB> {
    /// The conditions the row meets for a call passing `arguments` for the
    /// input parameters in order, or `None` when one reads a parameter and
    /// the call's values are not known.
    fn under(&self, arguments: Option<&[&Expr]>) -> Option<Cow<'_, [Expr]>> {
        if self.bound.is_empty() {
            return Some(Cow::Borrowed(&self.conditions));
        }
        let arguments = arguments?;
        let mut conditions = Vec::with_capacity(self.conditions.len() + self.bound.len());
        conditions.extend_from_slice(&self.conditions);
        for condition in &self.bound {
            conditions.push(bound_to(condition, arguments)?);
        }
        Some(Cow::Owned(conditions))
    }

    /// What the row is known to meet once drawn by a call passing
    /// `arguments`, [`Self::under`] those, or the conditions reading no
    /// parameter, and the membership.
    fn known(&self, arguments: Option<&[&Expr]>) -> Cow<'_, [Expr]> {
        let mut known = self
            .under(arguments)
            .unwrap_or(Cow::Borrowed(&self.conditions));
        let member = self.member.as_ref().and_then(|member| match arguments {
            Some(arguments) => bound_to(member, arguments),
            None => (!reads_parameter(member)).then(|| member.clone()),
        });
        if let Some(member) = member {
            known.to_mut().push(member);
        }
        known
    }
}

/// The leaf `SELECT`s of a function body not read yet, and the rows read.
struct Drawing<'a, DB: DatabaseLike> {
    /// Each leaf not read yet. Every row of a leaf reaches the result.
    leaves: Vec<*const Select>,
    arms: Arms<'a, DB>,
    /// `SELECT f($1, …)` calling the function, a `SECURITY DEFINER` one, with
    /// its own arguments. A policy calling it with the same arguments gets
    /// the same set, which holds the column of each row drawn.
    member: Option<Box<Query>>,
}

impl<'a, DB: DatabaseLike> Drawing<'a, DB> {
    /// Adds the row of `table` whose `column` the function returns, meeting
    /// `conditions`, with its membership in the function's own set.
    fn push(
        &mut self,
        table: &'a DB::Table,
        column: &'a DB::Column,
        conditions: Vec<Expr>,
        exhaustive: bool,
    ) {
        let (bound, conditions) = conditions.into_iter().partition(reads_parameter);
        self.arms.arms.push(Arm {
            drawn: Rc::new(Drawn {
                table,
                column,
                conditions,
                bound,
                member: self
                    .member
                    .as_ref()
                    .map(|member| in_set(column.column_name(), member.clone())),
            }),
            exhaustive,
        });
    }
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
    /// their stored names, admits only rows every caller's policies for
    /// `statement` admit, of which every caller may select every column.
    /// The written row is the row the filter tests with each column of
    /// `assigned` set to its value, over the stored names too.
    fn admits_every_caller(
        &self,
        table: &DB::Table,
        filter: &Expr,
        statement: RowStatement,
        assigned: &[(String, Expr)],
    ) -> Result<bool, LookupError> {
        Ok(self.gates_admit(table, filter, statement, assigned, &[])?
            && self.confinement.selectable_by_every_caller(table)?)
    }

    /// Whether every caller's policies admit inserting into `table` the row
    /// `row` writes, each column by its stored name, its values stating
    /// columns of the row `filter` tests as [`Self::admits_every_caller`]
    /// reads them, and the columns of `opaque` holding values the rule does
    /// not follow. One that `returning` reads back every caller has to be
    /// allowed to select too.
    fn admits_inserted(
        &self,
        table: &DB::Table,
        filter: &Expr,
        returning: bool,
        row: &[(String, Expr)],
        opaque: &[String],
    ) -> Result<bool, LookupError> {
        Ok(self.gates_admit(
            table,
            filter,
            RowStatement::Insert { returning },
            row,
            opaque,
        )? && (!returning || self.confinement.selectable_by_every_caller(table)?))
    }

    /// Whether the gates of every caller's policies for `statement` on
    /// `table` admit the rows `filter` admits, a condition on the written
    /// row tested with each column of `assigned` set to its value and none
    /// naming a column of `opaque`. A conjunct comparing a written value
    /// with itself holds as [`left_to_prove`] reads it, the value not `NULL`
    /// where its column is `NOT NULL`.
    fn gates_admit(
        &self,
        table: &DB::Table,
        filter: &Expr,
        statement: RowStatement,
        assigned: &[(String, Expr)],
        opaque: &[String],
    ) -> Result<bool, LookupError> {
        let database = self.confinement.database;
        let mut written = Vec::with_capacity(assigned.len());
        for (column, value) in assigned {
            let refused = !column_named(database, table, column)?
                .expect("written columns belong to their table")
                .is_nullable(database)?;
            written.push((value, refused));
        }
        for caller in &self.confinement.callers {
            let security = match table.row_security(statement, acting(*caller), database) {
                Ok(security) => security,
                Err(RowSecurityError::Lookup(error)) => return Err(error),
                Err(_) => return Ok(false),
            };
            let admitted = match security.gates() {
                Some(gates) => {
                    let (existing, rewritten): (Vec<_>, Vec<_>) = gates
                        .iter()
                        .partition(|gate| gate.row() == RowVersion::Existing);
                    admits(database, table, existing, self, |condition| {
                        clause_implies(self, filter, condition, &[])
                    })? && admits(database, table, rewritten, self, |condition| {
                        if names_any(condition.original, opaque) {
                            return Ok(false);
                        }
                        match new_row(condition.original, assigned) {
                            Some(new) => match left_to_prove(&new, &written) {
                                Some(left) => {
                                    clause_implies(self, filter, &Condition::new(self, &left), &[])
                                }
                                None => Ok(true),
                            },
                            None => Ok(false),
                        }
                    })?
                }
                None => security.exemption().is_some(),
            };
            if !admitted {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A policy condition states the columns of its table by their stored names,
/// as a confined filter does once renamed.
impl<DB: DatabaseLike> Columns for Body<'_, '_, DB> {
    type Tested = String;

    fn is_set_within(&self, narrower: &Expr, wider: &Expr) -> Result<bool, LookupError> {
        let ladders = &self.confinement.ladders;
        self.confinement.deployment.is_set_within(
            narrower,
            wider,
            |_| Ok(None),
            |narrower, wider| ladders.within(narrower, wider),
        )
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

    /// A policy names a relation as the schema's search path resolves it.
    fn relation(&self, name: &ObjectName) -> Option<StoredRelation> {
        stored_relation_named(self.confinement.database, name, None)
    }

    fn inlined(&self, call: &Function) -> Option<Expr> {
        helper_value(self.confinement, call)
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
struct CallerBound<'r, 'a, DB: DatabaseLike> {
    confinement: &'r Confinement<'a, DB>,
    /// The search path the names of the walked body resolve on.
    path: Option<&'r [(Cow<'r, str>, bool)]>,
    /// The `WITH` items in reach of the walked term, whose bodies it does
    /// not hold.
    around: Option<&'r WithScopes>,
    /// The `WITH` items of the queries the walk stands in.
    items: WithScopes,
    /// The functions whose bodies the walk stands in.
    reading: Vec<*const DB::Function>,
    /// The relations of subqueries the walked term holds true only for
    /// finding a row in, or of a guard's queries, whose reads of tables with
    /// row-level security every caller's policies admit, so a caller finds
    /// every row the owner does.
    positive: Vec<*const TableFactor>,
}

impl<'r, 'a, DB: DatabaseLike> CallerBound<'r, 'a, DB> {
    /// The walk over a term of a body whose names resolve on `path`, with the
    /// `WITH` items `around` in reach.
    fn new(
        confinement: &'r Confinement<'a, DB>,
        path: Option<&'r [(Cow<'r, str>, bool)]>,
        around: Option<&'r WithScopes>,
    ) -> Self {
        Self {
            confinement,
            path,
            around,
            items: WithScopes::default(),
            reading: Vec::new(),
            positive: Vec::new(),
        }
    }

    /// Whether `node` evaluates alike for a caller and for the owner.
    fn reads_alike<N: Visit + ?Sized>(&mut self, node: &N) -> Result<bool, LookupError> {
        match walk(node, self) {
            ControlFlow::Continue(()) => Ok(true),
            ControlFlow::Break(found) => found.map_or(Ok(false), Err),
        }
    }

    /// Whether `call` may reach a function of the schema that runs as its
    /// caller and may return otherwise for the caller than for the owner, or
    /// a `VOLATILE` built-in such as `random()`, which a policy repeating the
    /// term evaluates anew.
    fn evaluates_otherwise<'c>(
        &mut self,
        call: impl Into<WrittenCall<'c>>,
    ) -> Result<bool, LookupError> {
        let database = self.confinement.database;
        for function in database.functions_reached_by(call, IdentifierCase::Folded)? {
            let otherwise = if function.target_name().schema() == Some("pg_catalog") {
                function.volatility() == FunctionBehavior::Volatile
            } else {
                function.security_mode() != FunctionSecurity::Definer
                    && !self.invoked_alike(function)?
            };
            if otherwise {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether `function`, running as its caller, returns alike for the
    /// caller and the owner. It has to be one `LANGUAGE sql` query that is
    /// not `VOLATILE`, sets no parameter but `search_path`, and that every
    /// caller may execute, whose body reads alike in turn. A body without
    /// its own `search_path` resolves its names on the caller's, so each has
    /// to mean alike on any path, as [`names_alike_anywhere`] takes them.
    fn invoked_alike(&mut self, function: &'a DB::Function) -> Result<bool, LookupError> {
        let confinement = self.confinement;
        let database = confinement.database;
        let address = ptr::from_ref(function);
        if self.reading.contains(&address)
            || function.volatility() == FunctionBehavior::Volatile
            || !sets_only_search_path(function)
            || !confinement.executable_by_every_caller(function)?
        {
            return Ok(false);
        }
        let Some(query) = sql_query_body(database, function)? else {
            return Ok(false);
        };
        let path = function.search_path(database)?;
        if path.is_none() && !names_alike_anywhere(database, &query) {
            return Ok(false);
        }
        let mut within = CallerBound::new(confinement, path.as_deref(), None);
        within.reading = mem::take(&mut self.reading);
        within.reading.push(address);
        let alike = within.reads_alike(query.as_ref());
        self.reading = within.reading;
        self.reading.pop();
        alike
    }

    /// Whether the relation `factor` reads under `name` may hold other rows
    /// for the caller than for the owner. A `WITH` item of the walked queries
    /// reads what its walked body reads, and of the other relations only a
    /// stored table every caller may select every column of reads alike,
    /// one with row-level security only as a relation of `positive`.
    fn reads_otherwise(
        &self,
        factor: &TableFactor,
        name: &ObjectName,
    ) -> Result<bool, LookupError> {
        if self.items.binding(name).is_some() {
            return Ok(false);
        }
        if self
            .around
            .is_some_and(|around| around.binding(name).is_some())
        {
            return Ok(true);
        }
        let database = self.confinement.database;
        Ok(match stored_table(database, name, self.path)? {
            Some(table) => {
                table.has_row_level_security(database)?
                    && !self.positive.contains(&ptr::from_ref(factor))
                    || !self.confinement.selectable_by_every_caller(table)?
            }
            None => true,
        })
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

impl<DB: DatabaseLike> Visitor for CallerBound<'_, '_, DB> {
    type Break = Option<LookupError>;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.items.enter(query);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.items.leave(query);
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        let Expr::Function(call) = expression else {
            return ControlFlow::Continue(());
        };
        if is_role_read(expression) || reads_session_state(call) {
            return ControlFlow::Break(None);
        }
        Self::verdict(self.evaluates_otherwise(call))
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table {
            name, args: None, ..
        } = factor
        {
            return Self::verdict(self.reads_otherwise(factor, name));
        }
        WrittenCall::relation(factor).map_or(ControlFlow::Continue(()), |call| {
            Self::verdict(self.evaluates_otherwise(call))
        })
    }
}

/// Whether `call` asks what privileges or roles the current role holds, such
/// as `has_table_privilege` or `pg_has_role`, or reads the search path, as
/// `current_schema`, `to_regclass` or `current_setting('search_path')` do,
/// which the function's own `SET search_path` changes.
fn reads_session_state(call: &Function) -> bool {
    call.name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .is_some_and(|name| {
            let name = name.value.to_lowercase();
            (name.starts_with("has_") && name.ends_with("_privilege"))
                || name.starts_with("to_reg")
                || (name.starts_with("pg_") && name.ends_with("_is_visible"))
                || matches!(
                    name.as_str(),
                    "pg_has_role" | "row_security_active" | "current_schema" | "current_schemas"
                )
                || (matches!(name.as_str(), "current_setting" | "set_config")
                    && !names_other_setting_than_search_path(call))
        })
}

/// Whether the first argument of `call` is a literal naming a setting other
/// than `search_path`.
fn names_other_setting_than_search_path(call: &Function) -> bool {
    matches!(
        &call.args,
        FunctionArguments::List(list) if matches!(
            list.args.first(),
            Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(value))))
                if matches!(&value.value, Value::SingleQuotedString(setting)
                    if !setting.eq_ignore_ascii_case("search_path"))
        )
    )
}

/// Pushes onto `found` the relations of each subquery `condition` holds true
/// only for finding a row in, reached through `AND` and `OR`. That is an
/// `EXISTS` or `IN` over a query inner-joining its relations and yielding
/// one row of columns or constants for each row passing its `WHERE`, which
/// an `IN` does not limit and an `EXISTS` limits to no fewer than one, and
/// in turn each such subquery of that `WHERE`. Finding more rows in them
/// never turns `condition` false.
fn positive_relations(condition: &Expr, found: &mut Vec<*const TableFactor>) {
    let subquery = match unnested(condition) {
        Expr::Exists {
            subquery,
            negated: false,
        } if keeps_existence(subquery) => subquery,
        Expr::In {
            target: InTarget::Subquery(subquery),
            negated: false,
            ..
        } if subquery.limit_clause.is_none() => subquery,
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And | BinaryOperator::Or,
            right,
        } => {
            positive_relations(left, found);
            positive_relations(right, found);
            return;
        }
        _ => return,
    };
    let Some(select) = witnessed(subquery) else {
        return;
    };
    let inner = select.from.iter().flat_map(|from| &from.joins).all(|join| {
        matches!(
            join.join_operator,
            JoinOperator::Join(_) | JoinOperator::Inner(_) | JoinOperator::CrossJoin(_)
        )
    });
    if !inner || subquery.fetch.is_some() || !subquery.pipe_operators.is_empty() {
        return;
    }
    found.extend(select.from.iter().flat_map(relations).map(ptr::from_ref));
    if let Some(selection) = &select.selection {
        positive_relations(selection, found);
    }
}

/// Pushes onto `found` every relation of the queries `expression` holds.
fn relations_within(expression: &Expr, found: &mut Vec<*const TableFactor>) {
    struct Relations<'f>(&'f mut Vec<*const TableFactor>);
    impl Visitor for Relations<'_> {
        type Break = Infallible;

        fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Infallible> {
            self.0.push(ptr::from_ref(factor));
            ControlFlow::Continue(())
        }
    }
    let ControlFlow::Continue(()) = walk(expression, &mut Relations(found));
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
    /// Whether the body's query holds a `WITH` of its own, whose items may
    /// stand where its names read stored tables.
    scoped: bool,
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
    /// The relation the body writes and how, read as a `SELECT` of the rows
    /// it writes, which each caller has to be allowed to write alike.
    written: Option<(*const TableFactor, Write)>,
    /// The `INSERT` the body runs, read as the `SELECT`s of the rows it
    /// inserts, which each caller has to be allowed to insert alike.
    inserted: Option<Insertion<'a, DB>>,
}

/// How a body writes the rows of the relation it reads them from.
enum Write {
    /// A `DELETE`.
    Delete,
    /// An `UPDATE` writing each column of `columns`, by its stored name, as
    /// the expression the `SELECT` projects at the same position. The first
    /// `set` are those its `SET` names, the others those its triggers do.
    Update { columns: Vec<String>, set: usize },
}

/// The columns a `BEFORE ROW` maintenance trigger assigns.
struct Maintenance {
    /// Each column it assigns, by its stored name, with what it assigns it,
    /// reading `NEW` as the row before the trigger runs.
    assignments: Vec<(String, Expr)>,
    /// The `WHEN` condition it fires under.
    condition: Option<Expr>,
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
        let mut owners = owners.to_vec();
        if query.with.is_some() {
            owners.push(query);
        }
        self.items.enter(query);
        let confined = match self.confines_nested(query, held, &owners) {
            Ok(true) => self.confines(&query.body, held, &owners, &query.locks),
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
    /// reads and the locks `locks` takes on its rows, a body that writes or
    /// reads `TABLE` never, nor one locking the rows of a set operation, a
    /// parenthesized query or a `VALUES` list.
    fn confines(
        &self,
        body: &SetExpr,
        held: &[&Expr],
        owners: &[&Query],
        locks: &[LockClause],
    ) -> Result<bool, LookupError> {
        match body {
            SetExpr::Select(select) => self.confines_select(select, held, owners, locks),
            _ if !locks.is_empty() => Ok(false),
            SetExpr::SetOperation { left, right, .. } => {
                Ok(self.confines(left, held, owners, &[])?
                    && self.confines(right, held, owners, &[])?)
            }
            SetExpr::Query(_) | SetExpr::Values(_) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Whether each relation with row-level security a `SELECT` reads is
    /// confined by the filters that drop its rows, the conditions `held` of
    /// the outer rows, and what the sets they test its columns against tell.
    /// A relation `locks` locks has to be a stored table, and one with
    /// row-level security has its rows admitted by each caller's gates for
    /// a locking `SELECT`, which every caller holds `UPDATE` on a column of,
    /// as PostgreSQL requires of a caller locking those rows directly.
    fn confines_select(
        &self,
        select: &Select,
        held: &[&Expr],
        owners: &[&Query],
        locks: &[LockClause],
    ) -> Result<bool, LookupError> {
        let filters = self.filters(select, held, owners)?;
        let inserted = self
            .inserted
            .as_ref()
            .filter(|insertion| insertion.rows.iter().any(|row| ptr::eq(*row, select)));
        if let Some(insertion) = inserted
            && let Some(admitted) = self.admits_inserted_alone(insertion, select)?
        {
            return Ok(admitted);
        }
        for from in &select.from {
            for (position, relation) in relations(from).enumerate() {
                let locked = locks.iter().any(|lock| locks_relation(lock, relation));
                if locked
                    && !matches!(relation, TableFactor::Table { name, args: None, .. }
                        if self.items.binding(name).is_none())
                {
                    return Ok(false);
                }
                let table = match self.read(relation)? {
                    Read::Open if inserted.is_none() => continue,
                    Read::Open | Read::Unconfined => return Ok(false),
                    Read::Protected(table) => table,
                };
                let Stated {
                    resolver,
                    equalities,
                    mut conditions,
                    caller_bound,
                    ..
                } = self.stated(&filters, from, position)?;
                let mut drawn = Vec::new();
                for condition in &conditions {
                    drawn.extend(self.drawn_condition(table, condition, &conditions)?);
                }
                for condition in &caller_bound {
                    drawn.extend(self.implied(table, condition, &conditions)?);
                }
                conditions.extend(drawn);
                let witnessed = self.witnessed_sets(
                    &filters,
                    owners,
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
                let filter = conjunction(conditions);
                let rename = |reference: &Expr| term(&resolver, reference, relation, &equalities);
                let admitted = self
                    .admits_relation(select, table, relation, &filter, locked, rename)?
                    && match inserted {
                        Some(insertion) => {
                            self.admits_inserted(insertion, select, &filter, rename)?
                        }
                        None => true,
                    };
                if !admitted {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Whether every caller may read, alike, the rows of `table`, read as
    /// `relation` of `select`, that `filter` admits, writing them as the body
    /// does, or locking them where `locked`, `rename` naming each column the
    /// `SELECT` projects as a column of the rows.
    fn admits_relation(
        &self,
        select: &Select,
        table: &DB::Table,
        relation: &TableFactor,
        filter: &Expr,
        locked: bool,
        rename: impl Fn(&Expr) -> Option<Term>,
    ) -> Result<bool, LookupError> {
        let body = &self.body;
        Ok(match &self.written {
            Some((written, write)) if ptr::eq(*written, relation) => {
                body.confinement.writable_by_every_caller(table, write)?
                    && match write {
                        Write::Delete => body.admits_every_caller(
                            table,
                            filter,
                            RowStatement::Delete { reads: true },
                            &[],
                        )?,
                        Write::Update { columns, .. } => {
                            match self.assigned(select, columns, rename)? {
                                Some(assigned) => body.admits_every_caller(
                                    table,
                                    filter,
                                    RowStatement::Update { reads: true },
                                    &assigned,
                                )?,
                                None => false,
                            }
                        }
                    }
            }
            _ if locked => {
                body.confinement.lockable_by_every_caller(table)?
                    && body.admits_every_caller(table, filter, RowStatement::SelectLocking, &[])?
            }
            _ => body.admits_every_caller(table, filter, RowStatement::Select, &[])?,
        })
    }

    /// Whether every caller may insert, alike, the rows `select` projects as
    /// `insertion` writes them, when `select` reads no relation, or `false`
    /// when it reads more than one. `None` when it reads one, whose filters
    /// the rows meet.
    fn admits_inserted_alone(
        &self,
        insertion: &Insertion<'a, DB>,
        select: &Select,
    ) -> Result<Option<bool>, LookupError> {
        match select.from.as_slice() {
            [] => {
                self.admits_inserted(insertion, select, &conjunction(Vec::new()), |reference| {
                    match self.context.reference(reference) {
                        Ok(Some((ColumnDefinition::Parameter { ordinal, .. }, _))) => {
                            Some(Term::Parameter(ordinal))
                        }
                        _ => None,
                    }
                })
                .map(Some)
            }
            [from] if from.joins.is_empty() => Ok(None),
            _ => Ok(Some(false)),
        }
    }

    /// Whether every caller may insert, alike, the rows `select` projects as
    /// `insertion` writes them. Those rows meet `filter`, stated over the
    /// stored names of the columns of the row they are drawn from, and
    /// `rename` resolves each column and parameter they read.
    fn admits_inserted(
        &self,
        insertion: &Insertion<'a, DB>,
        select: &Select,
        filter: &Expr,
        rename: impl Fn(&Expr) -> Option<Term>,
    ) -> Result<bool, LookupError> {
        let Some(mut row) = self.assigned(select, &insertion.columns, rename)? else {
            return Ok(false);
        };
        row.extend(insertion.defaults.iter().cloned());
        let confinement = self.body.confinement;
        Ok(confinement
            .insertable_by_every_caller(insertion.table, &insertion.columns[..insertion.named])?
            && self.body.admits_inserted(
                insertion.table,
                filter,
                insertion.returning,
                &row,
                &insertion.opaque,
            )?)
    }

    /// The value each column of `columns` a write writes takes, the
    /// expression `select` projects at its position, with each column and
    /// parameter it reads named as `rename` resolves it, or `None` when one
    /// may evaluate otherwise for a caller than for the owner or `rename`
    /// resolves none for a name it reads.
    fn assigned(
        &self,
        select: &Select,
        columns: &[String],
        rename: impl Fn(&Expr) -> Option<Term>,
    ) -> Result<Option<Vec<(String, Expr)>>, LookupError> {
        let mut assigned = Vec::with_capacity(columns.len());
        for (column, item) in columns.iter().zip(&select.projection) {
            let value = match item {
                SelectItem::UnnamedExpr(value) if self.reads_alike(value)? => value,
                _ => return Ok(None),
            };
            let Some(value) = renamed(
                value,
                &rename,
                |name| self.subquery_relation(name),
                |call| helper_value(self.body.confinement, call),
            ) else {
                return Ok(None);
            };
            assigned.push((column.clone(), value));
        }
        Ok(Some(assigned))
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
        let mut sources = self.sources(select, owners);
        let found: Vec<&Select> = filter.iter().copied().filter_map(semi_join).collect();
        let nested: Vec<Source<'_>> = filter
            .iter()
            .copied()
            .filter_map(unscoped_semi_join)
            .flat_map(|found| self.sources(found, owners))
            .collect();
        let merges = self.merges(select, &sources)?;
        let once: Vec<Source<'_>> = nested
            .iter()
            .filter(|source| {
                sources
                    .iter()
                    .chain(&nested)
                    .filter(|other| ptr::eq(other.body, source.body))
                    .count()
                    == 1
            })
            .copied()
            .collect();
        sources.extend(once);
        let witnessed = found
            .into_iter()
            .chain(sources.iter().map(|source| source.body))
            .flat_map(|found| found.selection.iter().flat_map(conjuncts))
            .collect();
        let mut rejected = Vec::with_capacity(select.from.len());
        for from in &select.from {
            rejected.push(self.rejected(from, &filter)?);
        }
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
        let mut caller_bound = Vec::new();
        let mut whole = true;
        for &(clause, conjunct) in &dropping {
            let stated = renamed(
                conjunct,
                |reference| term(&resolver, reference, relation, &equalities),
                |name| self.subquery_relation(name),
                |call| helper_value(self.body.confinement, call),
            );
            match stated {
                Some(stated) if self.reads_alike(conjunct)? => {
                    conditions.push(stated);
                }
                Some(stated) => {
                    caller_bound.push(stated);
                    whole &= !matches!(clause, Clause::Where);
                }
                None => whole &= !matches!(clause, Clause::Where),
            }
            if let Some(membership) = self.joined_set(&resolver, &equalities, relation, conjunct) {
                if self.reads_alike(&membership)? {
                    conditions.push(membership);
                } else {
                    caller_bound.push(membership);
                }
            }
        }
        if let Some(found) = self.joined_rows(filters, &resolver, &equalities, relation, &dropping)
        {
            if self.reads_alike(&found)? {
                conditions.push(found);
            } else {
                caller_bound.push(found);
            }
        }
        Ok(Stated {
            resolver,
            equalities,
            conditions,
            caller_bound,
            whole,
        })
    }

    /// Whether `expression`, a term of the walked body, evaluates alike for
    /// a caller and for the owner. Every query nested in the body has its
    /// reads confined by now, so a subquery the term holds true only for
    /// finding a row in finds, for the owner, only rows each caller finds.
    fn reads_alike(&self, expression: &Expr) -> Result<bool, LookupError> {
        let mut caller_bound =
            CallerBound::new(self.body.confinement, self.path, Some(&self.items));
        positive_relations(expression, &mut caller_bound.positive);
        caller_bound.reads_alike(expression)
    }

    /// `EXISTS`, written as [`renamed`] writes a subquery, over the stored
    /// tables besides `relation` holding a row on every row the `SELECT`
    /// yields, of its `FROM`, its sources and the queries its `WHERE` finds
    /// a row of, under the conjuncts and `IN` equalities that read them.
    fn joined_rows<'r>(
        &self,
        filters: &Filters<'_>,
        resolver: &Resolver<'r, '_, 'a, DB>,
        equalities: &Equalities<'r>,
        relation: &TableFactor,
        dropping: &[(Clause, &Expr)],
    ) -> Option<Expr> {
        let mut joined = Vec::new();
        let mut read = Vec::new();
        let found = filters
            .filter
            .iter()
            .copied()
            .filter_map(unscoped_semi_join);
        for select in iter::once(filters.from).chain(found.map(|select| select.from.as_slice())) {
            self.found_tables(select, &filters.sources, relation, &mut joined, &mut read);
        }
        let write =
            |expression| written_over_joined(resolver, equalities, relation, &joined, expression);
        let mut conditions: Vec<String> = dropping
            .iter()
            .filter(|(clause, _)| !matches!(clause, Clause::Held))
            .filter_map(|(_, conjunct)| write(conjunct))
            .filter(|(_, reads_joined)| *reads_joined)
            .map(|(conjunct, _)| conjunct.to_string())
            .collect();
        for conjunct in &filters.filter {
            if let Expr::In { expr, .. } = unnested(conjunct)
                && let Some((projected, _)) = semi_join(conjunct).and_then(carried_column)
                && let Some((tested, tested_joined)) = write(expr)
                && let Some((projected, projected_joined)) = write(projected)
                && (tested_joined || projected_joined)
            {
                conditions.push(format!("{tested} = {projected}"));
            }
        }
        if conditions.is_empty() {
            return None;
        }
        Parser::new(&PostgreSqlDialect {})
            .try_with_sql(&format!(
                "EXISTS (SELECT 1 FROM {} WHERE {})",
                read.join(", "),
                conditions.join(" AND ")
            ))
            .and_then(|mut parser| parser.parse_expr())
            .ok()
            .and_then(|found| {
                renamed(
                    &found,
                    |reference| match reference {
                        Expr::CompoundIdentifier(parts) => parts
                            .last()
                            .map(|column| Term::Column(column.value.clone())),
                        _ => None,
                    },
                    |name| self.subquery_relation(name),
                    |call| helper_value(self.body.confinement, call),
                )
            })
    }

    /// Adds to `joined` each stored table but `relation` that holds a row on
    /// every row `from` yields, of `from` itself or of the body of one of
    /// `sources` that does, and to `read` the `FROM` item reading it under
    /// the alias `"1.i"` of its index `i` in `joined`.
    fn found_tables(
        &self,
        from: &[TableWithJoins],
        sources: &[Source<'_>],
        relation: &TableFactor,
        joined: &mut Vec<*const TableFactor>,
        read: &mut Vec<String>,
    ) {
        for item in from {
            for (position, factor) in relations(item).enumerate() {
                if !present(item, position) || ptr::eq(factor, relation) {
                    continue;
                }
                if let Some(source) = sources
                    .iter()
                    .find(|source| ptr::eq(source.relation, factor))
                {
                    if !source.scoped {
                        self.found_tables(&source.body.from, &[], relation, joined, read);
                    }
                } else if let TableFactor::Table {
                    name,
                    alias,
                    args: None,
                    ..
                } = factor
                    && alias.as_ref().is_none_or(|alias| alias.columns.is_empty())
                    && let Some(stored) = self.subquery_relation(name)
                {
                    read.push(format!("{} AS \"1.{}\"", stored.name, joined.len()));
                    joined.push(ptr::from_ref(factor));
                }
            }
        }
    }

    /// `column IN (SELECT schema.f(…))` when `conjunct` holds the `column` of
    /// `relation` equal to the only column a call `f(…)` in a `FROM` item
    /// returns, passing each argument as a literal or a parameter. A row
    /// an outer join fills with `NULL`s never holds it equal.
    fn joined_set<'r>(
        &self,
        resolver: &Resolver<'r, '_, 'a, DB>,
        equalities: &Equalities<'r>,
        relation: &TableFactor,
        conjunct: &Expr,
    ) -> Option<Expr> {
        let (left, right) = match unnested(conjunct) {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => (left.as_ref(), right.as_ref()),
            Expr::In { expr, .. } => (
                expr.as_ref(),
                semi_join(conjunct).and_then(carried_column)?.0,
            ),
            _ => return None,
        };
        [(left, right), (right, left)]
            .into_iter()
            .find_map(|(tested, drawn)| {
                let Term::Column(column) = term(resolver, tested, relation, equalities)? else {
                    return None;
                };
                let (
                    ColumnDefinition::FunctionResult {
                        function,
                        data_type: FunctionResultType::Scalar { .. },
                    },
                    binding,
                ) = resolver.reference(unnested(drawn))?
                else {
                    return None;
                };
                let arguments: Vec<String> = self
                    .passed(binding.entry()?.factor(), function)?
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                Some(in_set(&column, call_of(function, &arguments)?))
            })
    }

    /// What `condition`, stated of the columns of `table` besides its
    /// `conditions`, implies of the row through the sets it tests columns
    /// against. A term reading alike implies itself, a test against a set
    /// the conditions [`Self::drawn_condition`] carries over, `AND` what
    /// either side implies and `OR` what each side does.
    fn implied(
        &self,
        table: &'a DB::Table,
        condition: &Expr,
        conditions: &[Expr],
    ) -> Result<Option<Expr>, LookupError> {
        if let Expr::BinaryOp {
            left,
            op: op @ (BinaryOperator::And | BinaryOperator::Or),
            right,
        } = unnested(condition)
        {
            let left = self.implied(table, left, conditions)?;
            let right = self.implied(table, right, conditions)?;
            return Ok(match (left, right) {
                (Some(left), Some(right)) => Some(Expr::BinaryOp {
                    left: Box::new(left),
                    op: op.clone(),
                    right: Box::new(right),
                }),
                (left, right) if *op == BinaryOperator::And => left.or(right),
                _ => None,
            });
        }
        if self.reads_alike(condition)? {
            return Ok(Some(condition.clone()));
        }
        self.drawn_condition(table, condition, conditions)
    }

    /// The stored table `name` reads in a subquery of a filter, which no
    /// `WITH` item in reach shadows.
    fn subquery_relation(&self, name: &ObjectName) -> Option<StoredRelation> {
        if self.items.binding(name).is_some() {
            return None;
        }
        stored_relation_named(self.body.confinement.database, name, self.path)
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
    /// conditions that carry over to the row, those reading a parameter
    /// stated of the argument the call passes when each is a literal or a
    /// parameter.
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
        let arguments = positional_arguments(call, function).filter(|arguments| {
            arguments.iter().all(|argument| {
                literal(argument).is_some() || parameter_ordinal(unwrapped(argument)).is_some()
            })
        });
        let tested_kinds = discriminators(database, table, column, conditions)?;
        let mut alternatives = Vec::new();
        for arm in &arms.arms {
            let drawn = arm.drawn.as_ref();
            let source = drawn.column;
            let kinds = discriminators(database, drawn.table, source, &drawn.conditions)?;
            if apart(&tested_kinds, &kinds) {
                continue;
            }
            let met = drawn.known(arguments.as_deref());
            let carried = carried_conditions(database, drawn, &met, table, column)?;
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
    /// tests a column against, when a row of a table the `SELECT` `filters`
    /// filters reads, or a query an `EXISTS` or `IN` of its `WHERE` finds,
    /// meets every condition of an exhaustive arm of the helper over that
    /// table, those reading a parameter stated of the literal the policy
    /// passes, and the filters hold the column the arm returns equal to
    /// `column`. `owners` are the queries around whose `WITH` holds items
    /// in reach.
    fn witnessed_sets(
        &self,
        filters: &Filters<'_>,
        owners: &[&Query],
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
        let arguments: Vec<Option<Vec<&Expr>>> = sets
            .iter()
            .map(|set| set.literals.then(|| listed_arguments(&set.call)).flatten())
            .collect();
        let mut found = Vec::new();
        for condition in &filters.filter {
            if let Some(select) = semi_join(condition) {
                found.push(self.filters(select, &[], owners)?);
            }
        }
        for scope in iter::once(filters).chain(&found) {
            for from in scope.from {
                for (position, joined) in relations(from).enumerate() {
                    let same = ptr::eq(joined, relation);
                    let Some(joined_table) = self.stored(joined)? else {
                        continue;
                    };
                    if !same && !present(from, position) {
                        continue;
                    }
                    let arms: Vec<_> = sets
                        .iter()
                        .zip(&arguments)
                        .flat_map(|(set, arguments)| {
                            set.arms
                                .arms
                                .iter()
                                .filter(|arm| arm.exhaustive && arm.drawn.table == joined_table)
                                .filter_map(move |arm| {
                                    let met = arm.drawn.under(arguments.as_deref())?;
                                    Some((&set.call, arm.drawn.as_ref(), met))
                                })
                        })
                        .collect();
                    if arms.is_empty() {
                        continue;
                    }
                    let stated;
                    let row = if same {
                        conditions
                    } else {
                        stated = self.stated(scope, from, position)?;
                        stated.conditions.as_slice()
                    };
                    let clause = conjunction(row.to_vec());
                    for (members, drawn, met) in arms {
                        if !self.implies_every(&clause, &met)? {
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
    /// rows the body reads, some arm of it is exhaustive for the literals
    /// the call passes, and a `STRICT` function gets no argument that may be
    /// `NULL`.
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
            let literals = positional_arguments(&written, helper)
                .is_some_and(|passed| passed.iter().all(|argument| literal(argument).is_some()));
            let arms = confinement.arms(helper)?;
            if arms
                .arms
                .iter()
                .any(|arm| arm.exhaustive && (arm.drawn.bound.is_empty() || literals))
            {
                sets.push(SetCall {
                    call: written,
                    literals,
                    arms,
                });
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
                    self.draw_select(select, drawing)?;
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

    /// Adds to `drawing` the row of a stored table whose column the leaf
    /// `select` returns, with what its filters state of the row, or the rows
    /// of the function whose call it returns the value of, with what those
    /// state of that function's parameters for the arguments the call passes,
    /// and marks the arms incomplete for any other leaf.
    fn draw_select(
        &self,
        select: &Select,
        drawing: &mut Drawing<'a, DB>,
    ) -> Result<(), LookupError> {
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
                    conditions,
                    whole: stated,
                    ..
                } = self.stated(&filters, from, position)?;
                if let Some(Term::Column(name)) = term(&resolver, projected, relation, &equalities)
                    && let Some(column) =
                        column_named(self.body.confinement.database, table, &name)?
                {
                    drawing.push(
                        table,
                        column,
                        conditions,
                        stated && select.from.len() == 1 && from.joins.is_empty(),
                    );
                    return Ok(());
                }
            } else if let Some(call) = whole_call(relation)
                && let Some(function) = called(self.body.confinement.database, call)?
            {
                let called = self.body.confinement.arms(function)?;
                let passed = self.passed(relation, function);
                let passed: Option<Vec<&Expr>> =
                    passed.as_ref().map(|passed| passed.iter().collect());
                drawing.arms.complete &= called.complete;
                for arm in &called.arms {
                    let drawn = &arm.drawn;
                    if drawing.member.is_none() && drawn.bound.is_empty() && drawn.member.is_none()
                    {
                        drawing.arms.arms.push(Arm {
                            drawn: Rc::clone(drawn),
                            exhaustive: false,
                        });
                        continue;
                    }
                    let conditions = drawn.known(passed.as_deref()).into_owned();
                    drawing.push(drawn.table, drawn.column, conditions, false);
                }
                return Ok(());
            }
        }
        drawing.arms.complete = false;
        Ok(())
    }

    /// The arguments `relation`, a call to `function`, passes it, each a
    /// literal or an input parameter of the body read as `$n`, or `None`
    /// when one is neither.
    fn passed(&self, relation: &TableFactor, function: &DB::Function) -> Option<Vec<Expr>> {
        relation_arguments(relation, function)?
            .into_iter()
            .map(|argument| {
                if literal(argument).is_some() || parameter_ordinal(argument).is_some() {
                    return Some(argument.clone());
                }
                match self.context.reference(argument).ok().flatten()? {
                    (ColumnDefinition::Parameter { ordinal, .. }, _) => Some(parameter(ordinal)),
                    _ => None,
                }
            })
            .collect()
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
                        scoped: query.with.is_some(),
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
    /// The other filters over those names, which may evaluate otherwise for
    /// a caller than for the owner. A row such a filter tests against the
    /// set of a function still meets the conditions the function draws the
    /// set under.
    caller_bound: Vec<Expr>,
    /// Whether `conditions` states every conjunct of the `WHERE`.
    whole: bool,
}

/// The call of a function a policy tests a column against, as written,
/// with the rows the function draws from.
struct SetCall<'a, DB: DatabaseLike> {
    call: Function,
    /// Whether the call passes a literal for each input parameter.
    literals: bool,
    arms: Rc<Arms<'a, DB>>,
}

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
fn set_membership(column: &str, members: &Function) -> Option<Expr> {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(&format!("SELECT {members}"))
        .and_then(|mut parser| parser.parse_query())
        .ok()
        .map(|query| in_set(column, query))
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

/// The stored table `name` reads on `path`, under its schema-qualified
/// stored name, `None` for any other relation or one that fails to resolve.
fn stored_relation_named<DB: DatabaseLike>(
    database: &DB,
    name: &ObjectName,
    path: Option<&[(Cow<'_, str>, bool)]>,
) -> Option<StoredRelation> {
    let table = stored_table(database, name, path).ok()??;
    let columns = table.columns(database).ok()?;
    let schema = schema_of(database, table.stored_table_schema());
    Some(StoredRelation {
        name: ObjectName::from(vec![
            Ident::with_quote('"', schema.as_ref()),
            Ident::with_quote('"', table.stored_table_name().as_ref()),
        ]),
        columns: columns
            .map(|column| column.column_name().to_owned())
            .collect(),
    })
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

/// The `conditions` the row `drawn` meets that hold of the row of `table`
/// whose `column` equals the `source` column of the row drawn, over the
/// columns of `table`. When `source` is `column` and unique in `table`, the
/// row drawn is that row and each condition holds of it. Otherwise the
/// value drawn carries the conditions on `source` when `=` compares both
/// columns by the same identity. When `column` is unique in `table`, a
/// foreign key of the drawn row that binds it maps `source` onto `column`
/// carries those on each column it maps onto one compared alike.
fn carried_conditions<DB: DatabaseLike>(
    database: &DB,
    drawn: &Drawn<'_, DB>,
    conditions: &[Expr],
    table: &DB::Table,
    column: &DB::Column,
) -> Result<Vec<Expr>, LookupError> {
    let source = drawn.column;
    let unique = unique_alone(database, table, column)?;
    if unique && source == column {
        return Ok(conditions.to_vec());
    }
    let mut renames: Vec<(&str, &str)> = Vec::new();
    if same_identity(database, source, column)? {
        renames.push((source.column_name(), column.column_name()));
    }
    if unique {
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
    Ok(conditions
        .iter()
        .filter_map(|condition| {
            renamed(
                condition,
                |reference| {
                    let name = stored_name(reference)?;
                    renames
                        .iter()
                        .find(|(from, _)| *from == name)
                        .map(|(_, to)| Term::Column((*to).to_owned()))
                },
                |_| None,
                |_| None,
            )
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
/// reached pins the columns its table holds to literals and the columns a
/// key fills from a column pinned before, the first also those `conditions`
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
        for held in table.columns(database)? {
            if let Some(values) = held_values(database, held)? {
                fixed.extend(pin(database, held, &values)?);
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

/// `condition` with each input parameter it reads as `$n` replaced by the
/// argument `arguments` holds for it, or `None` when one holds none.
fn bound_to(condition: &Expr, arguments: &[&Expr]) -> Option<Expr> {
    let mut bound = condition.clone();
    let unbound = visit_expressions_mut(&mut bound, |expression| {
        let Some(ordinal) = parameter_ordinal(expression) else {
            return ControlFlow::Continue(());
        };
        match arguments.get(ordinal) {
            Some(argument) => {
                *expression = (*argument).clone();
                ControlFlow::Continue(())
            }
            None => ControlFlow::Break(()),
        }
    });
    unbound.is_continue().then_some(bound)
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

/// Whether `lock` may lock the rows of `relation`, every relation of its
/// `SELECT` without `OF`, or the stored table `OF` names by its alias or,
/// unaliased, by its own name. A relation other than a table may hold the
/// one `OF` names.
fn locks_relation(lock: &LockClause, relation: &TableFactor) -> bool {
    let Some(of) = &lock.of else {
        return true;
    };
    let TableFactor::Table { name, alias, .. } = relation else {
        return true;
    };
    let [locked] = of.0.as_slice() else {
        return false;
    };
    let named = match alias {
        Some(alias) => Some(&alias.name),
        None => name.0.last().and_then(ObjectNamePart::as_ident),
    };
    locked.as_ident().zip(named).is_some_and(|(locked, named)| {
        normalize_identifier(&locked.value, locked.quote_style.is_some())
            == normalize_identifier(&named.value, named.quote_style.is_some())
    })
}

/// `SELECT returned… FROM target, using… WHERE selection`, the rows `delete`
/// deletes joined to the `USING` rows that select them, projecting what its
/// `RETURNING` returns of them, with the name of the table it deletes from,
/// when it deletes from one table.
fn deleted_rows(delete: Delete) -> Option<(Query, ObjectName)> {
    let Delete {
        tables,
        from: FromTable::WithFromKeyword(mut from),
        on_cluster: None,
        using,
        selection,
        returning,
        output: None,
        order_by,
        limit: None,
        settings: None,
        ..
    } = delete
    else {
        return None;
    };
    if !tables.is_empty() || !order_by.is_empty() {
        return None;
    }
    let [
        TableWithJoins {
            relation: TableFactor::Table { name, .. },
            joins,
        },
    ] = from.as_slice()
    else {
        return None;
    };
    if !joins.is_empty() {
        return None;
    }
    let target = name.clone();
    from.extend(using.into_iter().flatten());
    Some((
        rows_query(returning.unwrap_or_default(), from, selection),
        target,
    ))
}

/// A write of a table, as the triggers on it fire on it.
#[derive(Clone, Copy)]
enum Fired<'s> {
    /// A `DELETE`.
    Delete,
    /// An `UPDATE` setting each column, by its stored name, to its value.
    Update(&'s [(String, Expr)]),
    /// An `INSERT`.
    Insert,
}

/// Whether a trigger firing on `event` fires on the write `fired`.
fn fires_on(event: &TriggerEvent, fired: Fired<'_>) -> bool {
    match (event, fired) {
        (TriggerEvent::Delete, Fired::Delete) | (TriggerEvent::Insert, Fired::Insert) => true,
        (TriggerEvent::Update(columns), Fired::Update(set)) => {
            columns.is_empty()
                || columns.iter().any(|column| {
                    let name = normalize_identifier(&column.value, column.quote_style.is_some());
                    set.iter().any(|(set, _)| *set == name)
                })
        }
        _ => false,
    }
}

/// An `UPDATE` of one table, setting each column by its name.
struct Updated {
    /// The name of the table it updates.
    target: ObjectName,
    /// The name the columns of that table are qualified by.
    visible: Ident,
    /// Each column it writes, by its stored name, with the value it writes,
    /// those its `SET` names first.
    assigned: Vec<(String, Expr)>,
    /// How many columns of `assigned` its `SET` names.
    set: usize,
    /// The updated table, then the `FROM` rows that select its rows.
    from: Vec<TableWithJoins>,
    selection: Option<Expr>,
    returning: Vec<SelectItem>,
}

impl Updated {
    /// `update`, when it updates one table, setting each column by its name.
    fn new(update: Update) -> Option<Self> {
        let Update {
            table,
            on_cluster: None,
            assignments,
            from: joined,
            selection,
            returning,
            output: None,
            or: None,
            order_by,
            limit: None,
            settings: None,
            ..
        } = update
        else {
            return None;
        };
        if !table.joins.is_empty() || !order_by.is_empty() {
            return None;
        }
        let TableFactor::Table { name, alias, .. } = &table.relation else {
            return None;
        };
        let visible = match alias {
            Some(alias) => alias.name.clone(),
            None => name.0.last()?.as_ident()?.clone(),
        };
        let target = name.clone();
        let mut assigned = Vec::with_capacity(assignments.len());
        for Assignment { target, value } in assignments {
            let AssignmentTarget::ColumnName(ObjectName(parts)) = target else {
                return None;
            };
            let [ObjectNamePart::Identifier(column)] = parts.as_slice() else {
                return None;
            };
            assigned.push((
                normalize_identifier(&column.value, column.quote_style.is_some()).into_owned(),
                value,
            ));
        }
        let set = assigned.len();
        let mut from = vec![table];
        match joined {
            None => {}
            Some(UpdateTableFromKind::AfterSet(joined)) => from.extend(joined),
            Some(UpdateTableFromKind::BeforeSet(_)) => return None,
        }
        Some(Self {
            target,
            visible,
            assigned,
            set,
            from,
            selection,
            returning: returning.unwrap_or_default(),
        })
    }

    /// What the `SET` sets each column it names to.
    fn set(&self) -> &[(String, Expr)] {
        &self.assigned[..self.set]
    }

    /// Writes what `maintenance` assigns, when it fires, over what the
    /// update writes before it runs, or `None` when what it assigns or the
    /// condition it fires under reads the row in a nested query.
    fn maintain(&mut self, maintenance: &Maintenance) -> Option<()> {
        let folded = maintained(maintenance, |record, field| {
            Some(match record {
                Record::Old => self.column(field),
                Record::New => self.written(field),
            })
        })?;
        for (column, value) in folded {
            match self.assigned.iter_mut().find(|(held, _)| *held == column) {
                Some((_, held)) => *held = value,
                None => self.assigned.push((column, value)),
            }
        }
        Some(())
    }

    /// What the update writes the column whose stored name is `column`.
    fn written(&self, column: &str) -> Expr {
        match self.assigned.iter().find(|(held, _)| held == column) {
            Some((_, value)) => Expr::Nested(Box::new(value.clone())),
            None => self.column(column),
        }
    }

    /// The column of the updated row whose stored name is `column`.
    fn column(&self, column: &str) -> Expr {
        Expr::CompoundIdentifier(vec![self.visible.clone(), Ident::with_quote('"', column)])
    }

    /// `SELECT value…, returned… FROM target, from… WHERE selection`, the
    /// rows the update writes joined to the `FROM` rows that select them,
    /// projecting the value it writes each column and then what `RETURNING`
    /// returns, with how it writes them. A column `RETURNING` names, bare or
    /// qualified, reads as the value it is written, and a wildcard stays as
    /// written. `None` when a query nested in `RETURNING` names such a
    /// column.
    fn rows(self) -> Option<(Query, Write)> {
        let Self {
            visible,
            assigned,
            set,
            from,
            selection,
            returning,
            ..
        } = self;
        let returned = returning
            .into_iter()
            .map(|item| match item {
                SelectItem::UnnamedExpr(expression) => {
                    with_assigned(&expression, &assigned, Some(&visible))
                        .map(SelectItem::UnnamedExpr)
                }
                SelectItem::ExprWithAlias { expr, alias } => {
                    with_assigned(&expr, &assigned, Some(&visible))
                        .map(|expr| SelectItem::ExprWithAlias { expr, alias })
                }
                wildcard => Some(wildcard),
            })
            .collect::<Option<Vec<_>>>()?;
        let (columns, values): (Vec<String>, Vec<Expr>) = assigned.into_iter().unzip();
        let projection = values
            .into_iter()
            .map(SelectItem::UnnamedExpr)
            .chain(returned)
            .collect();
        Some((
            rows_query(projection, from, selection),
            Write::Update { columns, set },
        ))
    }
}

/// A record a trigger reads the written row through.
#[derive(Clone, Copy)]
enum Record {
    /// `OLD`, the row before the write.
    Old,
    /// `NEW`, the row the write writes.
    New,
}

/// What `maintenance` assigns each column, by its stored name, when it
/// fires, each field of `OLD` and `NEW` it reads read as `field` gives it by
/// the field's stored name. `None` when `field` gives none for one, or a
/// query nested in an assignment or in the condition reads either record.
fn maintained(
    maintenance: &Maintenance,
    field: impl Fn(Record, &str) -> Option<Expr>,
) -> Option<Vec<(String, Expr)>> {
    let unread = Cell::new(false);
    let row = |expression: &Expr| {
        let row = replaced(expression, |reference| {
            let Expr::CompoundIdentifier(parts) = reference else {
                return None;
            };
            let [record, name] = parts.as_slice() else {
                return None;
            };
            let record =
                match normalize_identifier(&record.value, record.quote_style.is_some()).as_ref() {
                    "old" => Record::Old,
                    "new" => Record::New,
                    _ => return None,
                };
            let read = field(
                record,
                &normalize_identifier(&name.value, name.quote_style.is_some()),
            );
            unread.set(unread.get() || read.is_none());
            read
        });
        row.filter(|_| !unread.get())
    };
    let condition = match &maintenance.condition {
        Some(condition) => Some(row(condition)?),
        None => None,
    };
    let mut folded = Vec::with_capacity(maintenance.assignments.len());
    for (column, value) in &maintenance.assignments {
        let mut value = row(value)?;
        if let Some(condition) = &condition {
            value = Expr::Case {
                case_token: AttachedToken::empty(),
                end_token: AttachedToken::empty(),
                operand: None,
                conditions: vec![CaseWhen {
                    condition: condition.clone(),
                    result: value,
                }],
                else_result: Some(Box::new(field(Record::New, column)?)),
            };
        }
        folded.push((column.clone(), value));
    }
    Some(folded)
}

/// What an `INSERT` writes a column it does not name.
enum Fill {
    /// Its default, or `NULL` without one, reading alike anywhere.
    Value(Box<Expr>),
    /// The value of an identity or generated column, which the rule does
    /// not follow.
    Opaque,
    /// A default that may evaluate otherwise for a caller than for the
    /// owner.
    Otherwise,
}

/// An `INSERT` into one table naming each column it writes.
struct Inserted {
    /// The name of the table it inserts into.
    target: ObjectName,
    /// The name its `RETURNING` qualifies the columns of that table by.
    visible: Ident,
    /// The stored name of each column it names.
    named: Vec<String>,
    /// The values each row it inserts writes the named columns with.
    rows: Vec<Vec<Expr>>,
    /// The query envelope and its detached `SELECT`, or `None` for `VALUES`.
    source: Option<(Box<Query>, Box<Select>)>,
    returning: Vec<SelectItem>,
}

impl Inserted {
    /// `insert`, when it inserts into one table the rows of a `VALUES` list
    /// or of one `SELECT`, naming each column it writes by its name, with no
    /// `ON CONFLICT`.
    fn new(insert: Insert) -> Option<Self> {
        let Insert {
            or: None,
            ignore: false,
            table: TableObject::TableName(target),
            table_alias,
            columns,
            by_name: false,
            overwrite: false,
            source: Some(mut source),
            assignments,
            partitioned: None,
            after_columns,
            overriding: None,
            on: None,
            returning,
            output: None,
            replace_into: false,
            priority: None,
            insert_alias: None,
            settings: None,
            format_clause: None,
            multi_table_insert_type: None,
            multi_table_into_clauses,
            multi_table_when_clauses,
            multi_table_else_clause: None,
            ..
        } = insert
        else {
            return None;
        };
        if columns.is_empty()
            || !assignments.is_empty()
            || !after_columns.is_empty()
            || !multi_table_into_clauses.is_empty()
            || !multi_table_when_clauses.is_empty()
        {
            return None;
        }
        let visible = match table_alias {
            Some(alias) => alias.alias,
            None => target.0.last()?.as_ident()?.clone(),
        };
        let named = columns
            .iter()
            .map(|column| match column.0.as_slice() {
                [ObjectNamePart::Identifier(column)] => Some(
                    normalize_identifier(&column.value, column.quote_style.is_some()).into_owned(),
                ),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        let plain = source.with.is_none()
            && source.order_by.is_none()
            && source.limit_clause.is_none()
            && source.fetch.is_none()
            && source.locks.is_empty();
        let body = mem::replace(
            source.body.as_mut(),
            SetExpr::Values(Values {
                explicit_row: false,
                value_keyword: false,
                rows: Vec::new(),
            }),
        );
        let (rows, source) = match body {
            SetExpr::Values(values) if plain => (
                values.rows.into_iter().map(|row| row.content).collect(),
                None,
            ),
            SetExpr::Select(mut select) => {
                let values = mem::take(&mut select.projection)
                    .into_iter()
                    .map(|item| match item {
                        SelectItem::UnnamedExpr(value)
                        | SelectItem::ExprWithAlias { expr: value, .. } => Some(value),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()?;
                (vec![values], Some((source, select)))
            }
            _ => return None,
        };
        Some(Self {
            target,
            visible,
            named,
            rows,
            source,
            returning: returning.unwrap_or_default(),
        })
    }

    /// `SELECT value…, returned…` of the rows the insert writes into
    /// `table`, those of its `SELECT` or the `UNION ALL` of one for each row
    /// of its `VALUES`, projecting the value it writes each column, with
    /// what its triggers `maintained` assign folded in, then what
    /// `RETURNING` returns, with how it writes them. `filled` gives what it
    /// writes the columns it does not name. A column `RETURNING` names reads
    /// as the value it is written, `NULL` for an identity or generated one,
    /// and a wildcard as every column. `None` when it names a column `table`
    /// lacks or one column twice, leaves a column to a default that may
    /// evaluate otherwise, a trigger reads `OLD` or a column of an identity
    /// or generated value, or a query nested in `RETURNING` names a column.
    fn rows<'a, DB: DatabaseLike>(
        self,
        table: &'a DB::Table,
        filled: Vec<(String, Fill)>,
        maintained_by: &[Maintenance],
    ) -> Option<(Query, Insertion<'a, DB>)> {
        let Self {
            visible,
            named,
            rows,
            source,
            returning,
            ..
        } = self;
        let order: Vec<String> = filled.iter().map(|(column, _)| column.clone()).collect();
        for (index, column) in named.iter().enumerate() {
            if !order.contains(column) || named[..index].contains(column) {
                return None;
            }
        }
        let mut defaults = Vec::new();
        let mut opaque = Vec::new();
        for (column, fill) in filled {
            if named.contains(&column) {
                continue;
            }
            match fill {
                Fill::Value(value) => defaults.push((column, *value)),
                Fill::Opaque => opaque.push(column),
                Fill::Otherwise => return None,
            }
        }
        let mut written = Vec::with_capacity(rows.len());
        for values in rows {
            if values.len() != named.len() {
                return None;
            }
            let row = named.iter().cloned().zip(values).collect();
            written.push(maintained_row(row, &defaults, maintained_by)?);
        }
        let columns: Vec<String> = written
            .first()?
            .iter()
            .map(|(column, _)| column.clone())
            .collect();
        defaults.retain(|(column, _)| !columns.contains(column));
        opaque.retain(|column| !columns.contains(column));
        let mut selects = Vec::with_capacity(written.len());
        for row in written {
            let full: Vec<(String, Expr)> = row
                .iter()
                .chain(&defaults)
                .cloned()
                .chain(
                    opaque
                        .iter()
                        .map(|column| (column.clone(), Expr::Value(Value::Null.into()))),
                )
                .collect();
            let mut projection: Vec<SelectItem> = row
                .into_iter()
                .map(|(_, value)| SelectItem::UnnamedExpr(value))
                .collect();
            projection.extend(returned_items(&returning, &full, &visible, &order)?);
            selects.push(projection);
        }
        let query = inserted_query(source, selects)?;
        Some((
            query,
            Insertion {
                rows: Vec::new(),
                table,
                columns,
                named: named.len(),
                defaults,
                opaque,
                returning: !returning.is_empty(),
            },
        ))
    }
}

/// `row`, the value an insert writes each column it names, with what each
/// trigger of `maintained_by` assigns folded in, `NEW` reading the row as
/// written so far and each other column as `defaults` gives it. `None` when
/// a trigger reads `OLD`, a column `defaults` lacks, or the row in a nested
/// query.
fn maintained_row(
    mut row: Vec<(String, Expr)>,
    defaults: &[(String, Expr)],
    maintained_by: &[Maintenance],
) -> Option<Vec<(String, Expr)>> {
    for maintenance in maintained_by {
        let folded = maintained(maintenance, |record, field| match record {
            Record::Old => None,
            Record::New => row
                .iter()
                .chain(defaults)
                .find(|(column, _)| column == field)
                .map(|(_, value)| Expr::Nested(Box::new(value.clone()))),
        })?;
        for (column, value) in folded {
            match row.iter_mut().find(|(held, _)| *held == column) {
                Some((_, held)) => *held = value,
                None => row.push((column, value)),
            }
        }
    }
    Some(row)
}

/// What `returning` returns of a row an insert writes each column of as
/// `full` gives it, each column a `RETURNING` item names, bare or qualified
/// by `visible`, read as its value, and a wildcard as every column in the
/// table's `order`. `None` when a query nested in an item names a column or
/// an item is another wildcard.
fn returned_items(
    returning: &[SelectItem],
    full: &[(String, Expr)],
    visible: &Ident,
    order: &[String],
) -> Option<Vec<SelectItem>> {
    let every = || {
        order
            .iter()
            .filter_map(|column| full.iter().find(|(held, _)| held == column))
            .map(|(_, value)| SelectItem::UnnamedExpr(Expr::Nested(Box::new(value.clone()))))
    };
    let mut returned = Vec::with_capacity(returning.len());
    for item in returning {
        match item {
            SelectItem::UnnamedExpr(expression) => returned.push(SelectItem::UnnamedExpr(
                with_assigned(expression, full, Some(visible))?,
            )),
            SelectItem::ExprWithAlias { expr, alias } => {
                returned.push(SelectItem::ExprWithAlias {
                    expr: with_assigned(expr, full, Some(visible))?,
                    alias: alias.clone(),
                });
            }
            SelectItem::Wildcard(_) => returned.extend(every()),
            SelectItem::QualifiedWildcard(
                SelectItemQualifiedWildcardKind::ObjectName(ObjectName(parts)),
                _,
            ) if matches!(parts.as_slice(), [ObjectNamePart::Identifier(named)] if same_name(named, visible)) =>
            {
                returned.extend(every());
            }
            _ => return None,
        }
    }
    Some(returned)
}

/// The query of the rows an insert writes, its `source` query projecting
/// the one projection of `selects`, or the `UNION ALL` of a `SELECT` of each
/// of them for the rows of a `VALUES` list.
fn inserted_query(
    source: Option<(Box<Query>, Box<Select>)>,
    selects: Vec<Vec<SelectItem>>,
) -> Option<Query> {
    if let Some((mut source, mut select)) = source {
        let [projection] = <[_; 1]>::try_from(selects).ok()?;
        select.projection = projection;
        *source.body = SetExpr::Select(select);
        return Some(*source);
    }
    let mut bodies = selects
        .into_iter()
        .map(|projection| rows_query(projection, Vec::new(), None));
    let mut query = bodies.next()?;
    for row in bodies {
        query.body = Box::new(SetExpr::SetOperation {
            op: SetOperator::Union,
            set_quantifier: SetQuantifier::All,
            left: query.body,
            right: row.body,
        });
    }
    Some(query)
}

/// A body's statement read as a query, with how it writes the rows of the
/// relation the query reads them from, or the `INSERT` of the rows it yields.
type Queried<'a, DB> = (Statement, Option<Write>, Option<Insertion<'a, DB>>);

/// An `INSERT` a body runs, read as the `SELECT`s of the rows it inserts.
struct Insertion<'a, DB: DatabaseLike> {
    /// The `SELECT` of each row it inserts, or of all of them.
    rows: Vec<*const Select>,
    /// The table it inserts into.
    table: &'a DB::Table,
    /// Each column it writes, by its stored name, as the expression each
    /// `SELECT` projects at the same position. The first `named` are those
    /// it names, the others those its triggers assign.
    columns: Vec<String>,
    named: usize,
    /// Each other column, by its stored name, with its default or `NULL`.
    defaults: Vec<(String, Expr)>,
    /// The other columns, of an identity or generated value.
    opaque: Vec<String>,
    /// Whether it has a `RETURNING`.
    returning: bool,
}

/// Collects the `SELECT`s outside nested queries through set operations.
fn selects(body: &SetExpr, found: &mut Vec<*const Select>) {
    if let SetExpr::SetOperation { left, right, .. } = body {
        selects(left, found);
        selects(right, found);
    } else {
        found.push(ptr::from_ref(
            body.as_select()
                .expect("inserted queries contain SELECT rows"),
        ));
    }
}

/// Whether `condition` names, bare or qualified, a column whose stored name
/// `columns` holds.
fn names_any(condition: &Expr, columns: &[String]) -> bool {
    !columns.is_empty()
        && visit_expressions(condition, |expression| {
            let name = match expression {
                Expr::Identifier(name) => Some(name),
                Expr::CompoundIdentifier(parts) => parts.last(),
                _ => None,
            };
            if name.is_some_and(|name| {
                let name = normalize_identifier(&name.value, name.quote_style.is_some());
                columns.iter().any(|column| *column == name)
            }) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .is_break()
}

/// `SELECT projection FROM from WHERE selection`, projecting `NULL` when
/// `projection` is empty.
fn rows_query(
    projection: Vec<SelectItem>,
    from: Vec<TableWithJoins>,
    selection: Option<Expr>,
) -> Query {
    let mut select = Parser::new(&PostgreSqlDialect {})
        .try_with_sql("SELECT NULL")
        .and_then(|mut parser| parser.parse_select())
        .expect("SELECT NULL parses");
    if !projection.is_empty() {
        select.projection = projection;
    }
    select.from = from;
    select.selection = selection;
    Query {
        with: None,
        body: Box::new(SetExpr::Select(Box::new(select))),
        order_by: None,
        limit_clause: None,
        fetch: None,
        locks: Vec::new(),
        for_clause: None,
        settings: None,
        format_clause: None,
        pipe_operators: Vec::new(),
    }
}

/// `condition`, over the stored names of a row's columns, tested on the row
/// with each column of `assigned` set to its value, or `None` when a query
/// nested in it names such a column, which may be a column of its own.
fn new_row(condition: &Expr, assigned: &[(String, Expr)]) -> Option<Expr> {
    with_assigned(condition, assigned, None)
}

/// `expression` with each column of `assigned` it names, bare or qualified
/// by `qualifier` when one is given, replaced by its value, or `None` when a
/// query nested in it names such a column.
fn with_assigned(
    expression: &Expr,
    assigned: &[(String, Expr)],
    qualifier: Option<&Ident>,
) -> Option<Expr> {
    replaced(expression, |reference| {
        let name = match reference {
            Expr::Identifier(name) => name,
            Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                [.., named, name] if qualifier.is_none_or(|visible| same_name(named, visible)) => {
                    name
                }
                _ => return None,
            },
            _ => return None,
        };
        let name = normalize_identifier(&name.value, name.quote_style.is_some());
        assigned
            .iter()
            .find(|(column, _)| *column == name)
            .map(|(_, value)| Expr::Nested(Box::new(value.clone())))
    })
}

/// `expression` with each expression `replacement` gives a replacement for
/// replaced by it, or `None` when one sits in a query nested in
/// `expression`.
fn replaced(expression: &Expr, replacement: impl Fn(&Expr) -> Option<Expr>) -> Option<Expr> {
    /// Replaces what `replacement` replaces outside nested queries.
    struct Replacing<F> {
        replacement: F,
        depth: usize,
    }
    impl<F: Fn(&Expr) -> Option<Expr>> VisitorMut for Replacing<F> {
        type Break = ();
        fn pre_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            self.depth += 1;
            ControlFlow::Continue(())
        }
        fn post_visit_query(&mut self, _query: &mut Query) -> ControlFlow<()> {
            self.depth -= 1;
            ControlFlow::Continue(())
        }
        fn post_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            let Some(replacement) = (self.replacement)(expression) else {
                return ControlFlow::Continue(());
            };
            if self.depth > 0 {
                return ControlFlow::Break(());
            }
            *expression = replacement;
            ControlFlow::Continue(())
        }
    }
    let mut replaced = expression.clone();
    let mut replacing = Replacing {
        replacement,
        depth: 0,
    };
    VisitMut::visit(&mut replaced, &mut replacing)
        .is_continue()
        .then_some(replaced)
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
    call_of(function, &arguments)
}

/// `SELECT schema.name(arguments)` calling `function`, its schema `public`
/// when its name has none.
fn call_of<F: FunctionLike>(function: &F, arguments: &[String]) -> Option<Box<Query>> {
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

/// The `SELECT` that `condition`, an `EXISTS` or `IN` over a query, finds
/// a row of that passes its `WHERE` whenever `condition` holds.
fn semi_join(condition: &Expr) -> Option<&Select> {
    witnessed(semi_joined(condition)?)
}

/// [`semi_join`] when its query holds no `WITH` of its own, so that each
/// name it reads resolves as it would around it.
fn unscoped_semi_join(condition: &Expr) -> Option<&Select> {
    semi_joined(condition)
        .filter(|query| query.with.is_none())
        .and_then(witnessed)
}

/// The query of `condition`, an `EXISTS` or `IN` that holds when it finds
/// a row.
fn semi_joined(condition: &Expr) -> Option<&Query> {
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
    Some(subquery)
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

/// `expression` with each column of a relation of `joined` it reads written
/// `"1.i".name` by the index `i` of the relation, each column [`term`]
/// states of `relation` written `"0".name` and each input parameter `$n`,
/// with whether it reads a column of `joined`, when it holds no subquery.
fn written_over_joined<DB: DatabaseLike>(
    resolver: &Resolver<'_, '_, '_, DB>,
    equalities: &Equalities<'_>,
    relation: &TableFactor,
    joined: &[*const TableFactor],
    expression: &Expr,
) -> Option<(Expr, bool)> {
    let qualified = |row: String, column: String| {
        Expr::CompoundIdentifier(vec![
            Ident::with_quote('"', row),
            Ident::with_quote('"', column),
        ])
    };
    let mut written = Vec::new();
    let mut reads_joined = false;
    let unwritable = visit_expressions(expression, |expression| {
        if matches!(
            expression,
            Expr::Subquery(_)
                | Expr::Exists { .. }
                | Expr::In {
                    target: InTarget::Subquery(_),
                    ..
                }
        ) {
            return ControlFlow::Break(());
        }
        if !is_column_reference(expression) {
            return ControlFlow::Continue(());
        }
        let joined_column = resolver
            .reference(expression)
            .and_then(|(_, binding)| match resolver.node(&binding)? {
                Node::Column { factor, name } => joined
                    .iter()
                    .position(|joined| ptr::eq(*joined, factor))
                    .map(|index| qualified(format!("1.{index}"), name.into_owned())),
                Node::Merged { .. } => None,
            });
        reads_joined |= joined_column.is_some();
        let column = joined_column.or_else(|| {
            Some(match term(resolver, expression, relation, equalities)? {
                Term::Column(name) => qualified("0".to_owned(), name),
                Term::Parameter(ordinal) => parameter(ordinal),
            })
        });
        match column {
            Some(column) => {
                written.push(column);
                ControlFlow::Continue(())
            }
            None => ControlFlow::Break(()),
        }
    });
    if unwritable.is_break() {
        return None;
    }
    let mut written = written.into_iter();
    let mut rewritten = expression.clone();
    let _ = visit_expressions_mut(&mut rewritten, |expression| {
        if is_column_reference(expression)
            && let Some(column) = written.next()
        {
            *expression = column;
        }
        ControlFlow::<()>::Continue(())
    });
    Some((rewritten, reads_joined))
}

/// The value `call` returns as its function's body writes it, when `call`
/// passes nothing to one schema function [`CallerBound::invoked_alike`]
/// accepts, whose body selects a cast to its declared type or a call of a
/// function declared to return that type, every name of which means alike
/// wherever it is written.
fn helper_value<DB: DatabaseLike>(
    confinement: &Confinement<'_, DB>,
    call: &Function,
) -> Option<Expr> {
    let database = confinement.database;
    if !matches!(&call.args, FunctionArguments::List(list) if list.args.is_empty() && list.clauses.is_empty())
        || call.filter.is_some()
        || call.over.is_some()
    {
        return None;
    }
    let [function] = reached(database, call)?[..] else {
        return None;
    };
    if function.target_name().schema() == Some("pg_catalog")
        || function.returns_set()
        || !CallerBound::new(confinement, None, None)
            .invoked_alike(function)
            .ok()?
    {
        return None;
    }
    let declared = function.normalized_return_type_name(database)?;
    let query = sql_query_body(database, function).ok()??;
    let value = selected_expression(&query)?;
    let typed = match value {
        Expr::Cast {
            kind: CastKind::Cast | CastKind::DoubleColon,
            data_type,
            ..
        } => normalize_postgres_type(&data_type.to_string()) == declared,
        Expr::Function(inner) => reached(database, inner).is_some_and(|functions| {
            !functions.is_empty()
                && functions.iter().all(|function| {
                    function.normalized_return_type_name(database).as_ref() == Some(&declared)
                })
        }),
        _ => false,
    };
    (typed && reads_alike_anywhere(database, value)).then(|| value.clone())
}

/// The functions `call` may reach.
fn reached<'a, DB: DatabaseLike>(
    database: &'a DB,
    call: &Function,
) -> Option<Vec<&'a DB::Function>> {
    database
        .functions_reached_by(call, IdentifierCase::Folded)
        .ok()
        .map(Iterator::collect)
}

/// Whether `value` calls a function that may be `VOLATILE`, whose result a
/// policy evaluating the call again need not see.
fn calls_volatile<DB: DatabaseLike>(database: &DB, value: &Expr) -> bool {
    visit_expressions(value, |expression| match expression {
        Expr::Function(call)
            if !reached(database, call).is_some_and(|functions| {
                !functions.is_empty()
                    && functions
                        .iter()
                        .all(|function| function.volatility() != FunctionBehavior::Volatile)
            }) =>
        {
            ControlFlow::Break(())
        }
        _ => ControlFlow::Continue(()),
    })
    .is_break()
}

/// Whether every name `value` holds means alike wherever it is written: it
/// reads no column or query, and every call and cast is one
/// [`named_alike_anywhere`] accepts.
fn reads_alike_anywhere<DB: DatabaseLike>(database: &DB, value: &Expr) -> bool {
    visit_expressions(value, |expression| {
        let anywhere = !matches!(
            expression,
            Expr::Identifier(_)
                | Expr::CompoundIdentifier(_)
                | Expr::Subquery(_)
                | Expr::Exists { .. }
                | Expr::In {
                    target: InTarget::Subquery(_),
                    ..
                }
        ) && named_alike_anywhere(database, expression);
        if anywhere {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
    })
    .is_continue()
}

/// Whether every name `query` writes means alike on any search path: each
/// relation is written schema-qualified, and each call and cast is one
/// [`named_alike_anywhere`] accepts.
fn names_alike_anywhere<DB: DatabaseLike>(database: &DB, query: &Query) -> bool {
    let qualified = |relation: &ObjectName| {
        if relation.0.len() > 1 {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
    };
    visit_relations(query, qualified).is_continue()
        && visit_expressions(query, |expression| {
            if named_alike_anywhere(database, expression) {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        })
        .is_continue()
}

/// Whether `expression`, when a call or a cast, names alike on any search
/// path: it casts to no type the path picks and calls a function written
/// schema-qualified or reaching only `pg_catalog`.
fn named_alike_anywhere<DB: DatabaseLike>(database: &DB, expression: &Expr) -> bool {
    match expression {
        Expr::Cast { data_type, .. } => match data_type {
            DataType::Regclass => false,
            DataType::Custom(name, _) => name.0.len() > 1,
            _ => true,
        },
        Expr::Function(call) => {
            call.name.0.len() > 1
                || reached(database, call).is_some_and(|functions| {
                    functions
                        .iter()
                        .all(|function| function.target_name().schema() == Some("pg_catalog"))
                })
        }
        _ => true,
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
