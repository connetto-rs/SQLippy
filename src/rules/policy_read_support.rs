//! The tables a policy clause reads through its sublinks, the views they read
//! and the functions it calls, each with the role whose policies apply there.

use std::{collections::BTreeSet, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    traits::{
        DataStatementLike, DatabaseLike, FunctionLike, PolicyLike, Relation, RoleLike, TableLike,
        ViewLike,
    },
};
use sqlparser::ast::{Expr, FunctionSecurity, Query, Visit, Visitor};

use crate::rules::{
    function_rules::unreadable_body, policy_support::held_by_name, walk_support::walk,
};

/// The roles a querying role holds the privileges of.
#[derive(Clone, PartialEq)]
pub(crate) enum Holder {
    /// Every policy applies, whatever its roles.
    Everyone,
    /// The named roles, empty for a role the schema does not declare.
    Roles(BTreeSet<String>),
}

/// The role whose policies apply to a read.
#[derive(Clone, PartialEq)]
pub(crate) enum Checker {
    /// The role the expansion runs as when the clause reads the table.
    Current,
    /// The querying role, through views that run with their reader's rights.
    Caller,
    /// The owner of a view or function that runs with its owner's rights.
    Owner(Holder),
}

/// The rights a view or function reads its relations with.
enum Rights<'db> {
    /// The reader's, for a view with `security_invoker` or an invoker function.
    Reader,
    /// Those of the named owner, which sql-traits reports as PostgreSQL stores it.
    Owner(&'db str),
    /// Those of an owner that bypasses row-level security or that the schema does not name.
    Bypassing,
}

impl<'db> Rights<'db> {
    /// The rights of an owner, or of the reader when the object takes them.
    fn of<DB: DatabaseLike>(database: &'db DB, reader: bool, owner: Option<&'db str>) -> Self {
        // An owner the schema does not name is whoever ran it, which may bypass every policy.
        match owner {
            _ if reader => Self::Reader,
            Some(owner) => match database.role(owner) {
                Some(role) if role.can_bypass_rls() || role.is_superuser() => Self::Bypassing,
                _ => Self::Owner(owner),
            },
            None => Self::Bypassing,
        }
    }
}

/// The roles checked where a read happens, for its direct table reads and for
/// the views it reads with their reader's rights, `None` inside a function
/// whose rights bypass every policy.
#[derive(Clone)]
struct Context {
    tables: Option<Checker>,
    readers: Option<Checker>,
}

impl Context {
    const SUBLINK: Self = Self {
        tables: Some(Checker::Current),
        readers: Some(Checker::Caller),
    };
    const BYPASSING: Self = Self {
        tables: None,
        readers: None,
    };
}

/// A base table read by a sublink of a policy clause or by a function it calls.
pub(crate) struct Read<'db, DB: DatabaseLike> {
    pub(crate) table: &'db DB::Table,
    /// The role whose policies apply to the read, `None` when it reads past
    /// them.
    pub(crate) checker: Option<Checker>,
    /// The sublink or call the clause reads the table through.
    pub(crate) via: String,
    /// Whether the read happens inside a called function.
    pub(crate) call: bool,
}

/// Collects the base tables read by the outermost query of every sublink of an
/// expression, so nested queries are resolved within their enclosing `WITH`,
/// and the tables read by every function the expression calls.
struct SublinkReads<'db, DB: DatabaseLike> {
    database: &'db DB,
    policy: &'db DB::Policy,
    depth: usize,
    found: bool,
    reads: Vec<Read<'db, DB>>,
}

impl<'db, DB: DatabaseLike> SublinkReads<'db, DB> {
    fn push(&mut self, table: &'db DB::Table, checker: Option<Checker>, via: &str, call: bool) {
        self.found |= call && checker.is_some();
        if !self
            .reads
            .iter()
            .any(|read| read.table == table && read.checker == checker && read.call == call)
        {
            self.reads.push(Read {
                table,
                checker,
                via: via.to_owned(),
                call,
            });
        }
    }

    /// Adds a table read with `rights`, past its policies when an owner
    /// bypasses them.
    fn table(
        &mut self,
        table: &'db DB::Table,
        rights: &Rights<'db>,
        context: &Context,
        via: &str,
        call: bool,
    ) -> Result<(), LookupError> {
        let checker = match *rights {
            Rights::Reader => context.readers.clone(),
            Rights::Owner(owner) if context.tables.is_some() => {
                let owns = table.owner(self.database)? == Some(owner);
                (!owns || table.has_forced_row_level_security(self.database)?)
                    .then(|| Checker::Owner(Holder::Roles(held_by_name(self.database, owner))))
            }
            Rights::Owner(_) | Rights::Bypassing => None,
        };
        self.push(table, checker, via, call);
        Ok(())
    }

    /// Adds the base tables a view reads, each with the role checked on it.
    ///
    /// A view nested in it decides its own rights, so it is followed even when
    /// this view's owner reads its tables past their policies.
    fn view(
        &mut self,
        view: &'db DB::View,
        context: &Context,
        via: &str,
        call: bool,
    ) -> Result<(), LookupError> {
        let database = self.database;
        let rights = Rights::of(database, view.is_security_invoker(), view.owner(database)?);
        for relation in DataStatementLike::<DB>::referenced_relations(view.definition(), database)?
        {
            match relation {
                Relation::View(inner) => self.view(inner, context, via, call)?,
                Relation::Table(table) => self.table(table, &rights, context, via, call)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Adds the tables a called function reads, through views and the
    /// functions it calls, each with the role its rights check.
    fn function(
        &mut self,
        function: &'db DB::Function,
        context: &Context,
        via: &str,
        visited: &mut Vec<&'db DB::Function>,
    ) -> Result<(), LookupError> {
        if visited.contains(&function) {
            return Ok(());
        }
        visited.push(function);
        let database = self.database;
        let invoker = function.security_mode() != FunctionSecurity::Definer;
        let rights = Rights::of(database, invoker, function.owner(database)?);
        let (inner, owner) = match rights {
            _ if context.tables.is_none() => (Context::BYPASSING, None),
            Rights::Reader => (context.clone(), None),
            Rights::Owner(owner) => {
                let checker = Checker::Owner(Holder::Roles(held_by_name(database, owner)));
                let inner = Context {
                    tables: Some(checker.clone()),
                    readers: Some(checker),
                };
                (inner, Some(owner))
            }
            Rights::Bypassing => (Context::BYPASSING, None),
        };
        let relations = match function.referenced_relations(database) {
            Err(error) if unreadable_body(&error) => Vec::new(),
            relations => relations?,
        };
        for relation in relations {
            match (relation, owner) {
                (Relation::View(view), _) => self.view(view, &inner, via, true)?,
                (Relation::Table(table), None) => {
                    self.push(table, inner.tables.clone(), via, true);
                }
                (Relation::Table(table), Some(owner)) => {
                    self.table(table, &Rights::Owner(owner), &inner, via, true)?;
                }
                _ => {}
            }
        }
        let called = match function.referenced_functions(database) {
            Err(error) if unreadable_body(&error) => Vec::new(),
            called => called?,
        };
        for called in called {
            self.function(called, &inner, via, visited)?;
        }
        Ok(())
    }

    /// Adds the tables the outermost query of a sublink reads, through views.
    fn query(&mut self, query: &Query) -> Result<(), LookupError> {
        let via = query.to_string();
        for relation in DataStatementLike::<DB>::referenced_relations(query, self.database)? {
            match relation {
                Relation::Table(table) => self.push(table, Some(Checker::Current), &via, false),
                Relation::View(view) => self.view(view, &Context::SUBLINK, &via, false)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Adds the tables read by every function a call in the clause may reach.
    fn call(&mut self, expression: &Expr) -> Result<(), LookupError> {
        let Expr::Function(call) = expression else {
            return Ok(());
        };
        let via = expression.to_string();
        for function in self.policy.functions_reached_by(call, self.database)? {
            self.function(function, &Context::SUBLINK, &via, &mut Vec::new())?;
        }
        Ok(())
    }
}

impl<DB: DatabaseLike> Visitor for SublinkReads<'_, DB> {
    type Break = LookupError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<LookupError> {
        self.depth += 1;
        if self.depth > 1 {
            return ControlFlow::Continue(());
        }
        self.found = true;
        self.query(query)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<LookupError> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        self.call(expression)
            .map_or_else(ControlFlow::Break, ControlFlow::Continue)
    }
}

/// Returns whether the node holds a sublink or a call that reads a table
/// past no policy, and every table it reads, past policies or not. A query
/// passed as the node is read as a sublink.
pub(crate) fn sublink_reads<'db, DB: DatabaseLike, N: Visit + ?Sized>(
    database: &'db DB,
    policy: &'db DB::Policy,
    node: Option<&N>,
) -> Result<(bool, Vec<Read<'db, DB>>), LookupError> {
    let Some(node) = node else {
        return Ok((false, Vec::new()));
    };
    let mut collector = SublinkReads {
        database,
        policy,
        depth: 0,
        found: false,
        reads: Vec::new(),
    };
    if let ControlFlow::Break(error) = walk(node, &mut collector) {
        return Err(error);
    }
    Ok((collector.found, collector.reads))
}
