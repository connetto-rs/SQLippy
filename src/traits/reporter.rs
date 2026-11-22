//! Submodule defining the `Reporter` through which rules raise violations.

use std::{borrow::Cow, ops::ControlFlow};

use sql_traits::{
    errors::LookupError,
    structs::{DefaultPrivilege, RoleSetting},
    traits::{
        ColumnLike, DatabaseLike, DomainLike, ExtensionLike, ForeignKeyLike, FunctionLike,
        IndexLike, PolicyLike, RoleLike, RoleMembershipLike, SequenceLike, TableIndexLike,
        TableLike, UserDefinedTypeLike, ViewLike,
    },
};
use sqlparser::ast::{ArgMode, Statement};

use crate::{
    deployment::Deployment,
    error::{
        AllowedObject, Error, FunctionAllowance, Interruption, Location, PolicySite,
        StatementAllowance, StatementSite, Violation,
    },
    lint::{Level, RuleMetadata},
};

/// A schema allowance whose table was resolved against the schema.
pub(crate) struct ResolvedAllowance<'db, DB: DatabaseLike> {
    pub(crate) rule: &'db str,
    pub(crate) table: Option<&'db DB::Table>,
    pub(crate) object: &'db AllowedObject,
}

/// The allowances a reporter consults, and which schema allowances excused a
/// violation so far.
pub(crate) struct Allowances<'run, DB: DatabaseLike> {
    pub(crate) schema: &'run [ResolvedAllowance<'run, DB>],
    pub(crate) used: &'run mut [bool],
    pub(crate) statements: &'run [StatementAllowance],
    pub(crate) functions: &'run [FunctionAllowance],
    pub(crate) functions_used: &'run mut [bool],
}

/// The name an index allowance matches: the index's constraint name, else
/// the name written for it.
///
/// # Errors
///
/// Returns a [`LookupError`] when `database` does not hold the index's table.
pub(crate) fn index_name<'db, I: IndexLike>(
    index: &'db I,
    database: &'db I::DB,
) -> Result<Option<Cow<'db, str>>, LookupError> {
    Ok(index
        .constraint_name(database)?
        .or_else(|| index.name().map(Cow::Borrowed)))
}

/// A function's name with the types of its input arguments as written, which
/// PostgreSQL identifies it by and tells overloads apart.
pub(crate) fn signature<DB: DatabaseLike>(function: &DB::Function, database: &DB) -> String {
    let arguments: Vec<_> = function
        .argument_modes()
        .zip(function.argument_type_names(database))
        .filter(|(mode, _)| *mode != ArgMode::Out)
        .map(|(_, name)| name)
        .collect();
    format!("{}({})", function.name(), arguments.join(", "))
}

/// Receives the violations of one rule and stamps them with its identity and
/// effective level.
pub struct Reporter<'run, DB: DatabaseLike> {
    database: &'run DB,
    deployment: &'run Deployment,
    rule: &'static RuleMetadata,
    level: Level,
    allowances: Allowances<'run, DB>,
    sink: &'run mut dyn FnMut(Error<DB>) -> ControlFlow<()>,
}

impl<'run, DB: DatabaseLike> Reporter<'run, DB> {
    pub(crate) fn new(
        database: &'run DB,
        deployment: &'run Deployment,
        rule: &'static RuleMetadata,
        level: Level,
        allowances: Allowances<'run, DB>,
        sink: &'run mut dyn FnMut(Error<DB>) -> ControlFlow<()>,
    ) -> Self {
        Self {
            database,
            deployment,
            rule,
            level,
            allowances,
            sink,
        }
    }

    /// Returns the deployment the constrainer was configured with.
    #[must_use]
    pub fn deployment(&self) -> &'run Deployment {
        self.deployment
    }

    /// Reports a violation spanning policy clauses, listed in traversal order,
    /// unless an allowance for this rule names one of their policies.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn policies(
        &mut self,
        sites: Vec<PolicySite<DB>>,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let excused = self.excused(|allowance| {
            sites.iter().any(|site| {
                allowance.table == Some(site.table.as_ref())
                    && matches!(allowance.object, AllowedObject::Policy(policy) if policy == site.policy.name())
            })
        });
        if excused {
            return Ok(());
        }
        let object = sites
            .iter()
            .map(|site| format!("{}.{}", site.table.table_name(), site.policy.name()))
            .collect::<Vec<_>>()
            .join(" -> ");
        self.emit(Location::Policies(sites), object, message, resolution)
    }

    /// Reports a violation on a sub-expression of a statement, unless a
    /// statement allowance for this rule names the same statement.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn statement(
        &mut self,
        statement: &Statement,
        expression: String,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let statement = statement.to_string();
        if self
            .allowances
            .statements
            .iter()
            .any(|allowance| allowance.excuses(self.rule, &statement))
        {
            return Ok(());
        }
        let object = expression.clone();
        self.emit(
            Location::Statement(StatementSite {
                statement,
                expression,
            }),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a table, unless an allowance for this rule
    /// names the table.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn table(
        &mut self,
        table: &DB::Table,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        if self.excused(|allowance| {
            allowance.table == Some(table) && *allowance.object == AllowedObject::Table
        }) {
            return Ok(());
        }
        let object = table.table_name().to_owned();
        self.emit(
            Location::Table(Box::new(table.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a column.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn column(
        &mut self,
        column: &DB::Column,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = format!(
            "{}.{}",
            column.table(self.database).table_name(),
            column.column_name()
        );
        self.emit(
            Location::Column(Box::new(column.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a foreign key, named by its constraint name,
    /// unless an allowance for this rule names that constraint.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Lookup`] when the key's table is not in the
    /// schema, and [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn foreign_key(
        &mut self,
        foreign_key: &DB::ForeignKey,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let host = foreign_key.host_table(self.database);
        let name = foreign_key.constraint_name(self.database)?;
        if self.excused(|allowance| {
            allowance.table == Some(host)
                && matches!(allowance.object, AllowedObject::ForeignKey(allowed) if Some(allowed.as_str()) == name.as_deref())
        }) {
            return Ok(());
        }
        let host = host.table_name();
        let object = match name {
            Some(name) => format!("{host}.{name}"),
            None => format!("{host} (unnamed foreign key)"),
        };
        self.emit(
            Location::ForeignKey(Box::new(foreign_key.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a unique constraint, unless an allowance for
    /// this rule names it.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Lookup`] when the constraint's table or
    /// columns are not in the schema, and [`Interruption::Halted`] when the
    /// caller needs no further violations.
    pub fn unique_index(
        &mut self,
        index: &DB::UniqueIndex,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        self.indexed(
            index,
            |index| Location::UniqueIndex(Box::new(index.clone())),
            message,
            resolution,
        )
    }

    /// Reports a violation on an index created with `CREATE INDEX`, unless an
    /// allowance for this rule names it.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Lookup`] when the index's table or columns are
    /// not in the schema, and [`Interruption::Halted`] when the caller needs
    /// no further violations.
    pub fn index(
        &mut self,
        index: &DB::Index,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        self.indexed(
            index,
            |index| Location::Index(Box::new(index.clone())),
            message,
            resolution,
        )
    }

    /// Reports a violation on `index`, named by [`index_name`] or else by its
    /// columns, unless an allowance for this rule names it.
    fn indexed<I: TableIndexLike<DB = DB>>(
        &mut self,
        index: &I,
        location: impl FnOnce(&I) -> Location<DB>,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let table = index.table(self.database);
        let name = index_name(index, self.database)?;
        if self.excused(|allowance| {
            allowance.table == Some(table)
                && matches!(allowance.object, AllowedObject::Index(allowed) if Some(allowed.as_str()) == name.as_deref())
        }) {
            return Ok(());
        }
        let object = if let Some(name) = name {
            format!("{}.{name}", table.table_name())
        } else {
            let columns: Vec<&str> = index
                .columns(self.database)?
                .map(ColumnLike::column_name)
                .collect();
            format!("{} ({})", table.table_name(), columns.join(", "))
        };
        self.emit(location(index), object, message, resolution)
    }

    /// Reports a violation on a view.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn view(
        &mut self,
        view: &DB::View,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = view.view_name().to_owned();
        self.emit(
            Location::View(Box::new(view.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a materialized view.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn materialized_view(
        &mut self,
        view: &DB::MaterializedView,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = view.view_name().to_owned();
        self.emit(
            Location::MaterializedView(Box::new(view.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a role.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn role(
        &mut self,
        role: &DB::Role,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = role.name().to_owned();
        self.emit(
            Location::Role(Box::new(role.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a membership of one role in another, under
    /// the name `role TO member`.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn role_membership(
        &mut self,
        membership: &DB::RoleMembership,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = format!("{} TO {}", membership.role_name(), membership.member_name());
        self.emit(
            Location::RoleMembership(Box::new(membership.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on an `ALTER ROLE ... SET` entry, under the name
    /// `role SET name`, with `ALL` for an entry of every role.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn role_setting(
        &mut self,
        setting: &RoleSetting,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = format!("{} SET {}", setting.role().unwrap_or("ALL"), setting.name());
        self.emit(
            Location::RoleSetting(setting.clone()),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a standing `ALTER DEFAULT PRIVILEGES` entry,
    /// under the name `object` gives it.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn default_privilege(
        &mut self,
        entry: &DefaultPrivilege<'_>,
        object: String,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        self.emit(
            Location::DefaultPrivilege(entry.clone().into_owned()),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a domain.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn domain(
        &mut self,
        domain: &DB::Domain,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = domain.name().to_owned();
        self.emit(
            Location::Domain(Box::new(domain.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a user-defined type.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn user_defined_type(
        &mut self,
        user_defined_type: &DB::UserDefinedType,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = user_defined_type.name().to_owned();
        self.emit(
            Location::UserDefinedType(Box::new(user_defined_type.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a grant, under the name of the object it
    /// grants on.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn grant(
        &mut self,
        grant: &DB::TableGrant,
        object: String,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        self.emit(
            Location::Grant(Box::new(grant.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on an extension.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn extension(
        &mut self,
        extension: &DB::Extension,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = extension.name().to_owned();
        self.emit(
            Location::Extension(Box::new(extension.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation on a sequence.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn sequence(
        &mut self,
        sequence: &DB::Sequence,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = sequence.sequence_name().to_owned();
        self.emit(
            Location::Sequence(Box::new(sequence.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Reports a violation in a function's definition, named with its
    /// argument types so overloads stay apart.
    ///
    /// A function an extension creates is skipped, since its install script
    /// owns the definition. PostgreSQL refuses to drop it, and the next
    /// `ALTER EXTENSION ... UPDATE` overwrites any `ALTER FUNCTION` on it.
    /// A violation the schema fixes with a `GRANT` or `REVOKE` goes through
    /// [`Self::function_privilege`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Lookup`] when `database` does not hold the
    /// function, and [`Interruption::Halted`] when the caller needs no
    /// further violations.
    pub fn function(
        &mut self,
        function: &DB::Function,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        if function.extension(self.database)?.is_some() {
            return Ok(());
        }
        self.function_privilege(function, message, resolution)
    }

    /// Reports a violation the schema fixes through the privileges on a
    /// function, such as `EXECUTE` held by a role that should not call it,
    /// named with its argument types so overloads stay apart.
    ///
    /// Unlike [`Self::function`], this reports a function an extension
    /// creates as well, whose privileges the schema grants and revokes.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn function_privilege(
        &mut self,
        function: &DB::Function,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let mut excused = false;
        for (allowance, used) in self
            .allowances
            .functions
            .iter()
            .zip(self.allowances.functions_used.iter_mut())
        {
            if allowance.excuses(self.rule, &function.target_name()) {
                *used = true;
                excused = true;
            }
        }
        if excused {
            return Ok(());
        }
        let object = signature(function, self.database);
        self.emit(
            Location::Function(Box::new(function.clone())),
            object,
            message,
            resolution,
        )
    }

    /// Marks every schema allowance for this rule that `accepts` takes as
    /// used, and returns whether there was one.
    fn excused(&mut self, accepts: impl Fn(&ResolvedAllowance<'run, DB>) -> bool) -> bool {
        let mut any = false;
        let allowances = &mut self.allowances;
        for (allowance, used) in allowances.schema.iter().zip(allowances.used.iter_mut()) {
            if allowance.rule == self.rule.name && accepts(allowance) {
                *used = true;
                any = true;
            }
        }
        any
    }

    fn emit(
        &mut self,
        location: Location<DB>,
        object: String,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let violation = Violation {
            rule: self.rule,
            level: self.level,
            location,
            object,
            message,
            resolution,
        };
        match (self.sink)(Error::Violation(Box::new(violation))) {
            ControlFlow::Continue(()) => Ok(()),
            ControlFlow::Break(()) => Err(Interruption::Halted),
        }
    }
}
