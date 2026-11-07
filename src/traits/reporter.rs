//! Submodule defining the `Reporter` through which rules raise violations.

use std::ops::ControlFlow;

use sql_traits::traits::{
    ColumnLike, DatabaseLike, DomainLike, ExtensionLike, ForeignKeyLike, FunctionLike, PolicyLike,
    RoleLike, SequenceLike, TableLike, ViewLike,
};
use sqlparser::ast::Statement;

use crate::{
    deployment::Deployment,
    error::{
        Error, Interruption, Location, PolicySite, StatementAllowance, StatementSite, Violation,
    },
    lint::{Level, RuleMetadata},
};

/// A policy allowance whose table was resolved against the schema.
pub(crate) struct ResolvedAllowance<'db, DB: DatabaseLike> {
    pub(crate) rule: &'db str,
    pub(crate) table: Option<&'db DB::Table>,
    pub(crate) policy: &'db str,
}

impl<DB: DatabaseLike> ResolvedAllowance<'_, DB> {
    fn excuses(&self, rule: &RuleMetadata, site: &PolicySite<DB>) -> bool {
        self.rule == rule.name
            && self.table == Some(site.table.as_ref())
            && self.policy == site.policy.name()
    }
}

/// The allowances a reporter consults, and which policy allowances excused a
/// violation so far.
pub(crate) struct Allowances<'run, DB: DatabaseLike> {
    pub(crate) policies: &'run [ResolvedAllowance<'run, DB>],
    pub(crate) used: &'run mut [bool],
    pub(crate) statements: &'run [StatementAllowance],
}

/// A function's name with its argument types as written, which tells overloads
/// apart.
pub(crate) fn signature<DB: DatabaseLike>(function: &DB::Function, database: &DB) -> String {
    let arguments: Vec<_> = function.argument_type_names(database).collect();
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
        let mut excused = false;
        let allowances = &mut self.allowances;
        for (allowance, used) in allowances.policies.iter().zip(allowances.used.iter_mut()) {
            if sites.iter().any(|site| allowance.excuses(self.rule, site)) {
                *used = true;
                excused = true;
            }
        }
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

    /// Reports a violation on a table.
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

    /// Reports a violation on a foreign key.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn foreign_key(
        &mut self,
        foreign_key: &DB::ForeignKey,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let host = foreign_key.host_table(self.database).table_name();
        let object = match foreign_key.foreign_key_name() {
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

    /// Reports a violation on a function, named with its argument types so
    /// overloads stay apart.
    ///
    /// # Errors
    ///
    /// Returns [`Interruption::Halted`] when the caller needs no further
    /// violations.
    pub fn function(
        &mut self,
        function: &DB::Function,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        let object = signature(function, self.database);
        self.emit(
            Location::Function(Box::new(function.clone())),
            object,
            message,
            resolution,
        )
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
