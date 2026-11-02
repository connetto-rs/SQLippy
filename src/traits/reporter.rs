//! Submodule defining the `Reporter` through which rules raise violations.

use std::ops::ControlFlow;

use sql_traits::traits::{ColumnLike, DatabaseLike, ForeignKeyLike, PolicyLike, TableLike};

use crate::{
    deployment::Deployment,
    error::{Error, Interruption, Location, PolicySite, Violation},
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

/// Receives the violations of one rule and stamps them with its identity and
/// effective level.
pub struct Reporter<'run, DB: DatabaseLike> {
    database: &'run DB,
    deployment: &'run Deployment,
    rule: &'static RuleMetadata,
    level: Level,
    allowances: &'run [ResolvedAllowance<'run, DB>],
    used: &'run mut [bool],
    sink: &'run mut dyn FnMut(Error<DB>) -> ControlFlow<()>,
}

impl<'run, DB: DatabaseLike> Reporter<'run, DB> {
    pub(crate) fn new(
        database: &'run DB,
        deployment: &'run Deployment,
        rule: &'static RuleMetadata,
        level: Level,
        allowances: &'run [ResolvedAllowance<'run, DB>],
        used: &'run mut [bool],
        sink: &'run mut dyn FnMut(Error<DB>) -> ControlFlow<()>,
    ) -> Self {
        Self {
            database,
            deployment,
            rule,
            level,
            allowances,
            used,
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
        for (allowance, used) in self.allowances.iter().zip(self.used.iter_mut()) {
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
