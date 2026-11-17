//! Submodule providing the `TypeNameCaseCollision` rule.

use std::{borrow::Cow, collections::BTreeMap};

use sql_traits::traits::{DatabaseLike, DomainLike, TableLike, UserDefinedTypeLike, ViewLike};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

schema_rule!(
    /// Struct defining a rule that reports two objects of one schema whose
    /// names come from its pool of type names and differ only by case.
    ///
    /// The pool holds every user-defined type, of any kind, every domain and
    /// the row type of every table, view and materialized view. A name
    /// without a schema lands in `public`. Each colliding pair is reported
    /// once, on one of its objects, with a message naming both.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = TypeNameCaseCollision::default().into();
    /// let colliding = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TYPE \"Mood\" AS ENUM ('sad'); CREATE TYPE mood AS ENUM ('happy');",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&colliding).is_err());
    /// let apart = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE SCHEMA app; CREATE TYPE app.\"Mood\" AS ENUM ('sad'); CREATE TYPE mood AS ENUM ('happy');",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&apart).is_ok());
    /// ```
    TypeNameCaseCollision,
    LintGroup::Correctness,
    "PostgreSQL keeps the case of a quoted name and folds an unquoted one, so two types whose names differ only by case are told apart by quoting alone, and every tool that maps names without case merges them.",
    Some("https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS"),
    RuleExample {
        bad: "CREATE TYPE \"Mood\" AS ENUM ('sad'); CREATE TYPE mood AS ENUM ('happy');",
        good: "CREATE TYPE mood AS ENUM ('sad', 'happy');",
    }
);

/// An object whose name PostgreSQL takes from its schema's pool of type
/// names.
enum TypeNamed<'db, DB: DatabaseLike> {
    Type(&'db DB::UserDefinedType),
    Domain(&'db DB::Domain),
    Table(&'db DB::Table),
    View(&'db DB::View),
    MaterializedView(&'db DB::MaterializedView),
}

impl<'db, DB: DatabaseLike> TypeNamed<'db, DB> {
    /// What the object is, in lower case.
    fn kind(&self) -> &'static str {
        match self {
            Self::Type(_) => "type",
            Self::Domain(_) => "domain",
            Self::Table(_) => "table",
            Self::View(_) => "view",
            Self::MaterializedView(_) => "materialized view",
        }
    }

    /// The name as written and whether it was quoted.
    fn written_name(&self) -> (&'db str, bool) {
        match *self {
            Self::Type(user_type) => (user_type.name(), user_type.name_is_quoted()),
            Self::Domain(domain) => (domain.name(), domain.name_is_quoted()),
            Self::Table(table) => (table.table_name(), table.table_name_is_quoted()),
            Self::View(view) => (view.view_name(), view.view_name_is_quoted()),
            Self::MaterializedView(view) => (view.view_name(), view.view_name_is_quoted()),
        }
    }

    /// The name as written, in double quotes when it was quoted.
    fn written(&self) -> String {
        match self.written_name() {
            (name, true) => format!("\"{name}\""),
            (name, false) => name.to_owned(),
        }
    }

    /// The name PostgreSQL stores.
    fn stored_name(&self) -> Cow<'db, str> {
        match *self {
            Self::Type(user_type) => user_type.stored_name(),
            Self::Domain(domain) => domain.stored_name(),
            Self::Table(table) => table.stored_table_name(),
            Self::View(view) => view.stored_view_name(),
            Self::MaterializedView(view) => view.stored_view_name(),
        }
    }

    /// The schema PostgreSQL stores the object in, `public` when the name
    /// names none.
    fn stored_schema(&self) -> Cow<'db, str> {
        match *self {
            Self::Type(user_type) => user_type.stored_schema(),
            Self::Domain(domain) => domain.stored_schema(),
            Self::Table(table) => table.stored_table_schema(),
            Self::View(view) => view.stored_view_schema(),
            Self::MaterializedView(view) => view.stored_view_schema(),
        }
        .unwrap_or(Cow::Borrowed("public"))
    }

    fn report(
        &self,
        reporter: &mut Reporter<'_, DB>,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        match *self {
            Self::Type(user_type) => reporter.user_defined_type(user_type, message, resolution),
            Self::Domain(domain) => reporter.domain(domain, message, resolution),
            Self::Table(table) => reporter.table(table, message, resolution),
            Self::View(view) => reporter.view(view, message, resolution),
            Self::MaterializedView(view) => reporter.materialized_view(view, message, resolution),
        }
    }
}

/// Every object of `database` that takes a name from a pool of type names.
fn type_named<DB: DatabaseLike>(database: &DB) -> impl Iterator<Item = TypeNamed<'_, DB>> {
    database
        .user_defined_types()
        .map(TypeNamed::Type)
        .chain(database.domains().map(TypeNamed::Domain))
        .chain(database.tables_and_foreign_tables().map(TypeNamed::Table))
        .chain(database.views().map(TypeNamed::View))
        .chain(
            database
                .materialized_views()
                .map(TypeNamed::MaterializedView),
        )
}

impl<DB: DatabaseLike> SchemaRule for TypeNameCaseCollision<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        // A schema never holds two objects of one pool under one stored
        // name, so every pair sharing a folded name differs by case alone.
        let mut pools: BTreeMap<(Cow<'_, str>, String), Vec<TypeNamed<'_, DB>>> = BTreeMap::new();
        for named in type_named(database) {
            pools
                .entry((named.stored_schema(), named.stored_name().to_lowercase()))
                .or_default()
                .push(named);
        }
        for ((schema, _), pool) in &pools {
            for (index, later) in pool.iter().enumerate() {
                for earlier in &pool[..index] {
                    let (later_written, earlier_written) = (later.written(), earlier.written());
                    later.report(
                        reporter,
                        format!(
                            "In schema {schema}, {} {later_written} and {} {earlier_written} have names that differ only by case.",
                            later.kind(),
                            earlier.kind()
                        ),
                        format!(
                            "Rename {later_written} or {earlier_written} so the two names differ by more than case."
                        ),
                    )?;
                }
            }
        }
        Ok(())
    }
}
