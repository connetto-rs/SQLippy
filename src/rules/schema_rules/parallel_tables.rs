//! Submodule providing the `ParallelTables` rule.

use std::collections::HashMap;

use sql_traits::{
    errors::LookupError,
    traits::{
        CheckConstraintLike, ColumnLike, DataTypeLike, DatabaseLike, ForeignKeyLike, IndexLike,
        TableLike,
    },
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::index_support::shape,
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

schema_rule!(
    /// Struct defining a rule that reports tables whose columns and
    /// constraints are the same except for the tables their foreign keys
    /// reference.
    ///
    /// Each such table repeats the operations and constraints of the others,
    /// and a common parent of the referenced tables lets one table hold the
    /// rows. Columns are compared by name, type, nullability and default, and
    /// constraints by primary key, unique keys, checks and the columns and
    /// actions of each foreign key. Tables that reference the same tables are
    /// duplicates rather than parallels and are not reported. Neither are
    /// subtype tables extending different parents, whose primary key is a
    /// foreign key to a parent that differs between them, since one table
    /// under a common parent would no longer make each row a row of its own
    /// parent.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ParallelTables::default().into();
    /// let parallel = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE teams (id INT PRIMARY KEY);
    ///      CREATE TABLE people (id INT PRIMARY KEY);
    ///      CREATE TABLE team_grants (subject_id INT REFERENCES teams (id), permission TEXT);
    ///      CREATE TABLE person_grants (subject_id INT REFERENCES people (id), permission TEXT);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&parallel).is_err());
    /// let shared = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE subjects (id INT PRIMARY KEY);
    ///      CREATE TABLE grants (subject_id INT REFERENCES subjects (id), permission TEXT);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&shared).is_ok());
    /// ```
    ParallelTables,
    LintGroup::Pedantic,
    "Tables that differ only in the tables their foreign keys reference repeat every operation and constraint, where a common parent of the referenced tables lets one table hold the rows.",
    Some("https://www.postgresql.org/docs/current/ddl-constraints.html"),
    RuleExample {
        bad: "CREATE TABLE teams (id integer PRIMARY KEY);\n\
CREATE TABLE people (id integer PRIMARY KEY);\n\
CREATE TABLE team_grants (id integer PRIMARY KEY, subject_id integer NOT NULL REFERENCES teams (id), permission text NOT NULL);\n\
CREATE TABLE person_grants (id integer PRIMARY KEY, subject_id integer NOT NULL REFERENCES people (id), permission text NOT NULL);",
        good: "CREATE TABLE subjects (id integer PRIMARY KEY);\n\
CREATE TABLE teams (id integer PRIMARY KEY REFERENCES subjects (id));\n\
CREATE TABLE people (id integer PRIMARY KEY REFERENCES subjects (id));\n\
CREATE TABLE grants (id integer PRIMARY KEY, subject_id integer NOT NULL REFERENCES subjects (id), permission text NOT NULL);",
    }
);

/// What a table declares apart from the tables its foreign keys reference.
#[derive(Debug, PartialEq, Eq, Hash)]
struct Shape {
    /// Name, type, nullability and default of each column, in order.
    columns: Vec<(String, String, bool, Option<String>)>,
    /// The primary key columns, in order.
    primary_key: Vec<String>,
    /// Every unique key and unique index, with its predicate, sorted.
    unique_keys: Vec<String>,
    /// Every check, sorted.
    checks: Vec<String>,
    /// Host columns, referenced columns and actions of each foreign key,
    /// sorted.
    foreign_keys: Vec<String>,
}

/// The names of `columns`.
fn names<'db, C: ColumnLike + 'db>(columns: impl Iterator<Item = &'db C>) -> Vec<String> {
    columns
        .map(|column| column.column_name().to_owned())
        .collect()
}

/// The table a foreign key references and whether the foreign key makes its
/// host table a subtype of that table.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Target {
    /// Schema-qualified name of the referenced table, `None` for the host
    /// table itself.
    table: Option<String>,
    /// Whether the host columns are the host table's primary key.
    extends: bool,
}

/// The shape of `table` and the target of each foreign key, in the order of
/// `Shape::foreign_keys`.
fn shape_of<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
) -> Result<(Shape, Vec<Target>), LookupError> {
    let mut columns = Vec::new();
    for column in table.columns(database)? {
        columns.push((
            column.column_name().to_owned(),
            column
                .data_type(database)
                .normalized_name(database)
                .into_owned(),
            column.is_nullable(database)?,
            // A serial default names the column's own sequence, which differs
            // between tables even when the columns are the same.
            if column.is_serial(database) {
                Some("nextval(<own sequence>)".to_owned())
            } else {
                column.default_expression().map(ToString::to_string)
            },
        ));
    }
    let mut unique_keys = Vec::new();
    for index in table.unique_indices(database)? {
        unique_keys.push(shape(index.expression(database)?));
    }
    for index in table.indices(database)?.filter(|index| index.is_unique()) {
        let predicate = index
            .predicate()
            .map_or_else(String::new, |predicate| format!(" WHERE {predicate}"));
        unique_keys.push(format!("{}{predicate}", shape(index.expression(database)?)));
    }
    unique_keys.sort_unstable();
    let mut checks: Vec<String> = table
        .check_constraints(database)?
        .map(|check| check.expression(database).to_string())
        .collect();
    checks.sort_unstable();
    let primary_key = names(table.primary_key_columns(database)?);
    let mut foreign_keys = Vec::new();
    for foreign_key in table.foreign_keys(database)? {
        let referenced = foreign_key.referenced_table(database)?;
        let host_columns = names(foreign_key.host_columns(database)?);
        let target = Target {
            table: (referenced != table).then(|| {
                format!(
                    "{}.{}",
                    referenced.table_schema().unwrap_or_default(),
                    referenced.table_name()
                )
            }),
            extends: host_columns.len() == primary_key.len()
                && host_columns
                    .iter()
                    .all(|column| primary_key.contains(column)),
        };
        foreign_keys.push((
            format!(
                "({}) REFERENCES ({}) ON DELETE {} ON UPDATE {} {}",
                host_columns.join(", "),
                names(foreign_key.referenced_columns(database)?).join(", "),
                foreign_key.on_delete(database),
                foreign_key.on_update(database),
                foreign_key.match_kind(database),
            ),
            target,
        ));
    }
    foreign_keys.sort_unstable();
    let (foreign_keys, targets) = foreign_keys.into_iter().unzip();
    Ok((
        Shape {
            columns,
            primary_key,
            unique_keys,
            checks,
            foreign_keys,
        },
        targets,
    ))
}

/// Whether two tables of one shape, whose foreign keys reference `targets`
/// and `earlier`, reference different tables and none of the differing
/// references is a subtype key.
fn parallel(targets: &[Target], earlier: &[Target]) -> bool {
    let mut differing = targets
        .iter()
        .zip(earlier)
        .filter(|(target, earlier_target)| target.table != earlier_target.table)
        .peekable();
    differing.peek().is_some() && differing.all(|(target, _)| !target.extends)
}

/// The tables of one shape met so far, each with its foreign key targets.
type SameShape<'db, T> = Vec<(&'db T, Vec<Target>)>;

impl<DB: DatabaseLike> SchemaRule for ParallelTables<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut by_shape: HashMap<Shape, SameShape<'_, DB::Table>> = HashMap::new();
        for table in database.tables() {
            let (shape, targets) = shape_of(database, table)?;
            if targets.is_empty() {
                continue;
            }
            let earlier_tables = by_shape.entry(shape).or_default();
            if let Some((earlier, _)) = earlier_tables
                .iter()
                .find(|(_, earlier_targets)| parallel(&targets, earlier_targets))
            {
                let (name, earlier) = (table.table_name(), earlier.table_name());
                reporter.table(
                    table,
                    format!(
                        "Table '{name}' declares the columns and constraints of '{earlier}' and differs only in the tables its foreign keys reference."
                    ),
                    format!(
                        "Give the tables '{name}' and '{earlier}' reference a common parent and keep their rows in one table referencing it, unless the two kinds of row must stay apart."
                    ),
                )?;
            }
            earlier_tables.push((table, targets));
        }
        Ok(())
    }
}
