//! Submodule providing the `MixedMultivaluedFacts` rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{grant_support::tenant_columns, key_support::indexed_keys},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

rule_definition!(
    /// Struct defining a rule that reports a table whose every column is key
    /// and whose key joins three or more participants, so its rows may
    /// combine independent one-to-many facts of one entity.
    ///
    /// When an employee's projects and dependents vary independently, a table
    /// keyed by all three must store every project with every dependent, and
    /// a missing combination reads as a fact nobody stated. This is the
    /// multivalued dependency of fourth normal form. Whether the facts are
    /// independent is a judgment about meaning, and a genuine three-way fact
    /// such as a supplier shipping a part to a project has the same shape, so
    /// the rule says what a table may hold, never what it does.
    ///
    /// A table qualifies when one unique key holds every column, the table has
    /// at least three columns, and no narrower unique key exists. Columns held
    /// by exactly the same foreign keys form one participant, so a composite
    /// foreign key counts once, and a column no foreign key holds is a
    /// participant of its own. Columns of the declared tenant key scope the
    /// others and are no participant, and neither is a participant that one
    /// foreign key holds exactly while two other foreign keys hold it along
    /// with more columns, as a tenant column referencing its tenant does.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = MixedMultivaluedFacts::default().into();
    /// let mixed = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE employees (id INT PRIMARY KEY);
    ///      CREATE TABLE employee_facts (employee_id INT REFERENCES employees (id),
    ///        project TEXT, dependent TEXT, PRIMARY KEY (employee_id, project, dependent));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&mixed).is_err());
    /// let split = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE employees (id INT PRIMARY KEY);
    ///      CREATE TABLE employee_projects (employee_id INT REFERENCES employees (id),
    ///        project TEXT, PRIMARY KEY (employee_id, project));
    ///      CREATE TABLE employee_dependents (employee_id INT REFERENCES employees (id),
    ///        dependent TEXT, PRIMARY KEY (employee_id, dependent));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&split).is_ok());
    /// ```
    MixedMultivaluedFacts,
    register_table_rule,
    LintGroup::Pedantic,
    "A table keyed by every column that mixes two independent one-to-many facts of one entity must store every combination of them, so each fact repeats across the other and an update can leave a combination missing.",
    Some("https://dl.acm.org/doi/10.1145/320557.320571"),
    RuleExample {
        bad: "CREATE TABLE employees (id bigint PRIMARY KEY);\n\
CREATE TABLE employee_projects_dependents (employee_id bigint REFERENCES employees (id), project_name text, dependent_name text, PRIMARY KEY (employee_id, project_name, dependent_name));",
        good: "CREATE TABLE employees (id bigint PRIMARY KEY);\n\
CREATE TABLE employee_projects (employee_id bigint REFERENCES employees (id), project_name text, PRIMARY KEY (employee_id, project_name));\n\
CREATE TABLE employee_dependents (employee_id bigint REFERENCES employees (id), dependent_name text, PRIMARY KEY (employee_id, dependent_name));",
    }
);

/// Columns of a table that exactly the same foreign keys hold.
struct Participant<'db, DB: DatabaseLike> {
    /// The columns, in table order.
    columns: Vec<&'db DB::Column>,
    /// Positions of the foreign keys holding them, empty for a column no
    /// foreign key holds.
    holders: Vec<usize>,
}

impl<DB: DatabaseLike> Participant<'_, DB> {
    /// The names of the columns, in table order.
    fn names(&self) -> impl Iterator<Item = &str> {
        self.columns.iter().copied().map(ColumnLike::column_name)
    }

    /// The columns as `(a, b)`, followed by the columns of `then`.
    fn render_with(&self, then: Option<&Self>) -> String {
        let names: Vec<&str> = self
            .names()
            .chain(then.into_iter().flat_map(Self::names))
            .collect();
        format!("({})", names.join(", "))
    }
}

/// Whether one unique key of `table` holds all of its `width` columns and no
/// narrower unique key exists, so no column is a fact about part of the key.
fn is_all_key<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    width: usize,
) -> Result<bool, LookupError> {
    let mut keys = indexed_keys(database, table)?;
    keys.push(table.primary_key_columns(database)?.collect());
    let mut whole = false;
    for mut key in keys.into_iter().filter(|key| !key.is_empty()) {
        key.sort_unstable();
        key.dedup();
        if key.len() < width {
            return Ok(false);
        }
        whole = true;
    }
    Ok(whole)
}

/// Joins at least two rendered items as `a, b and c`.
fn enumerate(items: &[String]) -> String {
    let last = items.len() - 1;
    format!("{} and {}", items[..last].join(", "), items[last])
}

impl<DB: DatabaseLike> TableRule for MixedMultivaluedFacts<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let columns: Vec<&DB::Column> = table.columns(database)?.collect();
        if columns.len() < 3 || !is_all_key(database, table, columns.len())? {
            return Ok(());
        }
        let tenant = tenant_columns(database, reporter.deployment(), table)?.unwrap_or_default();
        let mut foreign_keys: Vec<Vec<&DB::Column>> = Vec::new();
        for foreign_key in table.foreign_keys(database)? {
            let mut held: Vec<&DB::Column> = foreign_key
                .host_columns(database)?
                .filter(|column| !tenant.contains(column))
                .collect();
            held.sort_unstable();
            held.dedup();
            if !held.is_empty() && !foreign_keys.contains(&held) {
                foreign_keys.push(held);
            }
        }
        let mut participants: Vec<Participant<'_, DB>> = Vec::new();
        for column in columns
            .into_iter()
            .filter(|column| !tenant.contains(column))
        {
            let holders: Vec<usize> = foreign_keys
                .iter()
                .enumerate()
                .filter_map(|(position, held)| held.contains(&column).then_some(position))
                .collect();
            match participants
                .iter_mut()
                .find(|participant| !holders.is_empty() && participant.holders == holders)
            {
                Some(participant) => participant.columns.push(column),
                None => participants.push(Participant {
                    columns: vec![column],
                    holders,
                }),
            }
        }
        participants.retain(|participant| {
            participant.holders.len() < 3
                || !participant
                    .holders
                    .iter()
                    .any(|&position| foreign_keys[position].len() == participant.columns.len())
        });
        if participants.len() < 3 {
            return Ok(());
        }
        let most = participants
            .iter()
            .map(|participant| participant.holders.len())
            .max()
            .unwrap_or_default();
        let mut widest = participants
            .iter()
            .enumerate()
            .filter(|(_, participant)| participant.holders.len() == most);
        let entity = match (widest.next(), widest.next()) {
            (Some((position, _)), None) if most > 0 => Some(position),
            _ => None,
        };
        let name = table.table_name();
        let (message, suggestion) = if let Some(position) = entity {
            let entity = participants.remove(position);
            let shared = entity.render_with(None);
            let others: Vec<String> = participants
                .iter()
                .map(|participant| participant.render_with(None))
                .collect();
            let tables: Vec<String> = participants
                .iter()
                .map(|participant| entity.render_with(Some(participant)))
                .collect();
            let others = enumerate(&others);
            (
                format!(
                    "Every column of '{name}' is key, so {others} may be independent facts of {shared}, and then every combination of them must be stored."
                ),
                format!(
                    "If {others} vary independently for each {shared}, split '{name}' into tables keyed by {}. Allow this rule on '{name}' when each row records one fact about all of them.",
                    enumerate(&tables)
                ),
            )
        } else {
            let all: Vec<String> = participants
                .iter()
                .map(|participant| participant.render_with(None))
                .collect();
            (
                format!(
                    "Every column of '{name}' is key across {}, so two of them may be independent facts of another, and then every combination of them must be stored.",
                    enumerate(&all)
                ),
                format!(
                    "If two of them vary independently for a third, split '{name}' into one table per fact, each keyed by that third. Allow this rule on '{name}' when each row records one fact about all of them."
                ),
            )
        };
        reporter.table(table, message, suggestion)?;
        Ok(())
    }
}
