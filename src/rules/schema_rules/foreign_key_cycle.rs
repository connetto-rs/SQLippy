//! Submodule providing the `ForeignKeyCycle` rule.

use std::collections::{HashMap, VecDeque};

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

schema_rule!(
    /// Struct defining a rule that reports foreign keys referencing one
    /// another in a cycle through two or more distinct tables.
    ///
    /// No table of such a cycle can be filled, emptied or restored before the
    /// others, so writes need deferred constraints or a later update, and a
    /// data-only restore needs disabled triggers. A self-referencing table is
    /// not a cycle between tables and is not reported, and neither are
    /// several paths that lead to one table without returning. Deferrable
    /// keys still close a cycle. Each set of tables that reach one another
    /// through their keys is reported once, on the table of the set the
    /// schema lists first, with the shortest cycle from that table back to
    /// itself and every other key between distinct tables of the set.
    /// A cycle can record a deliberate mutual participation, so the rule only
    /// runs when enabled.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ForeignKeyCycle::default().into();
    /// let cycle = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE parents (id INT PRIMARY KEY, child_id INT);
    ///      CREATE TABLE children (id INT PRIMARY KEY, parent_id INT REFERENCES parents (id));
    ///      ALTER TABLE parents ADD FOREIGN KEY (child_id) REFERENCES children (id);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&cycle).is_err());
    /// let tree = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE nodes (id INT PRIMARY KEY, parent_id INT REFERENCES nodes (id));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&tree).is_ok());
    /// ```
    ForeignKeyCycle,
    LintGroup::Restriction,
    "Tables whose foreign keys reference one another in a cycle cannot be written or restored one table after another, so inserts and deletes need deferred constraints or later updates and a data-only restore needs disabled triggers.",
    Some("https://github.com/postgres/postgres/blob/master/src/bin/pg_dump/pg_dump_sort.c"),
    RuleExample {
        bad: "CREATE TABLE parents (id bigint PRIMARY KEY, child_id bigint);\n\
CREATE TABLE children (id bigint PRIMARY KEY, parent_id bigint REFERENCES parents (id));\n\
ALTER TABLE parents ADD FOREIGN KEY (child_id) REFERENCES children (id);",
        good: "CREATE TABLE nodes (id bigint PRIMARY KEY, parent_id bigint REFERENCES nodes (id));",
    }
);

/// The foreign keys of each table, by the position of the table in the
/// schema, paired with the position of the table each key references.
/// Self-references are left out.
type Edges<'db, DB> = Vec<Vec<(usize, &'db <DB as DatabaseLike>::ForeignKey)>>;

/// Strongly connected components of the graph whose node `node` has the
/// successors `edges[node]`, each in ascending node order, found by Tarjan's
/// algorithm on an explicit stack so long chains do not exhaust the call
/// stack.
fn components<T>(edges: &[Vec<(usize, T)>]) -> Vec<Vec<usize>> {
    const UNVISITED: usize = usize::MAX;
    let mut index = vec![UNVISITED; edges.len()];
    let mut low = vec![0; edges.len()];
    let mut on_stack = vec![false; edges.len()];
    let mut stack = Vec::new();
    let mut next = 0;
    let mut components = Vec::new();
    for root in 0..edges.len() {
        if index[root] != UNVISITED {
            continue;
        }
        index[root] = next;
        low[root] = next;
        next += 1;
        stack.push(root);
        on_stack[root] = true;
        let mut frames = vec![(root, 0)];
        while let Some(frame) = frames.last_mut() {
            let node = frame.0;
            if let Some(&(successor, _)) = edges[node].get(frame.1) {
                frame.1 += 1;
                if index[successor] == UNVISITED {
                    index[successor] = next;
                    low[successor] = next;
                    next += 1;
                    stack.push(successor);
                    on_stack[successor] = true;
                    frames.push((successor, 0));
                } else if on_stack[successor] {
                    low[node] = low[node].min(index[successor]);
                }
                continue;
            }
            frames.pop();
            if let Some(&(parent, _)) = frames.last() {
                low[parent] = low[parent].min(low[node]);
            }
            if low[node] == index[node] {
                let mut component = Vec::new();
                while let Some(member) = stack.pop() {
                    on_stack[member] = false;
                    component.push(member);
                    if member == node {
                        break;
                    }
                }
                component.sort_unstable();
                components.push(component);
            }
        }
    }
    components.sort_unstable();
    components
}

/// The edges, each as its host node and its position among the host's
/// edges, of a shortest cycle from `start` back to `start` through the nodes
/// `inside` accepts, which must form a strongly connected component of two
/// or more nodes holding `start`.
fn shortest_cycle<T>(
    edges: &[Vec<(usize, T)>],
    inside: impl Fn(usize) -> bool,
    start: usize,
) -> Vec<(usize, usize)> {
    let mut reached: Vec<Option<(usize, usize)>> = vec![None; edges.len()];
    let mut queue = VecDeque::from([start]);
    loop {
        let node = queue
            .pop_front()
            .expect("a strongly connected component holds a cycle through each of its nodes");
        for (position, &(target, _)) in edges[node].iter().enumerate() {
            if target == start {
                let mut cycle = vec![(node, position)];
                let mut current = node;
                while let Some(step) = reached[current] {
                    cycle.push(step);
                    current = step.0;
                }
                cycle.reverse();
                return cycle;
            }
            if inside(target) && reached[target].is_none() {
                reached[target] = Some((node, position));
                queue.push_back(target);
            }
        }
    }
}

/// The names of `columns`, separated by commas.
fn column_list<'db, C: ColumnLike + 'db>(columns: impl Iterator<Item = &'db C>) -> String {
    columns
        .map(ColumnLike::column_name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `foreign_key` spelled as `host(columns) -> referenced(columns)`.
fn spell<DB: DatabaseLike>(
    database: &DB,
    host: &DB::Table,
    referenced: &DB::Table,
    foreign_key: &DB::ForeignKey,
) -> Result<String, LookupError> {
    Ok(format!(
        "{}({}) -> {}({})",
        host.table_name(),
        column_list(foreign_key.host_columns(database)?),
        referenced.table_name(),
        column_list(foreign_key.referenced_columns(database)?),
    ))
}

/// `items` joined as an English list.
fn english_list(items: &[String]) -> String {
    match items {
        [rest @ .., last] if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => items.concat(),
    }
}

impl<DB: DatabaseLike> SchemaRule for ForeignKeyCycle<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let tables: Vec<&DB::Table> = database.tables().collect();
        let positions: HashMap<&DB::Table, usize> = tables
            .iter()
            .enumerate()
            .map(|(position, &table)| (table, position))
            .collect();
        let mut edges: Edges<'_, DB> = Vec::with_capacity(tables.len());
        for &table in &tables {
            let mut keys = Vec::new();
            for foreign_key in table.foreign_keys(database)? {
                let referenced = foreign_key.referenced_table(database)?;
                if referenced == table {
                    continue;
                }
                keys.push((positions[referenced], foreign_key));
            }
            edges.push(keys);
        }
        let mut component_of = vec![0; tables.len()];
        let components = components(&edges);
        for (number, component) in components.iter().enumerate() {
            for &member in component {
                component_of[member] = number;
            }
        }
        for (number, component) in components.iter().enumerate() {
            let [start, _, ..] = component[..] else {
                continue;
            };
            let cycle = shortest_cycle(&edges, |node| component_of[node] == number, start);
            let mut steps = Vec::with_capacity(cycle.len());
            for &(host, position) in &cycle {
                let (target, foreign_key) = edges[host][position];
                steps.push(spell(database, tables[host], tables[target], foreign_key)?);
            }
            let mut others = Vec::new();
            for &host in component {
                for (position, &(target, foreign_key)) in edges[host].iter().enumerate() {
                    if component_of[target] == number && !cycle.contains(&(host, position)) {
                        others.push(format!(
                            "`{}`",
                            spell(database, tables[host], tables[target], foreign_key)?
                        ));
                    }
                }
            }
            let names: Vec<String> = component
                .iter()
                .map(|&member| format!("'{}'", tables[member].table_name()))
                .collect();
            let also = match others.len() {
                0 => String::new(),
                1 => format!(
                    " The foreign key {} also runs between these tables.",
                    english_list(&others)
                ),
                _ => format!(
                    " The foreign keys {} also run between these tables.",
                    english_list(&others)
                ),
            };
            let first = tables[start].table_name();
            reporter.table(
                tables[start],
                format!(
                    "Tables {} reference one another through the foreign key cycle `{}`.{also}",
                    english_list(&names),
                    steps.join(" -> "),
                ),
                format!(
                    "Drop a foreign key of the cycle so each table can be written after the tables it references, or allow this rule on table '{first}' when the mutual participation is deliberate."
                ),
            )?;
        }
        Ok(())
    }
}
