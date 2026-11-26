//! Submodule providing the `OneToManyEdgeTable` rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{closed_set_support::checked_values, key_support::equality_keys},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

rule_definition!(
    /// Struct defining a rule that reports a table holding a one-to-many
    /// relationship apart from its child.
    ///
    /// The table is reported when one foreign key, the child's, holds a
    /// unique key of the table, exactly one other foreign key, the parent's,
    /// reaches columns outside it, and every column of the table belongs to
    /// one of the two. Each child then has at most one parent, which a
    /// foreign key on the child stores without the extra join. A column the
    /// two keys do not cover, or a child key column pinned to one constant,
    /// marks a subtype carrying its own attributes, which is left alone.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = OneToManyEdgeTable::default().into();
    /// let edge = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE parents (id INT PRIMARY KEY);
    ///      CREATE TABLE children (id INT PRIMARY KEY);
    ///      CREATE TABLE child_parents (
    ///          child_id INT PRIMARY KEY REFERENCES children (id),
    ///          parent_id INT NOT NULL REFERENCES parents (id)
    ///      );",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&edge).is_err());
    /// let many_to_many = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE parents (id INT PRIMARY KEY);
    ///      CREATE TABLE children (id INT PRIMARY KEY);
    ///      CREATE TABLE child_parents (
    ///          child_id INT REFERENCES children (id),
    ///          parent_id INT REFERENCES parents (id),
    ///          PRIMARY KEY (child_id, parent_id)
    ///      );",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&many_to_many).is_ok());
    /// ```
    OneToManyEdgeTable,
    register_table_rule,
    LintGroup::Pedantic,
    "A one-to-many relationship kept in a table keyed by the child costs a join on every read, and a parent every child must have needs a trigger where a foreign key on the child needs `NOT NULL`.",
    Some("https://search.worldcat.org/isbn/9780133970777"),
    RuleExample {
        bad: "CREATE TABLE parents (id bigint PRIMARY KEY);\n\
CREATE TABLE children (id bigint PRIMARY KEY);\n\
CREATE TABLE child_parents (child_id bigint PRIMARY KEY REFERENCES children (id), parent_id bigint NOT NULL REFERENCES parents (id));",
        good: "CREATE TABLE parents (id bigint PRIMARY KEY);\n\
CREATE TABLE children (id bigint PRIMARY KEY, parent_id bigint NOT NULL REFERENCES parents (id));",
    }
);

impl<DB: DatabaseLike> TableRule for OneToManyEdgeTable<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut keys = equality_keys(database, table)?;
        keys.push(table.primary_key_columns(database)?.collect());
        keys.retain(|key| !key.is_empty());
        let foreign_keys: Vec<&DB::ForeignKey> = table.foreign_keys(database)?.collect();
        for &child in &foreign_keys {
            let child_columns: Vec<&DB::Column> = child.host_columns(database)?.collect();
            if child.is_self_referential(database)?
                || !keys
                    .iter()
                    .any(|key| key.iter().all(|column| child_columns.contains(column)))
                || pins_a_constant(database, &child_columns)?
            {
                continue;
            }
            let mut parents = Vec::new();
            for &other in &foreign_keys {
                if std::ptr::eq(other, child) {
                    continue;
                }
                let own: Vec<&DB::Column> = other
                    .host_columns(database)?
                    .filter(|column| !child_columns.contains(column))
                    .collect();
                if !own.is_empty() {
                    parents.push((other, own));
                }
            }
            let [(parent, parent_columns)] = parents.as_slice() else {
                continue;
            };
            let parent_host: Vec<&DB::Column> = parent.host_columns(database)?.collect();
            if !table
                .columns(database)?
                .all(|column| child_columns.contains(&column) || parent_host.contains(&column))
            {
                continue;
            }
            let children = child.referenced_table(database)?.table_name();
            let parent_table = parent.referenced_table(database)?.table_name();
            let moved = parent_columns
                .iter()
                .copied()
                .map(ColumnLike::column_name)
                .collect::<Vec<_>>()
                .join(", ");
            let name = table.table_name();
            reporter.table(
                table,
                format!(
                    "'{name}' holds one '{parent_table}' reference ({moved}) per '{children}' row, a one-to-many relationship kept apart from its child."
                ),
                format!(
                    "Store ({moved}) on '{children}' as a foreign key to '{parent_table}', unless the relationship needs a lifetime or access boundary of its own."
                ),
            )?;
            return Ok(());
        }
        Ok(())
    }
}

/// Whether a check or a generated constant holds one of `columns` to a single
/// value, the discriminator of a subtype.
fn pins_a_constant<DB: DatabaseLike>(
    database: &DB,
    columns: &[&DB::Column],
) -> Result<bool, LookupError> {
    for &column in columns {
        if column.generated_constant().is_some()
            || checked_values(database, column)?.is_some_and(|values| values.len() == 1)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
