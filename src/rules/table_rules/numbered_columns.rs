//! Submodule providing the `NumberedColumns` rule.

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

rule_definition!(
    /// Struct defining a rule that reports a table holding one attribute in
    /// numbered columns, such as `phone1`, `phone2` and `phone3`.
    ///
    /// A column name ending in digits, after one optional `_`, is a slot of
    /// the stem before them, compared case-insensitively, and a column named
    /// the bare stem is a slot too. A table is reported for a stem with two
    /// or more slots whose numbers run consecutively from 0 or 1, or from 2
    /// when the bare stem is a column, so `email`, `email2` is reported while
    /// `ipv4`, `ipv6` and `sha1`, `sha256` are not.
    ///
    /// Columns such as `address_line_1` and `address_line_2`, or the corners
    /// `x1` and `x2` of a box, are numbered on purpose, so the rule is
    /// `pedantic`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = NumberedColumns::default().into();
    ///
    /// let numbered = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE contacts (id BIGINT PRIMARY KEY, phone1 TEXT, phone2 TEXT, phone3 TEXT);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&numbered).is_err());
    ///
    /// let child = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE contacts (id BIGINT PRIMARY KEY);
    ///      CREATE TABLE contact_phones (
    ///          contact_id BIGINT NOT NULL REFERENCES contacts (id),
    ///          phone TEXT NOT NULL,
    ///          PRIMARY KEY (contact_id, phone)
    ///      );",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&child).is_ok());
    /// ```
    NumberedColumns,
    register_table_rule,
    LintGroup::Pedantic,
    "Numbered columns hold one attribute in a fixed number of slots, so one more value needs a migration, a lookup tests every slot and nothing keeps one value out of two slots.",
    Some("https://www.schemacrawler.com/lint.html"),
    RuleExample {
        bad: "CREATE TABLE contacts (id BIGINT PRIMARY KEY, phone1 TEXT, phone2 TEXT, phone3 TEXT);",
        good: "CREATE TABLE contacts (id BIGINT PRIMARY KEY);\n\
CREATE TABLE contact_phones (\n\
    contact_id BIGINT NOT NULL REFERENCES contacts (id),\n\
    phone TEXT NOT NULL,\n\
    PRIMARY KEY (contact_id, phone)\n\
);",
    },
    Basis::Names
);

/// The lowercase stem and number of a column name ending in digits, the stem
/// without one `_` before them, or `None` for a name without both.
fn numbered(name: &str) -> Option<(String, u32)> {
    let unnumbered = name.trim_end_matches(|c: char| c.is_ascii_digit());
    let number = name[unnumbered.len()..].parse().ok()?;
    let stem = unnumbered.strip_suffix('_').unwrap_or(unnumbered);
    (!stem.is_empty()).then(|| (stem.to_ascii_lowercase(), number))
}

/// Whether the numbers of a stem's columns, sorted and without repeats, and
/// a column named the bare stem make two or more slots of one numbering.
fn slots(numbers: &[u32], bare: bool) -> bool {
    numbers
        .windows(2)
        .all(|pair| pair[1].checked_sub(pair[0]) == Some(1))
        && numbers
            .first()
            .is_some_and(|&first| first <= 1 || (first == 2 && bare))
        && numbers.len() + usize::from(bare) >= 2
}

impl<DB: DatabaseLike> TableRule for NumberedColumns<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let names: Vec<&str> = table
            .columns(database)?
            .map(ColumnLike::column_name)
            .collect();
        let mut stems: Vec<(String, Vec<u32>)> = Vec::new();
        for (stem, number) in names.iter().filter_map(|name| numbered(name)) {
            match stems.iter_mut().find(|(known, _)| *known == stem) {
                Some((_, numbers)) => numbers.push(number),
                None => stems.push((stem, vec![number])),
            }
        }
        for (stem, mut numbers) in stems {
            numbers.sort_unstable();
            numbers.dedup();
            let bare = names.iter().any(|name| name.eq_ignore_ascii_case(&stem));
            if !slots(&numbers, bare) {
                continue;
            }
            let columns: Vec<&str> = names
                .iter()
                .copied()
                .filter(|name| {
                    name.eq_ignore_ascii_case(&stem)
                        || numbered(name).is_some_and(|(other, _)| other == stem)
                })
                .collect();
            let table_name = table.table_name();
            reporter.table(
                table,
                format!(
                    "Table '{table_name}' holds '{stem}' in numbered columns '{}', so one more value needs a migration, a lookup tests every column and nothing keeps one value out of two of them.",
                    columns.join("', '")
                ),
                format!(
                    "Move '{stem}' to a child table with a row per value, a foreign key to '{table_name}' and a unique constraint on that key and the value."
                ),
            )?;
        }
        Ok(())
    }
}
