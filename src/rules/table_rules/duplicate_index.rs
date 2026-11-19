//! Submodule providing the `DuplicateIndex` rule.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DatabaseLike, IndexLike, TableLike},
};
use sqlparser::ast::{IndexType, ObjectName, ObjectNamePart, OrderBySort};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        index_support::shape,
        policy_support::{is_column_reference, unnested},
    },
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// One key of an index as PostgreSQL compares it, the defaults a statement
/// may leave out written in.
#[derive(PartialEq, Eq)]
struct Key {
    expression: String,
    descending: bool,
    nulls_first: bool,
    operator_class: Option<String>,
}

/// Everything PostgreSQL keeps about an index apart from its identity.
#[derive(PartialEq, Eq)]
struct Definition {
    keys: Vec<Key>,
    predicate: Option<String>,
    method: IndexType,
    unique: bool,
    nulls_distinct: bool,
    includes: Vec<String>,
}

/// An index of a relation, with whether it backs a key constraint and
/// whether every key is a bare column.
struct Entry {
    name: String,
    constraint: bool,
    plain: bool,
    definition: Definition,
}

impl Entry {
    fn of<DB: DatabaseLike, I: IndexLike<DB = DB>>(
        database: &DB,
        index: &I,
        constraint: bool,
    ) -> Result<Self, LookupError> {
        let mut plain = true;
        let keys = index
            .keys(database)?
            .map(|key| {
                plain &= is_column_reference(unnested(key.expression()));
                let descending = matches!(key.order(), Some(OrderBySort::Desc));
                Key {
                    expression: shape(key.expression()),
                    descending,
                    nulls_first: key.nulls_first().unwrap_or(descending),
                    operator_class: key.operator_class().map(folded),
                }
            })
            .collect::<Vec<_>>();
        let mut includes = index
            .include_columns(database)?
            .map(|column| column.column_name().to_owned())
            .collect::<Vec<_>>();
        includes.sort_unstable();
        let name = index.name().map_or_else(
            || {
                keys.iter()
                    .map(|key| key.expression.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            str::to_owned,
        );
        Ok(Self {
            name,
            constraint,
            plain,
            definition: Definition {
                keys,
                predicate: index.predicate().map(shape),
                method: index.access_method().cloned().unwrap_or(IndexType::BTree),
                unique: constraint || index.is_unique(),
                nulls_distinct: index.nulls_distinct(),
                includes,
            },
        })
    }

    /// Whether another rule reports this index as the later of an identical
    /// pair: two key constraints for `duplicate_unique_index`, and plain
    /// non-unique indexes over columns alone for `prefix_redundant_index`.
    fn reported_elsewhere(&self, earlier: &Self) -> bool {
        (self.constraint && earlier.constraint)
            || (self.plain
                && !self.definition.unique
                && self.definition.predicate.is_none()
                && self.definition.includes.is_empty())
    }
}

/// `name` with each unquoted part folded to lower case, as PostgreSQL
/// resolves it.
fn folded(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|part| match part {
            ObjectNamePart::Identifier(ident) if ident.quote_style.is_none() => {
                ident.value.to_lowercase()
            }
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Struct defining a rule that reports an index identical to another index
/// of the same relation.
///
/// Two indexes are identical when they agree on every key, with its
/// expression, collation, direction, null ordering and operator class, and
/// on predicate, access method, uniqueness, null treatment and included
/// columns. An omitted direction is ascending and an omitted null ordering
/// is the default for the direction. An operator class is compared as
/// written, so a key naming its type's default class differs from one
/// naming none. Of two identical indexes the later one is reported, and an
/// index never stands in for a key constraint, which only
/// `duplicate_unique_index` compares with another. Identical plain
/// indexes over columns alone are left to `prefix_redundant_index`.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DuplicateIndex::default().into();
/// let schema = "CREATE TABLE t (a TEXT); CREATE INDEX t_lower ON t ((lower(a))) WHERE a IS NOT NULL;";
/// let duplicate = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE INDEX t_lower_again ON t ((lower(a))) WHERE a IS NOT NULL;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&duplicate).is_err());
/// let other = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE INDEX t_lower_all ON t ((lower(a)));"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&other).is_ok());
/// ```
pub struct DuplicateIndex<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DuplicateIndex<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DuplicateIndex<DB>> for GenericConstrainer<DB> {
    fn from(rule: DuplicateIndex<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DuplicateIndex<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DuplicateIndex),
            group: LintGroup::Perf,
            rationale: "An index identical to another serves no lookup and enforces no constraint the other does not, and still costs space and every write.",
            source: Some(
                "https://github.com/supabase/splinter/blob/main/lints/0009_duplicate_index.sql",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE public.documents (identifier integer PRIMARY KEY, title text);\n\
CREATE INDEX documents_title_first ON public.documents ((lower(title))) WHERE title IS NOT NULL;\n\
CREATE INDEX documents_title_second ON public.documents ((lower(title))) WHERE title IS NOT NULL;",
                good: "CREATE TABLE public.documents (identifier integer PRIMARY KEY, title text);\n\
CREATE INDEX documents_title_first ON public.documents ((lower(title))) WHERE title IS NOT NULL;",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for DuplicateIndex<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut entries = Vec::new();
        for index in table.unique_indices(database)? {
            entries.push(Entry::of(database, index, true)?);
        }
        for index in table.indices(database)? {
            entries.push(Entry::of(database, index, false)?);
        }
        for (position, entry) in entries.iter().enumerate() {
            let Some(earlier) = entries[..position]
                .iter()
                .find(|earlier| earlier.definition == entry.definition)
            else {
                continue;
            };
            if entry.reported_elsewhere(earlier) {
                continue;
            }
            reporter.table(
                table,
                format!(
                    "Index '{}' on '{}' repeats index '{}' in every key, predicate, method, uniqueness and included column, so '{}' serves every lookup it does.",
                    entry.name,
                    table.table_name(),
                    earlier.name,
                    earlier.name
                ),
                format!("DROP INDEX {};", entry.name),
            )?;
        }
        Ok(())
    }
}
