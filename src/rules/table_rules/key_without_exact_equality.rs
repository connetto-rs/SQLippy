//! Submodule providing the `KeyWithoutExactEquality` rule, which reports key
//! columns whose type does not compare values exactly.

use sql_traits::{
    errors::LookupError,
    structs::IdentifierCase,
    traits::{
        ColumnLike, DataTypeLike, DatabaseLike, ForeignKeyLike, IndexLike, TableLike,
        UniqueIndexLike,
    },
    utils::scalar_family::ScalarFamily,
};
use sqlparser::ast::Expr;

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::policy_support::unnested,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// How a type with inexact equality compares, completing a sentence about it.
fn inexact_equality<T: DataTypeLike>(data_type: &T, database: &T::DB) -> Option<&'static str> {
    let data_type = data_type.base_type(database).unwrap_or(data_type);
    match data_type.scalar_family(database) {
        Some(ScalarFamily::Interval) => Some(
            "compares intervals by total length with a month as 30 days, so '1 mon' and '30 days' are one key value",
        ),
        Some(ScalarFamily::Float) => Some(
            "stores rounded binary fractions, so a value computed as 0.1 + 0.2 is not found by 0.3 and a `real` key is not found by a `double precision` value",
        ),
        _ => data_type
            .array_element(database)
            .and_then(|element| inexact_equality(element, database)),
    }
}

/// Struct defining a rule that reports a primary key, unique constraint,
/// unique index or foreign key over a column of a type without exact
/// equality: `interval`, `real`, `double precision`, an array of them, or a
/// domain over any of these.
///
/// A unique index over an expression of such a column compares the
/// expression, so it is not reported.
///
/// # Example
///
/// ```rust
/// use sql_rules::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = KeyWithoutExactEquality::default().into();
///
/// let interval_key =
///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE spans (span INTERVAL PRIMARY KEY);").unwrap();
/// assert!(constrainer.validate_schema(&interval_key).is_err());
///
/// let integer_key = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE spans (id INT PRIMARY KEY, span INTERVAL);",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&integer_key).is_ok());
/// ```
pub struct KeyWithoutExactEquality<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for KeyWithoutExactEquality<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<KeyWithoutExactEquality<DB>> for GenericConstrainer<DB> {
    fn from(rule: KeyWithoutExactEquality<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for KeyWithoutExactEquality<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "KeyWithoutExactEquality",
            group: LintGroup::Suspicious,
            rationale: "A key over a type whose equality is not exact merges values that differ or misses values that look the same, and engines without the type, such as SQLite, cannot reproduce PostgreSQL's comparison.",
            source: Some(
                "https://www.postgresql.org/docs/current/datatype-numeric.html#DATATYPE-FLOAT",
            ),
        };
        &METADATA
    }
}

/// Columns an index names directly, leaving out those only inside an
/// expression.
fn named_columns<'db, I: IndexLike>(
    index: &'db I,
    database: &'db I::DB,
) -> Result<Vec<&'db <I::DB as DatabaseLike>::Column>, LookupError> {
    let entries = match index.expression(database)? {
        Expr::Tuple(entries) => entries.as_slice(),
        entry => std::slice::from_ref(entry),
    };
    let names: Vec<_> = entries
        .iter()
        .filter_map(|entry| match unnested(entry) {
            Expr::Identifier(ident) => Some(ident),
            Expr::CompoundIdentifier(parts) => parts.last(),
            _ => None,
        })
        .collect();
    Ok(index
        .columns(database)?
        .filter(|column| {
            names.iter().any(|name| {
                IdentifierCase::AsWritten.identifiers_match(
                    column.column_name(),
                    column.column_name_is_quoted(),
                    &name.value,
                    name.quote_style.is_some(),
                )
            })
        })
        .collect())
}

impl<DB: DatabaseLike> TableRule for KeyWithoutExactEquality<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let mut keys: Vec<(&str, Vec<&DB::Column>)> = Vec::new();
        for unique in table.unique_indices(database)? {
            let kind = if unique.is_primary_key(database)? {
                "primary key"
            } else {
                "unique constraint"
            };
            keys.push((kind, named_columns(unique, database)?));
        }
        for index in table.indices(database)?.filter(|index| index.is_unique()) {
            keys.push(("unique index", named_columns(index, database)?));
        }
        for foreign_key in table.foreign_keys(database)? {
            keys.push(("foreign key", foreign_key.host_columns(database)?.collect()));
        }
        for (key, columns) in keys {
            for column in columns {
                let data_type = column.data_type(database);
                let Some(comparison) = inexact_equality(data_type, database) else {
                    continue;
                };
                let name = column.column_name();
                let type_name = data_type.normalized_name(database);
                reporter.column(
                    column,
                    format!(
                        "Column '{name}' of a {key} on '{}' is `{type_name}`, which {comparison}.",
                        table.table_name()
                    ),
                    format!(
                        "Key '{}' on an integer, text or uuid column and keep '{name}' as an ordinary column.",
                        table.table_name()
                    ),
                )?;
            }
        }
        Ok(())
    }
}
