//! Submodule providing the `NarrowerReferencingColumn` rule.

use sql_traits::traits::{ColumnLike, DataTypeLike, DatabaseLike, ForeignKeyLike, TableLike};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::type_support::describe,
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a rule that reports a foreign-key column whose type
/// modifier is narrower than the referenced column's.
///
/// PostgreSQL accepts a foreign key between columns of one type with
/// different modifiers and casts the referencing value to its own column
/// first. A shorter length or a smaller integer part rejects some parent keys,
/// so they can never be referenced. A smaller numeric scale rounds `1.5` to
/// `2` and references the parent row `2`. A smaller fractional-second
/// precision rounds a timestamp off its parent. A referencing column without
/// a limit, or with a wider one, holds every parent key and is not reported,
/// and columns of different types are left to `incompatible_foreign_key`.
///
/// The rule does not run on SQLite, which has no enforced type modifiers.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NarrowerReferencingColumn::default().into();
///
/// let narrower = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE parents (id varchar(20) PRIMARY KEY);
///      CREATE TABLE children (parent_id varchar(10) REFERENCES parents(id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&narrower).is_err());
///
/// let matching = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE parents (id varchar(20) PRIMARY KEY);
///      CREATE TABLE children (parent_id varchar(20) REFERENCES parents(id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&matching).is_ok());
/// ```
pub struct NarrowerReferencingColumn<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NarrowerReferencingColumn<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NarrowerReferencingColumn<DB>> for GenericConstrainer<DB> {
    fn from(rule: NarrowerReferencingColumn<DB>) -> Self {
        let mut constrainer = Self::default();
        constrainer.register_foreign_key_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for NarrowerReferencingColumn<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(NarrowerReferencingColumn),
            group: LintGroup::Suspicious,
            rationale: "A narrower foreign-key modifier can reject parent keys or round them to a different parent row.",
            source: Some("https://www.postgresql.org/docs/current/datatype.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE parents (id varchar(20) PRIMARY KEY);\nCREATE TABLE children (parent_id varchar(10) REFERENCES parents(id));",
                good: "CREATE TABLE parents (id varchar(20) PRIMARY KEY);\nCREATE TABLE children (parent_id varchar(20) REFERENCES parents(id));",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

/// Whether a finite limit excludes values admitted by the other limit.
fn narrower<T: Ord>(child: Option<T>, parent: Option<T>) -> bool {
    child.is_some_and(|child| parent.is_none_or(|parent| child < parent))
}

/// The decimal digits available before the decimal point.
fn integer_digits<T: DataTypeLike>(data_type: &T, database: &T::DB) -> Option<i128> {
    Some(
        i128::from(data_type.numeric_precision(database)?)
            - i128::from(data_type.numeric_scale(database)?),
    )
}

impl<DB: DatabaseLike> ForeignKeyRule for NarrowerReferencingColumn<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &DB,
        foreign_key: &DB::ForeignKey,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        let table = foreign_key.host_table(database);
        let parent_table = foreign_key.referenced_table(database)?;
        for (column, parent_column) in foreign_key
            .host_columns(database)?
            .zip(foreign_key.referenced_columns(database)?)
        {
            let child = column.data_type(database);
            let parent = parent_column.data_type(database);
            if child.base_type(database).is_some()
                || parent.base_type(database).is_some()
                || child.normalized_name(database) != parent.normalized_name(database)
            {
                continue;
            }
            let consequence = if narrower(
                child.max_character_length(database),
                parent.max_character_length(database),
            ) || narrower(
                child.max_bit_length(database),
                parent.max_bit_length(database),
            ) {
                "some parent keys cannot be referenced"
            } else if narrower(
                child.numeric_scale(database),
                parent.numeric_scale(database),
            ) {
                "rounding can reference a different parent row"
            } else if narrower(
                integer_digits(child, database),
                integer_digits(parent, database),
            ) {
                "some parent keys overflow and cannot be referenced"
            } else if narrower(
                child.fractional_seconds_precision(database),
                parent.fractional_seconds_precision(database),
            ) {
                "rounding can move a key off its parent"
            } else {
                continue;
            };
            reporter.foreign_key(
                foreign_key,
                format!("Foreign key column `{}.{}` of type `{}` is narrower than parent column `{}.{}` of type `{}`, so {consequence}.",
                    table.table_name(), column.column_name(), describe(child, database),
                    parent_table.table_name(), parent_column.column_name(), describe(parent, database)),
                "Use modifiers that preserve every parent key.".to_owned(),
            )?;
        }
        Ok(())
    }
}
