//! Submodule providing the `PolymorphicReference` rule.

use std::borrow::Cow;

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DataTypeLike, DatabaseLike, IndexLike, TableLike},
};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::index_support::entry_columns,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
    vocabulary::{Ending, Vocabulary},
};

rule_definition!(
    /// Struct defining a rule that reports a table holding a reference to a
    /// row of one of several tables in a discriminator column, such as
    /// `target_type`, beside an identifier column, such as `target_id`, that
    /// no foreign key checks.
    ///
    /// A column whose name closes with a discriminator term of the
    /// deployment's vocabularies, `type` or `kind` in English, after a
    /// non-empty stem, pairs with the column named that stem and an
    /// identifier term, `id` in English, compared case-insensitively. The
    /// discriminator's type does not matter, so a text, enumeration or
    /// checked column pairs alike. The pair is reported unless one of these
    /// holds.
    ///
    /// - A foreign key of the table includes the identifier column, alone or
    ///   with the discriminator in a composite key to a table every target
    ///   extends.
    /// - The table's primary key is the identifier column, alone or with the
    ///   discriminator, so the pair describes the row itself.
    /// - The identifier column's type is the type of no primary key or unique
    ///   key column in the schema, so no table holds a row it could name, as
    ///   for a `provider_id TEXT` naming an object of an external service.
    ///
    /// A historical record such as `audit_log(entity_type, entity_id)` keeps
    /// the identifier of a row that may since be deleted, so no foreign key
    /// fits it. The rule reports it, and an allowance on the table excuses
    /// it.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = PolymorphicReference::default().into();
    ///
    /// let polymorphic = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE posts (id BIGINT PRIMARY KEY);
    ///      CREATE TABLE photos (id BIGINT PRIMARY KEY);
    ///      CREATE TABLE comments (
    ///          id BIGINT PRIMARY KEY,
    ///          target_type TEXT NOT NULL CHECK (target_type IN ('post', 'photo')),
    ///          target_id BIGINT NOT NULL
    ///      );",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&polymorphic).is_err());
    ///
    /// let common_target = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE targets (id BIGINT PRIMARY KEY, kind TEXT NOT NULL, UNIQUE (id, kind));
    ///      CREATE TABLE comments (
    ///          id BIGINT PRIMARY KEY,
    ///          target_type TEXT NOT NULL,
    ///          target_id BIGINT NOT NULL,
    ///          FOREIGN KEY (target_id, target_type) REFERENCES targets (id, kind)
    ///      );",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&common_target).is_ok());
    /// ```
    PolymorphicReference,
    register_table_rule,
    LintGroup::Pedantic,
    "A discriminator column selects the table an identifier names a row of, which no foreign key can follow, so the identifier can name a missing row or a row of the wrong table.",
    Some("https://search.worldcat.org/isbn/9780133970777"),
    RuleExample {
        bad: "CREATE TABLE posts (id BIGINT PRIMARY KEY);\n\
CREATE TABLE photos (id BIGINT PRIMARY KEY);\n\
CREATE TABLE comments (\n\
    id BIGINT PRIMARY KEY,\n\
    target_type TEXT NOT NULL CHECK (target_type IN ('post', 'photo')),\n\
    target_id BIGINT NOT NULL\n\
);",
        good: "CREATE TABLE targets (id BIGINT PRIMARY KEY, kind TEXT NOT NULL, UNIQUE (id, kind));\n\
CREATE TABLE posts (\n\
    id BIGINT PRIMARY KEY,\n\
    kind TEXT NOT NULL CHECK (kind = 'post'),\n\
    FOREIGN KEY (id, kind) REFERENCES targets (id, kind)\n\
);\n\
CREATE TABLE photos (\n\
    id BIGINT PRIMARY KEY,\n\
    kind TEXT NOT NULL CHECK (kind = 'photo'),\n\
    FOREIGN KEY (id, kind) REFERENCES targets (id, kind)\n\
);\n\
CREATE TABLE comments (\n\
    id BIGINT PRIMARY KEY,\n\
    target_type TEXT NOT NULL,\n\
    target_id BIGINT NOT NULL,\n\
    FOREIGN KEY (target_id, target_type) REFERENCES targets (id, kind)\n\
);",
    },
    Basis::Names
);

/// The first non-empty stem `name` closes with a term of `ending` after in
/// one of the vocabularies, or `None` when there is none.
fn stem<'n>(vocabularies: &[Vocabulary], ending: Ending, name: &'n str) -> Option<&'n str> {
    vocabularies
        .iter()
        .filter_map(|vocabulary| vocabulary.stem(ending, name))
        .find(|stem| !stem.is_empty())
}

/// The normalized type names of every column of a primary key, a unique
/// constraint or a unique index in the schema.
fn key_types<DB: DatabaseLike>(database: &DB) -> Result<Vec<Cow<'_, str>>, LookupError> {
    let mut types = Vec::new();
    for table in database.tables() {
        let mut columns = Vec::new();
        for unique in table.unique_indices(database)? {
            columns.extend(entry_columns(database, unique)?);
        }
        for index in table.indices(database)?.filter(|index| index.is_unique()) {
            columns.extend(entry_columns(database, index)?);
        }
        for column in columns.into_iter().flatten() {
            let name = column.data_type(database).normalized_name(database);
            if !types.contains(&name) {
                types.push(name);
            }
        }
    }
    Ok(types)
}

impl<DB: DatabaseLike> TableRule for PolymorphicReference<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let vocabularies = reporter.deployment().vocabularies();
        let columns: Vec<&DB::Column> = table.columns(database)?.collect();
        let mut pairs = Vec::new();
        for discriminator in &columns {
            let Some(discriminator_stem) = stem(
                vocabularies,
                Ending::Discriminator,
                discriminator.column_name(),
            ) else {
                continue;
            };
            let Some(identifier) = columns.iter().find(|column| {
                stem(vocabularies, Ending::Identifier, column.column_name())
                    .is_some_and(|stem| stem.eq_ignore_ascii_case(discriminator_stem))
            }) else {
                continue;
            };
            if identifier.is_part_of_foreign_key(database)? {
                continue;
            }
            let mut primary_key = table.primary_key_columns(database)?.peekable();
            if primary_key.peek().is_some()
                && primary_key.all(|column| column == *identifier || column == *discriminator)
            {
                continue;
            }
            pairs.push((*discriminator, *identifier));
        }
        if pairs.is_empty() {
            return Ok(());
        }
        let key_types = key_types(database)?;
        let table_name = table.table_name();
        for (discriminator, identifier) in pairs {
            let identifier_type = identifier.data_type(database).normalized_name(database);
            if !key_types.contains(&identifier_type) {
                continue;
            }
            let discriminator = discriminator.column_name();
            let identifier = identifier.column_name();
            reporter.table(
                table,
                format!(
                    "Table '{table_name}' holds in '{discriminator}' and '{identifier}' a reference whose table '{discriminator}' selects, and no foreign key checks '{identifier}', so it can name a missing row or a row of the wrong table."
                ),
                format!(
                    "Make every table '{discriminator}' selects extend one table and reference it with a foreign key on '{identifier}', or on '{identifier}' and '{discriminator}' together, or replace the pair with one foreign key column per selected table."
                ),
            )?;
        }
        Ok(())
    }
}
