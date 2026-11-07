//! Submodule providing the `SerialColumn`, `NarrowIntegerKey` and
//! `ClientWrittenCounterKey` rules.

use sql_traits::{
    errors::LookupError,
    traits::{ColumnLike, DataTypeLike, DatabaseLike, TableLike},
};
use sqlparser::{ast::Expr, dialect::PostgreSqlDialect, parser::Parser};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::grant_support::is_client_written,
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// Whether the column's type is `integer` or `smallint`.
fn is_narrow_integer<DB: DatabaseLike>(database: &DB, column: &DB::Column) -> bool {
    matches!(
        column
            .data_type(database)
            .normalized_name(database)
            .to_ascii_lowercase()
            .as_str(),
        "int" | "integer" | "int4" | "smallint" | "int2"
    )
}

/// Whether the column's type is an integer of any width.
fn is_integer<DB: DatabaseLike>(database: &DB, column: &DB::Column) -> bool {
    is_narrow_integer(database, column)
        || matches!(
            column
                .data_type(database)
                .normalized_name(database)
                .to_ascii_lowercase()
                .as_str(),
            "bigint" | "int8"
        )
}

/// Whether the column belongs to its table's primary key.
fn in_primary_key<DB: DatabaseLike>(
    database: &DB,
    column: &DB::Column,
) -> Result<bool, LookupError> {
    Ok(column
        .table(database)
        .primary_key_columns(database)?
        .any(|key| key == column))
}

/// Whether the column's default draws from a sequence.
fn defaults_to_nextval<C: ColumnLike>(column: &C) -> bool {
    column
        .default_value()
        .and_then(|default| {
            Parser::new(&PostgreSqlDialect {})
                .try_with_sql(&default)
                .ok()?
                .parse_expr()
                .ok()
        })
        .is_some_and(|default| {
            matches!(&default, Expr::Function(call) if call
                .name
                .0
                .last()
                .and_then(|part| part.as_ident())
                .is_some_and(|ident| ident.value.eq_ignore_ascii_case("nextval")))
        })
}

rule_definition!(
    /// Struct defining a rule that reports a `serial`, `smallserial` or
    /// `bigserial` column outside client-written tables.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = SerialColumn::default().into();
    /// let serial = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id BIGSERIAL);").unwrap();
    /// assert!(constrainer.validate_schema(&serial).is_err());
    /// let identity = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE t (id BIGINT GENERATED ALWAYS AS IDENTITY);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&identity).is_ok());
    /// ```
    SerialColumn,
    register_column_rule,
    LintGroup::Style,
    "A serial column owns a separate sequence that needs its own grants and dependency handling, while an identity column keeps the counter part of the column.",
    Some("https://wiki.postgresql.org/wiki/Don%27t_Do_This")
);

impl<DB: DatabaseLike> ColumnRule for SerialColumn<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table = column.table(database);
        if !column.is_serial(database) || is_client_written(database, reporter.deployment(), table)
        {
            return Ok(());
        }
        let name = column.column_name();
        reporter.column(
            column,
            format!("Column '{}.{name}' is serial, which draws from a sequence that needs grants of its own.", table.table_name()),
            format!("Declare '{name}' as GENERATED ALWAYS AS IDENTITY."),
        )?;
        Ok(())
    }
}

rule_definition!(
    /// Struct defining a rule that reports an `integer` or `smallint` primary
    /// key or identity column outside client-written tables.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = NarrowIntegerKey::default().into();
    /// let narrow = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT PRIMARY KEY);").unwrap();
    /// assert!(constrainer.validate_schema(&narrow).is_err());
    /// let wide = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id BIGINT PRIMARY KEY);").unwrap();
    /// assert!(constrainer.validate_schema(&wide).is_ok());
    /// ```
    NarrowIntegerKey,
    register_column_rule,
    LintGroup::Pedantic,
    "An integer key overflows at 2,147,483,647 values over the table's lifetime, and a smallint key at 32,767.",
    Some("https://github.com/sbdchd/squawk/blob/master/docs/docs/prefer-bigint-over-int.md")
);

impl<DB: DatabaseLike> ColumnRule for NarrowIntegerKey<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table = column.table(database);
        if !is_narrow_integer(database, column)
            || is_client_written(database, reporter.deployment(), table)
            || (column.identity_generation(database).is_none()
                && !in_primary_key(database, column)?)
        {
            return Ok(());
        }
        let name = column.column_name();
        reporter.column(
            column,
            format!("Key column '{}.{name}' is a 32-bit or 16-bit integer, which overflows over the table's lifetime.", table.table_name()),
            format!("Declare '{name}' as bigint."),
        )?;
        Ok(())
    }
}

rule_definition!(
    /// Struct defining a rule that reports a primary key column minted by a
    /// counter on a client-written table.
    ///
    /// A `serial` or identity column, a default drawing from `nextval`, or an
    /// integer key with no default is minted by a counter. Each replica mints
    /// its own sequence, so two offline clients mint the same key and the server
    /// refuses the second row when it syncs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> = ClientWrittenCounterKey::default().into();
    /// constrainer.set_deployment(Deployment::default().with_client_written_table("public", "notes"));
    /// let counted =
    ///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE notes (id BIGSERIAL PRIMARY KEY);").unwrap();
    /// assert!(constrainer.validate_schema(&counted).is_err());
    /// let minted = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE notes (id UUID PRIMARY KEY DEFAULT gen_random_uuid());",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&minted).is_ok());
    /// ```
    ClientWrittenCounterKey,
    register_column_rule,
    LintGroup::Suspicious,
    "Each replica of a client-written table mints its own counter values, so two offline clients mint the same key and the server refuses the second row when it syncs.",
    None
);

impl<DB: DatabaseLike> ColumnRule for ClientWrittenCounterKey<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table = column.table(database);
        let counted = column.is_serial(database)
            || column.identity_generation(database).is_some()
            || defaults_to_nextval(column)
            || (is_integer(database, column) && column.default_value().is_none());
        if !counted
            || !is_client_written(database, reporter.deployment(), table)
            || !in_primary_key(database, column)?
        {
            return Ok(());
        }
        let name = column.column_name();
        reporter.column(
            column,
            format!("Key column '{}.{name}' is minted by a counter on a client-written table, so two offline clients can mint the same key.", table.table_name()),
            format!("Let clients mint '{name}' as a UUID, for example `uuid PRIMARY KEY DEFAULT gen_random_uuid()`."),
        )?;
        Ok(())
    }
}
