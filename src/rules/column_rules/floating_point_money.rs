//! Submodule providing the `FloatingPointMoney` rule.

use sql_traits::{
    traits::{ColumnLike, DataTypeLike, DatabaseLike, TableLike},
    utils::scalar_family::ScalarFamily,
};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::{name_support::names_money, type_support::underlying_type},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

rule_definition!(
    /// Struct defining a rule that reports a column whose name names an
    /// amount of money and whose type is floating point.
    ///
    /// The name is matched against the deployment's vocabularies, English
    /// unless it selects others, and the type is read through arrays and
    /// domains, so `prices amount_t[]` over `amount_t AS real` is reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = FloatingPointMoney::default().into();
    /// let float = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (total_price REAL);").unwrap();
    /// assert!(constrainer.validate_schema(&float).is_err());
    /// let exact = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (total_price NUMERIC);").unwrap();
    /// assert!(constrainer.validate_schema(&exact).is_ok());
    /// ```
    FloatingPointMoney,
    register_column_rule,
    LintGroup::Suspicious,
    "Floating-point types store most decimal fractions approximately, so summed amounts drift by fractions of a cent and fail to equal the exact total.",
    Some("https://www.postgresql.org/docs/current/datatype-numeric.html#DATATYPE-FLOAT")
);

impl<DB: DatabaseLike> ColumnRule for FloatingPointMoney<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let data_type = column.data_type(database);
        let column_name = column.column_name();
        if underlying_type(database, data_type).scalar_family(database) != Some(ScalarFamily::Float)
            || !names_money(reporter.deployment().vocabularies(), column_name)
        {
            return Ok(());
        }
        let table_name = column.table(database).table_name();
        reporter.column(
            column,
            format!(
                "Column '{table_name}.{column_name}' names an amount of money but is typed `{}`, which stores most decimal amounts inexactly.",
                data_type.name(database)
            ),
            "Declare it `numeric`, which stores decimal amounts exactly, with the currency in an adjacent column when amounts in more than one currency share it.".to_owned(),
        )?;
        Ok(())
    }
}
