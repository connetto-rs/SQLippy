//! Submodule providing the `FloatingPointMoney` rule.

use sql_traits::{traits::DatabaseLike, utils::scalar_family::ScalarFamily};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    rules::name_support::{NameHint, names_money},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};

/// A money-named column stored as floating point.
const HINT: NameHint = NameHint {
    families: &[ScalarFamily::Float],
    names: names_money,
    holds: "an amount of money",
    flaw: "which stores most decimal amounts inexactly",
    resolution: "Declare it `numeric`, which stores decimal amounts exactly, with the currency in an adjacent column when amounts in more than one currency share it.",
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
        HINT.check(database, column, reporter)
    }
}
