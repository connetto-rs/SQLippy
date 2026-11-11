//! Submodule providing the `SingularColumnName` constraint, which enforces
//! that the last segment of column names is singular.

use inflection_rs::inflection::singularize;

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleMetadata},
    traits::{ColumnRule, Constrainer, GenericConstrainer, Reporter},
};
use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

/// Struct defining a constraint that enforces that the last segment of a
/// column name is singular.
///
/// For column names with underscores (e.g., `user_account`), only the last
/// segment after the final underscore is checked for singularity.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `SingularColumnName` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = SingularColumnName::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (users INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (user INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
///
/// let invalid_segment = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (user_accounts INT);").unwrap();
/// assert!(constrainer.validate_schema(&invalid_segment).is_err());
///
/// let valid_segment = ParserDB::parse::<GenericDialect>("CREATE TABLE mytable (user_account INT);").unwrap();
/// assert!(constrainer.validate_schema(&valid_segment).is_ok());
///
/// // Latin singulars and plurals
/// for (name, singular) in [
///     ("spectrum", true),
///     ("spectra", false),
///     ("matrix", true),
///     ("matrices", false),
///     ("taxon", true),
///     ("taxa", false),
/// ] {
///     let schema = ParserDB::parse::<GenericDialect>(&format!("CREATE TABLE mytable ({name} INT);")).unwrap();
///     assert_eq!(constrainer.validate_schema(&schema).is_ok(), singular, "{name}");
/// }
/// ```
pub struct SingularColumnName<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for SingularColumnName<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<SingularColumnName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: SingularColumnName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_column_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for SingularColumnName<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "SingularColumnName",
            group: LintGroup::Style,
            rationale: "One naming convention keeps queries predictable, and this crate names a column after the single value it holds.",
            source: None,
            basis: Basis::Names,
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ColumnRule for SingularColumnName<DB> {
    type Database = DB;

    fn check_column(
        &self,
        database: &Self::Database,
        column: &<Self::Database as DatabaseLike>::Column,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let column_name = column.column_name();
        let last_segment = column_name.split('_').next_back().unwrap_or(column_name);

        let singularized = singularize(last_segment);
        if singularized == last_segment {
            return Ok(());
        }

        let table_name = column.table(database).table_name();
        let expected_name: std::borrow::Cow<'_, str> = if column_name.contains('_') {
            let prefix = &column_name[..column_name.rfind('_').unwrap()];
            std::borrow::Cow::Owned(format!("{prefix}_{singularized}"))
        } else {
            std::borrow::Cow::Borrowed(&singularized)
        };
        reporter.column(
            column,
            format!("Column '{column_name}' in table '{table_name}' has plural last segment '{last_segment}'."),
            format!(
                "Rename '{column_name}' to '{expected_name}' in table '{table_name}', singularizing the last segment '{last_segment}' to '{singularized}'."
            ),
        )?;
        Ok(())
    }
}
