//! What the whole snake_case words of a column name say the column holds,
//! and the check of the rules reporting a column whose stored type disagrees.

use sql_traits::{
    traits::{ColumnLike, DataTypeLike, DatabaseLike, TableLike},
    utils::scalar_family::ScalarFamily,
};

use crate::{
    error::Interruption, rules::type_support::underlying_type, traits::Reporter,
    vocabulary::Vocabulary,
};

/// The non-empty snake_case words of a name.
fn words(name: &str) -> impl Iterator<Item = &str> {
    name.split('_').filter(|word| !word.is_empty())
}

/// Whether the name names an amount of money in one of the vocabularies,
/// holding a money term and no ratio term, so `total_price` does and
/// `tax_rate` does not.
pub(crate) fn names_money(vocabularies: &[Vocabulary], name: &str) -> bool {
    let mut money = false;
    for word in words(name) {
        if vocabularies
            .iter()
            .any(|vocabulary| vocabulary.is_ratio_term(word))
        {
            return false;
        }
        money |= vocabularies
            .iter()
            .any(|vocabulary| vocabulary.is_money_term(word));
    }
    money
}

/// Whether the first word of the name opens a yes or no state in one of the
/// vocabularies, as `is` opens `is_active`.
pub(crate) fn names_flag(vocabularies: &[Vocabulary], name: &str) -> bool {
    words(name).next().is_some_and(|word| {
        vocabularies
            .iter()
            .any(|vocabulary| vocabulary.is_flag_prefix(word))
    })
}

/// Whether the last word of the name closes the name of a uuid in one of the
/// vocabularies, as `uuid` closes `owner_uuid`.
pub(crate) fn names_uuid(vocabularies: &[Vocabulary], name: &str) -> bool {
    words(name).last().is_some_and(|word| {
        vocabularies
            .iter()
            .any(|vocabulary| vocabulary.is_uuid_term(word))
    })
}

/// A column whose name says what it holds while its stored type cannot hold
/// that faithfully, as one rule reports it.
pub(crate) struct NameHint {
    /// Scalar families of the stored types reported.
    pub(crate) families: &'static [ScalarFamily],
    /// Whether a column name says the column holds what the hint is about.
    pub(crate) names: fn(&[Vocabulary], &str) -> bool,
    /// What the name says the column holds, such as `an amount of money`.
    pub(crate) holds: &'static str,
    /// What the stored type does wrong, ending the message.
    pub(crate) flaw: &'static str,
    /// The type to declare instead, and why.
    pub(crate) resolution: &'static str,
}

impl NameHint {
    /// Reports `column` when its name says what the hint is about and its
    /// type, through arrays and domains, is stored in one of the families.
    pub(crate) fn check<DB: DatabaseLike>(
        &self,
        database: &DB,
        column: &DB::Column,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        let data_type = column.data_type(database);
        let column_name = column.column_name();
        if !underlying_type(database, data_type)
            .scalar_family(database)
            .is_some_and(|family| self.families.contains(&family))
            || !(self.names)(reporter.deployment().vocabularies(), column_name)
        {
            return Ok(());
        }
        let table_name = column.table(database).table_name();
        reporter.column(
            column,
            format!(
                "Column '{table_name}.{column_name}' names {} but is typed `{}`, {}.",
                self.holds,
                data_type.name(database),
                self.flaw
            ),
            self.resolution.to_owned(),
        )?;
        Ok(())
    }
}
