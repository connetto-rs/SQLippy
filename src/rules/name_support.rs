//! What the whole snake_case words of a column name say the column holds,
//! and the check of the rules reporting a column whose stored type disagrees.

use sql_traits::{
    traits::{ColumnLike, DataTypeLike, DatabaseLike, TableLike},
    utils::scalar_family::ScalarFamily,
};

use crate::{
    error::Interruption,
    rules::type_support::underlying_type,
    traits::Reporter,
    vocabulary::{Ending, Vocabulary},
};

/// The non-empty snake_case words of a name.
fn words(name: &str) -> impl Iterator<Item = &str> {
    name.split('_').filter(|word| !word.is_empty())
}

/// Whether the name names an amount of money in one of the vocabularies,
/// holding a money term and no ratio term and closing with neither a count
/// nor an identifier term, so `total_price` does while `tax_rate`,
/// `payment_count` and `tax_id` do not.
pub(crate) fn names_money(vocabularies: &[Vocabulary], name: &str) -> bool {
    if closes_with(vocabularies, Ending::Count, name)
        || closes_with(vocabularies, Ending::Identifier, name)
    {
        return false;
    }
    let mut money = false;
    for word in words(name) {
        if in_vocabularies(vocabularies, Vocabulary::is_ratio_term, word) {
            return false;
        }
        money |= in_vocabularies(vocabularies, Vocabulary::is_money_term, word);
    }
    money
}

/// Whether one of the vocabularies holds `word` as the term `is_term` tests.
fn in_vocabularies(
    vocabularies: &[Vocabulary],
    is_term: fn(&Vocabulary, &str) -> bool,
    word: &str,
) -> bool {
    vocabularies
        .iter()
        .any(|vocabulary| is_term(vocabulary, word))
}

/// Whether the first word of the name opens a yes or no state in one of the
/// vocabularies, as `is` opens `is_active`.
pub(crate) fn names_flag(vocabularies: &[Vocabulary], name: &str) -> bool {
    words(name)
        .next()
        .is_some_and(|word| in_vocabularies(vocabularies, Vocabulary::is_flag_prefix, word))
}

/// Whether the last words of the name are a term of `ending` in one of the
/// vocabularies.
fn closes_with(vocabularies: &[Vocabulary], ending: Ending, name: &str) -> bool {
    vocabularies
        .iter()
        .any(|vocabulary| vocabulary.ends(ending, name))
}

/// Whether the name closes with a term of `ending` and does not open with a
/// flag prefix, since a flag-prefixed name such as `is_turned_on` holds a yes
/// or no state whatever its last word says.
fn names_ending(vocabularies: &[Vocabulary], ending: Ending, name: &str) -> bool {
    !names_flag(vocabularies, name) && closes_with(vocabularies, ending, name)
}

/// Whether the name closes with a uuid term in one of the vocabularies, as
/// `uuid` closes `owner_uuid`.
pub(crate) fn names_uuid(vocabularies: &[Vocabulary], name: &str) -> bool {
    names_ending(vocabularies, Ending::Uuid, name)
}

/// Whether the name closes with a moment term in one of the vocabularies, as
/// `at` closes `created_at`.
pub(crate) fn names_moment(vocabularies: &[Vocabulary], name: &str) -> bool {
    names_ending(vocabularies, Ending::Moment, name)
}

/// Whether the name closes with an address term in one of the vocabularies,
/// as `ip` closes `client_ip` and `ip_address` closes `server_ip_address`.
pub(crate) fn names_address(vocabularies: &[Vocabulary], name: &str) -> bool {
    names_ending(vocabularies, Ending::Address, name)
}

/// Whether the name closes with a JSON term in one of the vocabularies, as
/// `json` closes `payload_json`.
pub(crate) fn names_json(vocabularies: &[Vocabulary], name: &str) -> bool {
    names_ending(vocabularies, Ending::Json, name)
}

/// Whether the name closes with a count term in one of the vocabularies and
/// holds no average term, so `item_count` names a count and `avg_count` does
/// not.
pub(crate) fn names_count(vocabularies: &[Vocabulary], name: &str) -> bool {
    names_ending(vocabularies, Ending::Count, name)
        && !words(name).any(|word| in_vocabularies(vocabularies, Vocabulary::is_average_term, word))
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
    /// Whether the column's name says what the hint is about and its type,
    /// through arrays and domains, is stored in one of the families.
    pub(crate) fn matches<DB: DatabaseLike>(
        &self,
        database: &DB,
        column: &DB::Column,
        vocabularies: &[Vocabulary],
    ) -> bool {
        underlying_type(database, column.data_type(database))
            .scalar_family(database)
            .is_some_and(|family| self.families.contains(&family))
            && (self.names)(vocabularies, column.column_name())
    }

    /// Reports `column` when the hint [`matches`](Self::matches) it.
    pub(crate) fn check<DB: DatabaseLike>(
        &self,
        database: &DB,
        column: &DB::Column,
        reporter: &mut Reporter<'_, DB>,
    ) -> Result<(), Interruption> {
        if !self.matches(database, column, reporter.deployment().vocabularies()) {
            return Ok(());
        }
        let table_name = column.table(database).table_name();
        reporter.column(
            column,
            format!(
                "Column '{table_name}.{}' names {} but is typed `{}`, {}.",
                column.column_name(),
                self.holds,
                column.data_type(database).name(database),
                self.flaw
            ),
            self.resolution.to_owned(),
        )?;
        Ok(())
    }
}
