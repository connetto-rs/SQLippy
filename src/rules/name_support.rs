//! What the whole snake_case words of a column name say the column holds.

use crate::vocabulary::Vocabulary;

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
