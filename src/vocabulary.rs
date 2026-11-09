//! Words of one language that tell what a column holds, which the rules
//! reading column names match against.

use std::{borrow::Cow, sync::LazyLock};

/// English words naming an amount of money.
const ENGLISH_MONEY_TERMS: [&str; 31] = [
    "price",
    "prices",
    "cost",
    "costs",
    "amount",
    "amounts",
    "balance",
    "balances",
    "fee",
    "fees",
    "tax",
    "taxes",
    "salary",
    "salaries",
    "wage",
    "wages",
    "revenue",
    "revenues",
    "expense",
    "expenses",
    "expenditure",
    "expenditures",
    "payment",
    "payments",
    "refund",
    "refunds",
    "discount",
    "discounts",
    "budget",
    "budgets",
    "cents",
];

/// English words turning an amount into a rate or a share of it.
const ENGLISH_RATIO_TERMS: [&str; 6] =
    ["rate", "rates", "ratio", "ratios", "percent", "percentage"];

/// The vocabulary a deployment that selects none is matched against.
static ENGLISH: LazyLock<Vocabulary> = LazyLock::new(Vocabulary::english);

/// Words of one language that tell what a column holds.
///
/// A rule matches each term against the whole snake_case words of a column
/// name, ignoring ASCII case, so `price` matches `total_price` and not
/// `priceless`. A deployment selects the vocabularies its schema uses with
/// [`Deployment::with_vocabulary`](crate::deployment::Deployment::with_vocabulary),
/// and English applies when it selects none.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let italian = Vocabulary::default()
///     .with_money_term("prezzo")
///     .with_ratio_term("aliquota");
/// let mut constrainer: GenericConstrainer<ParserDB> = FloatingPointMoney::default().into();
/// constrainer.set_deployment(Deployment::default().with_vocabulary(italian));
/// let prezzo = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (prezzo REAL);").unwrap();
/// assert!(constrainer.validate_schema(&prezzo).is_err());
/// let aliquota =
///     ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (prezzo_aliquota REAL);").unwrap();
/// assert!(constrainer.validate_schema(&aliquota).is_ok());
/// ```
#[derive(Debug, Clone, Default)]
pub struct Vocabulary {
    money_terms: Vec<Cow<'static, str>>,
    ratio_terms: Vec<Cow<'static, str>>,
}

impl Vocabulary {
    /// Returns the English vocabulary.
    #[must_use]
    pub fn english() -> Self {
        Self {
            money_terms: ENGLISH_MONEY_TERMS.into_iter().map(Cow::Borrowed).collect(),
            ratio_terms: ENGLISH_RATIO_TERMS.into_iter().map(Cow::Borrowed).collect(),
        }
    }

    /// Adds a word naming an amount of money, such as `price`.
    #[must_use]
    pub fn with_money_term(mut self, term: impl Into<Cow<'static, str>>) -> Self {
        self.money_terms.push(term.into());
        self
    }

    /// Adds a word turning an amount into a rate or a share, such as `rate`,
    /// so `tax_rate` does not name an amount of money.
    #[must_use]
    pub fn with_ratio_term(mut self, term: impl Into<Cow<'static, str>>) -> Self {
        self.ratio_terms.push(term.into());
        self
    }

    /// Returns whether `word` names an amount of money.
    pub(crate) fn is_money_term(&self, word: &str) -> bool {
        self.money_terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case(word))
    }

    /// Returns whether `word` turns an amount into a rate or a share.
    pub(crate) fn is_ratio_term(&self, word: &str) -> bool {
        self.ratio_terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case(word))
    }

    /// Returns the English vocabulary, built once.
    pub(crate) fn english_default() -> &'static Self {
        &ENGLISH
    }
}
