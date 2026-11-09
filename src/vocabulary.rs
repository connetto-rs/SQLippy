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

/// English words opening the name of a yes or no state.
const ENGLISH_FLAG_PREFIXES: [&str; 5] = ["is", "has", "can", "should", "was"];

/// English words closing the name of a uuid.
const ENGLISH_UUID_TERMS: [&str; 1] = ["uuid"];

/// English words closing the name of a moment or a day.
const ENGLISH_MOMENT_TERMS: [&str; 6] = ["at", "on", "date", "time", "timestamp", "birthday"];

/// The vocabulary a deployment that selects none is matched against.
static ENGLISH: LazyLock<Vocabulary> = LazyLock::new(Vocabulary::english);

/// Whether `word` is one of `terms`, ignoring ASCII case.
fn holds(terms: &[Cow<'static, str>], word: &str) -> bool {
    terms.iter().any(|term| term.eq_ignore_ascii_case(word))
}

/// Words of one language that tell what a column holds.
///
/// A rule matches each term against the whole snake_case words of a column
/// name, ignoring ASCII case, so `price` matches `total_price` and not
/// `priceless`. A flag prefix must be the first word, and a uuid or moment
/// term the last. A deployment selects the vocabularies its schema uses with
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
    flag_prefixes: Vec<Cow<'static, str>>,
    uuid_terms: Vec<Cow<'static, str>>,
    moment_terms: Vec<Cow<'static, str>>,
}

impl Vocabulary {
    /// Returns the English vocabulary.
    #[must_use]
    pub fn english() -> Self {
        let words = |terms: &[&'static str]| terms.iter().copied().map(Cow::Borrowed).collect();
        Self {
            money_terms: words(&ENGLISH_MONEY_TERMS),
            ratio_terms: words(&ENGLISH_RATIO_TERMS),
            flag_prefixes: words(&ENGLISH_FLAG_PREFIXES),
            uuid_terms: words(&ENGLISH_UUID_TERMS),
            moment_terms: words(&ENGLISH_MOMENT_TERMS),
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

    /// Adds a word opening the name of a yes or no state, such as `is`, so
    /// `is_active` names one.
    #[must_use]
    pub fn with_flag_prefix(mut self, prefix: impl Into<Cow<'static, str>>) -> Self {
        self.flag_prefixes.push(prefix.into());
        self
    }

    /// Adds a word closing the name of a uuid, such as `uuid`, so `owner_uuid`
    /// names one.
    #[must_use]
    pub fn with_uuid_term(mut self, term: impl Into<Cow<'static, str>>) -> Self {
        self.uuid_terms.push(term.into());
        self
    }

    /// Adds a word closing the name of a moment or a day, such as `at`, so
    /// `created_at` names one.
    #[must_use]
    pub fn with_moment_term(mut self, term: impl Into<Cow<'static, str>>) -> Self {
        self.moment_terms.push(term.into());
        self
    }

    /// Returns whether `word` names an amount of money.
    pub(crate) fn is_money_term(&self, word: &str) -> bool {
        holds(&self.money_terms, word)
    }

    /// Returns whether `word` turns an amount into a rate or a share.
    pub(crate) fn is_ratio_term(&self, word: &str) -> bool {
        holds(&self.ratio_terms, word)
    }

    /// Returns whether `word` opens the name of a yes or no state.
    pub(crate) fn is_flag_prefix(&self, word: &str) -> bool {
        holds(&self.flag_prefixes, word)
    }

    /// Returns whether `word` closes the name of a uuid.
    pub(crate) fn is_uuid_term(&self, word: &str) -> bool {
        holds(&self.uuid_terms, word)
    }

    /// Returns whether `word` closes the name of a moment or a day.
    pub(crate) fn is_moment_term(&self, word: &str) -> bool {
        holds(&self.moment_terms, word)
    }

    /// Returns the English vocabulary, built once.
    pub(crate) fn english_default() -> &'static Self {
        &ENGLISH
    }
}
