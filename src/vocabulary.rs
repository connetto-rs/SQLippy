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
const ENGLISH_MOMENT_TERMS: [&str; 5] = ["at", "date", "time", "timestamp", "birthday"];

/// English terms closing the name of an IP address or network.
const ENGLISH_ADDRESS_TERMS: [&str; 3] = ["ip", "cidr", "ip_address"];

/// English terms closing the name of a JSON document.
const ENGLISH_JSON_TERMS: [&str; 1] = ["json"];

/// English terms closing the name of a count of things.
const ENGLISH_COUNT_TERMS: [&str; 3] = ["count", "quantity", "qty"];

/// English words turning a count into an average of counts.
const ENGLISH_AVERAGE_TERMS: [&str; 4] = ["avg", "average", "mean", "median"];

/// English terms closing the name of an identifier.
const ENGLISH_IDENTIFIER_TERMS: [&str; 1] = ["id"];

/// The vocabulary a deployment that selects none is matched against.
static ENGLISH: LazyLock<Vocabulary> = LazyLock::new(Vocabulary::english);

/// Whether `word` is one of `terms`, ignoring ASCII case.
fn holds(terms: &[Cow<'static, str>], word: &str) -> bool {
    terms.iter().any(|term| term.eq_ignore_ascii_case(word))
}

/// Whether the last `snake_case` words of `name` are the words of `term`,
/// ignoring ASCII case. A term without words matches nothing.
fn ends_with_words(name: &str, term: &str) -> bool {
    let mut name_words = name.rsplit('_').filter(|word| !word.is_empty());
    let mut term_words = term.rsplit('_').filter(|word| !word.is_empty()).peekable();
    term_words.peek().is_some()
        && term_words.all(|term_word| {
            name_words
                .next()
                .is_some_and(|name_word| name_word.eq_ignore_ascii_case(term_word))
        })
}

/// What the closing words of a column name say the column holds.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Ending {
    /// A uuid.
    Uuid,
    /// A moment or a day.
    Moment,
    /// An IP address or network.
    Address,
    /// A JSON document.
    Json,
    /// A count of things.
    Count,
    /// An identifier.
    Identifier,
}

/// Words of one language that tell what a column holds.
///
/// A rule matches each term against the whole `snake_case` words of a column
/// name, ignoring ASCII case, so `price` matches `total_price` and not
/// `priceless`. A flag prefix must be the first word. A uuid, moment,
/// address, JSON or count term must close the name, and a term of several
/// words such as `ip_address` matches the name's last words. A deployment
/// selects the vocabularies its schema uses with
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
    address_terms: Vec<Cow<'static, str>>,
    json_terms: Vec<Cow<'static, str>>,
    count_terms: Vec<Cow<'static, str>>,
    average_terms: Vec<Cow<'static, str>>,
    identifier_terms: Vec<Cow<'static, str>>,
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
            address_terms: words(&ENGLISH_ADDRESS_TERMS),
            json_terms: words(&ENGLISH_JSON_TERMS),
            count_terms: words(&ENGLISH_COUNT_TERMS),
            average_terms: words(&ENGLISH_AVERAGE_TERMS),
            identifier_terms: words(&ENGLISH_IDENTIFIER_TERMS),
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

    /// Adds a term closing the name of an IP address or network, such as
    /// `ip` or `ip_address`, so `client_ip` names one.
    #[must_use]
    pub fn with_address_term(mut self, term: impl Into<Cow<'static, str>>) -> Self {
        self.address_terms.push(term.into());
        self
    }

    /// Adds a term closing the name of a JSON document, such as `json`, so
    /// `payload_json` names one.
    #[must_use]
    pub fn with_json_term(mut self, term: impl Into<Cow<'static, str>>) -> Self {
        self.json_terms.push(term.into());
        self
    }

    /// Adds a term closing the name of a count of things, such as `count` or
    /// `qty`, so `item_count` names one.
    #[must_use]
    pub fn with_count_term(mut self, term: impl Into<Cow<'static, str>>) -> Self {
        self.count_terms.push(term.into());
        self
    }

    /// Adds a word turning a count into an average of counts, such as `avg`,
    /// so `avg_count` does not name a count.
    #[must_use]
    pub fn with_average_term(mut self, term: impl Into<Cow<'static, str>>) -> Self {
        self.average_terms.push(term.into());
        self
    }

    /// Adds a term closing the name of an identifier, such as `id`, so
    /// `tax_id` names an identifier rather than an amount of money.
    #[must_use]
    pub fn with_identifier_term(mut self, term: impl Into<Cow<'static, str>>) -> Self {
        self.identifier_terms.push(term.into());
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

    /// Returns whether `word` turns a count into an average of counts.
    pub(crate) fn is_average_term(&self, word: &str) -> bool {
        holds(&self.average_terms, word)
    }

    /// Returns whether the last words of `name` are one of the terms of
    /// `ending`, as `owner_uuid` ends with `uuid` and `server_ip_address`
    /// with `ip_address`.
    pub(crate) fn ends(&self, ending: Ending, name: &str) -> bool {
        let terms = match ending {
            Ending::Uuid => &self.uuid_terms,
            Ending::Moment => &self.moment_terms,
            Ending::Address => &self.address_terms,
            Ending::Json => &self.json_terms,
            Ending::Count => &self.count_terms,
            Ending::Identifier => &self.identifier_terms,
        };
        terms.iter().any(|term| ends_with_words(name, term))
    }

    /// Returns the English vocabulary, built once.
    pub(crate) fn english_default() -> &'static Self {
        &ENGLISH
    }
}
