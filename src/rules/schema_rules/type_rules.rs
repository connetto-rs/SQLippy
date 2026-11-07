//! Submodule providing the rules reporting data types and temporal constructs
//! wherever the schema holds them.

use sql_traits::traits::{ColumnLike, DatabaseLike, DomainLike, PolicyLike, TableLike, ViewLike};

use crate::{
    error::{Interruption, PolicySite},
    lint::{LintGroup, Rule, RuleMetadata},
    rules::type_support::{TypeFlaw, TypeSite, type_uses},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule, reporter::signature},
};

/// Which uses of its flaw a type rule reports.
#[derive(Clone, Copy)]
enum Tables {
    /// Every use.
    All,
    /// Uses outside client-written tables.
    Others,
    /// Uses on client-written tables.
    ClientWritten,
}

/// What a type rule says about one use.
struct Wording {
    flaw: TypeFlaw,
    tables: Tables,
    problem: &'static str,
    echo: Option<&'static str>,
    resolution: &'static str,
}

/// Reports one use of the rule's flaw.
fn report_one<DB: DatabaseLike>(
    database: &DB,
    reporter: &mut Reporter<'_, DB>,
    site: &TypeSite<'_, DB>,
    written: &str,
    wording: &Wording,
    echo: &str,
) -> Result<(), Interruption> {
    let problem = wording.problem;
    let resolution = wording.resolution.to_owned();
    match *site {
        TypeSite::Column(column) => reporter.column(
            column,
            format!(
                "Column '{}.{}' uses {written}, {problem}{echo}",
                column.table(database).table_name(),
                column.column_name()
            ),
            resolution,
        ),
        TypeSite::Check(table) => reporter.table(
            table,
            format!(
                "A check on '{}' uses {written}, {problem}{echo}",
                table.table_name()
            ),
            resolution,
        ),
        TypeSite::Policy(table, policy, clause) => reporter.policies(
            vec![PolicySite {
                table: Box::new(table.clone()),
                policy: Box::new(policy.clone()),
                clause,
                expression: written.to_owned(),
            }],
            format!(
                "Policy '{}' on '{}' uses {written} in its {clause} clause, {problem}{echo}",
                policy.name(),
                table.table_name()
            ),
            resolution,
        ),
        TypeSite::Domain(domain) => reporter.domain(
            domain,
            format!("Domain '{}' uses {written}, {problem}", domain.name()),
            resolution,
        ),
        TypeSite::View(view) => reporter.view(
            view,
            format!("View '{}' uses {written}, {problem}", view.view_name()),
            resolution,
        ),
        TypeSite::MaterializedView(view) => reporter.materialized_view(
            view,
            format!(
                "Materialized view '{}' uses {written}, {problem}",
                view.view_name()
            ),
            resolution,
        ),
        TypeSite::Function(function) => reporter.function(
            function,
            format!(
                "Function '{}' uses {written}, {problem}",
                signature(function, database)
            ),
            resolution,
        ),
    }
}

/// Reports every use of the rule's flaw.
fn report<DB: DatabaseLike>(
    database: &DB,
    reporter: &mut Reporter<'_, DB>,
    wording: &Wording,
) -> Result<(), Interruption> {
    let deployment = reporter.deployment();
    for site in type_uses(database)? {
        let client_written = site.client_written(database, deployment);
        let in_scope = match wording.tables {
            Tables::All => true,
            Tables::Others => !client_written,
            Tables::ClientWritten => client_written,
        };
        let echo = wording
            .echo
            .filter(|_| client_written)
            .map_or_default(|echo| format!(" {echo}"));
        let found = site
            .found
            .iter()
            .filter(|(flaw, _)| in_scope && *flaw == wording.flaw);
        for (_, written) in found {
            report_one(database, reporter, &site.site, written, wording, &echo)?;
        }
    }
    Ok(())
}

/// Defines a rule reporting one type flaw.
macro_rules! type_rule {
    (
        $(#[$doc:meta])*
        $name:ident, $group:expr, $rationale:literal, $source:expr,
        $wording:expr
    ) => {
        rule_definition!($(#[$doc])* $name, register_schema_rule, $group, $rationale, $source);

        impl<DB: DatabaseLike> SchemaRule for $name<DB> {
            type Database = DB;

            fn check_schema(
                &self,
                database: &Self::Database,
                reporter: &mut Reporter<'_, Self::Database>,
            ) -> Result<(), Interruption> {
                report(database, reporter, &$wording)
            }
        }
    };
}

const WIKI: Option<&str> = Some("https://wiki.postgresql.org/wiki/Don%27t_Do_This");

type_rule!(
    /// Struct defining a rule that reports `timestamp` without time zone,
    /// in column, domain and function types and in casts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = TimestampWithoutTimeZone::default().into();
    /// let naive = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (at TIMESTAMP);").unwrap();
    /// assert!(constrainer.validate_schema(&naive).is_err());
    /// let zoned = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (at TIMESTAMPTZ);").unwrap();
    /// assert!(constrainer.validate_schema(&zoned).is_ok());
    /// ```
    TimestampWithoutTimeZone,
    LintGroup::Suspicious,
    "A timestamp without time zone stores a wall-clock reading with no zone, so the database cannot tell which moment it names, and a change of TimeZone shifts its comparisons with the current time.",
    WIKI,
    Wording {
        flaw: TypeFlaw::NaiveTimestamp,
        tables: Tables::All,
        problem: "which records no time zone, so the moment it names depends on the session's TimeZone.",
        echo: None,
        resolution: "Use `timestamptz`, which records a single moment.",
    }
);

type_rule!(
    /// Struct defining a rule that reports `time with time zone`, and
    /// `CURRENT_TIME`, which returns it.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = TimeWithTimeZone::default().into();
    /// let zoned = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (at TIMETZ);").unwrap();
    /// assert!(constrainer.validate_schema(&zoned).is_err());
    /// let plain = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (at TIME);").unwrap();
    /// assert!(constrainer.validate_schema(&plain).is_ok());
    /// ```
    TimeWithTimeZone,
    LintGroup::Suspicious,
    "A time with time zone carries an offset without a date, so it cannot follow daylight saving, and PostgreSQL implements it only for SQL compliance.",
    WIKI,
    Wording {
        flaw: TypeFlaw::TimeWithTimeZone,
        tables: Tables::All,
        problem: "a time with an offset and no date, which cannot follow daylight saving.",
        echo: None,
        resolution: "Use `timestamptz`, or `time` with the zone kept apart.",
    }
);

type_rule!(
    /// Struct defining a rule that reports `timestamp(0)` and
    /// `timestamptz(0)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ZeroPrecisionTimestamp::default().into();
    /// let rounded = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (at TIMESTAMPTZ(0));").unwrap();
    /// assert!(constrainer.validate_schema(&rounded).is_err());
    /// let exact = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (at TIMESTAMPTZ);").unwrap();
    /// assert!(constrainer.validate_schema(&exact).is_ok());
    /// ```
    ZeroPrecisionTimestamp,
    LintGroup::Suspicious,
    "A timestamp with precision 0 rounds the fractional second instead of truncating it, so storing the current time can store a moment up to half a second in the future.",
    WIKI,
    Wording {
        flaw: TypeFlaw::RoundedTimestamp,
        tables: Tables::All,
        problem: "which rounds the fractional second, so a stored time can lie up to half a second in the future.",
        echo: Some(
            "Clients write this table, so the server stores a time other than the one the client wrote and the echo rewrites the client's row."
        ),
        resolution: "Drop the precision, or truncate on purpose with `date_trunc('second', ...)`.",
    }
);

type_rule!(
    /// Struct defining a rule that reports `char(n)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = BlankPaddedCharacter::default().into();
    /// let padded = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (code CHAR(5));").unwrap();
    /// assert!(constrainer.validate_schema(&padded).is_err());
    /// let text = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (code VARCHAR(5));").unwrap();
    /// assert!(constrainer.validate_schema(&text).is_ok());
    /// ```
    BlankPaddedCharacter,
    LintGroup::Suspicious,
    "char(n) pads values with spaces to its width and accepts shorter ones, so stored values differ from the values written.",
    WIKI,
    Wording {
        flaw: TypeFlaw::BlankPaddedCharacter,
        tables: Tables::All,
        problem: "which pads values with spaces to its width and accepts shorter ones.",
        echo: Some(
            "Clients write this table, so the echo hands the client a padded value it never wrote."
        ),
        resolution: "Use `text` or `varchar(n)`, with a length check if the width is fixed.",
    }
);

type_rule!(
    /// Struct defining a rule that reports `money`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = MoneyType::default().into();
    /// let money = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (price MONEY);").unwrap();
    /// assert!(constrainer.validate_schema(&money).is_err());
    /// let numeric = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (price NUMERIC);").unwrap();
    /// assert!(constrainer.validate_schema(&numeric).is_ok());
    /// ```
    MoneyType,
    LintGroup::Suspicious,
    "money rounds to the locale's fraction digits and stores no currency, so fractions of a cent are lost and the amount's currency depends on a server setting.",
    WIKI,
    Wording {
        flaw: TypeFlaw::Money,
        tables: Tables::All,
        problem: "which rounds fractions of a cent and stores no currency.",
        echo: None,
        resolution: "Use `numeric`, with the currency in a column of its own.",
    }
);

type_rule!(
    /// Struct defining a rule that reports `json` where `jsonb` serves.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = JsonType::default().into();
    /// let text = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (doc JSON);").unwrap();
    /// assert!(constrainer.validate_schema(&text).is_err());
    /// let binary = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (doc JSONB);").unwrap();
    /// assert!(constrainer.validate_schema(&binary).is_ok());
    /// ```
    JsonType,
    LintGroup::Perf,
    "json keeps the input text and reparses it on every use, while jsonb stores a parsed form that is faster to process and supports indexing.",
    Some("https://www.postgresql.org/docs/current/datatype-json.html"),
    Wording {
        flaw: TypeFlaw::Json,
        tables: Tables::All,
        problem: "which reparses its text on every use and supports no indexing, while `jsonb` keeps no white space, key order or duplicate keys.",
        echo: Some(
            "Clients write this table, so with `jsonb` the echo hands the client back normalized JSON text."
        ),
        resolution: "Use `jsonb`, unless the exact text or key order must be kept.",
    }
);

type_rule!(
    /// Struct defining a rule that reports `numeric(p, s)` outside
    /// client-written tables.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ScaledNumeric::default().into();
    /// let scaled = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (x NUMERIC(10, 2));").unwrap();
    /// assert!(constrainer.validate_schema(&scaled).is_err());
    /// let checked = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE t (x NUMERIC CHECK (x = round(x, 2)) CHECK (abs(x) < 10 ^ 8));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&checked).is_ok());
    /// ```
    ScaledNumeric,
    LintGroup::Pedantic,
    "numeric(p, s) rounds a value with more fractional digits than s, so the database stores a value nobody wrote, and a check on the same column only sees the rounded value.",
    Some("https://www.postgresql.org/docs/current/datatype-numeric.html"),
    Wording {
        flaw: TypeFlaw::ScaledNumeric,
        tables: Tables::Others,
        problem: "which rounds excess fractional digits instead of refusing them.",
        echo: None,
        resolution: "Declare an unscaled `numeric` with `CHECK (x = round(x, s))` and `CHECK (abs(x) < 10 ^ (p - s))`, so excess digits are refused.",
    }
);

type_rule!(
    /// Struct defining a rule that reports `numeric(p, s)` on a table the
    /// deployment declares client-written.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sql_rules::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> = ClientWrittenScaledNumeric::default().into();
    /// constrainer.set_deployment(Deployment::default().with_client_written_table("public", "t"));
    /// let scaled = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (x NUMERIC(10, 2));").unwrap();
    /// assert!(constrainer.validate_schema(&scaled).is_err());
    /// let other = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE u (x NUMERIC(10, 2));").unwrap();
    /// assert!(constrainer.validate_schema(&other).is_ok());
    /// ```
    ClientWrittenScaledNumeric,
    LintGroup::Suspicious,
    "numeric(p, s) rounds a value with more fractional digits than s, so on a table clients write the server stores a value the client never wrote and the echo rewrites the client's row.",
    Some("https://www.postgresql.org/docs/current/datatype-numeric.html"),
    Wording {
        flaw: TypeFlaw::ScaledNumeric,
        tables: Tables::ClientWritten,
        problem: "which rounds excess fractional digits instead of refusing them.",
        echo: Some(
            "Clients write this table, so the echo rewrites the client's row with the rounded value."
        ),
        resolution: "Declare an unscaled `numeric` with `CHECK (x = round(x, s))` and `CHECK (abs(x) < 10 ^ (p - s))`, so excess digits are refused.",
    }
);
