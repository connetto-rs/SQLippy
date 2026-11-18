//! Submodule providing the `SensitiveColumnsExposed` rule.

use sql_traits::traits::{ColumnLike, DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::grant_support::client_reach,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Column names holding credentials, personal identifiers, financial,
/// medical, device or key material, as Splinter lists them.
const SENSITIVE_NAMES: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "secret_key",
    "private_key",
    "api_key",
    "apikey",
    "auth_key",
    "token",
    "jwt",
    "access_token",
    "refresh_token",
    "oauth_token",
    "session_token",
    "bearer_token",
    "auth_code",
    "session_id",
    "session_key",
    "session_secret",
    "recovery_code",
    "backup_code",
    "verification_code",
    "otp",
    "two_factor",
    "2fa_secret",
    "2fa_code",
    "ssn",
    "social_security",
    "social_security_number",
    "driver_license",
    "drivers_license",
    "license_number",
    "passport_number",
    "passport_id",
    "national_id",
    "tax_id",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "cvn",
    "bank_account",
    "account_number",
    "routing_number",
    "iban",
    "swift_code",
    "bic",
    "health_record",
    "medical_record",
    "patient_id",
    "insurance_number",
    "health_insurance",
    "medical_insurance",
    "treatment",
    "mac_address",
    "macaddr",
    "imei",
    "device_uuid",
    "pgp_key",
    "gpg_key",
    "ssh_key",
    "certificate",
    "license_key",
    "activation_key",
    "facial_recognition",
];

rule_definition!(
    /// Struct defining a rule that reports a table without row-level security
    /// that a client role reaches, through a grant or an exposed schema, and
    /// whose columns are named for credentials, personal identifiers,
    /// financial, medical, device or key material, such as `password`,
    /// `api_key`, `ssn` or `iban`.
    ///
    /// A column name matches when it equals one of Splinter's sensitive names
    /// ignoring ASCII case, with `-` read as `_`. The finding lists every
    /// matched column of the table.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let mut constrainer: GenericConstrainer<ParserDB> = SensitiveColumnsExposed::default().into();
    /// constrainer.set_deployment(Deployment::default().with_anonymous_role("anon"));
    ///
    /// let open = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE ROLE anon; CREATE TABLE keys (id INT, api_key TEXT); GRANT SELECT ON keys TO anon;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&open).is_err());
    ///
    /// let protected = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE ROLE anon; CREATE TABLE keys (id INT, api_key TEXT);
    ///      ALTER TABLE keys ENABLE ROW LEVEL SECURITY;
    ///      GRANT SELECT ON keys TO anon;",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&protected).is_ok());
    /// ```
    SensitiveColumnsExposed,
    register_table_rule,
    LintGroup::Suspicious,
    "A client role reaching a table without row-level security reads every row, so a column holding credentials or personal data is disclosed for every user at once.",
    Some("https://github.com/supabase/splinter/blob/main/lints/0023_sensitive_columns_exposed.sql"),
    RuleExample {
        bad: "CREATE TABLE public.credentials (identifier INT PRIMARY KEY, token TEXT);\n\
GRANT SELECT ON public.credentials TO PUBLIC;",
        good: "CREATE TABLE public.credentials (identifier INT PRIMARY KEY, token TEXT);\n\
REVOKE ALL ON public.credentials FROM PUBLIC;\n\
ALTER TABLE public.credentials ENABLE ROW LEVEL SECURITY;",
    },
    Basis::Names
);

/// Whether `column` equals the sensitive `name`, ignoring ASCII case and
/// reading `-` as `_`.
fn names_sensitive(column: &str, name: &str) -> bool {
    column.len() == name.len()
        && column
            .bytes()
            .zip(name.bytes())
            .all(|(written, sensitive)| {
                let written = if written == b'-' {
                    b'_'
                } else {
                    written.to_ascii_lowercase()
                };
                written == sensitive
            })
}

impl<DB: DatabaseLike> TableRule for SensitiveColumnsExposed<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if table.has_row_level_security(database)? {
            return Ok(());
        }
        let mut sensitive = Vec::new();
        for column in table.columns(database)? {
            let name = column.column_name();
            if SENSITIVE_NAMES
                .iter()
                .any(|sensitive| names_sensitive(name, sensitive))
            {
                sensitive.push(name);
            }
        }
        if sensitive.is_empty() {
            return Ok(());
        }
        let reasons = client_reach(database, reporter.deployment(), table)?;
        if reasons.is_empty() {
            return Ok(());
        }
        let name = table.table_name();
        let columns = sensitive.join(", ");
        let reasons = reasons.into_iter().collect::<Vec<_>>().join(" and ");
        reporter.table(
            table,
            format!("Table '{name}' has no row-level security and {reasons}, so a client role reads the sensitive column(s) {columns} of every row."),
            format!("ALTER TABLE {name} ENABLE ROW LEVEL SECURITY; with policies limiting each client to its own rows, or move {columns} to a table no client role reaches."),
        )?;
        Ok(())
    }
}
