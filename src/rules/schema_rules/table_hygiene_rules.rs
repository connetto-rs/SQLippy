//! Submodule providing the rules on a table's own setup: row-level security
//! without policies, overlapping permissive policies, `reg*` columns and
//! disabled autovacuum.

use std::collections::BTreeSet;

use sql_traits::traits::{ColumnLike, DataTypeLike, DatabaseLike, PolicyLike, TableLike};
use sqlparser::ast::CreatePolicyType;

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::policy_support::{Command, held_by_name, policy_roles},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

schema_rule!(
    /// Struct defining a rule that reports a table with row-level security
    /// enabled and no policy.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = RowLevelSecurityWithoutPolicies::default().into();
    /// let schema = "CREATE TABLE audit (id INT); ALTER TABLE audit ENABLE ROW LEVEL SECURITY;";
    /// let empty = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    /// assert!(constrainer.validate_schema(&empty).is_err());
    /// let covered = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE POLICY audit_read ON audit FOR SELECT USING (true);"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&covered).is_ok());
    /// ```
    RowLevelSecurityWithoutPolicies,
    LintGroup::Suspicious,
    "With row-level security enabled and no policy, PostgreSQL denies every row to every role but the owner, so the table looks empty to the application.",
    Some("https://www.postgresql.org/docs/current/ddl-rowsecurity.html"),
    RuleExample {
        bad: "CREATE TABLE audit (id INT);\n\
ALTER TABLE audit ENABLE ROW LEVEL SECURITY;",
        good: "CREATE TABLE audit (id INT);\n\
ALTER TABLE audit ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY audit_read ON audit FOR SELECT USING (true);",
    }
);

impl<DB: DatabaseLike> SchemaRule for RowLevelSecurityWithoutPolicies<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for table in database.tables() {
            if !table.has_row_level_security(database)?
                || table.policies(database)?.next().is_some()
            {
                continue;
            }
            let name = table.table_name();
            reporter.table(
                table,
                format!("Table '{name}' has row-level security enabled and no policy, so every role but its owner sees and changes no row."),
                format!("Create the policies '{name}' needs, or allow this finding if the table is meant to be closed to every role."),
            )?;
        }
        Ok(())
    }
}

schema_rule!(
    /// Struct defining a rule that reports two or more permissive policies
    /// applying to the same command for the same role.
    ///
    /// A policy for `PUBLIC` applies to every role, and a policy for a role
    /// applies to the roles that inherit it.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = MultiplePermissivePolicies::default().into();
    /// let schema = "CREATE TABLE orders (owner TEXT, is_admin BOOL); ALTER TABLE orders ENABLE ROW LEVEL SECURITY;";
    /// let split = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE POLICY own ON orders FOR SELECT USING (owner = current_user);
    ///      CREATE POLICY admin ON orders FOR SELECT USING (is_admin);"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&split).is_err());
    /// let merged = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE POLICY own_or_admin ON orders FOR SELECT USING (owner = current_user OR is_admin);"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&merged).is_ok());
    /// ```
    MultiplePermissivePolicies,
    LintGroup::Perf,
    "PostgreSQL evaluates every permissive policy that applies to a role and command for each row, so several of them cost more than one policy holding the whole condition.",
    Some(
        "https://github.com/supabase/splinter/blob/main/lints/0006_multiple_permissive_policies.sql"
    ),
    RuleExample {
        bad: "CREATE TABLE orders (owner TEXT, is_admin BOOL);\n\
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own ON orders FOR SELECT USING (owner = current_setting('app.user_id', true));\n\
CREATE POLICY admin ON orders FOR SELECT USING (is_admin);",
        good: "CREATE TABLE orders (owner TEXT, is_admin BOOL);\n\
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n\
CREATE POLICY own_or_admin ON orders FOR SELECT USING (owner = current_setting('app.user_id', true) OR is_admin);",
    }
);

impl<DB: DatabaseLike> SchemaRule for MultiplePermissivePolicies<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for table in database.tables() {
            let permissive: Vec<(&DB::Policy, Option<Vec<String>>)> = table
                .policies(database)?
                .filter(|policy| policy.policy_type() == CreatePolicyType::Permissive)
                .map(|policy| (policy, policy_roles(database, policy)))
                .collect();
            let mut roles: BTreeSet<Option<&str>> = BTreeSet::from([None]);
            for (_, names) in &permissive {
                roles.extend(names.iter().flatten().map(|name| Some(name.as_str())));
            }
            let mut seen: Vec<(Command, Vec<String>)> = Vec::new();
            for command in Command::ALL {
                for role in &roles {
                    let held = role.map(|role| held_by_name(database, role));
                    let applying: Vec<&DB::Policy> = permissive
                        .iter()
                        .filter(|(policy, names)| {
                            command.covered_by(policy.command())
                                && match (names, &held) {
                                    (None, _) => true,
                                    (Some(_), None) => false,
                                    (Some(names), Some(held)) => {
                                        names.iter().any(|name| held.contains(name))
                                    }
                                }
                        })
                        .map(|(policy, _)| *policy)
                        .collect();
                    let names: Vec<String> = applying
                        .iter()
                        .map(|policy| policy.name().to_owned())
                        .collect();
                    if applying.len() < 2 || seen.contains(&(command, names.clone())) {
                        continue;
                    }
                    seen.push((command, names.clone()));
                    let who = role
                        .map_or_else(|| "every role".to_owned(), |role| format!("role '{role}'"));
                    reporter.policies(
                        applying
                            .iter()
                            .map(|policy| PolicySite {
                                table: Box::new(table.clone()),
                                policy: Box::new((*policy).clone()),
                                clause: PolicyClause::To,
                                expression: policy.name().to_owned(),
                            })
                            .collect(),
                        format!(
                            "Permissive policies {} on '{}' all apply to {} for {who}, so each row evaluates every one of them.",
                            names
                                .iter()
                                .map(|name| format!("'{name}'"))
                                .collect::<Vec<_>>()
                                .join(", "),
                            table.table_name(),
                            format!("{command:?}").to_uppercase()
                        ),
                        "Merge them into one policy whose condition ORs theirs, or keep them apart deliberately with an allowance.".to_owned(),
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// The object-reference types `pg_upgrade` cannot carry over in user tables.
const UNSUPPORTED_REG_TYPES: [&str; 8] = [
    "regcollation",
    "regconfig",
    "regdictionary",
    "regnamespace",
    "regoper",
    "regoperator",
    "regproc",
    "regprocedure",
];

schema_rule!(
    /// Struct defining a rule that reports a column of a `reg*` type that
    /// `pg_upgrade` does not support.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = RegColumnType::default().into();
    /// let reg = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE ns_map (ns REGNAMESPACE);").unwrap();
    /// assert!(constrainer.validate_schema(&reg).is_err());
    /// let text = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE ns_map (ns TEXT);").unwrap();
    /// assert!(constrainer.validate_schema(&text).is_ok());
    /// ```
    RegColumnType,
    LintGroup::Suspicious,
    "A column of a reg* type stores object identifiers that pg_upgrade cannot carry over, so it blocks an in-place upgrade.",
    Some("https://www.postgresql.org/docs/current/pgupgrade.html"),
    RuleExample {
        bad: "CREATE TABLE namespaces (name REGNAMESPACE);",
        good: "CREATE TABLE namespaces (name TEXT);",
    }
);

impl<DB: DatabaseLike> SchemaRule for RegColumnType<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for table in database.tables() {
            for column in table.columns(database)? {
                let data_type = column.data_type(database);
                let name = data_type.normalized_name(database).to_ascii_lowercase();
                if !UNSUPPORTED_REG_TYPES.contains(&name.as_str()) {
                    continue;
                }
                let column_name = column.column_name();
                reporter.column(
                    column,
                    format!(
                        "Column '{}.{column_name}' is of type {name}, which pg_upgrade cannot carry over.",
                        table.table_name()
                    ),
                    format!("Store '{column_name}' as text, or as the object's name, and cast it when needed."),
                )?;
            }
        }
        Ok(())
    }
}

schema_rule!(
    /// Struct defining a rule that reports a table with the
    /// `autovacuum_enabled` storage parameter turned off.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = AutovacuumDisabledTable::default().into();
    /// let off = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE staging (id INT) WITH (autovacuum_enabled = false);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&off).is_err());
    /// let default = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE staging (id INT);").unwrap();
    /// assert!(constrainer.validate_schema(&default).is_ok());
    /// ```
    AutovacuumDisabledTable,
    LintGroup::Perf,
    "Without autovacuum, dead tuples accumulate and the table bloats, and its statistics go stale.",
    Some("https://github.com/supabase/splinter/blob/main/lints/0030_autovacuum_disabled.sql"),
    RuleExample {
        bad: "CREATE TABLE staging (id INT) WITH (autovacuum_enabled = false);",
        good: "CREATE TABLE staging (id INT);",
    }
);

impl<DB: DatabaseLike> SchemaRule for AutovacuumDisabledTable<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for table in database.tables() {
            let disabled = table
                .storage_parameter("autovacuum_enabled")
                .is_some_and(|value| {
                    matches!(
                        value.trim_matches('\'').to_ascii_lowercase().as_str(),
                        "false" | "off" | "no" | "0"
                    )
                });
            if !disabled {
                continue;
            }
            let name = table.table_name();
            reporter.table(
                table,
                format!("Table '{name}' turns autovacuum off, so its dead tuples accumulate and it bloats."),
                format!("ALTER TABLE {name} RESET (autovacuum_enabled); unless something else vacuums it."),
            )?;
        }
        Ok(())
    }
}
