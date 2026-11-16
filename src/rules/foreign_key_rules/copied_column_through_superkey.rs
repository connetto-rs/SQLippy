//! Submodule providing the `CopiedColumnThroughSuperkey` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::IdentifierCase,
    traits::{CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, IndexLike, TableLike},
};
use sqlparser::ast::{Expr, Ident, ReferentialAction, visit_expressions_mut};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        index_support::{indexed, shape},
        key_support::key_pairs,
    },
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

rule_definition!(
    /// Struct defining a rule that reports an `ON UPDATE CASCADE` foreign key
    /// to a unique key strictly containing the referenced primary key, whose
    /// extra columns the referencing table uses as no key of its own.
    ///
    /// Such a column only mirrors its parent, which a join on the primary key
    /// already reaches, and the cascade rewrites every copy when the parent
    /// changes. An extra column that the referencing table also keys on,
    /// through another foreign key, its primary key, a unique constraint or
    /// an index leading with it, keeps rows consistent across tables, as a
    /// tenant column does, and is not reported. Neither is one a check of the
    /// referencing table reads in a form the referenced table does not
    /// declare, as a subtype discriminator does to limit which parents may be
    /// referenced.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> =
    ///     CopiedColumnThroughSuperkey::default().into();
    /// let parent = "CREATE TABLE accounts (id INT PRIMARY KEY, label TEXT NOT NULL, UNIQUE (id, label));";
    /// let copied = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{parent} CREATE TABLE notes (account_id INT, label TEXT,
    ///        FOREIGN KEY (account_id, label) REFERENCES accounts (id, label) ON UPDATE CASCADE);"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&copied).is_err());
    /// let joined = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{parent} CREATE TABLE notes (account_id INT REFERENCES accounts (id));"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&joined).is_ok());
    /// ```
    CopiedColumnThroughSuperkey,
    register_foreign_key_rule,
    LintGroup::Pedantic,
    "A column copied from its parent through a key wider than the parent's primary key repeats a value a join already reaches, and ON UPDATE CASCADE rewrites every copy when the parent changes.",
    Some("https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-FK"),
    RuleExample {
        bad: "CREATE TABLE accounts (id integer PRIMARY KEY, label text NOT NULL, UNIQUE (id, label));\n\
CREATE TABLE notes (id integer PRIMARY KEY, account_id integer NOT NULL, label text NOT NULL, FOREIGN KEY (account_id, label) REFERENCES accounts (id, label) ON UPDATE CASCADE);",
        good: "CREATE TABLE accounts (id integer PRIMARY KEY, label text NOT NULL);\n\
CREATE TABLE notes (id integer PRIMARY KEY, account_id integer NOT NULL REFERENCES accounts (id));\n\
CREATE VIEW labeled_notes AS SELECT notes.id, notes.account_id, accounts.label FROM notes JOIN accounts ON accounts.id = notes.account_id;",
    }
);

/// Whether `table` keys on `column` other than through `foreign_key`: through
/// another of its foreign keys, its primary key, a unique key holding the
/// column, or an index leading with it.
fn keyed<DB: DatabaseLike>(
    database: &DB,
    table: &DB::Table,
    column: &DB::Column,
    foreign_key: &DB::ForeignKey,
) -> Result<bool, LookupError> {
    for other in table.foreign_keys(database)? {
        if other != foreign_key && other.host_columns(database)?.any(|host| host == column) {
            return Ok(true);
        }
    }
    for index in table.unique_indices(database)? {
        if index.columns(database)?.any(|key| key == column) {
            return Ok(true);
        }
    }
    for index in table.indices(database)?.filter(|index| index.is_unique()) {
        if index.columns(database)?.any(|key| key == column) {
            return Ok(true);
        }
    }
    indexed(database, table, column)
}

/// `expression` with each column `foreign_key` references renamed to the host
/// column it pairs with.
fn renamed_to_host<DB: DatabaseLike>(
    database: &DB,
    foreign_key: &DB::ForeignKey,
    expression: &Expr,
) -> Result<Expr, LookupError> {
    let pairs = key_pairs(database, foreign_key)?;
    let rename = |ident: &mut Ident| {
        if let Some((host, _)) = pairs.iter().find(|(_, referenced)| {
            IdentifierCase::AsWritten.identifiers_match(
                referenced.column_name(),
                referenced.column_name_is_quoted(),
                &ident.value,
                ident.quote_style.is_some(),
            )
        }) {
            *ident = if host.column_name_is_quoted() {
                Ident::with_quote('"', host.column_name())
            } else {
                Ident::new(host.column_name())
            };
        }
    };
    let mut expression = expression.clone();
    let _ = visit_expressions_mut(&mut expression, |node| {
        match node {
            Expr::Identifier(ident) => rename(ident),
            Expr::CompoundIdentifier(parts) => {
                if let Some(last) = parts.last_mut() {
                    rename(last);
                }
            }
            _ => {}
        }
        ControlFlow::<()>::Continue(())
    });
    Ok(expression)
}

/// Whether a check of `host` reads `column`, which `foreign_key` copies from
/// `source`, in a form no check of the referenced table declares on `source`.
fn narrowed<DB: DatabaseLike>(
    database: &DB,
    host: &DB::Table,
    column: &DB::Column,
    source: &DB::Column,
    foreign_key: &DB::ForeignKey,
) -> Result<bool, LookupError> {
    let parent = foreign_key.referenced_table(database)?;
    let mut declared = Vec::new();
    for check in parent.check_constraints(database)? {
        if check.columns(database)?.any(|read| read == source) {
            let renamed = renamed_to_host(database, foreign_key, check.expression(database))?;
            declared.push(shape(&renamed));
        }
    }
    for check in host.check_constraints(database)? {
        if check.columns(database)?.any(|read| read == column)
            && !declared.contains(&shape(check.expression(database)))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

impl<DB: DatabaseLike> ForeignKeyRule for CopiedColumnThroughSuperkey<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if foreign_key.on_update(database) != ReferentialAction::Cascade {
            return Ok(());
        }
        let parent = foreign_key.referenced_table(database)?;
        let primary_key: Vec<&DB::Column> = parent.primary_key_columns(database)?.collect();
        let referenced: Vec<&DB::Column> = foreign_key.referenced_columns(database)?.collect();
        if primary_key.is_empty()
            || referenced.len() <= primary_key.len()
            || !primary_key.iter().all(|column| referenced.contains(column))
        {
            return Ok(());
        }
        let host = foreign_key.host_table(database);
        let mut copied = Vec::new();
        for (column, source) in foreign_key.host_columns(database)?.zip(referenced) {
            if !primary_key.contains(&source)
                && !keyed(database, host, column, foreign_key)?
                && !narrowed(database, host, column, source, foreign_key)?
            {
                copied.push(format!("'{}'", column.column_name()));
            }
        }
        if copied.is_empty() {
            return Ok(());
        }
        let (host_name, parent_name) = (host.table_name(), parent.table_name());
        let copied = copied.join(", ");
        reporter.foreign_key(
            foreign_key,
            format!(
                "A foreign key of '{host_name}' copies {copied} from '{parent_name}' through a key wider than its primary key, and ON UPDATE CASCADE rewrites the copy whenever '{parent_name}' changes."
            ),
            format!(
                "Reference the primary key of '{parent_name}' alone, drop {copied} from '{host_name}' and read it through a join."
            ),
        )?;
        Ok(())
    }
}
