//! Submodule providing the `DuplicateForeignKey` constraint, which reports a
//! foreign key repeating another one, or implied by a wider one, of the same
//! table.

use std::hash::{DefaultHasher, Hash, Hasher};

use sql_traits::{
    errors::LookupError,
    structs::ConstraintDeferral,
    traits::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike},
};
use sqlparser::ast::ReferentialAction;

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::key_support::checks_every_row_of,
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that reports a foreign key repeating another
/// one of the same table, or implied by a wider one.
///
/// A narrower foreign key is implied when its column pairs are a strict
/// subset of a wider key to the same table, the wider key checks every row
/// the narrower one checks, and both act the same way on parent writes.
/// The wider key checks every such row when its extra host columns are
/// `NOT NULL` or it is `MATCH FULL`. Both keys must share their `ON DELETE`
/// action among `NO ACTION`, `RESTRICT` and `CASCADE`, their `ON UPDATE`
/// action among `NO ACTION` and `RESTRICT`, and their deferral, unless the
/// wider key is not deferrable.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `duplicate_foreign_key` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DuplicateForeignKey::default().into();
///
/// let invalid_schema =
///     ParserDB::parse::<GenericDialect>(
///         "CREATE TABLE MyTable (id INT PRIMARY KEY REFERENCES MyTable (id), FOREIGN KEY (id) REFERENCES MyTable (id));",
///     )
///     .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err(), "1) Foreign keys must be unique per table");
///
/// let invalid_schema2 = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE MyTable (id INT PRIMARY KEY, FOREIGN KEY (id) REFERENCES MyTable (id), FOREIGN KEY (id) REFERENCES MyTable (id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema2).is_err(), "2) Foreign keys must be unique per table");
///
/// let implied = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE accounts (id INT PRIMARY KEY, tenant_id INT NOT NULL, UNIQUE (id, tenant_id));
///      CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL,
///        FOREIGN KEY (account_id) REFERENCES accounts (id),
///        FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&implied).is_err(), "3) The wider key implies the narrower one");
///
/// let valid_schema = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE mytable (id INT PRIMARY KEY, FOREIGN KEY (id) REFERENCES mytable (id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema).is_ok());
/// ```
pub struct DuplicateForeignKey<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DuplicateForeignKey<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DuplicateForeignKey<DB>> for GenericConstrainer<DB> {
    fn from(constraint: DuplicateForeignKey<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for DuplicateForeignKey<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DuplicateForeignKey),
            group: LintGroup::Complexity,
            rationale: "A foreign key repeated, or implied by a wider key to the same table, enforces nothing more and is checked again on every write.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE accounts (id INT PRIMARY KEY, tenant_id INT NOT NULL, UNIQUE (id, tenant_id));\n\
CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL, FOREIGN KEY (account_id) REFERENCES accounts (id), FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id));",
                good: "CREATE TABLE accounts (id INT PRIMARY KEY, tenant_id INT NOT NULL, UNIQUE (id, tenant_id));\n\
CREATE TABLE notes (id INT PRIMARY KEY, account_id INT NOT NULL, tenant_id INT NOT NULL, FOREIGN KEY (account_id, tenant_id) REFERENCES accounts (id, tenant_id));",
            },
        };
        &METADATA
    }
}

/// Returns the foreign key as written, `FOREIGN KEY (..) REFERENCES t (..)`.
fn definition<DB: DatabaseLike>(
    foreign_key: &DB::ForeignKey,
    database: &DB,
) -> Result<String, LookupError> {
    let host_columns: Vec<_> = foreign_key
        .host_columns(database)?
        .map(ColumnLike::column_name)
        .collect();
    let referenced_columns: Vec<_> = foreign_key
        .referenced_columns(database)?
        .map(ColumnLike::column_name)
        .collect();
    Ok(format!(
        "FOREIGN KEY ({}) REFERENCES {} ({})",
        host_columns.join(", "),
        foreign_key.referenced_table(database)?.table_name(),
        referenced_columns.join(", ")
    ))
}

/// Returns whether `wider` makes `narrower` redundant: its column pairs
/// strictly contain those of `narrower`, it checks every row `narrower`
/// checks, and a parent write that passes one passes the other.
fn implies<DB: DatabaseLike>(
    wider: &DB::ForeignKey,
    narrower: &DB::ForeignKey,
    database: &DB,
) -> Result<bool, LookupError> {
    if wider.number_of_host_columns(database)? <= narrower.number_of_host_columns(database)?
        || !checks_every_row_of(database, wider, narrower)?
    {
        return Ok(false);
    }
    // A partly NULL row the narrower `MATCH FULL` key refuses passes a wider
    // `MATCH SIMPLE` key.
    if narrower.match_full(database)
        && !wider.match_full(database)
        && narrower.has_nullable_host_columns(database)?
    {
        return Ok(false);
    }
    // Rows a `NOT VALID` wider key never checked rely on the narrower key.
    if narrower.is_validated(database)? && !wider.is_validated(database)? {
        return Ok(false);
    }
    // The checks of both keys fire in one statement in creation order, so a
    // narrower check can fail before a wider action fixes the child rows.
    let on_delete = narrower.on_delete(database);
    let on_update = narrower.on_update(database);
    let wider_deferral = wider.deferral(database);
    Ok(on_delete == wider.on_delete(database)
        && matches!(
            on_delete,
            ReferentialAction::NoAction | ReferentialAction::Restrict | ReferentialAction::Cascade
        )
        && on_update == wider.on_update(database)
        && matches!(
            on_update,
            ReferentialAction::NoAction | ReferentialAction::Restrict
        )
        && (wider_deferral == ConstraintDeferral::NotDeferrable
            || wider_deferral == narrower.deferral(database)))
}

impl<DB: DatabaseLike> TableRule for DuplicateForeignKey<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let table_name = table.table_name();
        let constraints = table.foreign_keys(database)?.collect::<Vec<_>>();
        let mut signatures_with_fks = constraints
            .iter()
            .map(|fk| {
                let mut hasher = DefaultHasher::new();
                for host_col in fk.host_columns(database)? {
                    host_col.hash(&mut hasher);
                }
                let referenced_table = fk.referenced_table(database)?;
                referenced_table.hash(&mut hasher);
                for referenced_col in fk.referenced_columns(database)? {
                    referenced_col.hash(&mut hasher);
                }
                Ok((hasher.finish(), *fk))
            })
            .collect::<Result<Vec<_>, LookupError>>()?;

        signatures_with_fks.sort_unstable_by_key(|(sig, _)| *sig);

        for window in signatures_with_fks.windows(2) {
            if let [(sig1, _), (sig2, fk)] = window
                && sig1 == sig2
            {
                let definition = definition(*fk, database)?;
                reporter.foreign_key(
                    *fk,
                    format!(
                        "Table '{table_name}' has a duplicate of the foreign key {definition}."
                    ),
                    format!(
                        "Remove one of the duplicate foreign key definitions from table '{table_name}'."
                    ),
                )?;
            }
        }

        for narrower in &constraints {
            for wider in &constraints {
                if implies(*wider, *narrower, database)? {
                    let narrower_definition = definition(*narrower, database)?;
                    let wider_definition = definition(*wider, database)?;
                    reporter.foreign_key(
                        *narrower,
                        format!(
                            "Table '{table_name}' has the foreign key {narrower_definition}, which the wider {wider_definition} already enforces."
                        ),
                        format!(
                            "Remove {narrower_definition} from table '{table_name}'."
                        ),
                    )?;
                    break;
                }
            }
        }
        Ok(())
    }
}
