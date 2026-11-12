//! Submodule providing the `NonRedundantExtensionDag` constraint, which
//! enforces that if a table extends multiple tables (via extension foreign
//! keys), the extended tables must form a non-redundant DAG structure.
//!
//! This means:
//! 1. No duplicate direct extensions to the same table
//! 2. No redundant paths (e.g., if A extends B and B extends C, then A
//!    shouldn't also directly extend C)

use sql_traits::traits::{DatabaseLike, TableLike};

use crate::{
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, TableRule},
};

/// Struct defining a constraint that enforces non-redundant extension DAG
/// structure for tables with multiple extensions.
///
/// # Example
///
/// Here follows an example of validating invalid SQL statements with the
/// `NonRedundantExtensionDag` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = NonRedundantExtensionDag::default().into();
///
/// // Invalid: Duplicate direct extension to the same table B
/// // The same primary key column (id) appears in two foreign keys to the same table
/// let invalid_duplicate = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE table_b (id INT PRIMARY KEY);
/// CREATE TABLE table_a (
///     id INT PRIMARY KEY,
///     FOREIGN KEY (id) REFERENCES table_b(id),
///     FOREIGN KEY (id) REFERENCES table_b(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_duplicate).is_err());
///
/// // Invalid: Redundant path (A -> B -> C and A -> C)
/// // table_a's id references both table_b and table_c, but table_b already extends table_c
/// let invalid_redundant = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE table_c (id INT PRIMARY KEY);
/// CREATE TABLE table_b (id INT PRIMARY KEY REFERENCES table_c(id));
/// CREATE TABLE table_a (
///     id INT PRIMARY KEY,
///     FOREIGN KEY (id) REFERENCES table_b(id),
///     FOREIGN KEY (id) REFERENCES table_c(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_redundant).is_err());
///
/// // The redundant extension is found whichever foreign key comes first
/// let invalid_reversed = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE table_c (id INT PRIMARY KEY);
/// CREATE TABLE table_b (id INT PRIMARY KEY REFERENCES table_c(id));
/// CREATE TABLE table_a (
///     id INT PRIMARY KEY,
///     FOREIGN KEY (id) REFERENCES table_c(id),
///     FOREIGN KEY (id) REFERENCES table_b(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_reversed).is_err());
///
/// // Valid: Non-redundant DAG (A -> B -> C and A -> D -> C)
/// // table_a's id references both table_b and table_d, which independently extend table_c
/// let valid_dag = ParserDB::parse::<GenericDialect>(
///     "
/// CREATE TABLE table_c (id INT PRIMARY KEY);
/// CREATE TABLE table_b (id INT PRIMARY KEY REFERENCES table_c(id));
/// CREATE TABLE table_d (id INT PRIMARY KEY REFERENCES table_c(id));
/// CREATE TABLE table_a (
///     id INT PRIMARY KEY,
///     FOREIGN KEY (id) REFERENCES table_b(id),
///     FOREIGN KEY (id) REFERENCES table_d(id)
/// );
/// ",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_dag).is_ok());
/// ```
pub struct NonRedundantExtensionDag<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for NonRedundantExtensionDag<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<NonRedundantExtensionDag<DB>> for GenericConstrainer<DB> {
    fn from(constraint: NonRedundantExtensionDag<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_table_rule(Box::new(constraint));
        constrainer
    }
}

impl<DB> Rule for NonRedundantExtensionDag<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "NonRedundantExtensionDag",
            group: LintGroup::Complexity,
            rationale: "A redundant extension edge repeats what the hierarchy already implies, so it adds a dependency the schema does not need.",
            source: None,
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (id INT PRIMARY KEY, FOREIGN KEY (id) REFERENCES parents(id), FOREIGN KEY (id) REFERENCES parents(id));",
                good: "CREATE TABLE parents (id INT PRIMARY KEY);\n\
CREATE TABLE children (id INT PRIMARY KEY, FOREIGN KEY (id) REFERENCES parents(id));",
            },
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> TableRule for NonRedundantExtensionDag<DB> {
    type Database = DB;

    fn check_table(
        &self,
        database: &Self::Database,
        table: &<Self::Database as DatabaseLike>::Table,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        // Collect all directly extended tables
        let extended_tables = table
            .extended_tables(database)?
            .collect::<Vec<&<DB as DatabaseLike>::Table>>();

        let table_name = table.table_name();
        for (i, first) in extended_tables.iter().enumerate() {
            for (j, second) in extended_tables.iter().enumerate() {
                if i >= j {
                    continue;
                }
                if first == second {
                    let duplicated = first.table_name();
                    reporter.table(
                        table,
                        format!("Table '{table_name}' extends '{duplicated}' more than once."),
                        format!(
                            "Remove the duplicate foreign key that makes table '{table_name}' extend '{duplicated}'."
                        ),
                    )?;
                } else {
                    let implied = if second.is_descendant_of(database, first)? {
                        Some((first, second))
                    } else if first.is_descendant_of(database, second)? {
                        Some((second, first))
                    } else {
                        None
                    };
                    if let Some((redundant, witness)) = implied {
                        let redundant = redundant.table_name();
                        let witness = witness.table_name();
                        reporter.table(
                            table,
                            format!(
                                "Table '{table_name}' extends '{redundant}' directly, but its extension of '{witness}' already implies it."
                            ),
                            format!(
                                "Remove the foreign key from table '{table_name}' that extends '{redundant}'."
                            ),
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}
