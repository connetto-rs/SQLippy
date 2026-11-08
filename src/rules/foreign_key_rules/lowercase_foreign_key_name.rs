//! Submodule providing the `LowercaseForeignKeyName` constraint, which enforces
//! that foreign key names, when defined, are lowercase.

use sql_traits::traits::{DatabaseLike, ForeignKeyLike};

use crate::{
    error::Interruption,
    lint::{LintGroup, Rule, RuleMetadata},
    traits::{Constrainer, ForeignKeyRule, GenericConstrainer, Reporter},
};

/// Struct defining a constraint that enforces that foreign key names are
/// lowercase.
///
/// # Example
///
/// Here follows an example of validating an invalid SQL statement with the
/// `LowercaseForeignKeyName` constraint.
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::GenericDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = LowercaseForeignKeyName::default().into();
///
/// let invalid_schema = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE mytable (id INT PRIMARY KEY, CONSTRAINT Fk FOREIGN KEY (id) REFERENCES mytable (id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&invalid_schema).is_err());
///
/// let valid_schema1 = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE mytable (id INT PRIMARY KEY, CONSTRAINT fk FOREIGN KEY (id) REFERENCES mytable (id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema1).is_ok());
///
/// let valid_schema2 = ParserDB::parse::<GenericDialect>(
///     "CREATE TABLE mytable (id INT PRIMARY KEY, FOREIGN KEY (id) REFERENCES mytable (id));",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&valid_schema2).is_ok());
/// ```
pub struct LowercaseForeignKeyName<C>(std::marker::PhantomData<C>);

impl<C> Default for LowercaseForeignKeyName<C> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<LowercaseForeignKeyName<DB>> for GenericConstrainer<DB> {
    fn from(constraint: LowercaseForeignKeyName<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_foreign_key_rule(Box::new(constraint));
        constrainer
    }
}

impl<C> Rule for LowercaseForeignKeyName<C> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "LowercaseForeignKeyName",
            group: LintGroup::Style,
            rationale: "PostgreSQL folds unquoted identifiers to lower case, so a mixed-case name has to be quoted in every statement.",
            source: Some(
                "https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS",
            ),
        };
        &METADATA
    }
}

impl<DB: DatabaseLike> ForeignKeyRule for LowercaseForeignKeyName<DB> {
    type Database = DB;

    fn check_foreign_key(
        &self,
        _database: &Self::Database,
        foreign_key: &<Self::Database as DatabaseLike>::ForeignKey,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if let Some(name) = foreign_key.foreign_key_name()
            && name.chars().any(char::is_uppercase)
        {
            reporter.foreign_key(
                foreign_key,
                format!("Foreign key name '{name}' is not lowercase."),
                format!("Rename the foreign key to '{}'.", name.to_lowercase()),
            )?;
        }
        Ok(())
    }
}
