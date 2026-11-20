//! The database engine a schema runs on, which decides the limits a rule
//! checks and the forms its advice names.

use std::fmt::{self, Display};

use sql_traits::traits::{DatabaseLike, DialectLike};
use sqlparser::dialect::SQLiteDialect;

/// A database engine the rules know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Engine {
    /// PostgreSQL.
    PostgreSql,
    /// SQLite.
    Sqlite,
}

impl Engine {
    /// Every engine.
    pub const ALL: [Self; 2] = [Self::PostgreSql, Self::Sqlite];

    /// Returns the engine `database` runs on, SQLite for a schema parsed in
    /// the SQLite dialect and PostgreSQL for any other.
    ///
    /// # Example
    ///
    /// ```
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::{GenericDialect, SQLiteDialect};
    ///
    /// let sqlite = ParserDB::parse::<SQLiteDialect>("CREATE TABLE t (id INTEGER);").unwrap();
    /// assert_eq!(Engine::of(&sqlite), Engine::Sqlite);
    /// let generic = ParserDB::parse::<GenericDialect>("CREATE TABLE t (id INT);").unwrap();
    /// assert_eq!(Engine::of(&generic), Engine::PostgreSql);
    /// ```
    #[must_use]
    pub fn of<DB: DatabaseLike>(database: &DB) -> Self {
        if database.dialect().sqlparser_dialect().is::<SQLiteDialect>() {
            Self::Sqlite
        } else {
            Self::PostgreSql
        }
    }

    /// Returns the engine's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PostgreSql => "PostgreSQL",
            Self::Sqlite => "SQLite",
        }
    }
}

impl Display for Engine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}
