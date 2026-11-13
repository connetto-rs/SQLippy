# SQLippy

[![CI](https://github.com/connetto-rs/SQLippy/workflows/Rust%20CI/badge.svg)](https://github.com/connetto-rs/SQLippy/actions)
[![Security Audit](https://github.com/connetto-rs/SQLippy/workflows/Security%20Audit/badge.svg)](https://github.com/connetto-rs/SQLippy/actions)
[![Codecov](https://codecov.io/gh/connetto-rs/SQLippy/branch/main/graph/badge.svg)](https://codecov.io/gh/connetto-rs/SQLippy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/sqlippy.svg)](https://crates.io/crates/sqlippy)
[![Docs.rs](https://docs.rs/sqlippy/badge.svg)](https://docs.rs/sqlippy)
[![Demo](https://img.shields.io/badge/demo-sqlippy.luca.phd-blue)](https://sqlippy.luca.phd/)

The crates.io and docs.rs badges resolve after the first release.

[Clippy](https://github.com/rust-lang/rust-clippy)-style lints for PostgreSQL schemas and the queries sent to them, built on [sql-traits](https://github.com/connetto-rs/sql-traits). Every finding says what is wrong, why, and how to fix it. Try it in the [browser demo](https://sqlippy.luca.phd/).

```rust
use sqlippy::prelude::*;
use sqlparser::dialect::GenericDialect;

let database = ParserDB::parse::<GenericDialect>(
    "CREATE TABLE Users (id INT PRIMARY KEY, name TEXT CHECK (LENGTH(name) <= 100));",
)
.unwrap();

let mut constrainer = DefaultConstrainer::<ParserDB>::default();
constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
constrainer.set_rule_level("singular_table_name", Level::Allow);

assert!(constrainer.validate_schema(&database).is_err());
for error in constrainer.diagnostics(&database) {
    println!("{error}");
}
```

Rules sit in Clippy's groups. `correctness` denies by default, `suspicious`, `perf`, `complexity` and `style` warn, and `pedantic` and `restriction` stay off until enabled. The [rules page](https://sqlippy.luca.phd/#/rules) lists every rule with SQL it reports and the same SQL corrected.
