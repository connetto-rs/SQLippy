# SQL Rules

[![CI](https://github.com/connetto-rs/sql-rules/workflows/Rust%20CI/badge.svg)](https://github.com/connetto-rs/sql-rules/actions)
[![Security Audit](https://github.com/connetto-rs/sql-rules/workflows/Security%20Audit/badge.svg)](https://github.com/connetto-rs/sql-rules/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Codecov](https://codecov.io/gh/connetto-rs/sql-rules/branch/main/graph/badge.svg)](https://codecov.io/gh/connetto-rs/sql-rules)

[SQL-traits](https://github.com/connetto-rs/sql-traits)-based lints for SQL schemas. Every rule belongs to a Clippy-style group whose default level is `allow`, `warn` or `deny`, and every violation explains why the shape is bad and how to fix it.

## Usage

```rust
use sql_rules::prelude::*;
use sqlparser::dialect::GenericDialect;

let database = ParserDB::parse::<GenericDialect>(
    "CREATE TABLE Users (id INT PRIMARY KEY, name TEXT CHECK (LENGTH(name) <= 100));",
)
.unwrap();

let mut constrainer = DefaultConstrainer::<ParserDB>::default();
constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
constrainer.set_rule_level("PluralTableName", Level::Allow);

// `validate_schema` stops at the first violation raised at `warn` or `deny`.
assert!(constrainer.validate_schema(&database).is_err());

// `diagnostics` returns every violation and lookup failure.
for error in constrainer.diagnostics(&database) {
    if let Error::Violation(violation) = error {
        println!("{violation}");
    }
}
```

A rule registered on its own, including a single rule converted with `.into()`, runs at least at `warn`. `DefaultConstrainer` registers every rule at its group's default. `allow_policy` excuses one rule's findings on a reviewed policy, and an allowance that excuses nothing fails validation.

## Rules

| Group | Default | Rules |
| :--- | :--- | :--- |
| `correctness` | `deny` | `PoliciesRequireRowLevelSecurity`, `PolicyReadCycle`, `DeadPermissivePolicy`, `TruncateGrantedToAnonymousRole`, `ClientRoleBypassesRowLevelSecurity`, `NoTautologicalCheckRule`, `NoNegationCheckRule`, `NoSurrogatePrimaryKeyInExtension` |
| `suspicious` | `warn` | `LatentPolicyReadCycle`, `TautologicalWithCheck`, `UnforcedRowLevelSecurity`, `ReachableTableWithoutRowLevelSecurity`, `ReachableMaterializedView`, `TruncateGrantedToAppRole`, `ChildWithoutRowLevelSecurity`, `SettableMembershipInBypassingRole`, `PolicyToCreatingRole`, `RoleKeyedPolicyWhenPooled`, `GrantOptionToClientRole`, `TextualColumnRule`, `CompatibleForeignKey`, `HasPrimaryKey`, `ExtensionForeignKeyOnDeleteCascade`, `NoForbiddenColumnInExtension`, `UniqueColumnNamesInExtensionGraph` |
| `complexity` | `warn` | `UniqueForeignKey`, `UniqueCheckRule`, `UniqueUniqueIndex`, `NonRedundantExtensionDag` |
| `style` | `warn` | `LowercaseTableName`, `LowercaseColumnName`, `LowercaseForeignKeyName`, `SnakeCaseTableName`, `SnakeCaseColumnName`, `PluralTableName`, `SingularColumnName`, `PrimaryKeyReferenceEndsWithId`, `NonCompositePrimaryKeyNamedId` |
| `pedantic` | `allow` | `ReferencesGrantedToClientRole`, `CascadeIntoRowLevelSecurityTable`, `PastTimeColumnRule`, `NonEmptyTextualColumnRule` |
| `restriction` | `allow` | `NoRustKeywordTableName`, `NoRustKeywordColumnName`, `NoRustKeywordForeignKeyName` |

Each rule's documentation states what it reports, and its violations carry the rationale and source.
