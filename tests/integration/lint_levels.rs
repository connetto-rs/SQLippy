//! Lint levels, groups and complete collection observed through the public constrainer API.

use sql_rules::prelude::*;
use sql_traits::errors::LookupError;
use sqlparser::dialect::PostgreSqlDialect;

fn parse(sql: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses")
}

/// Every violation, skipping rules listed as inactive and failing on anything
/// else.
fn violations<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    database: &ParserDB,
) -> Vec<Violation<ParserDB>> {
    constrainer
        .diagnostics(database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) => Some(*violation),
            Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn raised_by(violations: &[Violation<ParserDB>], rule: &str) -> Vec<Level> {
    violations
        .iter()
        .filter(|violation| violation.rule().name == rule)
        .map(Violation::level)
        .collect()
}

const UNCHECKED_TIMESTAMP: &str =
    "CREATE TABLE events (id INT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL);";

#[test]
fn groups_carry_their_clippy_names_and_default_levels() {
    let table: Vec<(String, String)> = LintGroup::ALL
        .iter()
        .map(|group| (group.to_string(), group.default_level().to_string()))
        .collect();
    assert_eq!(
        table,
        [
            ("correctness", "deny"),
            ("suspicious", "warn"),
            ("perf", "warn"),
            ("complexity", "warn"),
            ("style", "warn"),
            ("pedantic", "allow"),
            ("restriction", "allow"),
        ]
        .map(|(group, level)| (group.to_owned(), level.to_owned()))
    );
}

#[test]
fn an_individually_registered_allow_by_default_rule_runs_at_warn() {
    let constrainer: GenericConstrainer<ParserDB> = PastTimeColumnRule::default().into();
    let database = parse(UNCHECKED_TIMESTAMP);
    let Err(Error::Violation(violation)) = constrainer.validate_schema(&database) else {
        panic!("the explicitly registered pedantic rule must reject the schema");
    };
    assert_eq!(violation.rule().group, LintGroup::Pedantic);
    assert_eq!(violation.level(), Level::Warn);
}

#[test]
fn the_default_constrainer_leaves_pedantic_and_restriction_rules_at_allow() {
    let database = parse(
        "CREATE TABLE events (id INT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL, type INT NOT NULL);",
    );
    let raised = violations(&DefaultConstrainer::<ParserDB>::default(), &database);
    assert_eq!(raised_by(&raised, "PastTimeColumnRule"), []);
    assert_eq!(raised_by(&raised, "NoRustKeywordColumnName"), []);
}

#[test]
fn a_group_override_enables_a_default_registered_group() {
    let database = parse(UNCHECKED_TIMESTAMP);
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    constrainer.set_group_level(LintGroup::Pedantic, Level::Deny);
    let raised = violations(&constrainer, &database);
    assert_eq!(raised_by(&raised, "PastTimeColumnRule"), [Level::Deny]);
}

#[test]
fn a_rule_override_wins_over_its_group_override_in_either_order() {
    let database = parse(UNCHECKED_TIMESTAMP);
    let mut rule_first: GenericConstrainer<ParserDB> = PastTimeColumnRule::default().into();
    rule_first.set_rule_level("PastTimeColumnRule", Level::Allow);
    rule_first.set_group_level(LintGroup::Pedantic, Level::Deny);
    assert!(rule_first.validate_schema(&database).is_ok());

    let mut group_first: GenericConstrainer<ParserDB> = PastTimeColumnRule::default().into();
    group_first.set_group_level(LintGroup::Pedantic, Level::Deny);
    group_first.set_rule_level("PastTimeColumnRule", Level::Allow);
    assert!(group_first.validate_schema(&database).is_ok());
}

#[test]
fn warnings_fail_validation_and_carry_their_level() {
    let database = parse("CREATE TABLE Users (id INT PRIMARY KEY);");
    let constrainer: GenericConstrainer<ParserDB> = LowercaseTableName::default().into();
    let Err(Error::Violation(violation)) = constrainer.validate_schema(&database) else {
        panic!("a warn-level violation must fail validation");
    };
    assert_eq!(violation.level(), Level::Warn);
    assert_eq!(violation.rule().group, LintGroup::Style);
}

#[test]
fn correctness_rules_deny_by_default() {
    let database = parse("CREATE TABLE t (id INT PRIMARY KEY, CHECK (1 = 1));");
    let constrainer: GenericConstrainer<ParserDB> = NoTautologicalCheckRule::default().into();
    let Err(Error::Violation(violation)) = constrainer.validate_schema(&database) else {
        panic!("a tautological check must be rejected");
    };
    assert_eq!(violation.level(), Level::Deny);
    assert_eq!(violation.rule().group, LintGroup::Correctness);
}

#[test]
fn collection_reports_every_occurrence_within_one_object() {
    let database =
        parse("CREATE TABLE t (id INT PRIMARY KEY, CHECK (TRUE), CHECK (1 = 1), CHECK (id > 0));");
    let constrainer: GenericConstrainer<ParserDB> = NoTautologicalCheckRule::default().into();
    let raised = violations(&constrainer, &database);
    assert_eq!(raised_by(&raised, "NoTautologicalCheckRule").len(), 2);
}

#[test]
fn collection_reports_every_duplicate_check() {
    let database = parse(
        "CREATE TABLE t (id INT PRIMARY KEY, CHECK (id > 0), CHECK (id > 0), CHECK (id > 0));",
    );
    let constrainer: GenericConstrainer<ParserDB> = UniqueCheckRule::default().into();
    let raised = violations(&constrainer, &database);
    assert_eq!(raised_by(&raised, "UniqueCheckRule").len(), 2);
}

#[test]
fn collection_continues_across_rules_and_objects() {
    let database =
        parse("CREATE TABLE Alpha (Id INT PRIMARY KEY); CREATE TABLE Beta (Id INT PRIMARY KEY);");
    let mut constrainer = GenericConstrainer::<ParserDB>::default();
    constrainer.register_table_rule(Box::new(LowercaseTableName::default()));
    constrainer.register_column_rule(Box::new(LowercaseColumnName::default()));
    let raised = violations(&constrainer, &database);
    assert_eq!(raised_by(&raised, "LowercaseTableName").len(), 2);
    assert_eq!(raised_by(&raised, "LowercaseColumnName").len(), 2);
}

#[test]
fn text_length_accepts_an_enforced_declared_length() {
    let textual: GenericConstrainer<ParserDB> = TextualColumnRule::default().into();
    for declared in ["VARCHAR(100)", "CHARACTER VARYING(100)", "CHAR(8)"] {
        let database = parse(&format!(
            "CREATE TABLE notes (id INT PRIMARY KEY, title {declared});"
        ));
        assert!(textual.validate_schema(&database).is_ok(), "{declared}");
    }
    let unbounded = parse("CREATE TABLE notes (id INT PRIMARY KEY, title VARCHAR);");
    assert!(textual.validate_schema(&unbounded).is_err());
}

#[test]
fn text_length_accepts_any_bound_and_leaves_emptiness_to_its_own_rule() {
    let textual: GenericConstrainer<ParserDB> = TextualColumnRule::default().into();
    let bounded = parse(
        "CREATE TABLE notes (id INT PRIMARY KEY, nickname TEXT CHECK (LENGTH(nickname) <= 64), body TEXT CHECK (LENGTH(body) <= 1000000));
         CREATE INDEX notes_body ON notes (body);",
    );
    assert!(textual.validate_schema(&bounded).is_ok());

    let unbounded = parse("CREATE TABLE notes (id INT PRIMARY KEY, body TEXT CHECK (body <> ''));");
    let Err(Error::Violation(violation)) = textual.validate_schema(&unbounded) else {
        panic!("an unbounded text column must be reported");
    };
    assert_eq!(violation.rule().group, LintGroup::Suspicious);
    assert!(!violation.resolution().contains("255"));

    let non_empty: GenericConstrainer<ParserDB> = NonEmptyTextualColumnRule::default().into();
    assert!(non_empty.validate_schema(&unbounded).is_ok());
    assert!(non_empty.validate_schema(&bounded).is_err());
}

#[test]
fn every_violation_names_its_rule_by_type_name() {
    let database = parse("CREATE TABLE t (id INT PRIMARY KEY, CHECK (id > 0), CHECK (id > 0));");
    let constrainer: GenericConstrainer<ParserDB> = UniqueCheckRule::default().into();
    let Err(Error::Violation(violation)) = constrainer.validate_schema(&database) else {
        panic!("duplicate checks must be reported");
    };
    assert_eq!(violation.rule().name, "UniqueCheckRule");
}

#[test]
fn mismatched_foreign_key_types_are_suspicious_warnings() {
    let database = parse(
        "CREATE TABLE parent (id BIGINT PRIMARY KEY); CREATE TABLE child (id INT PRIMARY KEY, parent_id INT REFERENCES parent (id));",
    );
    let raised = violations(&DefaultConstrainer::<ParserDB>::default(), &database);
    let compatible: Vec<_> = raised
        .iter()
        .filter(|violation| violation.rule().name == "CompatibleForeignKey")
        .collect();
    assert_eq!(compatible.len(), 1);
    assert_eq!(compatible[0].rule().group, LintGroup::Suspicious);
    assert_eq!(compatible[0].level(), Level::Warn);
}

#[test]
fn the_latest_rule_level_wins() {
    let database = parse(UNCHECKED_TIMESTAMP);
    let mut constrainer: GenericConstrainer<ParserDB> = PastTimeColumnRule::default().into();
    constrainer.set_rule_level("PastTimeColumnRule", Level::Deny);
    constrainer.set_rule_level("PastTimeColumnRule", Level::Allow);
    assert!(constrainer.validate_schema(&database).is_ok());
}

#[test]
fn violations_locate_the_offending_object() {
    let database = parse("CREATE TABLE Notes (id INT PRIMARY KEY, Title TEXT);");
    let mut constrainer = GenericConstrainer::<ParserDB>::default();
    constrainer.register_table_rule(Box::new(LowercaseTableName::default()));
    constrainer.register_column_rule(Box::new(LowercaseColumnName::default()));
    let raised = violations(&constrainer, &database);
    let [table, column] = raised.as_slice() else {
        panic!(
            "expected one table and one column violation, got {}",
            raised.len()
        );
    };
    assert!(matches!(table.location(), Location::Table(table) if table.table_name() == "Notes"));
    assert!(
        matches!(column.location(), Location::Column(column) if column.column_name() == "Title")
    );
    assert_eq!(column.object(), "Notes.Title");
}

/// Fails its lookup on one named table and passes every other table.
struct LookupFailsOn(&'static str);

impl Rule for LookupFailsOn {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: "LookupFailsOn",
            group: LintGroup::Correctness,
            rationale: "Test rule.",
            source: None,
        };
        &METADATA
    }
}

impl TableRule for LookupFailsOn {
    type Database = ParserDB;

    fn check_table(
        &self,
        _database: &ParserDB,
        table: &<ParserDB as DatabaseLike>::Table,
        _reporter: &mut Reporter<'_, ParserDB>,
    ) -> Result<(), Interruption> {
        if table.table_name() == self.0 {
            Err(LookupError::TableNotFound {
                object_name: self.0.to_owned(),
            })?;
        }
        Ok(())
    }
}

#[test]
fn a_lookup_failure_is_reported_and_independent_checks_continue() {
    let database = parse(
        "CREATE TABLE BROKEN_FIRST (id INT PRIMARY KEY); CREATE TABLE Other (id INT PRIMARY KEY);",
    );
    let mut constrainer = GenericConstrainer::<ParserDB>::default();
    constrainer.register_table_rule(Box::new(LookupFailsOn("BROKEN_FIRST")));
    constrainer.register_table_rule(Box::new(LowercaseTableName::default()));

    let diagnostics = constrainer.diagnostics(&database);
    let lookups = diagnostics
        .iter()
        .filter(|error| matches!(error, Error::Lookup(LookupError::TableNotFound { .. })))
        .count();
    let mut flagged: Vec<_> = diagnostics
        .iter()
        .filter_map(|error| match error {
            Error::Violation(violation) => Some(violation.object()),
            Error::Lookup(_) | Error::UnusedAllowance(_) | Error::Inactive(_) => None,
        })
        .collect();
    flagged.sort_unstable();
    assert_eq!(lookups, 1);
    assert_eq!(flagged, ["BROKEN_FIRST", "Other"]);

    assert!(matches!(
        constrainer.validate_schema(&database),
        Err(Error::Lookup(_))
    ));
}

#[test]
fn the_default_constrainer_reports_every_rule_at_its_group_level() {
    let database = parse(
        "CREATE TABLE bases (id INT PRIMARY KEY, label TEXT CHECK (LENGTH(label) <= 10));
         CREATE TABLE lefts (id INT PRIMARY KEY REFERENCES bases (id) ON DELETE CASCADE);
         CREATE TABLE rights (id INT PRIMARY KEY REFERENCES bases (id) ON DELETE CASCADE);
         CREATE TABLE diamonds (
             id INT PRIMARY KEY,
             label TEXT CHECK (LENGTH(label) <= 10),
             FOREIGN KEY (id) REFERENCES lefts (id) ON DELETE CASCADE,
             FOREIGN KEY (id) REFERENCES rights (id) ON DELETE CASCADE
         );
         CREATE TABLE children (id SERIAL PRIMARY KEY DEFAULT 1 REFERENCES bases (id) ON DELETE CASCADE);
         CREATE TABLE notes_ (
             code INT PRIMARY KEY,
             tags INT,
             title_ INT,
             body TEXT,
             base INT,
             expires_at TIMESTAMPTZ,
             FOREIGN KEY (base) REFERENCES bases (id),
             FOREIGN KEY (base) REFERENCES bases (id),
             UNIQUE (tags),
             UNIQUE (tags),
             CHECK (code > 0),
             CHECK (code > 0)
         );",
    );
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
    constrainer.set_group_level(LintGroup::Perf, Level::Deny);
    let raised = violations(&constrainer, &database);
    for (rule, expected) in [
        ("NonCompositePrimaryKeyNamedId", [Level::Warn].as_slice()),
        ("SingularColumnName", &[Level::Warn]),
        ("SnakeCaseColumnName", &[Level::Warn]),
        ("SnakeCaseTableName", &[Level::Warn]),
        ("TextualColumnRule", &[Level::Warn]),
        ("NoSurrogatePrimaryKeyInExtension", &[Level::Deny]),
        ("UniqueColumnNamesInExtensionGraph", &[Level::Warn]),
        ("PrimaryKeyReferenceEndsWithId", &[Level::Warn, Level::Warn]),
        ("UniqueForeignKey", &[Level::Warn]),
        ("UniqueUniqueIndex", &[Level::Warn]),
        ("UniqueCheckRule", &[Level::Warn]),
    ] {
        assert_eq!(raised_by(&raised, rule), expected, "{rule}");
    }
    assert!(
        !raised
            .iter()
            .any(|violation| violation.rule().name == "PastTimeColumnRule"
                && violation.object() == "notes_.expires_at"),
        "a column naming a future instant is exempt"
    );
}
