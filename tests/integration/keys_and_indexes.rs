//! Keys and indexes, observed through the public constrainer API. The
//! behaviour each rule cites was measured on PostgreSQL 17.11 and 18.6.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const RULES: [&str; 8] = [
    "nullable_composite_foreign_key",
    "unindexed_foreign_key",
    "serial_column",
    "narrow_integer_key",
    "client_written_counter_key",
    "prefix_redundant_index",
    "repeated_index_column",
    "scaled_numeric",
];

/// Rule, level and object of every finding of this group.
fn findings<C: Constrainer<Database = ParserDB>>(
    constrainer: &C,
    sql: &str,
) -> Vec<(String, Level, String)> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    constrainer
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if RULES.contains(&violation.rule().name) => Some((
                violation.rule().name.to_owned(),
                violation.level(),
                violation.object().to_owned(),
            )),
            Error::Violation(_) | Error::Inactive(_) => None,
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

fn every_rule() -> DefaultConstrainer<ParserDB> {
    let mut constrainer = DefaultConstrainer::default();
    constrainer.set_group_level(LintGroup::Pedantic, Level::Warn);
    constrainer.set_deployment(Deployment::default().with_client_written_table("public", "notes"));
    constrainer
}

/// Rule and object of every finding of `rule`.
fn of(rule: &str, sql: &str) -> Vec<String> {
    findings(&every_rule(), sql)
        .into_iter()
        .filter(|(name, _, _)| name == rule)
        .map(|(_, _, object)| object)
        .collect()
}

/// The first quoted name of every `prefix_redundant_index` message.
fn redundant(sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    every_rule()
        .diagnostics(&database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == "prefix_redundant_index" => {
                violation.message().split('\'').nth(1).map(str::to_owned)
            }
            _ => None,
        })
        .collect()
}

const PARENT: &str = "CREATE TABLE p (a INT NOT NULL, b INT NOT NULL, PRIMARY KEY (a, b));";

#[test]
fn a_composite_key_that_can_point_nowhere_is_reported() {
    let found = of(
        "nullable_composite_foreign_key",
        &format!(
            "{PARENT}
             CREATE TABLE simple (a INT, b INT NOT NULL, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE full_match (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b) MATCH FULL);
             CREATE TABLE required (a INT NOT NULL, b INT NOT NULL, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE q (a INT PRIMARY KEY);
             CREATE TABLE single (a INT REFERENCES q (a));"
        ),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("simple"), "{found:?}");
}

#[test]
fn a_foreign_key_no_index_leads_with_is_reported() {
    let found = of(
        "unindexed_foreign_key",
        &format!(
            "{PARENT}
             CREATE TABLE bare (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE behind (a INT, b INT, c INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE INDEX ON behind (c, a, b);
             CREATE TABLE partial (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE INDEX ON partial (a, b) WHERE a > 0;
             CREATE TABLE swapped (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE INDEX ON swapped (b, a);
             CREATE TABLE wider (a INT, b INT, c INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE INDEX ON wider (a, b, c);
             CREATE TABLE keyed (a INT, b INT, PRIMARY KEY (a, b), FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE short (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE INDEX ON short (a);"
        ),
    );
    assert_eq!(found.len(), 4, "{found:?}");
    for table in ["bare", "behind", "partial", "short"] {
        assert!(
            found.iter().any(|object| object.contains(table)),
            "{table}: {found:?}"
        );
    }
}

#[test]
fn counters_and_narrow_keys_are_reported_per_table_kind() {
    let sql = "CREATE SEQUENCE s;
        CREATE TABLE logs (id SERIAL PRIMARY KEY, code SMALLINT GENERATED ALWAYS AS IDENTITY,
          big BIGSERIAL, plain INT);
        CREATE TABLE wide (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
        CREATE TABLE notes (id BIGSERIAL PRIMARY KEY);
        CREATE TABLE notes_seq (id BIGINT PRIMARY KEY DEFAULT nextval('s'));";
    assert_eq!(of("serial_column", sql), ["logs.id", "logs.big"]);
    assert_eq!(of("narrow_integer_key", sql), ["logs.id", "logs.code"]);
    assert_eq!(of("client_written_counter_key", sql), ["notes.id"]);
}

#[test]
fn every_counter_minting_a_client_written_key_is_reported() {
    let mut constrainer: GenericConstrainer<ParserDB> = ClientWrittenCounterKey::default().into();
    constrainer.set_deployment(
        Deployment::default()
            .with_client_written_table("public", "a")
            .with_client_written_table("public", "b")
            .with_client_written_table("public", "c")
            .with_client_written_table("public", "d")
            .with_client_written_table("public", "e")
            .with_client_written_table("public", "f"),
    );
    let found: Vec<String> = findings(
        &constrainer,
        "CREATE SEQUENCE s;
         CREATE TABLE a (id SERIAL PRIMARY KEY);
         CREATE TABLE b (id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY);
         CREATE TABLE c (id BIGINT PRIMARY KEY DEFAULT nextval('s'));
         CREATE TABLE d (id INT PRIMARY KEY);
         CREATE TABLE e (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), n BIGINT);
         CREATE TABLE f (id BIGINT PRIMARY KEY DEFAULT 7, n SERIAL);",
    )
    .into_iter()
    .map(|(_, _, object)| object)
    .collect();
    assert_eq!(found, ["a.id", "b.id", "c.id", "d.id"]);
}

#[test]
fn an_index_another_serves_is_reported() {
    let found = redundant(
        "CREATE TABLE t (a INT, b INT, c INT, UNIQUE (a, b));
         CREATE INDEX t_a ON t (a);
         CREATE INDEX t_b ON t (b);
         CREATE INDEX t_ab_again ON t (a, b);
         CREATE INDEX t_c1 ON t (c);
         CREATE INDEX t_c2 ON t (c);
         CREATE INDEX t_hash ON t USING hash (b);
         CREATE INDEX t_partial ON t (c) WHERE c > 0;
         CREATE UNIQUE INDEX t_unique_b ON t (b);
         CREATE INDEX t_expr ON t (lower(c::text));
         CREATE INDEX t_include ON t (a) INCLUDE (c);",
    );
    assert_eq!(found, ["t_a", "t_b", "t_ab_again", "t_c2"]);
}

#[test]
fn an_index_naming_a_column_twice_is_reported() {
    let constrainer = GenericConstrainer::from(RepeatedIndexColumn::default());
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE t (id INT PRIMARY KEY, a INT, b INT, c INT);
         CREATE INDEX t_a_a ON t (a, a);
         CREATE UNIQUE INDEX t_b_c_b ON t (b, c, b);
         CREATE INDEX t_a_b ON t (a, b);
         CREATE INDEX t_c_lower ON t (c, lower(c::text));
         CREATE INDEX ON t (c, c);",
    )
    .expect("schema parses");
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().name, "repeated_index_column");
                violation.message().to_owned()
            }
            other => panic!("unexpected failure: {other}"),
        })
        .collect();
    assert_eq!(
        messages,
        [
            "Index 't_a_a' on 't' names column 'a' more than once, and the repeated key orders and constrains nothing the first did not.",
            "Index 't_b_c_b' on 't' names column 'b' more than once, and the repeated key orders and constrains nothing the first did not.",
            "Index 't_c_c1_idx' on 't' names column 'c' more than once, and the repeated key orders and constrains nothing the first did not.",
        ]
    );
}

#[test]
fn an_index_on_a_schema_qualified_table_naming_a_column_twice_is_reported() {
    let constrainer = GenericConstrainer::from(RepeatedIndexColumn::default());
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE SCHEMA app;
         CREATE TABLE app.t (id INT PRIMARY KEY, a INT);
         CREATE INDEX t_a_a ON app.t (a, a);",
    )
    .expect("schema parses");
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| error.to_string())
        .collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(
        messages[0].contains("Index 't_a_a' on 't' names column 'a' more than once"),
        "{messages:?}"
    );
}

#[test]
fn only_btree_indexes_are_judged_for_a_repeated_column() {
    let constrainer = GenericConstrainer::from(RepeatedIndexColumn::default());
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE TABLE d (id INT PRIMARY KEY, a INT, doc JSONB);
         CREATE INDEX d_doc_both ON d USING gin (doc jsonb_ops, doc jsonb_path_ops);
         CREATE INDEX d_a_a ON d USING btree (a, a);",
    )
    .expect("schema parses");
    let messages: Vec<String> = constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| error.to_string())
        .collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains("Index 'd_a_a'"), "{messages:?}");
}

#[test]
fn each_rule_registered_alone_runs_at_warn() {
    let sql = format!(
        "{PARENT}
         CREATE TABLE c (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
         CREATE INDEX c_a ON c (a);
         CREATE INDEX c_a_again ON c (a);"
    );
    for (constrainer, rule) in [
        (
            GenericConstrainer::from(NullableCompositeForeignKey::default()),
            "nullable_composite_foreign_key",
        ),
        (
            GenericConstrainer::from(UnindexedForeignKey::default()),
            "unindexed_foreign_key",
        ),
        (
            GenericConstrainer::from(PrefixRedundantIndex::default()),
            "prefix_redundant_index",
        ),
    ] {
        let found = findings(&constrainer, &sql);
        assert_eq!(found.len(), 1, "{rule}: {found:?}");
        assert_eq!((found[0].0.as_str(), found[0].1), (rule, Level::Warn));
    }
}

#[test]
fn the_default_constrainer_applies_each_group() {
    let levels: Vec<(String, Level)> = findings(
        &DefaultConstrainer::<ParserDB>::default(),
        &format!(
            "{PARENT}
             CREATE TABLE c (id SERIAL PRIMARY KEY, a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));"
        ),
    )
    .into_iter()
    .map(|(rule, level, _)| (rule, level))
    .collect();
    assert_eq!(
        levels,
        [
            ("serial_column".to_owned(), Level::Warn),
            ("nullable_composite_foreign_key".to_owned(), Level::Warn),
            ("unindexed_foreign_key".to_owned(), Level::Warn),
        ]
    );
}
