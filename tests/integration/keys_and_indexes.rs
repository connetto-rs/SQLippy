//! Keys and indexes, observed through the public constrainer API. The
//! behaviour each rule cites was measured on PostgreSQL 17.11 and 18.6.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

const RULES: [&str; 9] = [
    "nullable_composite_foreign_key",
    "unindexed_foreign_key",
    "serial_column",
    "narrow_integer_key",
    "client_written_counter_key",
    "prefix_redundant_index",
    "duplicate_index",
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

/// The first quoted name of every `rule` message.
fn named_by(rule: &str, sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    first_names(&every_rule(), &database, rule)
}

/// The first quoted name of every `rule` message `constrainer` reports on
/// `database`.
fn first_names<C: Constrainer>(constrainer: &C, database: &C::Database, rule: &str) -> Vec<String> {
    constrainer
        .diagnostics(database)
        .into_iter()
        .filter_map(|error| match error {
            Error::Violation(violation) if violation.rule().name == rule => {
                violation.message().split('\'').nth(1).map(str::to_owned)
            }
            _ => None,
        })
        .collect()
}

/// The first quoted name of every `prefix_redundant_index` message.
fn redundant(sql: &str) -> Vec<String> {
    named_by("prefix_redundant_index", sql)
}

/// Indexes that each differ from `documents_base` in one fact PostgreSQL
/// keeps, and indexes that repeat one before them in another spelling.
const DOCUMENT_INDEXES: &str = "
    CREATE TABLE documents (identifier INT PRIMARY KEY, title TEXT, body TEXT, rank INT);
    CREATE INDEX documents_base ON documents ((lower(title)), rank) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX documents_descending ON documents ((lower(title)) DESC, rank) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX documents_nulls_first ON documents ((lower(title)) NULLS FIRST, rank) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX documents_pattern ON documents ((lower(title)) text_pattern_ops, rank) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX documents_collated ON documents ((lower(title)) COLLATE \"C\", rank) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX documents_other_predicate ON documents ((lower(title)), rank) INCLUDE (body) WHERE rank > 0;
    CREATE INDEX documents_total ON documents ((lower(title)), rank) INCLUDE (body);
    CREATE INDEX documents_hash ON documents USING hash ((lower(title))) WHERE title IS NOT NULL;
    CREATE INDEX documents_btree ON documents ((lower(title))) WHERE title IS NOT NULL;
    CREATE UNIQUE INDEX documents_unique ON documents ((lower(title)), rank) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX documents_no_include ON documents ((lower(title)), rank) WHERE title IS NOT NULL;
    CREATE INDEX documents_other_include ON documents ((lower(title)), rank) INCLUDE (identifier) WHERE title IS NOT NULL;
    CREATE INDEX documents_reordered ON documents (rank, (lower(title))) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX documents_ascending ON documents ((lower(title)) ASC NULLS LAST, rank ASC) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX documents_spelled ON documents ((LOWER(Title)), Rank) INCLUDE (Body) WHERE Title IS NOT NULL;
    CREATE UNIQUE INDEX documents_unique_again ON documents ((lower(title)), rank) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX documents_descending_again ON documents ((lower(title)) DESC NULLS FIRST, rank) INCLUDE (body) WHERE title IS NOT NULL;
";

/// What `duplicate_index` reports on [`DOCUMENT_INDEXES`].
const DOCUMENT_DUPLICATES: [&str; 4] = [
    "documents_ascending",
    "documents_spelled",
    "documents_unique_again",
    "documents_descending_again",
];

#[test]
fn an_index_repeating_another_is_reported() {
    let found = named_by(
        "duplicate_index",
        "CREATE TABLE public.documents (identifier integer PRIMARY KEY, title text);
         CREATE INDEX documents_title_first ON public.documents ((lower(title))) WHERE title IS NOT NULL;
         CREATE INDEX documents_title_second ON public.documents ((lower(title))) WHERE title IS NOT NULL;",
    );
    assert_eq!(found, ["documents_title_second"]);
}

#[test]
fn an_index_differing_in_any_fact_postgresql_keeps_is_not_a_duplicate() {
    assert_eq!(
        named_by("duplicate_index", DOCUMENT_INDEXES),
        DOCUMENT_DUPLICATES
    );
}

#[test]
fn live_indexes_differing_in_any_fact_postgresql_keeps_are_not_duplicates() {
    let (_container, database) = crate::live_catalog::catalog("public", DOCUMENT_INDEXES);
    let constrainer: GenericConstrainer<pg_diesel::PgDieselDatabase> =
        DuplicateIndex::default().into();
    let mut found = first_names(&constrainer, &database, "duplicate_index");
    found.sort_unstable();
    let mut expected = DOCUMENT_DUPLICATES;
    expected.sort_unstable();
    assert_eq!(found, expected);
}

#[test]
fn a_unique_index_repeating_a_key_constraint_is_reported() {
    let found = named_by(
        "duplicate_index",
        "CREATE TABLE accounts (identifier INT PRIMARY KEY, email TEXT UNIQUE, handle TEXT,
           UNIQUE NULLS NOT DISTINCT (handle));
         CREATE UNIQUE INDEX accounts_email ON accounts (email);
         CREATE UNIQUE INDEX accounts_identifier ON accounts (identifier);
         CREATE UNIQUE INDEX accounts_handle ON accounts (handle);
         CREATE INDEX accounts_email_plain ON accounts (email);",
    );
    assert_eq!(found, ["accounts_email", "accounts_identifier"]);
}

/// Keys and unique indexes over one column that PostgreSQL checks at
/// different times, besides one key repeated as written and one unique
/// index repeating the primary key.
const DEFERRED_KEYS: &str = "
    CREATE TABLE ledgers (identifier INT PRIMARY KEY, code TEXT, slot INT,
      UNIQUE (code) DEFERRABLE,
      UNIQUE (slot), UNIQUE (slot) DEFERRABLE, UNIQUE (slot) DEFERRABLE INITIALLY DEFERRED);
    ALTER TABLE ledgers ADD UNIQUE (code) DEFERRABLE;
    CREATE UNIQUE INDEX ledgers_code ON ledgers (code);
    CREATE UNIQUE INDEX ledgers_identifier ON ledgers (identifier);
";

#[test]
fn keys_checked_at_different_times_are_not_duplicates() {
    assert_eq!(
        named_by("duplicate_index", DEFERRED_KEYS),
        ["ledgers_identifier"]
    );
    let database = ParserDB::parse::<PostgreSqlDialect>(DEFERRED_KEYS).expect("schema parses");
    let unique = GenericConstrainer::from(DuplicateUniqueIndex::default());
    assert_eq!(
        first_names(&unique, &database, "duplicate_unique_index"),
        ["ledgers"]
    );
}

#[test]
fn live_keys_checked_at_different_times_are_not_duplicates() {
    let (_container, database) = crate::live_catalog::catalog("public", DEFERRED_KEYS);
    let index: GenericConstrainer<pg_diesel::PgDieselDatabase> = DuplicateIndex::default().into();
    assert_eq!(
        first_names(&index, &database, "duplicate_index"),
        ["ledgers_identifier"]
    );
    let unique: GenericConstrainer<pg_diesel::PgDieselDatabase> =
        DuplicateUniqueIndex::default().into();
    assert_eq!(
        first_names(&unique, &database, "duplicate_unique_index"),
        ["ledgers"]
    );
}

#[test]
fn a_quoted_operator_class_names_the_class_it_quotes() {
    let found = named_by(
        "duplicate_index",
        "CREATE TABLE documents (identifier INT PRIMARY KEY, title TEXT);
         CREATE INDEX documents_pattern ON documents (title text_pattern_ops) WHERE title IS NOT NULL;
         CREATE INDEX documents_pattern_quoted ON documents (title \"text_pattern_ops\") WHERE title IS NOT NULL;
         CREATE INDEX documents_pattern_qualified ON documents (title pg_catalog.\"text_pattern_ops\") WHERE title IS NOT NULL;",
    );
    assert_eq!(found, ["documents_pattern_quoted"]);
}

/// Indexes on a materialized view, two of which repeat one before them.
const TITLE_INDEXES: &str = "
    CREATE TABLE documents (identifier INT PRIMARY KEY, title TEXT, body TEXT);
    CREATE MATERIALIZED VIEW titles AS SELECT identifier, title, body FROM documents;
    CREATE UNIQUE INDEX titles_identifier ON titles (identifier);
    CREATE INDEX titles_lower ON titles ((lower(title))) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX titles_lower_descending ON titles ((lower(title)) DESC) INCLUDE (body) WHERE title IS NOT NULL;
    CREATE INDEX titles_lower_again ON titles ((LOWER(Title))) INCLUDE (Body) WHERE title IS NOT NULL;
    CREATE INDEX titles_body ON titles (body);
    CREATE INDEX titles_body_again ON titles (body);
    CREATE MATERIALIZED VIEW bodies AS SELECT identifier, body FROM documents;
    CREATE INDEX bodies_body ON bodies (body);
";

#[test]
fn an_index_repeating_another_on_a_materialized_view_is_reported() {
    let mut found = named_by("duplicate_index", TITLE_INDEXES);
    found.sort_unstable();
    assert_eq!(found, ["titles_body_again", "titles_lower_again"]);
}

#[test]
fn a_live_index_repeating_another_on_a_materialized_view_is_reported() {
    let (_container, database) = crate::live_catalog::catalog("public", TITLE_INDEXES);
    let constrainer: GenericConstrainer<pg_diesel::PgDieselDatabase> =
        DuplicateIndex::default().into();
    let mut found = first_names(&constrainer, &database, "duplicate_index");
    found.sort_unstable();
    assert_eq!(found, ["titles_body_again", "titles_lower_again"]);
}

#[test]
fn duplicates_another_rule_reports_are_left_to_it() {
    let sql = "CREATE TABLE t (a INT, b INT, UNIQUE (a));
         ALTER TABLE t ADD UNIQUE (a);
         CREATE INDEX t_b ON t (b);
         CREATE INDEX t_b_again ON t (b);";
    assert_eq!(named_by("duplicate_index", sql), Vec::<String>::new());
    assert_eq!(redundant(sql), ["t_b_again"]);
    let database = ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses");
    let unique = GenericConstrainer::from(DuplicateUniqueIndex::default());
    assert_eq!(
        first_names(&unique, &database, "duplicate_unique_index"),
        ["t"]
    );
}

const PARENT: &str = "CREATE TABLE p (a INT NOT NULL, b INT NOT NULL, PRIMARY KEY (a, b));";

#[test]
fn a_composite_key_that_can_point_nowhere_is_reported() {
    let found = of(
        "nullable_composite_foreign_key",
        &format!(
            "{PARENT}
             CREATE TABLE simple (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE unenforced (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b) NOT ENFORCED);
             CREATE TABLE optional (a INT, b INT NOT NULL, FOREIGN KEY (a, b) REFERENCES p (a, b));
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
fn a_composite_key_whose_checks_keep_nullable_columns_null_together_is_not_reported() {
    let found = of(
        "nullable_composite_foreign_key",
        "CREATE TABLE w (a INT NOT NULL, b INT NOT NULL, c INT NOT NULL, PRIMARY KEY (a, b, c));
         CREATE TABLE tied (a INT, b INT, c INT NOT NULL,
           CHECK ((a IS NULL) = (b IS NULL)),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE untied (a INT, b INT, c INT NOT NULL,
           CHECK ((a IS NULL) = (b IS NULL)) NOT ENFORCED,
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE mirrored (a INT, b INT, c INT NOT NULL,
           CHECK ((b IS NOT NULL) = (a IS NOT NULL)),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE conjoined (a INT, b INT, c INT NOT NULL,
           CHECK (c > 0 AND (a IS NULL) = (b IS NULL)),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE chained (a INT, b INT, c INT NOT NULL, x INT,
           CHECK ((x IS NULL) = (a IS NULL)),
           CHECK ((x IS NULL) = (b IS NULL)),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE crossed (a INT, b INT, c INT NOT NULL,
           CHECK ((a IS NULL) = (b IS NOT NULL)),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE loose (a INT, b INT, c INT NOT NULL, x INT,
           CHECK ((a IS NULL) = (x IS NULL)),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE disjoined (a INT, b INT, c INT NOT NULL,
           CHECK ((a IS NULL) = (b IS NULL) OR c > 0),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE equated (a INT, b INT, c INT NOT NULL,
           CHECK (a = b),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE partly (a INT, b INT, c INT,
           CHECK ((a IS NULL) = (b IS NULL)),
           FOREIGN KEY (a, b, c) REFERENCES w (a, b, c));
         CREATE TABLE discriminated (kind TEXT NOT NULL, a INT, b INT, c INT NOT NULL,
           CHECK ((kind = 'root') = (a IS NULL)),
           CHECK ((kind = 'root') = (b IS NULL)),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE undiscriminated (kind TEXT, a INT, b INT, c INT NOT NULL,
           CHECK ((kind = 'root') = (a IS NULL)),
           CHECK ((kind = 'root') = (b IS NULL)),
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         CREATE TABLE unvalidated (a INT, b INT, c INT NOT NULL,
           FOREIGN KEY (a, c, b) REFERENCES w (a, b, c));
         ALTER TABLE unvalidated ADD CHECK ((a IS NULL) = (b IS NULL)) NOT VALID;",
    );
    assert_eq!(found.len(), 8, "{found:?}");
    for table in [
        "crossed",
        "loose",
        "disjoined",
        "equated",
        "partly",
        "untied",
        "undiscriminated",
        "unvalidated",
    ] {
        assert!(
            found
                .iter()
                .any(|object| object.starts_with(&format!("{table}."))),
            "{table}: {found:?}"
        );
    }
}

#[test]
fn a_foreign_key_no_index_leads_with_is_reported() {
    let found = of(
        "unindexed_foreign_key",
        &format!(
            "{PARENT}
             CREATE TABLE bare (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE unenforced (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b) NOT ENFORCED);
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
fn a_foreign_key_a_unique_key_inside_it_finds_is_not_reported() {
    let found = of(
        "unindexed_foreign_key",
        &format!(
            "{PARENT}
             CREATE TABLE subtype (a INT PRIMARY KEY, b INT NOT NULL, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE constrained (a INT, b INT, UNIQUE (b), FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE deferred (a INT, b INT, UNIQUE (b) DEFERRABLE, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE initially_deferred (a INT, b INT, UNIQUE (b) DEFERRABLE INITIALLY DEFERRED, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE indexed (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE UNIQUE INDEX ON indexed (b);
             CREATE TABLE outside (a INT, b INT, c INT, UNIQUE (a, c), FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE TABLE partial (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE UNIQUE INDEX ON partial (a) WHERE b > 0;
             CREATE TABLE computed (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE UNIQUE INDEX ON computed (abs(a));"
        ),
    );
    assert_eq!(found.len(), 3, "{found:?}");
    for table in ["outside", "partial", "computed"] {
        assert!(
            found.iter().any(|object| object.contains(table)),
            "{table}: {found:?}"
        );
    }
}

#[test]
fn a_foreign_key_an_index_on_a_referenced_unique_key_finds_is_not_reported() {
    let found = of(
        "unindexed_foreign_key",
        "CREATE TABLE parents (id INT PRIMARY KEY, kind INT NOT NULL, UNIQUE (id, kind));
         CREATE TABLE prefixed (parent_id INT NOT NULL, parent_kind INT NOT NULL,
           FOREIGN KEY (parent_id, parent_kind) REFERENCES parents (id, kind));
         CREATE INDEX ON prefixed (parent_id);
         CREATE TABLE trailed (parent_id INT NOT NULL, parent_kind INT NOT NULL, at INT,
           FOREIGN KEY (parent_id, parent_kind) REFERENCES parents (id, kind));
         CREATE INDEX ON trailed (parent_id, at);
         CREATE TABLE keyed (parent_id INT NOT NULL, parent_kind INT NOT NULL, other INT,
           PRIMARY KEY (parent_id, other),
           FOREIGN KEY (parent_kind, parent_id) REFERENCES parents (kind, id));
         CREATE TABLE repeated (parent_id INT NOT NULL, parent_kind INT NOT NULL,
           FOREIGN KEY (parent_id, parent_kind) REFERENCES parents (id, kind));
         CREATE INDEX ON repeated (parent_kind, parent_kind, parent_id);
         CREATE TABLE by_kind (parent_id INT NOT NULL, parent_kind INT NOT NULL,
           FOREIGN KEY (parent_id, parent_kind) REFERENCES parents (id, kind));
         CREATE INDEX ON by_kind (parent_kind);
         CREATE TABLE behind (parent_id INT NOT NULL, parent_kind INT NOT NULL, at INT,
           FOREIGN KEY (parent_id, parent_kind) REFERENCES parents (id, kind));
         CREATE INDEX ON behind (at, parent_id);
         CREATE TABLE partial (parent_id INT NOT NULL, parent_kind INT NOT NULL,
           FOREIGN KEY (parent_id, parent_kind) REFERENCES parents (id, kind));
         CREATE INDEX ON partial (parent_id) WHERE parent_kind > 0;
         CREATE TABLE computed (parent_id INT NOT NULL, parent_kind INT NOT NULL,
           FOREIGN KEY (parent_id, parent_kind) REFERENCES parents (id, kind));
         CREATE INDEX ON computed (abs(parent_id));
         CREATE TABLE loose (id INT, kind INT, UNIQUE (id, kind));
         CREATE UNIQUE INDEX ON loose (id) WHERE kind > 0;
         CREATE TABLE loosely (loose_id INT NOT NULL, loose_kind INT NOT NULL,
           FOREIGN KEY (loose_id, loose_kind) REFERENCES loose (id, kind));
         CREATE INDEX ON loosely (loose_id);",
    );
    assert_eq!(found.len(), 5, "{found:?}");
    for table in ["by_kind", "behind", "partial", "computed", "loosely"] {
        assert!(
            found.iter().any(|object| object.contains(table)),
            "{table}: {found:?}"
        );
    }
}

#[test]
fn a_foreign_key_only_an_expression_leads_with_is_reported() {
    let found = of(
        "unindexed_foreign_key",
        &format!(
            "{PARENT}
             CREATE TABLE q (a INT PRIMARY KEY);
             CREATE TABLE single (a INT REFERENCES q (a));
             CREATE INDEX ON single (abs(a));
             CREATE TABLE first (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE INDEX ON first ((abs(a)), b);
             CREATE TABLE second (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE INDEX ON second (b, (a + b));
             CREATE TABLE trailing (a INT, b INT, c INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE INDEX ON trailing (b, a, abs(c));
             CREATE TABLE parenthesised (a INT, b INT, FOREIGN KEY (a, b) REFERENCES p (a, b));
             CREATE INDEX ON parenthesised ((a), b);"
        ),
    );
    assert_eq!(found.len(), 3, "{found:?}");
    for table in ["single", "first", "second"] {
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
