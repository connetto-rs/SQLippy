//! Rewrite rules, inheritance, identifiers, unvalidated constraints, schema
//! creation, unlogged tables and wildcard views, observed through the public
//! constrainer API. The behaviour each rule cites was measured on PostgreSQL
//! 17.11 and 18.6.

mod rule_findings;

use rule_findings::findings;
use sql_rules::prelude::*;

/// Objects `rule` reports, registered alone.
fn objects<R>(rule: R, sql: &str) -> Vec<String>
where
    R: sql_rules::lint::Rule + Into<GenericConstrainer<ParserDB>>,
{
    let name = rule.metadata().name;
    findings(&rule.into(), name, sql)
        .into_iter()
        .map(|(level, object, _)| {
            assert_eq!(level, Level::Warn);
            object
        })
        .collect()
}

#[test]
fn rewrite_rules_are_reported_on_their_relation() {
    assert_eq!(
        objects(
            QueryRewriteRule::default(),
            "CREATE TABLE t (id INT); CREATE TABLE log (id INT);
             CREATE VIEW v AS SELECT id FROM t;
             CREATE RULE on_table AS ON INSERT TO t DO ALSO INSERT INTO log VALUES (NEW.id);
             CREATE RULE on_view AS ON INSERT TO v DO INSTEAD INSERT INTO t VALUES (NEW.id);"
        ),
        ["t", "v"]
    );
}

#[test]
fn inheritance_children_are_reported_and_partitions_are_not() {
    assert_eq!(
        objects(
            TableInheritance::default(),
            "CREATE TABLE parent (id INT PRIMARY KEY);
             CREATE TABLE child () INHERITS (parent);
             CREATE TABLE events (at DATE) PARTITION BY RANGE (at);
             CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');"
        ),
        ["child"]
    );
}

#[test]
fn identifiers_over_63_bytes_are_reported_on_every_object() {
    let long = |prefix: &str| format!("{prefix}{}", "x".repeat(64 - prefix.len()));
    let (table, column, index, key, policy, view, role, domain, function) = (
        long("t"),
        long("c"),
        long("i"),
        long("k"),
        long("p"),
        long("v"),
        long("r"),
        long("d"),
        long("f"),
    );
    let found = objects(
        TruncatedIdentifier::default(),
        &format!(
            "CREATE TABLE parent (id INT PRIMARY KEY);
             CREATE TABLE {table} (id INT, {column} INT,
               CONSTRAINT {key} FOREIGN KEY (id) REFERENCES parent (id));
             CREATE INDEX {index} ON {table} (id);
             ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
             CREATE POLICY {policy} ON {table} USING (true);
             CREATE VIEW {view} AS SELECT id FROM parent;
             CREATE MATERIALIZED VIEW m{view} AS SELECT id FROM parent;
             CREATE ROLE {role};
             CREATE DOMAIN {domain} AS INT;
             CREATE FUNCTION {function}() RETURNS INT LANGUAGE sql AS 'SELECT 1';
             CREATE TABLE short_enough_{} (id INT);",
            "y".repeat(50)
        ),
    );
    assert_eq!(found.len(), 10, "{found:?}");
}

#[test]
fn reserved_keywords_naming_relations_columns_and_roles_are_reported() {
    assert_eq!(
        objects(
            ReservedKeywordIdentifier::default(),
            r#"CREATE TABLE "order" ("user" INT, "left" INT, name TEXT, value INT);
               CREATE VIEW "select" AS SELECT 1 AS one;
               CREATE MATERIALIZED VIEW "group" AS SELECT 1 AS one;
               CREATE ROLE "user";
               CREATE INDEX "join" ON "order" (name);
               CREATE FUNCTION "left"() RETURNS INT LANGUAGE sql AS 'SELECT 1';"#
        ),
        [
            "order",
            "order.user",
            "order.left",
            "select",
            "group",
            "user"
        ]
    );
}

#[test]
fn unvalidated_checks_and_foreign_keys_are_reported_until_validated() {
    assert_eq!(
        objects(
            UnvalidatedConstraint::default(),
            "CREATE TABLE parent (id INT PRIMARY KEY);
             CREATE TABLE ok (parent_id INT REFERENCES parent (id));
             CREATE TABLE t (x INT, parent_id INT);
             ALTER TABLE t ADD CONSTRAINT positive CHECK (x > 0) NOT VALID;
             ALTER TABLE t ADD CONSTRAINT small CHECK (x < 100) NOT VALID;
             ALTER TABLE t ADD CONSTRAINT to_parent FOREIGN KEY (parent_id) REFERENCES parent (id) NOT VALID;
             ALTER TABLE t VALIDATE CONSTRAINT small;"
        )
        .len(),
        2
    );
}

#[test]
fn create_on_a_schema_for_public_is_reported() {
    assert_eq!(
        objects(
            PublicSchemaCreate::default(),
            "CREATE SCHEMA app; CREATE ROLE writer;
             GRANT CREATE ON SCHEMA public TO PUBLIC;
             GRANT ALL ON SCHEMA app TO PUBLIC;
             GRANT USAGE ON SCHEMA app TO PUBLIC;
             GRANT CREATE ON SCHEMA app TO writer;
             CREATE TABLE t (id INT); GRANT SELECT ON t TO PUBLIC;"
        ),
        ["schema public", "schema app"]
    );
}

#[test]
fn unlogged_tables_and_wildcard_views_are_reported() {
    assert_eq!(
        objects(
            UnloggedTable::default(),
            "CREATE UNLOGGED TABLE cache (id INT); CREATE TABLE kept (id INT);"
        ),
        ["cache"]
    );
    assert_eq!(
        objects(
            WildcardView::default(),
            "CREATE TABLE t (a INT, b INT);
             CREATE VIEW star AS SELECT * FROM t;
             CREATE VIEW listed AS SELECT a, b FROM t;
             CREATE MATERIALIZED VIEW mstar AS SELECT * FROM t;
             CREATE MATERIALIZED VIEW mlisted AS SELECT a FROM t;"
        ),
        ["star", "mstar"]
    );
}

#[test]
fn the_default_constrainer_applies_each_group() {
    let sql = r#"CREATE UNLOGGED TABLE "order" (id INT);
        CREATE TABLE child () INHERITS ("order");
        CREATE VIEW star AS SELECT * FROM child;"#;
    let constrainer = DefaultConstrainer::<ParserDB>::default();
    let levels: Vec<(&str, usize)> = [
        "TableInheritance",
        "ReservedKeywordIdentifier",
        "UnloggedTable",
        "WildcardView",
    ]
    .into_iter()
    .map(|rule| (rule, findings(&constrainer, rule, sql).len()))
    .collect();
    assert_eq!(
        levels,
        [
            ("TableInheritance", 1),
            ("ReservedKeywordIdentifier", 1),
            ("UnloggedTable", 0),
            ("WildcardView", 0)
        ]
    );
}
