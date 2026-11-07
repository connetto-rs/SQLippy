//! Statement rules that read unique keys and foreign keys, observed through
//! the public constrainer API. The behaviour each rule cites was measured on
//! PostgreSQL 17.11 and 18.6.

use crate::{
    common::parse,
    rule_findings::{check_query_rule, statement, statement_levels},
};
use sql_rules::prelude::*;

const SHOP: &str = "
    CREATE TABLE customers (id INT PRIMARY KEY, email TEXT UNIQUE, login TEXT NOT NULL UNIQUE, team INT);
    CREATE TABLE orders (
        id INT PRIMARY KEY,
        customer_id INT NOT NULL REFERENCES customers (id),
        prio INT,
        code TEXT
    );
    CREATE UNIQUE INDEX orders_code ON orders (code) WHERE code IS NOT NULL;
    CREATE UNIQUE INDEX orders_lower_code ON orders (lower(code));
    CREATE TABLE tags (order_id INT NOT NULL, tag TEXT NOT NULL, UNIQUE NULLS NOT DISTINCT (order_id, tag));
    CREATE TABLE notes (body TEXT);";

#[test]
fn an_ambiguous_order_is_a_lookup_failure() {
    let constrainer: GenericConstrainer<ParserDB> = UnorderedLimit::default().into();
    assert!(matches!(
        constrainer.validate_statement(
            &parse(SHOP),
            &statement(
                "SELECT o.id FROM orders AS o JOIN customers AS c ON c.id = o.customer_id ORDER BY id LIMIT 1"
            )
        ),
        Err(Error::Lookup(_))
    ));
}

#[test]
fn order_keys_and_unread_tables_are_read_as_postgresql_does() {
    check_query_rule(
        SHOP,
        UnorderedLimit::default(),
        &[
            (
                "SELECT prio AS id FROM orders ORDER BY id LIMIT 5",
                &["LIMIT 5"],
            ),
            (
                "SELECT id, prio FROM orders ORDER BY 2 LIMIT 5",
                &["LIMIT 5"],
            ),
            ("SELECT *, id FROM orders ORDER BY 2 LIMIT 5", &["LIMIT 5"]),
            (
                "SELECT o.id, c.email FROM orders AS o JOIN customers AS c ON c.id = o.customer_id ORDER BY c.id LIMIT 3",
                &["LIMIT 3"],
            ),
            ("SELECT id FROM orders ORDER BY 1 LIMIT 5", &[]),
            ("SELECT id AS k FROM orders ORDER BY k LIMIT 5", &[]),
            (
                "SELECT team, count(*) FROM customers GROUP BY 1 ORDER BY team LIMIT 5",
                &[],
            ),
            (
                "SELECT c.id FROM customers AS c LEFT JOIN orders AS o ON o.customer_id = c.id ORDER BY c.id LIMIT 1",
                &[],
            ),
            (
                "SELECT c.* FROM customers AS c JOIN orders AS o ON o.customer_id = c.id ORDER BY c.id LIMIT 1",
                &[],
            ),
            (
                "SELECT * FROM customers AS c JOIN orders AS o ON o.customer_id = c.id ORDER BY c.id LIMIT 1",
                &["LIMIT 1"],
            ),
            (
                "SELECT id FROM customers WHERE EXISTS (SELECT * FROM orders LIMIT 1)",
                &[],
            ),
        ],
    );
}

#[test]
fn a_row_cap_over_rows_the_order_leaves_tied_is_reported() {
    check_query_rule(
        SHOP,
        UnorderedLimit::default(),
        &[
            ("SELECT id FROM orders LIMIT 1", &["LIMIT 1"]),
            ("SELECT id FROM orders OFFSET $1", &["OFFSET $1"]),
            (
                "SELECT id FROM orders FETCH FIRST 3 ROWS ONLY",
                &["FETCH FIRST 3 ROWS ONLY"],
            ),
            ("SELECT id FROM orders ORDER BY prio LIMIT 2", &["LIMIT 2"]),
            (
                "SELECT id FROM customers ORDER BY email LIMIT 5",
                &["LIMIT 5"],
            ),
            ("SELECT id FROM orders ORDER BY code LIMIT 5", &["LIMIT 5"]),
            (
                "SELECT id FROM orders ORDER BY lower(code) LIMIT 5",
                &["LIMIT 5"],
            ),
            (
                "SELECT o.id FROM orders AS o JOIN customers AS c ON c.id = o.customer_id ORDER BY c.id LIMIT 10",
                &["LIMIT 10"],
            ),
            (
                "SELECT team, count(*) FROM customers GROUP BY team ORDER BY count(*) LIMIT 5",
                &["LIMIT 5"],
            ),
            (
                "SELECT id FROM orders UNION SELECT id FROM customers LIMIT 1",
                &["LIMIT 1"],
            ),
            (
                "SELECT id FROM customers WHERE id IN (SELECT customer_id FROM orders LIMIT 5)",
                &["LIMIT 5"],
            ),
            ("SELECT body FROM notes ORDER BY body LIMIT 1", &["LIMIT 1"]),
            (
                "SELECT DISTINCT prio, code FROM orders ORDER BY prio LIMIT 5",
                &["LIMIT 5"],
            ),
            (
                "SELECT id FROM orders WHERE prio = abs($1) LIMIT 1",
                &["LIMIT 1"],
            ),
            ("SELECT id FROM orders ORDER BY id LIMIT 1", &[]),
            ("SELECT id FROM orders ORDER BY random() LIMIT 1", &[]),
            ("SELECT id FROM orders ORDER BY prio, id DESC LIMIT 2", &[]),
            ("SELECT id FROM customers ORDER BY login LIMIT 5", &[]),
            ("SELECT id FROM orders WHERE id = $1 LIMIT 1", &[]),
            ("SELECT id FROM orders WHERE $1 = id LIMIT 1", &[]),
            (
                "SELECT tag FROM tags WHERE order_id = 7 ORDER BY tag LIMIT 3",
                &[],
            ),
            (
                "SELECT o.id FROM orders AS o JOIN customers AS c ON c.id = o.customer_id ORDER BY o.id LIMIT 10",
                &[],
            ),
            (
                "SELECT o.id FROM orders AS o, customers AS c WHERE o.customer_id = c.id ORDER BY o.id LIMIT 10",
                &[],
            ),
            (
                "SELECT team, count(*) FROM customers GROUP BY team ORDER BY team LIMIT 5",
                &[],
            ),
            (
                "SELECT team, count(*) FROM customers WHERE team = $1 GROUP BY team LIMIT 5",
                &[],
            ),
            (
                "SELECT DISTINCT prio FROM orders ORDER BY prio LIMIT 5",
                &[],
            ),
            ("SELECT DISTINCT * FROM orders ORDER BY id LIMIT 1", &[]),
            ("SELECT count(*) FROM orders LIMIT 1", &[]),
            ("SELECT 1 FROM orders WHERE prio = $1 LIMIT 1", &[]),
            (
                "SELECT id FROM orders UNION SELECT id FROM customers ORDER BY id LIMIT 1",
                &[],
            ),
            (
                "SELECT d.id FROM (SELECT id FROM orders) AS d ORDER BY d.id LIMIT 1",
                &[],
            ),
            ("SELECT id FROM orders", &[]),
        ],
    );
}

#[test]
fn distinct_on_without_an_order_that_breaks_ties_is_reported() {
    check_query_rule(
        SHOP,
        UnorderedDistinctOn::default(),
        &[
            (
                "SELECT DISTINCT ON (prio) prio, id FROM orders",
                &["DISTINCT ON (prio)"],
            ),
            (
                "SELECT DISTINCT ON (prio) prio, id FROM orders ORDER BY prio",
                &["DISTINCT ON (prio)"],
            ),
            (
                "SELECT DISTINCT ON (prio) prio, id FROM orders ORDER BY prio, code",
                &["DISTINCT ON (prio)"],
            ),
            (
                "SELECT DISTINCT ON (prio) prio, id FROM orders ORDER BY prio, id DESC",
                &[],
            ),
            (
                "SELECT DISTINCT ON (d.prio) d.prio FROM (SELECT prio FROM orders) AS d ORDER BY d.prio",
                &[],
            ),
            ("SELECT DISTINCT prio FROM orders", &[]),
        ],
    );
}

#[test]
fn a_from_item_no_condition_links_is_reported() {
    check_query_rule(
        SHOP,
        UnlinkedFromItem::default(),
        &[
            ("SELECT * FROM customers, orders", &["orders"]),
            (
                "SELECT * FROM customers AS c, orders AS o, tags AS t WHERE o.customer_id = c.id",
                &["tags AS t"],
            ),
            (
                "SELECT * FROM customers AS c, orders AS o WHERE o.prio > 0",
                &["orders AS o"],
            ),
            (
                "SELECT * FROM customers AS c, orders AS o, tags AS t WHERE o.customer_id = c.id AND t.order_id = o.id",
                &[],
            ),
            ("SELECT * FROM customers CROSS JOIN orders", &[]),
            (
                "SELECT * FROM customers AS c, LATERAL (SELECT id FROM orders WHERE customer_id = c.id) AS o",
                &[],
            ),
            ("SELECT * FROM customers", &[]),
        ],
    );
}

#[test]
fn an_unlinked_from_item_names_the_foreign_key_that_would_link_it() {
    let mut constrainer = GenericConstrainer::default();
    constrainer.register_query_rule(Box::new(UnlinkedFromItem::default()));
    let database = parse(SHOP);
    let resolutions = |sql: &str| {
        constrainer
            .statement_diagnostics(&database, &statement(sql))
            .into_iter()
            .map(|error| match error {
                Error::Violation(violation) => violation.resolution().to_owned(),
                other => panic!("unexpected failure: {other}"),
            })
            .collect::<Vec<_>>()
    };
    for sql in [
        "SELECT * FROM customers AS c, orders AS o",
        "SELECT * FROM orders AS o, customers AS c",
    ] {
        let [linked] = <[String; 1]>::try_from(resolutions(sql)).expect("one finding");
        assert!(linked.contains("o.customer_id = c.id"), "{linked}");
    }
    let [unlinked] =
        <[String; 1]>::try_from(resolutions("SELECT * FROM orders, notes")).expect("one finding");
    assert!(!unlinked.contains(" = "), "{unlinked}");
}

#[test]
fn distinct_over_the_referenced_side_of_a_join_is_reported() {
    check_query_rule(
        SHOP,
        DistinctOverReferencedSide::default(),
        &[
            (
                "SELECT DISTINCT c.id, c.email FROM customers AS c JOIN orders AS o ON o.customer_id = c.id",
                &[
                    "SELECT DISTINCT c.id, c.email FROM customers AS c JOIN orders AS o ON o.customer_id = c.id",
                ],
            ),
            (
                "SELECT DISTINCT c.email FROM customers AS c, orders AS o WHERE c.id = o.customer_id AND o.prio > 1",
                &[
                    "SELECT DISTINCT c.email FROM customers AS c, orders AS o WHERE c.id = o.customer_id AND o.prio > 1",
                ],
            ),
            (
                "SELECT DISTINCT c.id, o.prio FROM customers AS c JOIN orders AS o ON o.customer_id = c.id",
                &[],
            ),
            (
                "SELECT c.id FROM customers AS c JOIN orders AS o ON o.customer_id = c.id",
                &[],
            ),
            (
                "SELECT DISTINCT o.customer_id FROM orders AS o JOIN customers AS c ON o.customer_id = c.id",
                &[],
            ),
            (
                "SELECT DISTINCT c.id FROM customers AS c JOIN orders AS o ON o.prio = c.team",
                &[],
            ),
            (
                "SELECT DISTINCT c.id FROM customers AS c LEFT JOIN orders AS o ON o.customer_id = c.id",
                &[],
            ),
            (
                "SELECT DISTINCT * FROM customers AS c JOIN orders AS o ON o.customer_id = c.id",
                &[],
            ),
            (
                "SELECT DISTINCT lower(c.email) FROM customers AS c JOIN orders AS o ON o.customer_id = c.id",
                &[],
            ),
            ("SELECT DISTINCT team FROM customers", &[]),
        ],
    );
}

#[test]
fn the_default_constrainer_runs_key_rules_at_their_group_levels() {
    let mut constrainer = DefaultConstrainer::<ParserDB>::default();
    let database = parse(SHOP);
    let sql = "SELECT DISTINCT c.id FROM customers AS c, orders AS o, notes WHERE o.customer_id = c.id LIMIT 1";
    let rules =
        |constrainer: &DefaultConstrainer<ParserDB>| statement_levels(constrainer, &database, sql);
    assert_eq!(
        rules(&constrainer),
        [
            ("UnorderedLimit", Level::Warn),
            ("UnlinkedFromItem", Level::Warn)
        ]
    );
    constrainer.set_rule_level("DistinctOverReferencedSide", Level::Warn);
    assert_eq!(
        rules(&constrainer),
        [
            ("UnorderedLimit", Level::Warn),
            ("UnlinkedFromItem", Level::Warn),
            ("DistinctOverReferencedSide", Level::Warn),
        ]
    );
}
