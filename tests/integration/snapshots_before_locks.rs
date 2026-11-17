//! Reads after a lock that a transaction-wide snapshot leaves stale.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for `function` over two tables.
fn findings(function: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE TABLE slots (id INT PRIMARY KEY, taken BOOLEAN NOT NULL);
         CREATE TABLE quotas (id INT PRIMARY KEY, room INT NOT NULL);
         {function}"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = SnapshotBeforeLock::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Suspicious);
                violation.to_string()
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

/// A PL/pgSQL function `reserve` running `body`.
fn plpgsql(body: &str) -> String {
    format!(
        "CREATE FUNCTION reserve(slot INT) RETURNS void LANGUAGE plpgsql VOLATILE AS $$ {body} $$;"
    )
}

const CHECK: &str = "IF (SELECT count(*) FROM slots) >= 10 THEN RAISE EXCEPTION 'full'; END IF; INSERT INTO slots VALUES (slot, true);";

#[test]
fn every_lock_kind_before_a_read_is_reported() {
    for lock in [
        "PERFORM pg_advisory_xact_lock(1);",
        "PERFORM pg_advisory_lock_shared(1);",
        "PERFORM pg_catalog.pg_try_advisory_xact_lock(1);",
        "LOCK TABLE quotas IN EXCLUSIVE MODE;",
        "PERFORM 1 FROM quotas WHERE id = 1 FOR UPDATE;",
        "PERFORM 1 FROM quotas WHERE id = 1 FOR SHARE;",
        "PERFORM 1 FROM quotas, slots WHERE quotas.id = slots.id FOR UPDATE;",
    ] {
        let found = findings(&plpgsql(&format!("BEGIN {lock} {CHECK} END")));
        assert_eq!(found.len(), 1, "{lock}: {found:?}");
        assert!(found[0].contains("reads 'slots'"), "{found:?}");
    }
}

#[test]
fn reads_before_the_lock_and_functions_without_locks_are_not_reported() {
    for body in [
        format!("BEGIN {CHECK} END"),
        format!("BEGIN {CHECK} PERFORM pg_advisory_xact_lock(1); END"),
        "BEGIN PERFORM pg_advisory_xact_lock(1); INSERT INTO slots VALUES (slot, true); END"
            .to_owned(),
    ] {
        assert!(findings(&plpgsql(&body)).is_empty(), "{body}");
    }
}

#[test]
fn a_guard_refusing_repeatable_read_before_the_lock_prevents_the_finding() {
    for guard in [
        "IF current_setting('transaction_isolation') <> 'read committed' THEN RAISE EXCEPTION 'rc'; END IF;",
        "IF current_setting('transaction_isolation') = 'repeatable read' THEN RAISE EXCEPTION 'rr'; END IF;",
        "IF current_setting('transaction_isolation') NOT IN ('read committed', 'serializable') THEN RAISE EXCEPTION 'rc'; END IF;",
        "IF NOT (current_setting('transaction_isolation') = 'read committed') THEN RAISE EXCEPTION 'rc'; END IF;",
        "ASSERT current_setting('transaction_isolation') = 'read committed';",
        "level := current_setting('transaction_isolation'); IF level IS DISTINCT FROM 'read committed' THEN RAISE EXCEPTION 'rc'; END IF;",
        "IF current_setting('transaction_isolation') = 'read committed' THEN NULL; ELSE RAISE EXCEPTION 'rc'; END IF;",
        "IF current_setting('transaction_isolation')::text <> 'read committed' THEN RAISE EXCEPTION 'rc'; END IF;",
        "IF current_setting('transaction_isolation') <> 'read committed' AND current_setting('transaction_isolation') <> 'read uncommitted' THEN RAISE EXCEPTION 'rc'; END IF;",
        "IF current_setting('transaction_isolation') = 'read committed' AND slot > 0 THEN NULL; ELSE RAISE EXCEPTION 'rc'; END IF;",
        "IF current_setting('transaction_isolation') = 'repeatable read' OR current_setting('transaction_isolation') = 'serializable' THEN RAISE EXCEPTION 'rr'; END IF;",
        "IF current_setting('transaction_isolation') = 'read committed' OR current_setting('transaction_isolation') = 'read uncommitted' THEN NULL; ELSE RAISE EXCEPTION 'rc'; END IF;",
    ] {
        let body = format!(
            "DECLARE level TEXT; BEGIN {guard} PERFORM pg_advisory_xact_lock(1); {CHECK} END"
        );
        assert!(findings(&plpgsql(&body)).is_empty(), "{guard}");
    }
}

#[test]
fn guards_that_let_repeatable_read_through_or_follow_the_lock_do_not_count() {
    for body in [
        format!(
            "BEGIN PERFORM pg_advisory_xact_lock(1); IF current_setting('transaction_isolation') <> 'read committed' THEN RAISE EXCEPTION 'rc'; END IF; {CHECK} END"
        ),
        format!(
            "BEGIN IF current_setting('transaction_isolation') = 'serializable' THEN RAISE EXCEPTION 'no'; END IF; PERFORM pg_advisory_xact_lock(1); {CHECK} END"
        ),
        format!(
            "BEGIN IF current_setting('transaction_isolation') <> 'read committed' THEN RAISE NOTICE 'rc'; END IF; PERFORM pg_advisory_xact_lock(1); {CHECK} END"
        ),
        format!(
            "BEGIN IF current_setting('search_path') <> 'public' THEN RAISE EXCEPTION 'path'; END IF; PERFORM pg_advisory_xact_lock(1); {CHECK} END"
        ),
        format!(
            "BEGIN IF current_setting('transaction_isolation') = 'serializable' OR slot > 0 THEN RAISE EXCEPTION 'no'; END IF; PERFORM pg_advisory_xact_lock(1); {CHECK} END"
        ),
    ] {
        assert_eq!(findings(&plpgsql(&body)).len(), 1, "{body}");
    }
}

#[test]
fn rereading_the_locked_rows_by_the_same_filter_is_exempt() {
    let same = plpgsql(
        "DECLARE left_room INT; BEGIN PERFORM 1 FROM quotas WHERE id = slot FOR UPDATE; SELECT room INTO left_room FROM quotas WHERE id = slot; END",
    );
    assert_eq!(findings(&same), Vec::<String>::new());
    let other = plpgsql(
        "DECLARE left_room INT; BEGIN PERFORM 1 FROM quotas WHERE id = slot FOR UPDATE; SELECT room INTO left_room FROM quotas WHERE id = slot + 1; END",
    );
    assert_eq!(findings(&other).len(), 1);
    let elsewhere = plpgsql(&format!(
        "BEGIN PERFORM 1 FROM quotas WHERE id = 1 FOR UPDATE; {CHECK} END"
    ));
    assert_eq!(findings(&elsewhere).len(), 1);
}

#[test]
fn a_lock_on_one_iteration_reaches_the_read_of_the_next() {
    let body = plpgsql(
        "DECLARE n INT; BEGIN FOR i IN 1..3 LOOP SELECT count(*) INTO n FROM slots; PERFORM pg_advisory_xact_lock(i); END LOOP; END",
    );
    assert_eq!(findings(&body).len(), 1);
}

#[test]
fn lock_on_one_branch_reaches_a_read_after_the_join() {
    let body = plpgsql(&format!(
        "BEGIN IF slot > 0 THEN PERFORM pg_advisory_xact_lock(1); END IF; {CHECK} END"
    ));
    assert_eq!(findings(&body).len(), 1);
}

#[test]
fn a_read_through_a_derived_table_is_reported() {
    let body = plpgsql(
        "DECLARE n INT; BEGIN PERFORM pg_advisory_xact_lock(1); SELECT count(*) INTO n FROM (SELECT 1 FROM slots) AS taken; END",
    );
    assert_eq!(findings(&body).len(), 1);
}

#[test]
fn a_transaction_end_drops_the_locks_and_only_a_chain_keeps_the_guard() {
    let after_lock = |end: &str| {
        plpgsql(&format!(
            "BEGIN PERFORM pg_advisory_xact_lock(1); {end} {CHECK} END"
        ))
    };
    assert_eq!(findings(&after_lock("COMMIT;")), Vec::<String>::new());
    assert_eq!(findings(&after_lock("ROLLBACK;")), Vec::<String>::new());
    assert_eq!(findings(&after_lock("")).len(), 1);
    let after_guard = |end: &str| {
        plpgsql(&format!(
            "BEGIN IF current_setting('transaction_isolation') <> 'read committed' THEN RAISE EXCEPTION 'rc'; END IF; {end} PERFORM pg_advisory_xact_lock(1); {CHECK} END"
        ))
    };
    assert_eq!(findings(&after_guard("COMMIT;")).len(), 1);
    assert_eq!(
        findings(&after_guard("COMMIT AND CHAIN;")),
        Vec::<String>::new()
    );
}

#[test]
fn sql_bodies_are_followed() {
    let body = "CREATE FUNCTION reserve(slot INT) RETURNS void LANGUAGE sql VOLATILE AS $$
        SELECT pg_advisory_xact_lock(1);
        INSERT INTO slots SELECT slot, true WHERE (SELECT count(*) FROM slots) < 10;
    $$;";
    assert_eq!(findings(body).len(), 1);
}

#[test]
fn non_volatile_functions_are_reported_despite_a_guard() {
    for volatility in ["STABLE", "IMMUTABLE"] {
        let body = format!(
            "CREATE FUNCTION room() RETURNS BIGINT LANGUAGE plpgsql {volatility} AS $$ BEGIN
               IF current_setting('transaction_isolation') <> 'read committed' THEN RAISE EXCEPTION 'rc'; END IF;
               PERFORM pg_advisory_xact_lock_shared(1);
               RETURN (SELECT count(*) FROM slots);
             END $$;"
        );
        let found = findings(&body);
        assert_eq!(found.len(), 1, "{volatility}");
        assert!(found[0].contains("VOLATILE"), "{found:?}");
    }
}
