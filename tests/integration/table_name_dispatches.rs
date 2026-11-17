//! Trigger functions choosing a branch by the firing table's name.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for a trigger function running `body`.
fn findings(body: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE TABLE events (kind TEXT);
         CREATE FUNCTION record() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE kind TEXT; BEGIN {body} RETURN NEW; END $$;"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = TableNameDispatch::default().into();
    constrainer
        .diagnostics(&database)
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => {
                assert_eq!(violation.rule().group, LintGroup::Pedantic);
                violation.to_string()
            }
            other => panic!("unexpected failure {other}"),
        })
        .collect()
}

#[test]
fn comparisons_of_the_table_name_with_a_literal_are_reported_once() {
    for body in [
        "IF TG_TABLE_NAME = 'notes' THEN INSERT INTO events VALUES ('note'); END IF;",
        "IF TG_TABLE_NAME = 'notes'::name THEN INSERT INTO events VALUES ('note'); END IF;",
        "IF 'notes' <> tg_relname THEN INSERT INTO events VALUES ('other'); END IF;",
        "IF TG_TABLE_NAME IN ('notes', 'folders') THEN INSERT INTO events VALUES ('x'); END IF;",
        "CASE TG_TABLE_NAME WHEN 'notes' THEN kind := 'note'; ELSE kind := 'other'; END CASE;",
        "kind := CASE WHEN TG_TABLE_NAME = 'notes' THEN 'note' ELSE 'other' END;",
        "INSERT INTO events SELECT 'note' WHERE TG_TABLE_NAME = 'notes';",
        "WHILE TG_TABLE_NAME = 'notes' LOOP EXIT; END LOOP;",
    ] {
        let found = findings(body);
        assert_eq!(found.len(), 1, "{body}: {found:?}");
    }
}

#[test]
fn reading_the_name_without_comparing_it_is_not_reported() {
    for body in [
        "INSERT INTO events VALUES (TG_TABLE_NAME);",
        "INSERT INTO events VALUES (TG_ARGV[0]);",
        "IF TG_OP = 'INSERT' THEN INSERT INTO events VALUES ('insert'); END IF;",
        "IF TG_TABLE_NAME = TG_ARGV[0] THEN INSERT INTO events VALUES ('x'); END IF;",
    ] {
        assert!(findings(body).is_empty(), "{body}");
    }
}

#[test]
fn a_variable_shadowing_the_trigger_name_is_not_reported() {
    let database = ParserDB::parse::<PostgreSqlDialect>(
        "CREATE FUNCTION record() RETURNS trigger LANGUAGE plpgsql AS $$
         DECLARE tg_table_name TEXT := 'fixed';
         BEGIN IF tg_table_name = 'notes' THEN RETURN NULL; END IF; RETURN NEW; END $$;",
    )
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = TableNameDispatch::default().into();
    assert!(constrainer.validate_schema(&database).is_ok());
}
