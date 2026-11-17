//! PL/pgSQL column references a parameter or variable makes ambiguous.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for `sql` after a table of notes.
fn findings(sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE TABLE notes (id INT PRIMARY KEY, new TEXT, label TEXT);
         CREATE TABLE audit (v TEXT);
         {sql}"
    ))
    .expect("schema parses");
    let constrainer: GenericConstrainer<ParserDB> = PlpgsqlAmbiguousName::default().into();
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

#[test]
fn every_collision_postgres_refuses_is_reported() {
    for (sql, kind) in [
        (
            "CREATE FUNCTION find_note(id INT) RETURNS INT LANGUAGE plpgsql AS $$
             DECLARE result INT; BEGIN SELECT id INTO result FROM notes WHERE notes.id = find_note.id; RETURN result; END $$;",
            "parameter 'id'",
        ),
        (
            "CREATE FUNCTION find_note() RETURNS INT LANGUAGE plpgsql AS $$
             DECLARE label TEXT := 'a'; result INT; BEGIN SELECT notes.id INTO result FROM notes WHERE label = 'a'; RETURN result; END $$;",
            "variable 'label'",
        ),
        (
            "CREATE FUNCTION upsert() RETURNS TABLE(id INT) LANGUAGE plpgsql AS $$
             BEGIN INSERT INTO notes (id) VALUES (2) ON CONFLICT (id) DO NOTHING; RETURN; END $$;",
            "output parameter 'id'",
        ),
        (
            "CREATE FUNCTION spread() RETURNS BIGINT LANGUAGE plpgsql AS $$
             DECLARE r notes; c BIGINT; BEGIN SELECT count(*) INTO c FROM (SELECT r.* FROM notes r) x; RETURN c; END $$;",
            "variable 'r'",
        ),
        (
            "CREATE FUNCTION first_id() RETURNS INT LANGUAGE plpgsql AS $$
             DECLARE notes notes; result INT; BEGIN SELECT notes.id INTO result FROM notes LIMIT 1; RETURN result; END $$;",
            "variable 'notes'",
        ),
        (
            "CREATE FUNCTION copy_new() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN INSERT INTO audit SELECT new FROM notes LIMIT 1; RETURN NEW; END $$;",
            "trigger variable 'new'",
        ),
    ] {
        let found = findings(sql);
        assert_eq!(found.len(), 1, "{sql}: {found:?}");
        assert!(found[0].contains(kind), "{kind}: {found:?}");
    }
}

#[test]
fn qualified_references_and_unshared_names_are_not_reported() {
    for sql in [
        "CREATE FUNCTION find_note(requested_id INT) RETURNS INT LANGUAGE plpgsql AS $$
         DECLARE result INT; BEGIN SELECT notes.id INTO result FROM notes WHERE notes.id = requested_id; RETURN result; END $$;",
        "CREATE FUNCTION find_note(id INT) RETURNS INT LANGUAGE plpgsql AS $$
         DECLARE result INT; BEGIN SELECT n.id INTO result FROM notes n WHERE n.id = find_note.id; RETURN result; END $$;",
        "CREATE FUNCTION plain_new() RETURNS TEXT LANGUAGE plpgsql AS $$
         DECLARE v TEXT; BEGIN SELECT new INTO v FROM notes LIMIT 1; RETURN v; END $$;",
        "CREATE FUNCTION copy_new() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN INSERT INTO audit VALUES (NEW.label); RETURN NEW; END $$;",
        "CREATE FUNCTION spread() RETURNS BIGINT LANGUAGE plpgsql AS $$
         DECLARE s INT; c BIGINT; BEGIN SELECT count(*) INTO c FROM (SELECT s.* FROM notes s) x; RETURN c; END $$;",
        "CREATE FUNCTION upsert() RETURNS TABLE(note_id INT) LANGUAGE plpgsql AS $$
         BEGIN INSERT INTO notes (id) VALUES (2) ON CONFLICT (id) DO NOTHING; RETURN; END $$;",
        "CREATE FUNCTION find_note(id INT) RETURNS INT LANGUAGE sql AS $$ SELECT notes.id FROM notes WHERE notes.id = $1 $$;",
    ] {
        assert_eq!(findings(sql), Vec::<String>::new(), "{sql}");
    }
}
