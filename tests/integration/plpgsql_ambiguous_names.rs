//! PL/pgSQL column references a parameter or variable makes ambiguous.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Messages of every finding for `sql` after a table of notes.
fn findings(sql: &str) -> Vec<String> {
    let database = ParserDB::parse::<PostgreSqlDialect>(&format!(
        "CREATE TABLE notes (id INT PRIMARY KEY, new TEXT, label TEXT);
         CREATE TABLE audit (v TEXT);
         CREATE TABLE errors (sqlstate TEXT);
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
        (
            "CREATE FUNCTION cursor_label() RETURNS INT LANGUAGE plpgsql AS $$
             DECLARE label CURSOR FOR SELECT 1; result INT; BEGIN SELECT notes.id INTO result FROM notes WHERE label = 'a'; RETURN result; END $$;",
            "cursor 'label'",
        ),
        (
            "CREATE FUNCTION cursor_parameter() RETURNS INT LANGUAGE plpgsql AS $$
             DECLARE c CURSOR (label TEXT) FOR SELECT notes.id FROM notes WHERE label = 'a'; result INT;
             BEGIN OPEN c('a'); FETCH c INTO result; RETURN result; END $$;",
            "cursor parameter 'label'",
        ),
        (
            "CREATE FUNCTION loop_index() RETURNS TEXT LANGUAGE plpgsql AS $$
             DECLARE v TEXT; BEGIN FOR id IN 1..1 LOOP SELECT notes.label INTO v FROM notes WHERE id = 1; END LOOP; RETURN v; END $$;",
            "loop variable 'id'",
        ),
        (
            "CREATE FUNCTION handler() RETURNS TEXT LANGUAGE plpgsql AS $$
             DECLARE v TEXT; BEGIN PERFORM 1/0; RETURN v;
             EXCEPTION WHEN others THEN SELECT errors.sqlstate INTO v FROM errors WHERE sqlstate = 'x'; RETURN v; END $$;",
            "exception variable 'sqlstate'",
        ),
        (
            "CREATE FUNCTION table_wildcard() RETURNS BIGINT LANGUAGE plpgsql AS $$
             DECLARE notes notes; c BIGINT; BEGIN SELECT count(*) INTO c FROM (SELECT notes.* FROM notes) x; RETURN c; END $$;",
            "variable 'notes'",
        ),
        (
            "CREATE FUNCTION derived_wildcard() RETURNS BIGINT LANGUAGE plpgsql AS $$
             DECLARE d notes; c BIGINT; BEGIN SELECT count(*) INTO c FROM (SELECT d.* FROM (SELECT * FROM notes) d) x; RETURN c; END $$;",
            "variable 'd'",
        ),
        (
            "CREATE FUNCTION joined_wildcard() RETURNS BIGINT LANGUAGE plpgsql AS $$
             DECLARE r notes; c BIGINT; BEGIN SELECT count(*) INTO c FROM (SELECT r.* FROM (notes r JOIN audit a ON true)) x; RETURN c; END $$;",
            "variable 'r'",
        ),
        (
            "CREATE FUNCTION merged(id INT) RETURNS VOID LANGUAGE plpgsql AS $$
             BEGIN PERFORM 1 FROM notes a JOIN notes b USING (id) WHERE id = 1; END $$;",
            "parameter 'id'",
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
        "CREATE FUNCTION drop_note() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
         BEGIN DELETE FROM public.notes WHERE id = OLD.id; RETURN NULL; END $$;
         CREATE TRIGGER notes_dropped AFTER DELETE ON audit FOR EACH ROW EXECUTE FUNCTION drop_note();",
        "CREATE FUNCTION drop_labelled_note() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
         BEGIN DELETE FROM public.notes WHERE id = OLD.id AND label = 'ownable'; RETURN NULL; END $$;
         CREATE TRIGGER labelled_notes_dropped AFTER DELETE ON notes FOR EACH ROW EXECUTE FUNCTION drop_labelled_note();",
        "CREATE FUNCTION drop_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
         BEGIN DELETE FROM public.audit WHERE v = OLD.label AND v <> OLD.new; RETURN NULL; END $$;
         CREATE TRIGGER audit_dropped AFTER DELETE ON notes FOR EACH ROW EXECUTE FUNCTION drop_audit();",
        "CREATE FUNCTION relabel_note() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
         BEGIN UPDATE public.notes SET label = OLD.label WHERE id = OLD.id; RETURN NULL; END $$;
         CREATE TRIGGER notes_relabelled AFTER UPDATE ON notes FOR EACH ROW EXECUTE FUNCTION relabel_note();",
        "CREATE FUNCTION spread() RETURNS BIGINT LANGUAGE plpgsql AS $$
         DECLARE s INT; c BIGINT; BEGIN SELECT count(*) INTO c FROM (SELECT s.* FROM notes s) x; RETURN c; END $$;",
        "CREATE FUNCTION upsert() RETURNS TABLE(note_id INT) LANGUAGE plpgsql AS $$
         BEGIN INSERT INTO notes (id) VALUES (2) ON CONFLICT (id) DO NOTHING; RETURN; END $$;",
        "CREATE FUNCTION hidden_by_join_alias() RETURNS BIGINT LANGUAGE plpgsql AS $$
         DECLARE r notes; c BIGINT; BEGIN SELECT count(*) INTO c FROM (SELECT r.* FROM (notes r JOIN audit a ON true) j) x; RETURN c; END $$;",
        "CREATE FUNCTION schema_qualified_wildcard() RETURNS BIGINT LANGUAGE plpgsql AS $$
         DECLARE notes notes; c BIGINT; BEGIN SELECT count(*) INTO c FROM (SELECT public.notes.* FROM public.notes) x; RETURN c; END $$;",
        "CREATE FUNCTION unparsable() RETURNS INT LANGUAGE plpgsql AS $$ BEGIN RETURN id $$;",
        "CREATE FUNCTION native() RETURNS INT LANGUAGE c AS 'library', 'symbol';",
        "CREATE FUNCTION find_note(id INT) RETURNS INT LANGUAGE sql AS $$ SELECT notes.id FROM notes WHERE notes.id = $1 $$;",
        "CREATE FUNCTION held_notes() RETURNS TABLE (note_id INT, label TEXT) LANGUAGE sql AS $$ SELECT id, label FROM notes $$;
         CREATE FUNCTION probe(affected_ids INT[]) RETURNS VOID LANGUAGE plpgsql AS $$ DECLARE checked INT;
         BEGIN FOR checked IN SELECT notes.id FROM notes WHERE notes.id IN (SELECT held.note_id FROM held_notes() held WHERE held.note_id = ANY (affected_ids)) LOOP END LOOP; END $$;",
        "CREATE FUNCTION held_notes() RETURNS TABLE (note_id INT, label TEXT) LANGUAGE sql AS $$ SELECT id, label FROM notes $$;
         CREATE FUNCTION probe(affected_ids INT[]) RETURNS VOID LANGUAGE plpgsql AS $$ DECLARE checked INT;
         BEGIN FOR checked IN SELECT held.note_id FROM held_notes() held WHERE held.note_id = ANY (affected_ids) LOOP END LOOP; END $$;",
        "CREATE FUNCTION held_notes() RETURNS TABLE (note_id INT, label TEXT) LANGUAGE sql AS $$ SELECT id, label FROM notes $$;
         CREATE FUNCTION probe(affected_ids INT[]) RETURNS VOID LANGUAGE plpgsql AS $$
         BEGIN PERFORM 1 FROM held_notes() held WHERE held.note_id = affected_ids[1]; END $$;",
        "CREATE FUNCTION held_notes() RETURNS TABLE (note_id INT, label TEXT) LANGUAGE sql AS $$ SELECT id, label FROM notes $$;
         CREATE FUNCTION probe(note_id INT) RETURNS VOID LANGUAGE plpgsql AS $$
         BEGIN PERFORM 1 FROM held_notes() held(renamed_id, renamed_label) WHERE held.renamed_id = note_id; END $$;",
        "CREATE FUNCTION held_rows() RETURNS SETOF record LANGUAGE sql AS $$ SELECT id FROM notes $$;
         CREATE FUNCTION probe(affected_id INT) RETURNS VOID LANGUAGE plpgsql AS $$
         BEGIN PERFORM 1 FROM held_rows() held WHERE held.id = affected_id; END $$;",
    ] {
        assert_eq!(findings(sql), Vec::<String>::new(), "{sql}");
    }
}
