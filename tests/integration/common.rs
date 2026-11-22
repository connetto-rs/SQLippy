//! Schema and constrainer helpers shared by the deployment-aware test suites.

use sqlippy::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

pub fn parse(sql: &str) -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(sql).expect("schema parses")
}

pub fn supabase() -> Deployment {
    Deployment::default()
        .with_anonymous_role("anon")
        .with_app_role("authenticated")
}

pub const ROLES: &str = "
    CREATE ROLE anon;
    CREATE ROLE authenticated;
    CREATE ROLE reporting;";

/// Rule name, level and object of every violation, failing on anything else.
pub fn findings(
    constrainer: impl Into<GenericConstrainer<ParserDB>>,
    deployment: Deployment,
    sql: &str,
) -> Vec<(String, Level, String)> {
    let mut constrainer = constrainer.into();
    constrainer.set_deployment(deployment);
    constrainer
        .diagnostics(&parse(&format!("{ROLES}{sql}")))
        .into_iter()
        .map(|error| match error {
            Error::Violation(violation) => (
                violation.rule().name.to_owned(),
                violation.level(),
                violation.object().to_owned(),
            ),
            other => panic!("unexpected failure: {other}"),
        })
        .collect()
}

pub fn finding(rule: &str, level: Level, object: &str) -> (String, Level, String) {
    (rule.to_owned(), level, object.to_owned())
}

pub const GUARDED_SUBTYPE: &str = "
    CREATE TYPE grantee_kind AS ENUM ('user', 'team', 'everyone');
    CREATE TABLE grantees (id UUID PRIMARY KEY, kind grantee_kind NOT NULL, UNIQUE (id, kind));
    CREATE TABLE users (
      id UUID PRIMARY KEY,
      kind grantee_kind NOT NULL DEFAULT 'user' CHECK (kind = 'user'),
      FOREIGN KEY (id, kind) REFERENCES grantees (id, kind)
    );
    CREATE TABLE teams (
      id UUID PRIMARY KEY,
      kind grantee_kind NOT NULL DEFAULT 'team' CHECK (kind = 'team'),
      FOREIGN KEY (id, kind) REFERENCES grantees (id, kind)
    );
    CREATE FUNCTION insert_grantee() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
    BEGIN
      INSERT INTO grantees (id, kind) VALUES (NEW.id, NEW.kind) ON CONFLICT (id, kind) DO NOTHING;
      RETURN NEW;
    END $$;
    CREATE TRIGGER users_grantee BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION insert_grantee();
    CREATE FUNCTION check_grantee_subtype() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
    BEGIN
      IF EXISTS (SELECT 1 FROM grantees grantee WHERE grantee.id = NEW.id AND grantee.kind = NEW.kind)
        AND NOT (CASE NEW.kind
          WHEN 'user' THEN EXISTS (SELECT 1 FROM users principal WHERE principal.id = NEW.id)
          WHEN 'team' THEN EXISTS (SELECT 1 FROM teams team WHERE team.id = NEW.id)
        END) THEN
        RAISE EXCEPTION 'grantee % requires its % row', NEW.id, NEW.kind;
      END IF;
      RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER grantees_subtype_required AFTER INSERT OR UPDATE ON grantees
      DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.kind IN ('user', 'team'))
      EXECUTE FUNCTION check_grantee_subtype();";

/// `schema` with each `(from, to)` replacing the one occurrence of `from`.
pub fn edited(schema: &str, edits: &[(&str, &str)]) -> String {
    edits.iter().fold(schema.to_owned(), |schema, (from, to)| {
        assert_eq!(schema.matches(from).count(), 1, "{from}");
        schema.replacen(from, to, 1)
    })
}
