//! Curated schemas shown as pills, each showing one family of rules, so a
//! visitor can see SQLippy's findings in one click.

/// Which Font Awesome glyph a pill shows. The concrete `Icon` is resolved in
/// `main.rs`, which owns the `dioxus-free-icons` dependency.
#[derive(Clone, Copy)]
pub enum ExampleIcon {
    /// Naming conventions.
    Naming,
    /// Column types.
    Types,
    /// Keys and constraints.
    Keys,
    /// Row-level security.
    Security,
    /// Functions.
    Functions,
    /// Application queries.
    Queries,
    /// A schema with nothing to report.
    Clean,
}

/// A named example schema.
pub struct Example {
    /// Pill label.
    pub label: &'static str,
    /// Tooltip describing what the example shows.
    pub description: &'static str,
    /// Pill glyph.
    pub icon: ExampleIcon,
    /// The SQL loaded into the editor.
    pub sql: &'static str,
}

const NAMING: &str = r#"-- Mixed-case quoted names must be quoted forever,
-- and plural or misnamed keys hide what a column holds.
CREATE TABLE "UserAccounts" (
    "ID" INT PRIMARY KEY,
    "EmailAddress" TEXT NOT NULL
);

CREATE TABLE orders (
    id INT PRIMARY KEY,
    buyer INT NOT NULL REFERENCES "UserAccounts" ("ID"),
    items TEXT NOT NULL
);
"#;

const TYPES: &str = r"-- Each column stores something other than what it means.
CREATE TABLE invoices (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    total_price DOUBLE PRECISION NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    due_time TIMETZ,
    reference CHAR(12) NOT NULL,
    customer_uuid TEXT NOT NULL,
    is_paid INTEGER NOT NULL,
    line_count NUMERIC(10, 2) NOT NULL,
    metadata JSON
);
";

const KEYS: &str = r"-- Checks that test nothing or reject every row, a table without
-- a primary key, and a foreign key no index serves.
CREATE TABLE products (
    id INT PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    price NUMERIC(10, 2) NOT NULL CHECK (1 = 1),
    discontinued_on DATE CHECK (false)
);

CREATE TABLE reviews (
    product_id INT NOT NULL REFERENCES products (id),
    rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5)
);
";

const SECURITY: &str = r"-- Row-level security for an API that connects as anon or authenticated
-- and names the caller with current_setting('app.user_id', true).
CREATE ROLE anon;
CREATE ROLE authenticated;

CREATE TABLE documents (
    id UUID PRIMARY KEY,
    owner_id VARCHAR(64) NOT NULL,
    body VARCHAR(10000) NOT NULL
);

-- The policy is written, but row-level security is never enabled.
CREATE POLICY documents_owner ON documents
    FOR SELECT TO authenticated
    USING (owner_id = current_setting('app.user_id', true));

CREATE TABLE notes (
    id UUID PRIMARY KEY,
    author_id VARCHAR(64) NOT NULL,
    body VARCHAR(10000) NOT NULL
);

ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

-- Authors edit their notes, but WITH CHECK (true) lets them
-- hand a note to anyone else.
CREATE POLICY notes_update ON notes
    FOR UPDATE TO authenticated
    USING (author_id = current_setting('app.user_id', true))
    WITH CHECK (true);

GRANT SELECT, TRUNCATE ON notes TO anon;
";

const FUNCTIONS: &str = r"-- A SECURITY DEFINER function runs with its owner's rights, so its
-- search_path decides which objects a caller can swap in.
CREATE ROLE authenticated;

CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    balance NUMERIC(12, 2) NOT NULL
);

ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;

CREATE POLICY accounts_owner ON accounts
    FOR SELECT TO authenticated
    USING (id::text = current_setting('app.user_id', true));

CREATE FUNCTION credit(account UUID, amount NUMERIC(12, 2)) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    AS $$ UPDATE accounts SET balance = balance + amount WHERE id = account $$;
";

const QUERIES: &str = r"-- Application statements are checked against the schema above them.
CREATE TABLE teams (
    id INT PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

CREATE TABLE members (
    id INT PRIMARY KEY,
    team_id INT REFERENCES teams (id),
    name VARCHAR(100) NOT NULL
);

CREATE INDEX members_team_id ON members (team_id);

CREATE TABLE banned_teams (
    team_id INT NOT NULL REFERENCES teams (id),
    banned_on DATE NOT NULL,
    PRIMARY KEY (team_id, banned_on)
);

-- NOT IN returns no row once the subquery yields a NULL team_id.
SELECT name FROM teams WHERE id NOT IN (SELECT team_id FROM members);

-- banned_teams has no id, so the inner id is teams.id and every team goes.
DELETE FROM teams WHERE id IN (SELECT id FROM banned_teams);
";

const CLEAN: &str = r"-- Nothing to report, even with the pedantic rules on.
CREATE TABLE authors (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(200) NOT NULL CHECK (name <> '')
);

CREATE TABLE books (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    author_id BIGINT NOT NULL REFERENCES authors (id),
    title VARCHAR(300) NOT NULL CHECK (title <> ''),
    published_on DATE NOT NULL
);

CREATE INDEX books_author_id ON books (author_id);
";

/// All examples, in pill order.
pub const EXAMPLES: &[Example] = &[
    Example {
        label: "Naming",
        description: "Quoted mixed-case names and misnamed keys",
        icon: ExampleIcon::Naming,
        sql: NAMING,
    },
    Example {
        label: "Column types",
        description: "Money in floating point, times without zones, flags and uuids as numbers or text",
        icon: ExampleIcon::Types,
        sql: TYPES,
    },
    Example {
        label: "Keys & checks",
        description: "Checks that test nothing or reject every row, a table without a primary key, an unindexed foreign key",
        icon: ExampleIcon::Keys,
        sql: KEYS,
    },
    Example {
        label: "Row-level security",
        description: "A policy on a table without row-level security, an always-true WITH CHECK, TRUNCATE for anonymous callers",
        icon: ExampleIcon::Security,
        sql: SECURITY,
    },
    Example {
        label: "Definer functions",
        description: "A SECURITY DEFINER function without a pinned search_path",
        icon: ExampleIcon::Functions,
        sql: FUNCTIONS,
    },
    Example {
        label: "Queries",
        description: "Application statements checked against the schema",
        icon: ExampleIcon::Queries,
        sql: QUERIES,
    },
    Example {
        label: "Clean",
        description: "A schema with nothing to report",
        icon: ExampleIcon::Clean,
        sql: CLEAN,
    },
];
