//! Submodule providing the rules on catalogue objects: rewrite rules, table
//! inheritance, long and reserved identifiers, unvalidated constraints,
//! schema creation by `PUBLIC`, unlogged tables and wildcard views.

use sql_traits::{
    errors::LookupError,
    traits::{
        CheckConstraintLike, ColumnLike, DatabaseLike, DomainLike, ForeignKeyLike, FunctionLike,
        GrantLike, IndexLike, PolicyLike, Relation, RoleLike, RuleLike, TableLike, ViewLike,
        grant::GrantTarget,
    },
};
use sqlparser::ast::Action;

use crate::{
    error::{Interruption, PolicyClause, PolicySite},
    lint::{LintGroup, Rule, RuleExample, RuleMetadata},
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
};

const WIKI: Option<&str> = Some("https://wiki.postgresql.org/wiki/Don%27t_Do_This");

schema_rule!(
    /// Struct defining a rule that reports a `CREATE RULE`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = QueryRewriteRule::default().into();
    /// let schema = "CREATE TABLE t (id INT); CREATE TABLE log (id INT);";
    /// let rewritten = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} CREATE RULE r AS ON INSERT TO t DO ALSO INSERT INTO log VALUES (NEW.id);"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&rewritten).is_err());
    /// assert!(constrainer.validate_schema(&ParserDB::parse::<PostgreSqlDialect>(schema).unwrap()).is_ok());
    /// ```
    QueryRewriteRule,
    LintGroup::Suspicious,
    "A rule rewrites the query before it runs, so it re-evaluates expressions such as defaults and sequences and does not do what it looks like it does.",
    WIKI,
    RuleExample {
        bad: "CREATE TABLE entries (id INT);\n\
CREATE TABLE audit (id INT);\n\
CREATE RULE log_insert AS ON INSERT TO entries DO ALSO INSERT INTO audit VALUES (NEW.id);",
        good: "CREATE TABLE entries (id INT);\n\
CREATE TABLE audit (id INT);\n\
CREATE FUNCTION record_insert() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN INSERT INTO audit VALUES (NEW.id); RETURN NEW; END $$;\n\
CREATE TRIGGER log_insert AFTER INSERT ON entries FOR EACH ROW EXECUTE FUNCTION record_insert();",
    }
);

impl<DB: DatabaseLike> SchemaRule for QueryRewriteRule<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for rule in database.rules() {
            let name = rule.name();
            let message = |relation: &str| {
                format!(
                    "Rule '{name}' on '{relation}' rewrites queries, which re-evaluates their expressions."
                )
            };
            let resolution = format!("Replace rule '{name}' with a trigger.");
            let relation = rule.relation(database)?;
            let view = match relation {
                Relation::View(view) => Some(view),
                _ => None,
            };
            let table = match relation {
                Relation::Table(table) => Some(table),
                _ => None,
            };
            if let Some(view) = view {
                reporter.view(view, message(view.view_name()), resolution.clone())?;
            }
            if let Some(table) = table {
                reporter.table(table, message(table.table_name()), resolution)?;
            }
        }
        Ok(())
    }
}

schema_rule!(
    /// Struct defining a rule that reports a table created with `INHERITS`.
    /// A partition is not reported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = TableInheritance::default().into();
    /// let schema = "CREATE TABLE parent (id INT PRIMARY KEY);";
    /// let child =
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} CREATE TABLE child () INHERITS (parent);"))
    ///         .unwrap();
    /// assert!(constrainer.validate_schema(&child).is_err());
    /// assert!(constrainer.validate_schema(&ParserDB::parse::<PostgreSqlDialect>(schema).unwrap()).is_ok());
    /// ```
    TableInheritance,
    LintGroup::Suspicious,
    "Indexes, unique constraints and foreign keys apply to single tables, not to their inheritance children, so a key unique in the parent repeats across children and a foreign key to the parent misses the children's rows.",
    Some("https://www.postgresql.org/docs/current/ddl-inherit.html"),
    RuleExample {
        bad: "CREATE TABLE parent (id INT PRIMARY KEY);\n\
CREATE TABLE child () INHERITS (parent);",
        good: "CREATE TABLE parent (id INT PRIMARY KEY);\n\
CREATE TABLE child (id INT PRIMARY KEY);",
    }
);

impl<DB: DatabaseLike> SchemaRule for TableInheritance<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for table in database.tables() {
            let parents: Vec<String> = table
                .inherits_from(database)?
                .map(|parent| format!("'{}'", parent.table_name()))
                .collect();
            if parents.is_empty() {
                continue;
            }
            let name = table.table_name();
            reporter.table(
                table,
                format!(
                    "Table '{name}' inherits from {}, whose keys and foreign keys do not cover '{name}'.",
                    parents.join(", ")
                ),
                "Use declarative partitioning, or separate tables with their own keys.".to_owned(),
            )?;
        }
        Ok(())
    }
}

/// An object whose name the identifier rules read, with the name.
enum Named<'db, DB: DatabaseLike> {
    Table(&'db DB::Table),
    Index(&'db DB::Table, &'db str),
    Column(&'db DB::Column),
    View(&'db DB::View),
    MaterializedView(&'db DB::MaterializedView),
    Role(&'db DB::Role),
    Domain(&'db DB::Domain),
    Function(&'db DB::Function),
    ForeignKey(&'db DB::ForeignKey, &'db str),
    Policy(&'db DB::Table, &'db DB::Policy),
}

impl<'db, DB: DatabaseLike> Named<'db, DB> {
    fn name(&self) -> &'db str {
        match *self {
            Self::Table(table) => table.table_name(),
            Self::Index(_, name) | Self::ForeignKey(_, name) => name,
            Self::Column(column) => column.column_name(),
            Self::View(view) => view.view_name(),
            Self::MaterializedView(view) => view.view_name(),
            Self::Role(role) => role.name(),
            Self::Domain(domain) => domain.name(),
            Self::Function(function) => function.name(),
            Self::Policy(_, policy) => policy.name(),
        }
    }

    /// Whether the object is a relation, a column or a role, whose names a
    /// reserved keyword cannot be.
    fn is_relation_column_or_role(&self) -> bool {
        matches!(
            self,
            Self::Table(_)
                | Self::Column(_)
                | Self::View(_)
                | Self::MaterializedView(_)
                | Self::Role(_)
        )
    }

    fn report(
        &self,
        reporter: &mut Reporter<'_, DB>,
        message: String,
        resolution: String,
    ) -> Result<(), Interruption> {
        match self {
            Self::Table(table) | Self::Index(table, _) => {
                reporter.table(table, message, resolution)
            }
            Self::Column(column) => reporter.column(column, message, resolution),
            Self::View(view) => reporter.view(view, message, resolution),
            Self::MaterializedView(view) => reporter.materialized_view(view, message, resolution),
            Self::Role(role) => reporter.role(role, message, resolution),
            Self::Domain(domain) => reporter.domain(domain, message, resolution),
            Self::Function(function) => reporter.function(function, message, resolution),
            Self::ForeignKey(foreign_key, _) => {
                reporter.foreign_key(foreign_key, message, resolution)
            }
            Self::Policy(table, policy) => reporter.policies(
                vec![PolicySite {
                    table: Box::new((*table).clone()),
                    policy: Box::new((*policy).clone()),
                    clause: PolicyClause::To,
                    expression: policy.name().to_owned(),
                }],
                message,
                resolution,
            ),
        }
    }
}

/// Every named object the identifier rules read.
fn named<DB: DatabaseLike>(database: &DB) -> Result<Vec<Named<'_, DB>>, LookupError> {
    let mut found = Vec::new();
    for table in database.tables_and_foreign_tables() {
        found.push(Named::Table(table));
        found.extend(table.columns(database)?.map(Named::Column));
        for index in table.indices(database)? {
            found.extend(index.name().map(|name| Named::Index(table, name)));
        }
        for index in table.unique_indices(database)? {
            found.extend(index.name().map(|name| Named::Index(table, name)));
        }
        for foreign_key in table.foreign_keys(database)? {
            found.extend(
                foreign_key
                    .foreign_key_name()
                    .map(|name| Named::ForeignKey(foreign_key, name)),
            );
        }
        found.extend(
            table
                .policies(database)?
                .map(|policy| Named::Policy(table, policy)),
        );
    }
    found.extend(database.views().map(Named::View));
    found.extend(database.materialized_views().map(Named::MaterializedView));
    found.extend(database.roles().map(Named::Role));
    found.extend(database.domains().map(Named::Domain));
    found.extend(
        database
            .functions()
            .filter(|function| function.target_name().schema() != Some("pg_catalog"))
            .map(Named::Function),
    );
    Ok(found)
}

/// Bytes PostgreSQL keeps of an identifier.
const NAMEDATALEN: usize = 63;

schema_rule!(
    /// Struct defining a rule that reports an identifier longer than 63
    /// bytes, which PostgreSQL truncates.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = TruncatedIdentifier::default().into();
    /// let long = ParserDB::parse::<PostgreSqlDialect>(&format!("CREATE TABLE {} (id INT);", "t".repeat(64)))
    ///     .unwrap();
    /// assert!(constrainer.validate_schema(&long).is_err());
    /// let short = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT);").unwrap();
    /// assert!(constrainer.validate_schema(&short).is_ok());
    /// ```
    TruncatedIdentifier,
    LintGroup::Suspicious,
    "PostgreSQL keeps only the first 63 bytes of an identifier, so two long names can collide and code naming the long form finds nothing.",
    Some("https://www.postgresql.org/docs/current/sql-syntax-lexical.html"),
    RuleExample {
        bad: "CREATE TABLE reports (this_column_name_is_longer_than_the_sixty_three_byte_limit_for_sql INT);",
        good: "CREATE TABLE reports (report_id INT);",
    }
);

impl<DB: DatabaseLike> SchemaRule for TruncatedIdentifier<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for object in named(database)? {
            let name = object.name();
            if name.len() <= NAMEDATALEN {
                continue;
            }
            object.report(
                reporter,
                format!(
                    "Identifier '{name}' is {} bytes long, and PostgreSQL keeps only its first {NAMEDATALEN}.",
                    name.len()
                ),
                format!("Shorten '{name}' to {NAMEDATALEN} bytes or fewer."),
            )?;
        }
        Ok(())
    }
}

/// Keywords PostgreSQL reserves, including the ones only a function or type
/// may use, from `pg_get_keywords()` on PostgreSQL 17 and 18.
const RESERVED: [&str; 101] = [
    "all",
    "analyse",
    "analyze",
    "and",
    "any",
    "array",
    "as",
    "asc",
    "asymmetric",
    "authorization",
    "binary",
    "both",
    "case",
    "cast",
    "check",
    "collate",
    "collation",
    "column",
    "concurrently",
    "constraint",
    "create",
    "cross",
    "current_catalog",
    "current_date",
    "current_role",
    "current_schema",
    "current_time",
    "current_timestamp",
    "current_user",
    "default",
    "deferrable",
    "desc",
    "distinct",
    "do",
    "else",
    "end",
    "except",
    "false",
    "fetch",
    "for",
    "foreign",
    "freeze",
    "from",
    "full",
    "grant",
    "group",
    "having",
    "ilike",
    "in",
    "initially",
    "inner",
    "intersect",
    "into",
    "is",
    "isnull",
    "join",
    "lateral",
    "leading",
    "left",
    "like",
    "limit",
    "localtime",
    "localtimestamp",
    "natural",
    "not",
    "notnull",
    "null",
    "offset",
    "on",
    "only",
    "or",
    "order",
    "outer",
    "overlaps",
    "placing",
    "primary",
    "references",
    "returning",
    "right",
    "select",
    "session_user",
    "similar",
    "some",
    "symmetric",
    "system_user",
    "table",
    "tablesample",
    "then",
    "to",
    "trailing",
    "true",
    "union",
    "unique",
    "user",
    "using",
    "variadic",
    "verbose",
    "when",
    "where",
    "window",
    "with",
];

schema_rule!(
    /// Struct defining a rule that reports a relation, column or role named
    /// by a reserved keyword, which must then be quoted everywhere.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = ReservedKeywordIdentifier::default().into();
    /// let reserved = ParserDB::parse::<PostgreSqlDialect>(r#"CREATE TABLE "order" (id INT);"#).unwrap();
    /// assert!(constrainer.validate_schema(&reserved).is_err());
    /// let plain = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE orders (id INT);").unwrap();
    /// assert!(constrainer.validate_schema(&plain).is_ok());
    /// ```
    ReservedKeywordIdentifier,
    LintGroup::Style,
    "A name that is a reserved keyword is a syntax error unquoted, so every statement naming it must quote it.",
    Some("https://www.postgresql.org/docs/current/sql-keywords-appendix.html"),
    RuleExample {
        bad: "CREATE TABLE orders (\"order\" INT);",
        good: "CREATE TABLE orders (order_id INT);",
    }
);

impl<DB: DatabaseLike> SchemaRule for ReservedKeywordIdentifier<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for object in named(database)? {
            let name = object.name();
            if !object.is_relation_column_or_role()
                || !RESERVED
                    .iter()
                    .any(|keyword| name.eq_ignore_ascii_case(keyword))
            {
                continue;
            }
            object.report(
                reporter,
                format!("Identifier '{name}' is a reserved keyword, so it must be quoted wherever it is named."),
                format!("Rename '{name}' to a word PostgreSQL does not reserve."),
            )?;
        }
        Ok(())
    }
}

schema_rule!(
    /// Struct defining a rule that reports a check or foreign key added
    /// `NOT VALID` and never validated.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnvalidatedConstraint::default().into();
    /// let schema = "CREATE TABLE t (x INT); ALTER TABLE t ADD CONSTRAINT positive CHECK (x > 0) NOT VALID;";
    /// let pending = ParserDB::parse::<PostgreSqlDialect>(schema).unwrap();
    /// assert!(constrainer.validate_schema(&pending).is_err());
    /// let validated = ParserDB::parse::<PostgreSqlDialect>(&format!(
    ///     "{schema} ALTER TABLE t VALIDATE CONSTRAINT positive;"
    /// ))
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&validated).is_ok());
    /// ```
    UnvalidatedConstraint,
    LintGroup::Suspicious,
    "A constraint added NOT VALID checks only rows written afterwards, so rows that existed before it are never checked until it is validated.",
    Some("https://www.postgresql.org/docs/current/sql-altertable.html"),
    RuleExample {
        bad: "CREATE TABLE counts (amount INT);\n\
ALTER TABLE counts ADD CONSTRAINT positive CHECK (amount > 0) NOT VALID;",
        good: "CREATE TABLE counts (amount INT);\n\
ALTER TABLE counts ADD CONSTRAINT positive CHECK (amount > 0) NOT VALID;\n\
ALTER TABLE counts VALIDATE CONSTRAINT positive;",
    }
);

impl<DB: DatabaseLike> SchemaRule for UnvalidatedConstraint<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let resolution = "Run ALTER TABLE ... VALIDATE CONSTRAINT once the existing rows comply.";
        for table in database.tables() {
            let name = table.table_name();
            for check in table.check_constraints(database)? {
                if check.is_validated(database)? {
                    continue;
                }
                reporter.table(
                    table,
                    format!(
                        "Check `{}` on '{name}' was added NOT VALID and never validated, so rows written before it are unchecked.",
                        check.expression(database)
                    ),
                    resolution.to_owned(),
                )?;
            }
            for foreign_key in table.foreign_keys(database)? {
                if foreign_key.is_validated(database)? {
                    continue;
                }
                reporter.foreign_key(
                    foreign_key,
                    format!("A foreign key of '{name}' was added NOT VALID and never validated, so rows written before it may reference nothing."),
                    resolution.to_owned(),
                )?;
            }
        }
        Ok(())
    }
}

schema_rule!(
    /// Struct defining a rule that reports `CREATE` on a schema granted to
    /// `PUBLIC`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = PublicSchemaCreate::default().into();
    /// let open = ParserDB::parse::<PostgreSqlDialect>("GRANT CREATE ON SCHEMA public TO PUBLIC;").unwrap();
    /// assert!(constrainer.validate_schema(&open).is_err());
    /// let usage = ParserDB::parse::<PostgreSqlDialect>("GRANT USAGE ON SCHEMA public TO PUBLIC;").unwrap();
    /// assert!(constrainer.validate_schema(&usage).is_ok());
    /// ```
    PublicSchemaCreate,
    LintGroup::Suspicious,
    "Any role holding CREATE on a schema can create objects in it that shadow others through search_path.",
    Some("https://www.postgresql.org/docs/current/ddl-schemas.html"),
    RuleExample {
        bad: "GRANT CREATE ON SCHEMA public TO PUBLIC;",
        good: "GRANT USAGE ON SCHEMA public TO PUBLIC;",
    }
);

impl<DB: DatabaseLike> SchemaRule for PublicSchemaCreate<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for grant in database.table_grants() {
            let GrantTarget::Schemas(schemas) = grant.target() else {
                continue;
            };
            let schemas: Vec<String> = schemas
                .map(|schema| format!("'{}'", schema.name()))
                .collect();
            let creates = grant.is_all_privileges()
                || grant
                    .privileges(database)
                    .any(|action| matches!(action, Action::Create { .. }));
            if !grant.applies_to_public() || !creates {
                continue;
            }
            let schemas = schemas.join(", ");
            reporter.grant(
                grant,
                format!("schema {}", schemas.replace('\'', "")),
                format!("Every role may create objects in {schemas}, which can shadow others through search_path."),
                format!("REVOKE CREATE ON SCHEMA {} FROM PUBLIC; and grant it to the roles that create objects there.", schemas.replace('\'', "")),
            )?;
        }
        Ok(())
    }
}

schema_rule!(
    /// Struct defining a rule that reports an `UNLOGGED` table.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = UnloggedTable::default().into();
    /// let unlogged = ParserDB::parse::<PostgreSqlDialect>("CREATE UNLOGGED TABLE t (id INT);").unwrap();
    /// assert!(constrainer.validate_schema(&unlogged).is_err());
    /// let logged = ParserDB::parse::<PostgreSqlDialect>("CREATE TABLE t (id INT);").unwrap();
    /// assert!(constrainer.validate_schema(&logged).is_ok());
    /// ```
    UnloggedTable,
    LintGroup::Pedantic,
    "An unlogged table is truncated after a crash or unclean shutdown, is not replicated to standbys, and is left out of logical replication.",
    Some("https://www.postgresql.org/docs/current/sql-createtable.html"),
    RuleExample {
        bad: "CREATE UNLOGGED TABLE entries (id INT);",
        good: "CREATE TABLE entries (id INT);",
    }
);

impl<DB: DatabaseLike> SchemaRule for UnloggedTable<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        for table in database.tables().filter(TableLike::is_unlogged) {
            let name = table.table_name();
            reporter.table(
                table,
                format!("Table '{name}' is UNLOGGED, so a crash empties it and neither standbys nor logical replication receive its rows."),
                format!("ALTER TABLE {name} SET LOGGED; unless losing its rows is acceptable."),
            )?;
        }
        Ok(())
    }
}

schema_rule!(
    /// Struct defining a rule that reports a view or materialized view
    /// written with `SELECT *`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = WildcardView::default().into();
    /// let schema = "CREATE TABLE t (a INT, b INT);";
    /// let star =
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} CREATE VIEW v AS SELECT * FROM t;")).unwrap();
    /// assert!(constrainer.validate_schema(&star).is_err());
    /// let listed =
    ///     ParserDB::parse::<PostgreSqlDialect>(&format!("{schema} CREATE VIEW v AS SELECT a, b FROM t;")).unwrap();
    /// assert!(constrainer.validate_schema(&listed).is_ok());
    /// ```
    WildcardView,
    LintGroup::Pedantic,
    "PostgreSQL expands the star when the view is created, so columns added to the table later never appear in the view.",
    Some("https://www.postgresql.org/docs/current/sql-createview.html"),
    RuleExample {
        bad: "CREATE TABLE entries (id INT, body TEXT);\n\
CREATE VIEW visible AS SELECT * FROM entries;",
        good: "CREATE TABLE entries (id INT, body TEXT);\n\
CREATE VIEW visible AS SELECT id, body FROM entries;",
    }
);

impl<DB: DatabaseLike> SchemaRule for WildcardView<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let message = |name: &str| {
            format!(
                "View '{name}' selects *, which PostgreSQL expands once, so columns added later never appear in it."
            )
        };
        let resolution = |name: &str| format!("List the columns '{name}' returns.");
        for view in database.views().filter(|view| view.selects_wildcard()) {
            let name = view.view_name();
            reporter.view(view, message(name), resolution(name))?;
        }
        for view in database
            .materialized_views()
            .filter(|view| view.selects_wildcard())
        {
            let name = view.view_name();
            reporter.materialized_view(view, message(name), resolution(name))?;
        }
        Ok(())
    }
}
