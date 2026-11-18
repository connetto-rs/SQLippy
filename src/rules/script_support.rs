//! What the earlier statements of a script establish for a later one: the
//! schemas it created and whether the session's `search_path` is trusted.

use std::{
    fmt::{self, Display, Formatter},
    ops::ControlFlow,
};

use sqlparser::ast::{
    ArgMode, ContextModifier, CreateAggregateArgs, CreateFunction, CreateFunctionBody,
    CreateProcedureBody, DataType, DiscardObject, Expr, FunctionArg, FunctionArgExpr,
    FunctionArguments, FunctionDefinitionSetParam, FunctionSetValue, Ident, ObjectName,
    ObjectNamePart, OperateFunctionArg, Reset, SchemaName, Set, Statement, Value, Visitor,
};

use super::{expression_site_support::parse_body, walk_support::walk};

/// A name as PostgreSQL stores it: folded to lower case unless quoted.
pub(crate) fn fold(ident: &Ident) -> String {
    if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_lowercase()
    }
}

/// The folded parts of `name`, or `None` when a part is not an identifier.
fn folded_parts(name: &ObjectName) -> Option<Vec<String>> {
    name.0
        .iter()
        .map(|part| part.as_ident().map(fold))
        .collect()
}

/// The text of a quoted or dollar-quoted string literal.
fn string_literal(expression: &Expr) -> Option<&str> {
    let Expr::Value(literal) = expression else {
        return None;
    };
    match &literal.value {
        Value::SingleQuotedString(text) | Value::EscapedStringLiteral(text) => Some(text),
        Value::DollarQuotedString(text) => Some(&text.value),
        _ => None,
    }
}

/// The schema `name` qualifies its object with, folded, or `None` for an
/// unqualified name.
pub(crate) fn schema_of(name: &ObjectName) -> Option<String> {
    let mut parts = folded_parts(name)?;
    parts.pop();
    parts.pop()
}

/// The schema `CREATE SCHEMA` names: its own name, or its owner's when only
/// `AUTHORIZATION` is written.
fn created_schema(name: &SchemaName) -> Option<String> {
    match name {
        SchemaName::Simple(name) | SchemaName::NamedAuthorization(name, _) => {
            folded_parts(name)?.pop()
        }
        SchemaName::UnnamedAuthorization(owner) => Some(fold(owner)),
    }
}

/// Whether `name` is the `search_path` setting.
pub(crate) fn is_search_path(name: &ObjectName) -> bool {
    matches!(name.0.as_slice(), [ObjectNamePart::Identifier(ident)]
        if ident.value.eq_ignore_ascii_case("search_path"))
}

/// One schema a `search_path` value names, as PostgreSQL stores it.
type PathEntry = String;

/// The schemas a `search_path` value list names, or `None` for a value that
/// is not a list of names and strings.
///
/// PostgreSQL quotes each string of the list as one name, so `'a, b'` names
/// the single schema `a, b`.
pub(crate) fn path_entries(values: &[Expr]) -> Option<Vec<PathEntry>> {
    values
        .iter()
        .map(|value| match value {
            Expr::Identifier(ident) => Some(fold(ident)),
            value => string_literal(value).map(str::to_owned),
        })
        .collect()
}

/// The single name a `search_path` value list spells with a comma inside
/// quotes, as several schemas written as one.
pub(crate) fn misquoted_path(values: &[Expr]) -> Option<&str> {
    let name = match values {
        [Expr::Identifier(ident)] if ident.quote_style.is_some() => ident.value.as_str(),
        [value] => string_literal(value)?,
        _ => return None,
    };
    name.contains(',').then_some(name)
}

/// The path a `set_config('search_path', value, ...)` string lists, read as
/// PostgreSQL splits a list setting.
fn split_path(value: &str) -> Vec<PathEntry> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            match entry
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
            {
                Some(quoted) => quoted.to_owned(),
                None => entry.to_lowercase(),
            }
        })
        .collect()
}

/// Whether the body of a routine setting `params` runs under a path the
/// script has established as trusted, `state` holding the session's path
/// when the routine is created.
///
/// The last `SET search_path` clause wins. `FROM CURRENT` stores the path in
/// force at creation, and `TO DEFAULT` or no clause leaves the caller's path.
fn routine_path_trusted(params: &[FunctionDefinitionSetParam], state: &ScriptState) -> bool {
    let Some(param) = params
        .iter()
        .rev()
        .find(|param| is_search_path(&param.name))
    else {
        return false;
    };
    match &param.value {
        FunctionSetValue::Values(values) => {
            path_entries(values).is_some_and(|path| state.trusted(&path))
        }
        FunctionSetValue::FromCurrent => state.path_trusted(),
        FunctionSetValue::Default => false,
    }
}

/// The statements of a string `body` PostgreSQL parses and resolves at each
/// call of a routine in `language`, or `None` for a body written in another
/// language or that does not parse.
fn deferred_body(body: &Expr, language: Option<&Ident>) -> Option<Vec<Statement>> {
    parse_body(string_literal(body)?, language.map(fold).as_deref())
}

/// The string body of `function`, which PostgreSQL resolves at each call.
///
/// A `BEGIN ATOMIC` or `RETURN` body stays in the statement's own tree,
/// where it is resolved with the session's path when the function is created.
fn string_body(function: &CreateFunction) -> Option<&Expr> {
    match &function.function_body {
        Some(
            CreateFunctionBody::AsBeforeOptions { body, .. }
            | CreateFunctionBody::AsAfterOptions(body),
        ) => Some(body),
        _ => None,
    }
}

/// Where a statement runs under a path the script has not established as
/// trusted.
pub(crate) enum Untrusted<'script> {
    /// The statement runs with the session's path.
    Session(&'script Statement),
    /// The body of a function or procedure created by the statement runs
    /// with its caller's path, or with a path naming untrusted schemas.
    Body {
        /// The `CREATE FUNCTION` or `CREATE PROCEDURE` statement.
        statement: &'script Statement,
        /// `function` or `procedure`.
        kind: &'static str,
        /// The routine's name.
        name: &'script ObjectName,
        /// The statements of its body.
        body: Vec<Statement>,
    },
}

/// The kind, name and string body of a routine `statement` creates whose
/// body runs under an untrusted path, `state` holding the statements before.
fn untrusted_body<'script>(
    statement: &'script Statement,
    state: &ScriptState,
) -> Option<(&'static str, &'script ObjectName, Vec<Statement>)> {
    match statement {
        Statement::CreateFunction(function)
            if !routine_path_trusted(&function.set_params, state) =>
        {
            let body = deferred_body(string_body(function)?, function.language.as_ref())?;
            Some(("function", &function.name, body))
        }
        Statement::CreateProcedure {
            name,
            language,
            body: CreateProcedureBody::AsString { body, .. },
            ..
        } => Some(("procedure", name, deferred_body(body, language.as_ref())?)),
        _ => None,
    }
}

/// Passes `visit` each statement of `statements` and each deferred routine
/// body that resolves names under a path the script has not established as
/// trusted, in script order.
pub(crate) fn untrusted<'script, E>(
    statements: &'script [Statement],
    mut visit: impl FnMut(Untrusted<'script>) -> Result<(), E>,
) -> Result<(), E> {
    let mut state = ScriptState::default();
    for statement in statements {
        if !state.path_trusted() {
            visit(Untrusted::Session(statement))?;
        }
        if let Some((kind, name, body)) = untrusted_body(statement, &state) {
            visit(Untrusted::Body {
                statement,
                kind,
                name,
                body,
            })?;
        }
        state.advance(statement);
    }
    Ok(())
}

/// The folded parts of `name` joined with dots.
fn qualified(name: &ObjectName) -> String {
    folded_parts(name).map_or_else(|| name.to_string(), |parts| parts.join("."))
}

/// `data_type` as PostgreSQL identifies an argument type: grammar aliases
/// spelled by their catalog name, without `pg_catalog.` or type modifiers.
fn canonical_type(data_type: &DataType) -> String {
    let written = data_type.to_string().to_lowercase();
    let mut depth = 0_usize;
    let mut unmodified = String::new();
    for character in written.chars() {
        match character {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => unmodified.push(character),
            _ => {}
        }
    }
    let dimensions = unmodified.matches('[').count();
    let base = unmodified
        .split('[')
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let base = base.strip_prefix("pg_catalog.").unwrap_or(&base);
    let canonical = match base {
        "int" | "int4" => "integer",
        "int2" => "smallint",
        "int8" => "bigint",
        "float4" => "real",
        "float" | "float8" | "double" => "double precision",
        "bool" => "boolean",
        "varchar" => "character varying",
        "char" | "bpchar" => "character",
        "decimal" => "numeric",
        "varbit" => "bit varying",
        "timestamp" => "timestamp without time zone",
        "timestamptz" => "timestamp with time zone",
        "time" => "time without time zone",
        "timetz" => "time with time zone",
        other => other,
    };
    format!("{canonical}{}", "[]".repeat(dimensions))
}

/// The input types of `arguments`, as a signature lists them.
fn input_types(arguments: &[OperateFunctionArg]) -> String {
    arguments
        .iter()
        .filter(|argument| !matches!(argument.mode, Some(ArgMode::Out)))
        .map(|argument| canonical_type(&argument.data_type))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The argument list of an aggregate's signature.
fn aggregate_types(arguments: &CreateAggregateArgs) -> String {
    match arguments {
        CreateAggregateArgs::Legacy => String::new(),
        CreateAggregateArgs::Star => "*".to_owned(),
        CreateAggregateArgs::List(arguments) => input_types(arguments),
        CreateAggregateArgs::OrderedSet { direct, aggregated } => {
            format!(
                "{} ORDER BY {}",
                input_types(direct),
                input_types(aggregated)
            )
        }
    }
}

/// An object a creation statement creates, identified as PostgreSQL finds an
/// existing one: functions and aggregates by signature, indexes by name in
/// their table's schema and triggers by table.
#[derive(PartialEq, Eq)]
pub(crate) enum Object {
    /// A schema.
    Schema(String),
    /// A function and its input types.
    Function(String),
    /// An aggregate and its argument list.
    Aggregate(String),
    /// A view.
    View(String),
    /// A materialized view.
    MaterializedView(String),
    /// A table.
    Table(String),
    /// A foreign table.
    ForeignTable(String),
    /// A sequence.
    Sequence(String),
    /// A collation.
    Collation(String),
    /// An index and the table it indexes.
    Index {
        /// The index's name.
        name: String,
        /// The table it indexes.
        table: String,
    },
    /// A trigger and the table it fires on.
    Trigger {
        /// The trigger's name.
        name: String,
        /// The table it fires on.
        table: String,
    },
    /// A foreign server, which no schema holds.
    Server(String),
}

impl Display for Object {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(name) => write!(formatter, "schema {name}"),
            Self::Function(signature) => write!(formatter, "function {signature}"),
            Self::Aggregate(signature) => write!(formatter, "aggregate {signature}"),
            Self::View(name) => write!(formatter, "view {name}"),
            Self::MaterializedView(name) => write!(formatter, "materialized view {name}"),
            Self::Table(name) => write!(formatter, "table {name}"),
            Self::ForeignTable(name) => write!(formatter, "foreign table {name}"),
            Self::Sequence(name) => write!(formatter, "sequence {name}"),
            Self::Collation(name) => write!(formatter, "collation {name}"),
            Self::Index { name, table } => write!(formatter, "index {name} on {table}"),
            Self::Trigger { name, table } => write!(formatter, "trigger {name} on {table}"),
            Self::Server(name) => write!(formatter, "server {name}"),
        }
    }
}

/// How a creation statement treats an object that already exists.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Guard {
    /// The statement fails, so success proves the script created the object.
    Unconditional,
    /// `OR REPLACE` takes the existing object over.
    OrReplace,
    /// `IF NOT EXISTS` keeps the existing object.
    IfNotExists,
}

impl Guard {
    /// The guard written as `or_replace` and `if_not_exists` say.
    fn of(or_replace: bool, if_not_exists: bool) -> Self {
        if or_replace {
            Self::OrReplace
        } else if if_not_exists {
            Self::IfNotExists
        } else {
            Self::Unconditional
        }
    }
}

/// What a creation statement creates.
pub(crate) struct Creation {
    /// The object created.
    pub(crate) object: Object,
    /// How an existing object is treated.
    pub(crate) guard: Guard,
    /// The schema the object lands in, when the statement qualifies it.
    pub(crate) schema: Option<String>,
}

impl Creation {
    fn new(object: Object, guard: Guard, schema: Option<String>) -> Self {
        Self {
            object,
            guard,
            schema,
        }
    }
}

/// What `statement` creates, or `None` for a statement creating nothing this
/// analysis tracks. Temporary objects are left out, since each session owns
/// its own.
pub(crate) fn creation(statement: &Statement) -> Option<Creation> {
    Some(match statement {
        Statement::CreateSchema {
            schema_name,
            if_not_exists,
            ..
        } => Creation::new(
            Object::Schema(created_schema(schema_name)?),
            Guard::of(false, *if_not_exists),
            None,
        ),
        Statement::CreateFunction(function) if !function.temporary => {
            let arguments = function.args.as_deref().unwrap_or_default();
            let signature = format!("{}({})", qualified(&function.name), input_types(arguments));
            Creation::new(
                Object::Function(signature),
                Guard::of(function.or_replace, function.if_not_exists),
                schema_of(&function.name),
            )
        }
        Statement::CreateAggregate(aggregate) => {
            let arguments = aggregate_types(&aggregate.args);
            let signature = format!("{}({arguments})", qualified(&aggregate.name));
            Creation::new(
                Object::Aggregate(signature),
                Guard::of(aggregate.or_replace, false),
                schema_of(&aggregate.name),
            )
        }
        Statement::CreateView(view) if !view.temporary => {
            let name = qualified(&view.name);
            Creation::new(
                if view.materialized {
                    Object::MaterializedView(name)
                } else {
                    Object::View(name)
                },
                Guard::of(view.or_replace, view.if_not_exists),
                schema_of(&view.name),
            )
        }
        Statement::CreateTable(table) if !table.temporary => Creation::new(
            Object::Table(qualified(&table.name)),
            Guard::of(table.or_replace, table.if_not_exists),
            schema_of(&table.name),
        ),
        Statement::CreateForeignTable(table) => Creation::new(
            Object::ForeignTable(qualified(&table.name)),
            Guard::of(false, table.if_not_exists),
            schema_of(&table.name),
        ),
        Statement::CreateCollation(collation) => Creation::new(
            Object::Collation(qualified(&collation.name)),
            Guard::of(false, collation.if_not_exists),
            schema_of(&collation.name),
        ),
        Statement::CreateSequence {
            temporary: false,
            if_not_exists,
            name,
            ..
        } => Creation::new(
            Object::Sequence(qualified(name)),
            Guard::of(false, *if_not_exists),
            schema_of(name),
        ),
        Statement::CreateIndex(index) => Creation::new(
            Object::Index {
                name: index.name.as_ref().map_or_else(String::new, qualified),
                table: qualified(&index.table_name),
            },
            Guard::of(false, index.if_not_exists),
            schema_of(&index.table_name),
        ),
        Statement::CreateTrigger(trigger) => Creation::new(
            Object::Trigger {
                name: qualified(&trigger.name),
                table: qualified(&trigger.table_name),
            },
            Guard::of(trigger.or_replace, false),
            schema_of(&trigger.table_name),
        ),
        Statement::CreateServer(server) => Creation::new(
            Object::Server(qualified(&server.name)),
            Guard::of(false, server.if_not_exists),
            None,
        ),
        _ => return None,
    })
}

/// The path state a transaction or savepoint started with, which a rollback
/// to it restores.
struct Frame {
    /// The savepoint's folded name, or `None` for the transaction's start.
    savepoint: Option<String>,
    /// Whether the session's path was trusted.
    session: bool,
    /// Whether the `SET LOCAL` path was trusted, when one was set.
    local: Option<bool>,
}

/// What the statements read so far establish.
///
/// The script starts outside a transaction, as `ParserDB` ingests it, so a
/// `SET LOCAL` before any `BEGIN` ends with its own statement.
#[derive(Default)]
pub(crate) struct ScriptState {
    /// Schemas created by `CREATE SCHEMA` without `IF NOT EXISTS`.
    created_schemas: Vec<String>,
    /// Other objects created without `OR REPLACE` or `IF NOT EXISTS`.
    created_objects: Vec<Object>,
    /// Whether the session's `search_path` is trusted.
    session_trusted: bool,
    /// Whether the transaction's `SET LOCAL` path is trusted, when one is set.
    local_trusted: Option<bool>,
    /// Whether a transaction is open.
    in_transaction: bool,
    /// The open transaction's start and savepoints, oldest first.
    frames: Vec<Frame>,
}

impl ScriptState {
    /// Whether the effective `search_path` is trusted.
    pub(crate) fn path_trusted(&self) -> bool {
        self.local_trusted.unwrap_or(self.session_trusted)
    }

    /// Whether an earlier statement created `schema` unconditionally.
    pub(crate) fn created(&self, schema: &str) -> bool {
        self.created_schemas.iter().any(|created| created == schema)
    }

    /// Whether an earlier statement established who owns what `creation`
    /// creates: the object itself created unconditionally, the schema it
    /// lands in created unconditionally, or for a trigger its table created
    /// unconditionally.
    pub(crate) fn establishes(&self, creation: &Creation) -> bool {
        self.created_objects.contains(&creation.object)
            || creation
                .schema
                .as_deref()
                .is_some_and(|schema| self.created(schema))
            || match &creation.object {
                Object::Schema(name) => self.created(name),
                Object::Trigger { table, .. } => self
                    .created_objects
                    .iter()
                    .any(|created| matches!(created, Object::Table(name) if name == table)),
                _ => false,
            }
    }

    /// Whether `path` searches only `pg_catalog` and schemas this script
    /// created, and ends with `pg_temp`.
    ///
    /// Without `pg_temp` named last PostgreSQL searches the temporary schema
    /// first for relations and types, where any session can create them.
    pub(crate) fn trusted(&self, path: &[PathEntry]) -> bool {
        let mut rest = match path {
            [first, rest @ ..] if first == "pg_catalog" => rest,
            _ => path,
        };
        while let [first, tail @ ..] = rest
            && self.created(first)
        {
            rest = tail;
        }
        matches!(rest, [last] if last == "pg_temp")
    }

    /// Records what `statement` establishes for the statements after it.
    pub(crate) fn advance(&mut self, statement: &Statement) {
        if let Some(creation) = creation(statement)
            && creation.guard == Guard::Unconditional
        {
            match creation.object {
                Object::Schema(name) => self.created_schemas.push(name),
                object => self.created_objects.push(object),
            }
        }
        match statement {
            Statement::Set(Set::SingleAssignment {
                scope,
                variable,
                values,
                ..
            }) if is_search_path(variable) => {
                let trusted = path_entries(values).is_some_and(|path| self.trusted(&path));
                self.set_path(trusted, matches!(scope, Some(ContextModifier::Local)));
            }
            Statement::Reset(reset)
                if match &reset.reset {
                    Reset::ALL => true,
                    Reset::ConfigurationParameter(name) => is_search_path(name),
                    Reset::SessionAuthorization => false,
                } =>
            {
                self.set_path(false, false);
            }
            Statement::Discard {
                object_type: DiscardObject::ALL,
            } => self.set_path(false, false),
            Statement::StartTransaction { .. } if !self.in_transaction => {
                self.in_transaction = true;
                self.push_frame(None);
            }
            Statement::Commit { chain, .. } if self.in_transaction => self.end_transaction(*chain),
            Statement::Rollback {
                chain,
                savepoint: None,
            } if self.in_transaction => {
                self.session_trusted = self
                    .frames
                    .first()
                    .map_or(self.session_trusted, |start| start.session);
                self.end_transaction(*chain);
            }
            Statement::Rollback {
                savepoint: Some(name),
                ..
            } => {
                if let Some(index) = self.savepoint(name) {
                    self.session_trusted = self.frames[index].session;
                    self.local_trusted = self.frames[index].local;
                    self.frames.truncate(index + 1);
                }
            }
            Statement::Savepoint { name } if self.in_transaction => {
                self.push_frame(Some(fold(name)));
            }
            Statement::ReleaseSavepoint { name } => {
                if let Some(index) = self.savepoint(name) {
                    self.frames.truncate(index);
                }
            }
            Statement::Query(_)
            | Statement::Insert(_)
            | Statement::Update(_)
            | Statement::Delete(_)
            | Statement::Merge(_)
            | Statement::Call(_) => {
                let _ = walk(statement, &mut SetConfigCalls(self));
            }
            Statement::CreateTable(table) => {
                if let Some(query) = &table.query {
                    let _ = walk(query, &mut SetConfigCalls(self));
                }
            }
            Statement::CreateView(view) if view.materialized => {
                let _ = walk(&view.query, &mut SetConfigCalls(self));
            }
            _ => {}
        }
    }

    /// Sets the session's path, or the transaction's when `local`. Outside a
    /// transaction a local path ends with its own statement.
    fn set_path(&mut self, trusted: bool, local: bool) {
        if !local {
            self.session_trusted = trusted;
            self.local_trusted = None;
        } else if self.in_transaction {
            self.local_trusted = Some(trusted);
        }
    }

    /// Opens a frame a rollback to `savepoint` returns to.
    fn push_frame(&mut self, savepoint: Option<String>) {
        self.frames.push(Frame {
            savepoint,
            session: self.session_trusted,
            local: self.local_trusted,
        });
    }

    /// The index of the latest frame of the savepoint `name`.
    fn savepoint(&self, name: &Ident) -> Option<usize> {
        let name = fold(name);
        self.frames
            .iter()
            .rposition(|frame| frame.savepoint.as_ref() == Some(&name))
    }

    /// Ends the transaction, opening the next at once when `chain`.
    fn end_transaction(&mut self, chain: bool) {
        self.local_trusted = None;
        self.frames.clear();
        if chain {
            self.push_frame(None);
        } else {
            self.in_transaction = false;
        }
    }
}

/// Applies each `set_config('search_path', ...)` call a statement makes.
struct SetConfigCalls<'state>(&'state mut ScriptState);

impl Visitor for SetConfigCalls<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        if let Expr::Function(function) = expression
            && folded_parts(&function.name).is_some_and(|parts| {
                matches!(parts.as_slice(), [name] if name == "set_config")
                    || matches!(parts.as_slice(), [schema, name]
                        if schema == "pg_catalog" && name == "set_config")
            })
            && let FunctionArguments::List(list) = &function.args
            && let [
                FunctionArg::Unnamed(FunctionArgExpr::Expr(name)),
                FunctionArg::Unnamed(FunctionArgExpr::Expr(value)),
                local,
            ] = list.args.as_slice()
            && string_literal(name).is_some_and(|name| name.eq_ignore_ascii_case("search_path"))
        {
            let trusted =
                string_literal(value).is_some_and(|value| self.0.trusted(&split_path(value)));
            let local = matches!(local,
                FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(literal)))
                    if literal.value == Value::Boolean(true));
            self.0.set_path(trusted, local);
        }
        ControlFlow::Continue(())
    }
}
