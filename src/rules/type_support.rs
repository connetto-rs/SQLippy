//! Data types and temporal constructs the type rules report, wherever the
//! schema holds them: column, domain and function types, and casts or calls
//! in defaults, checks, policies, views and SQL function bodies.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    traits::{
        CheckConstraintLike, ColumnLike, DataTypeLike, DatabaseLike, DomainLike, FunctionLike,
        PolicyLike, TableLike, ViewLike,
    },
};
use sqlparser::{
    ast::{
        ArrayElemTypeDef, DataType, ExactNumberInfo, Expr, FunctionArguments, TimezoneInfo,
        TypedString, Visit, Visitor,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::rules::walk_support::walk;
use crate::{deployment::Deployment, error::PolicyClause, rules::grant_support::is_client_written};

/// A type or temporal construct a type rule reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeFlaw {
    /// `timestamp` without time zone.
    NaiveTimestamp,
    /// `timetz`, or `CURRENT_TIME`, which returns it.
    TimeWithTimeZone,
    /// A timestamp rounded to whole seconds.
    RoundedTimestamp,
    /// `char(n)`.
    BlankPaddedCharacter,
    /// `money`.
    Money,
    /// `json`.
    Json,
    /// `numeric(p, s)`, or `numeric(p)`, whose scale is 0.
    ScaledNumeric,
}

/// The type a value of `data_type` is stored as, through array elements and
/// domains, so `prices amount_t[]` over `amount_t AS real` answers `real`.
pub(crate) fn underlying_type<'db, DB: DatabaseLike>(
    database: &'db DB,
    mut data_type: &'db DB::DataType,
) -> &'db DB::DataType {
    while let Some(inner) = data_type
        .array_element(database)
        .or_else(|| data_type.base_type(database))
    {
        data_type = inner;
    }
    data_type
}

/// The flaws of a declared type, its array elements included.
pub(crate) fn declared_flaws<'db, DB: DatabaseLike>(
    database: &'db DB,
    mut data_type: &'db DB::DataType,
) -> Vec<TypeFlaw> {
    while let Some(element) = data_type.array_element(database) {
        data_type = element;
    }
    let name = data_type.normalized_name(database).to_ascii_lowercase();
    let mut flaws = Vec::new();
    match name.as_str() {
        "timestamp without time zone" => flaws.push(TypeFlaw::NaiveTimestamp),
        "time with time zone" => flaws.push(TypeFlaw::TimeWithTimeZone),
        "char" | "character" if data_type.max_character_length(database).is_some() => {
            flaws.push(TypeFlaw::BlankPaddedCharacter);
        }
        "money" => flaws.push(TypeFlaw::Money),
        "json" => flaws.push(TypeFlaw::Json),
        "numeric" if data_type.numeric_scale(database).is_some() => {
            flaws.push(TypeFlaw::ScaledNumeric);
        }
        _ => {}
    }
    if name.starts_with("timestamp") && data_type.fractional_seconds_precision(database) == Some(0)
    {
        flaws.push(TypeFlaw::RoundedTimestamp);
    }
    flaws
}

/// The flaws of a type as written in an expression or a signature.
pub(crate) fn written_flaws(data_type: &DataType) -> Vec<TypeFlaw> {
    match data_type {
        DataType::Array(
            ArrayElemTypeDef::AngleBracket(element)
            | ArrayElemTypeDef::SquareBracket(element, _)
            | ArrayElemTypeDef::Parenthesis(element)
            | ArrayElemTypeDef::ParenthesisNotNull(element),
        ) => written_flaws(element),
        DataType::Timestamp(precision, zone) => {
            let naive = matches!(zone, TimezoneInfo::None | TimezoneInfo::WithoutTimeZone);
            [
                naive.then_some(TypeFlaw::NaiveTimestamp),
                (*precision == Some(0)).then_some(TypeFlaw::RoundedTimestamp),
            ]
            .into_iter()
            .flatten()
            .collect()
        }
        DataType::Time(_, TimezoneInfo::WithTimeZone | TimezoneInfo::Tz) => {
            vec![TypeFlaw::TimeWithTimeZone]
        }
        DataType::Char(_) | DataType::Character(_) => vec![TypeFlaw::BlankPaddedCharacter],
        DataType::Custom(name, _)
            if name
                .0
                .last()
                .and_then(|part| part.as_ident())
                .is_some_and(|ident| ident.value.eq_ignore_ascii_case("money")) =>
        {
            vec![TypeFlaw::Money]
        }
        DataType::JSON => vec![TypeFlaw::Json],
        DataType::Numeric(info) | DataType::Decimal(info) | DataType::Dec(info)
            if *info != ExactNumberInfo::None =>
        {
            vec![TypeFlaw::ScaledNumeric]
        }
        _ => Vec::new(),
    }
}

/// Collects the flawed casts, typed literals and `CURRENT_TIME` calls of a
/// node.
#[derive(Default)]
struct WrittenTypes(Vec<(TypeFlaw, String)>);

impl Visitor for WrittenTypes {
    type Break = ();

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<()> {
        match expression {
            Expr::Cast { data_type, .. } | Expr::TypedString(TypedString { data_type, .. }) => {
                let written = data_type.to_string();
                self.0.extend(
                    written_flaws(data_type)
                        .into_iter()
                        .map(|flaw| (flaw, written.clone())),
                );
            }
            Expr::Function(call)
                if matches!(call.args, FunctionArguments::None)
                    && call
                        .name
                        .0
                        .last()
                        .and_then(|part| part.as_ident())
                        .is_some_and(|ident| ident.value.eq_ignore_ascii_case("current_time")) =>
            {
                self.0
                    .push((TypeFlaw::TimeWithTimeZone, expression.to_string()));
            }
            _ => {}
        }
        ControlFlow::Continue(())
    }
}

/// The flawed constructs written in a node.
fn written_in<V: Visit + ?Sized>(node: &V) -> Vec<(TypeFlaw, String)> {
    let mut found = WrittenTypes::default();
    let _ = walk(node, &mut found);
    found.0
}

/// The place a flawed construct sits.
pub(crate) enum TypeSite<'db, DB: DatabaseLike> {
    Column(&'db DB::Column),
    Check(&'db DB::Table),
    Policy(&'db DB::Table, &'db DB::Policy, PolicyClause),
    Domain(&'db DB::Domain),
    View(&'db DB::View),
    MaterializedView(&'db DB::MaterializedView),
    Function(&'db DB::Function),
}

/// The flawed constructs one site holds, as written.
pub(crate) struct TypeUse<'db, DB: DatabaseLike> {
    pub(crate) site: TypeSite<'db, DB>,
    pub(crate) found: Vec<(TypeFlaw, String)>,
}

impl<DB: DatabaseLike> TypeUse<'_, DB> {
    /// The table the construct belongs to, when it belongs to one.
    fn table<'s>(&'s self, database: &'s DB) -> Option<&'s DB::Table> {
        match &self.site {
            TypeSite::Column(column) => Some(column.table(database)),
            TypeSite::Check(table) | TypeSite::Policy(table, _, _) => Some(*table),
            TypeSite::Domain(_)
            | TypeSite::View(_)
            | TypeSite::MaterializedView(_)
            | TypeSite::Function(_) => None,
        }
    }

    /// Whether the construct belongs to a table clients write.
    pub(crate) fn client_written(&self, database: &DB, deployment: &Deployment) -> bool {
        self.table(database)
            .is_some_and(|table| is_client_written(database, deployment, table))
    }
}

/// Parses a type name written in a signature.
fn parse_type(name: &str) -> Option<DataType> {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(name)
        .ok()?
        .parse_data_type()
        .ok()
}

/// Every flawed construct the schema holds.
pub(crate) fn type_uses<'db, DB: DatabaseLike>(
    database: &'db DB,
) -> Result<Vec<TypeUse<'db, DB>>, LookupError> {
    let mut uses = Vec::new();
    let mut add = |site: TypeSite<'db, DB>, found: Vec<(TypeFlaw, String)>| {
        uses.push(TypeUse { site, found });
    };
    for table in database.tables() {
        for column in table.columns(database)? {
            let data_type = column.data_type(database);
            let name = data_type.name(database).into_owned();
            let mut found: Vec<(TypeFlaw, String)> = declared_flaws(database, data_type)
                .into_iter()
                .map(|flaw| (flaw, name.clone()))
                .collect();
            let default = column.default_value().and_then(|default| {
                Parser::new(&PostgreSqlDialect {})
                    .try_with_sql(&default)
                    .ok()?
                    .parse_expr()
                    .ok()
            });
            found.extend(default.map_or_default(|default| written_in(&default)));
            add(TypeSite::Column(column), found);
        }
        for check in table.check_constraints(database)? {
            add(
                TypeSite::Check(table),
                written_in(check.expression(database)),
            );
        }
        for policy in table.policies(database)? {
            for (clause, expression) in [
                (PolicyClause::Using, policy.written_using(database)?),
                (PolicyClause::WithCheck, policy.written_check(database)?),
            ] {
                add(
                    TypeSite::Policy(table, policy, clause),
                    expression.map_or_default(written_in),
                );
            }
        }
    }
    for domain in database.domains() {
        let data_type = domain.data_type(database);
        let name = data_type.name(database).into_owned();
        add(
            TypeSite::Domain(domain),
            declared_flaws(database, data_type)
                .into_iter()
                .map(|flaw| (flaw, name.clone()))
                .collect(),
        );
    }
    for view in database.views() {
        add(TypeSite::View(view), written_in(view.definition()));
    }
    for view in database.materialized_views() {
        add(
            TypeSite::MaterializedView(view),
            written_in(view.definition()),
        );
    }
    let declared = database
        .functions()
        .filter(|function| function.target_name().schema() != Some("pg_catalog"));
    for function in declared {
        add(
            TypeSite::Function(function),
            function_flaws(database, function),
        );
    }
    Ok(uses)
}

/// The flawed types of a function's signature and SQL body.
fn function_flaws<DB: DatabaseLike>(
    database: &DB,
    function: &DB::Function,
) -> Vec<(TypeFlaw, String)> {
    let mut found = Vec::new();
    let signature = function
        .argument_type_names(database)
        .chain(function.return_type_name(database));
    for name in signature {
        for flaw in parse_type(&name).map_or_default(|parsed| written_flaws(&parsed)) {
            found.push((flaw, name.to_string()));
        }
    }
    if function
        .stored_language()
        .is_none_or(|language| language == "sql")
    {
        let body = function
            .body()
            .and_then(|body| Parser::parse_sql(&PostgreSqlDialect {}, body).ok())
            .unwrap_or_default();
        found.extend(written_in(&body));
        if let Ok(Some(body)) = function.body_expression(database) {
            found.extend(written_in(body.as_ref()));
        }
    }
    found
}
