//! Submodule providing the `CaseSensitiveEmail` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{ColumnDefinition, ExpressionContext},
    traits::{
        CheckConstraintLike, ColumnCollation, ColumnLike, DataTypeLike, DatabaseLike, FunctionLike,
        TableLike,
    },
};
use sqlparser::{
    ast::{
        BinaryOperator, Expr, Function, FunctionArg, FunctionArgExpr, SelectItem, SetExpr,
        Statement, Visit, Visitor,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        closed_set_support::names_cast_column,
        function_reach_support::{call_arguments, calls, literal_key, split},
        literal_support::text_literal,
        name_support::names_email,
        policy_support::{conjuncts, unnested},
        type_support::underlying_type,
        typed_site_support::{TypedFinder, TypedFinding, check_typed_sites},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, Reporter, SchemaRule},
    vocabulary::Vocabulary,
};

rule_definition!(
    /// Struct defining a rule that reports an email column compared
    /// case-sensitively with an email the request carries.
    ///
    /// The column side is a stored column whose name closes with an email
    /// term of the deployment's vocabularies, such as `email` or
    /// `owner_email`. The other side reads a `current_setting` whose name's
    /// last dotted part closes with an email term, such as
    /// `app.verified_email`, a JSON key named for an email, such as
    /// `auth.jwt() ->> 'email'`, or calls a `LANGUAGE sql` function whose body
    /// returns one, through `NULLIF`, casts and parentheses. The comparisons
    /// read are `=`, `<>` and `IS [NOT] DISTINCT FROM`. A `citext` column is
    /// not reported, nor a comparison whose request side is wrapped in
    /// `lower()` or `upper()`, directly or inside the function it calls,
    /// while the column side is wrapped in the same function or a check of
    /// the column holds it in that case. SMTP lets a mailbox's local part be
    /// case-sensitive, which is why the rule is pedantic. The rule reads
    /// views, materialized views, policies and SQL and PL/pgSQL function
    /// bodies.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sqlippy::prelude::*;
    /// use sqlparser::dialect::PostgreSqlDialect;
    ///
    /// let constrainer: GenericConstrainer<ParserDB> = CaseSensitiveEmail::default().into();
    /// let exact = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE invitations (id INT PRIMARY KEY, email TEXT NOT NULL);
    ///      CREATE VIEW invited AS SELECT id FROM invitations
    ///        WHERE email = current_setting('app.verified_email', true);",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&exact).is_err());
    /// let folded = ParserDB::parse::<PostgreSqlDialect>(
    ///     "CREATE TABLE invitations (id INT PRIMARY KEY, email TEXT NOT NULL CHECK (email = lower(email)));
    ///      CREATE VIEW invited AS SELECT id FROM invitations
    ///        WHERE email = lower(current_setting('app.verified_email', true));",
    /// )
    /// .unwrap();
    /// assert!(constrainer.validate_schema(&folded).is_ok());
    /// ```
    CaseSensitiveEmail,
    register_schema_rule,
    LintGroup::Pedantic,
    "Applications identify a mailbox regardless of letter case, so comparing stored addresses with the request's address case-sensitively refuses the same user under a case variant.",
    Some("https://www.postgresql.org/docs/current/citext.html"),
    RuleExample {
        bad: "CREATE TABLE invitations (id INT PRIMARY KEY, email TEXT NOT NULL);\n\
CREATE FUNCTION invited() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT id FROM invitations WHERE email = current_setting('app.verified_email', true) $$;",
        good: "CREATE TABLE invitations (id INT PRIMARY KEY, email TEXT NOT NULL CHECK (email = lower(email)));\n\
CREATE FUNCTION invited() RETURNS SETOF INT LANGUAGE sql STABLE AS $$ SELECT id FROM invitations WHERE email = lower(current_setting('app.verified_email', true)) $$;",
    },
    Basis::Names
);

/// How deep a request side is followed through the functions it calls.
const CALL_DEPTH: usize = 8;

/// A case a value is folded to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    /// Folded by `lower()`.
    Lower,
    /// Folded by `upper()`.
    Upper,
}

/// The case `function` folds its one argument to, and that argument.
fn folding(function: &Function) -> Option<(Case, &Expr)> {
    let case = if calls(function, "lower") {
        Case::Lower
    } else if calls(function, "upper") {
        Case::Upper
    } else {
        return None;
    };
    match call_arguments(function) {
        [FunctionArg::Unnamed(FunctionArgExpr::Expr(argument))] => Some((case, argument)),
        _ => None,
    }
}

/// The first argument of `function`, when it is a call to `NULLIF`.
fn nullif_value(function: &Function) -> Option<&Expr> {
    let [FunctionArg::Unnamed(FunctionArgExpr::Expr(value)), _] = call_arguments(function) else {
        return None;
    };
    matches!(split(&function.name), Some((None | Some("pg_catalog"), name)) if name.eq_ignore_ascii_case("nullif"))
        .then_some(value)
}

/// The expression a `LANGUAGE sql` function returns, when its body is
/// `RETURN expression` or one `SELECT expression` reading no relation.
fn returned_expression<DB: DatabaseLike>(database: &DB, function: &DB::Function) -> Option<Expr> {
    if function
        .stored_language()
        .is_some_and(|language| language != "sql")
    {
        return None;
    }
    if let Ok(Some(body)) = function.body_expression(database) {
        return Some(body.into_owned());
    }
    let mut statements = Parser::parse_sql(&PostgreSqlDialect {}, function.body()?).ok()?;
    let (Some(Statement::Query(query)), true) = (statements.pop(), statements.is_empty()) else {
        return None;
    };
    let SetExpr::Select(select) = *query.body else {
        return None;
    };
    if !select.from.is_empty() || select.selection.is_some() {
        return None;
    }
    let mut projection = select.projection.into_iter();
    match (projection.next(), projection.next()) {
        (
            Some(
                SelectItem::UnnamedExpr(expression)
                | SelectItem::ExprWithAlias {
                    expr: expression, ..
                },
            ),
            None,
        ) => Some(expression),
        _ => None,
    }
}

/// An email the request carries, as one side of a comparison reads it.
struct Source {
    /// Where the email comes from, described.
    origin: String,
    /// The case the side folds the email to, if any.
    folded: Option<Case>,
}

/// The email the request side `expression` reads, through parentheses,
/// casts, `NULLIF`, case folding and up to `depth` calls of `LANGUAGE sql`
/// functions returning one.
fn source<DB: DatabaseLike>(
    database: &DB,
    vocabularies: &[Vocabulary],
    expression: &Expr,
    depth: usize,
) -> Option<Source> {
    match expression {
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => {
            source(database, vocabularies, inner, depth)
        }
        Expr::BinaryOp {
            op: BinaryOperator::Arrow | BinaryOperator::LongArrow,
            right,
            ..
        } => {
            let key = text_literal(right)?;
            names_email(vocabularies, key).then(|| Source {
                origin: format!("JSON key '{key}'"),
                folded: None,
            })
        }
        Expr::BinaryOp {
            op: BinaryOperator::HashArrow | BinaryOperator::HashLongArrow,
            right,
            ..
        } => {
            let path = text_literal(right)?;
            let path = path.trim_matches(|character| character == '{' || character == '}');
            let key = path.rsplit_once(',').map_or(path, |(_, last)| last).trim();
            names_email(vocabularies, key).then(|| Source {
                origin: format!("JSON key '{key}'"),
                folded: None,
            })
        }
        Expr::Function(function) => {
            if let Some((case, argument)) = folding(function) {
                let mut found = source(database, vocabularies, argument, depth)?;
                found.folded = Some(case);
                return Some(found);
            }
            if let Some(value) = nullif_value(function) {
                return source(database, vocabularies, value, depth);
            }
            if matches!(split(&function.name), Some((None | Some("pg_catalog"), name)) if name.eq_ignore_ascii_case("current_setting"))
            {
                let setting = literal_key(function)?;
                let last = setting.rsplit_once('.').map_or(setting, |(_, last)| last);
                return names_email(vocabularies, last).then(|| Source {
                    origin: format!("setting '{setting}'"),
                    folded: None,
                });
            }
            if depth == 0 {
                return None;
            }
            let (schema, name) = split(&function.name)?;
            let arguments = call_arguments(function).len();
            let mut candidates = database.functions().filter(|candidate| {
                candidate.stored_name().eq_ignore_ascii_case(name)
                    && schema.is_none_or(|schema| {
                        candidate
                            .target_name()
                            .schema()
                            .is_some_and(|held| held.eq_ignore_ascii_case(schema))
                    })
                    && candidate.accepts_argument_count(arguments)
            });
            let (Some(called), None) = (candidates.next(), candidates.next()) else {
                return None;
            };
            let returned = returned_expression(database, called)?;
            let found = source(database, vocabularies, &returned, depth - 1)?;
            Some(Source {
                origin: format!("{} through '{function}'", found.origin),
                folded: found.folded,
            })
        }
        _ => None,
    }
}

/// An email column as one side of a comparison reads it.
struct EmailColumn {
    /// The column's `table.column` name.
    name: String,
    /// Whether the column's type compares case-insensitively.
    insensitive: bool,
    /// The case a check of the column holds it in, if any.
    held: Option<Case>,
    /// The case the side folds the column to, if any.
    folded: Option<Case>,
}

/// Whether the type named `type_name`, bare or schema-qualified, is
/// `citext`, which compares case-insensitively.
fn is_citext(type_name: &str) -> bool {
    type_name
        .rsplit('.')
        .next()
        .is_some_and(|name| name.trim_matches('"').eq_ignore_ascii_case("citext"))
}

/// The case a top-level conjunct `column = lower(column)`, in either order,
/// of a check of the column whose stored name is `stored` holds it in.
fn held_case(conjunct: &Expr, stored: &str) -> Option<Case> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = conjunct
    else {
        return None;
    };
    let folded = |bare: &Expr, call: &Expr| {
        let Expr::Function(function) = unnested(call) else {
            return None;
        };
        let (case, argument) = folding(function)?;
        (names_cast_column(bare, stored) && names_cast_column(argument, stored)).then_some(case)
    };
    folded(left, right).or_else(|| folded(right, left))
}

/// The email column the column side `expression` reads, through
/// parentheses, casts and case folding.
fn email_column<DB: DatabaseLike>(
    context: &ExpressionContext<'_, '_, DB>,
    vocabularies: &[Vocabulary],
    expression: &Expr,
) -> Result<Option<EmailColumn>, LookupError> {
    match expression {
        Expr::Nested(inner) => email_column(context, vocabularies, inner),
        Expr::Cast {
            expr: inner,
            data_type,
            ..
        } => Ok(
            email_column(context, vocabularies, inner)?.map(|mut column| {
                column.insensitive |= is_citext(&data_type.to_string());
                column
            }),
        ),
        Expr::Function(function) => {
            let Some((case, argument)) = folding(function) else {
                return Ok(None);
            };
            Ok(
                email_column(context, vocabularies, argument)?.map(|mut column| {
                    column.folded = Some(case);
                    column
                }),
            )
        }
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            let Some((
                ColumnDefinition::Base {
                    table,
                    column,
                    database,
                },
                _,
            )) = context.reference(expression)?
            else {
                return Ok(None);
            };
            if !names_email(vocabularies, column.column_name()) {
                return Ok(None);
            }
            let insensitive =
                is_citext(&underlying_type(database, column.data_type(database)).name(database))
                    || (Engine::of(database) == Engine::Sqlite
                        && matches!(
                            column.collation(database)?,
                            ColumnCollation::Named(collation)
                                if collation.name().name().eq_ignore_ascii_case("nocase")
                        ));
            let stored = column.stored_column_name();
            let mut held = None;
            for check in column
                .check_constraints(database)?
                .filter(|check| check.is_enforced())
            {
                held = held.or_else(|| {
                    conjuncts(check.expression(database))
                        .into_iter()
                        .find_map(|conjunct| held_case(conjunct, &stored))
                });
            }
            Ok(Some(EmailColumn {
                name: format!("{}.{}", table.table_name(), column.column_name()),
                insensitive,
                held,
                folded: None,
            }))
        }
        _ => Ok(None),
    }
}

/// Collects the case-sensitive comparisons of email columns with request
/// emails.
struct Comparisons<'c, 'q, 'db, 'v, DB: DatabaseLike> {
    database: &'db DB,
    context: &'c ExpressionContext<'q, 'db, DB>,
    vocabularies: &'v [Vocabulary],
    found: Vec<TypedFinding>,
}

impl<DB: DatabaseLike> Visitor for Comparisons<'_, '_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        let (Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq | BinaryOperator::NotEq,
            right,
        }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right)) = expression
        else {
            return ControlFlow::Continue(());
        };
        for (column_side, request_side) in [(left, right), (right, left)] {
            let Some(request) = source(self.database, self.vocabularies, request_side, CALL_DEPTH)
            else {
                continue;
            };
            let column = match email_column(self.context, self.vocabularies, column_side) {
                Ok(Some(column)) => column,
                Ok(None) => continue,
                Err(error) => return ControlFlow::Break(error),
            };
            let matched = column.insensitive
                || request
                    .folded
                    .is_some_and(|case| column.folded.or(column.held) == Some(case));
            if !matched {
                self.found.push(TypedFinding {
                    found: format!(
                        "`{expression}`, comparing column '{}' with the email in {} case-sensitively",
                        column.name, request.origin
                    ),
                    resolution: match Engine::of(self.database) {
                        Engine::PostgreSql => format!(
                            "Store addresses lowercased under `CHECK ({0} = lower({0}))` and compare them with `lower()` of the request's address, or type the column `citext`.",
                            column.name.rsplit('.').next().unwrap_or(&column.name)
                        ),
                        Engine::Sqlite => format!(
                            "Declare '{0}' `COLLATE NOCASE`, which folds ASCII letters only, or store addresses lowercased under `CHECK ({0} = lower({0}))` and compare them with `lower()` of the request's address.",
                            column.name.rsplit('.').next().unwrap_or(&column.name)
                        ),
                    },
                });
            }
            break;
        }
        ControlFlow::Continue(())
    }
}

/// Finds and explains case-sensitive email comparisons.
struct Finder<'v> {
    vocabularies: &'v [Vocabulary],
}

impl TypedFinder for Finder<'_> {
    fn reads_checks(&self) -> bool {
        false
    }

    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        database: &DB,
        context: &ExpressionContext<'_, '_, DB>,
        node: &V,
        _clause: bool,
    ) -> Result<Vec<TypedFinding>, LookupError> {
        let mut comparisons = Comparisons {
            database,
            context,
            vocabularies: self.vocabularies,
            found: Vec::new(),
        };
        if let ControlFlow::Break(error) = walk(node, &mut comparisons) {
            return Err(error);
        }
        Ok(comparisons.found)
    }

    fn problem(&self) -> &'static str {
        "so a mailbox written in another case does not match"
    }
}

impl<DB: DatabaseLike> SchemaRule for CaseSensitiveEmail<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        let finder = Finder {
            vocabularies: reporter.deployment().vocabularies(),
        };
        check_typed_sites(&finder, database, reporter)
    }
}
