//! Submodule providing the `DynamicSqlInjection` rule.

use sql_traits::{
    errors::LookupError,
    structs::{
        CallResolution, ColumnDefinition, Definition, DefinitionId, DefinitionSource,
        ExpressionContext, ExpressionScope, IdentifierCase, OperandType, Reaching, TypeCategory,
        VariableKind, VariableRead,
    },
    traits::{DatabaseLike, FunctionLike},
};
use sqlparser::ast::{BinaryOperator, Expr, Value};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{function_rules::unreadable_body, policy_support::unnested},
    traits::{Constrainer, FunctionRule, GenericConstrainer, Reporter, reporter::signature},
};

/// The `pg_catalog` functions whose result is safe to splice into SQL text.
const QUOTING: [&str; 3] = ["quote_ident", "quote_literal", "quote_nullable"];

/// Struct defining a rule that reports a PL/pgSQL `EXECUTE`, `RETURN QUERY
/// EXECUTE`, `OPEN ... FOR EXECUTE` or `FOR ... IN EXECUTE`, or a call of
/// `pg_catalog`'s `query_to_xml`, `query_to_xmlschema`,
/// `query_to_xml_and_xmlschema`, `ts_stat` or `ts_rewrite` in a SQL or
/// PL/pgSQL body, whose SQL text splices in a string value without quoting
/// it.
///
/// A value spliced with `||`, `concat`, `concat_ws` or a `format` `%s`
/// placeholder becomes SQL text, so a caller choosing the value can close
/// the literal or identifier it was meant to fill and run their own SQL.
/// Values passed with `USING`, wrapped in `pg_catalog`'s `quote_ident`,
/// `quote_literal` or `quote_nullable`, or filled into a `format` `%I` or
/// `%L` placeholder are escaped. Values of a non-string type, or cast to
/// one, cannot carry a quote and are not reported, and nor are values whose
/// type is unknown. A field of `NEW` or `OLD` in a trigger function is a
/// string when any table whose trigger runs the function gives that column
/// a string type.
///
/// A string variable of a PL/pgSQL body stands for every value that may
/// reach the site through branches and loops, so `s := 'SELECT ' || p;
/// EXECUTE s` is reported, and a variable only ever assigned constant or
/// quoted text is not. A variable an argument, a query or a command fills
/// is reported as the value it splices in.
///
/// The rule does not run on SQLite, which has no stored functions.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = DynamicSqlInjection::default().into();
/// let schema = "CREATE TABLE items (name TEXT);";
/// let spliced = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE FUNCTION named(p TEXT) RETURNS BIGINT LANGUAGE plpgsql AS $$
///        DECLARE r BIGINT;
///        BEGIN
///            EXECUTE 'SELECT count(*) FROM items WHERE name = ''' || p || '''' INTO r;
///            RETURN r;
///        END $$;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&spliced).is_err());
/// let bound = ParserDB::parse::<PostgreSqlDialect>(&format!(
///     "{schema} CREATE FUNCTION named(p TEXT) RETURNS BIGINT LANGUAGE plpgsql AS $$
///        DECLARE r BIGINT;
///        BEGIN
///            EXECUTE 'SELECT count(*) FROM items WHERE name = $1' INTO r USING p;
///            RETURN r;
///        END $$;"
/// ))
/// .unwrap();
/// assert!(constrainer.validate_schema(&bound).is_ok());
/// ```
pub struct DynamicSqlInjection<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for DynamicSqlInjection<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<DynamicSqlInjection<DB>> for GenericConstrainer<DB> {
    fn from(rule: DynamicSqlInjection<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_function_rule(Box::new(rule));
        constrainer
    }
}

impl<DB> Rule for DynamicSqlInjection<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(DynamicSqlInjection),
            group: LintGroup::Correctness,
            rationale: "A string value spliced into the SQL text a PL/pgSQL EXECUTE or a catalog function such as query_to_xml runs becomes SQL, so a caller choosing the value can end the literal or identifier it fills and run SQL of their own.",
            source: Some(
                "https://www.postgresql.org/docs/current/plpgsql-statements.html#PLPGSQL-QUOTE-LITERAL-EXAMPLE",
            ),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE items (name TEXT);\n\
CREATE FUNCTION named(p TEXT) RETURNS BIGINT LANGUAGE plpgsql AS $$ DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = ''' || p || '''' INTO r; RETURN r; END $$;",
                good: "CREATE TABLE items (name TEXT);\n\
CREATE FUNCTION named(p TEXT) RETURNS BIGINT LANGUAGE plpgsql AS $$ DECLARE r BIGINT; BEGIN EXECUTE 'SELECT count(*) FROM items WHERE name = $1' INTO r USING p; RETURN r; END $$;",
            },
        };
        &METADATA
    }

    fn engines(&self) -> &'static [Engine] {
        &[Engine::PostgreSql]
    }
}

/// The text of a string constant.
fn string_constant(expression: &Expr) -> Option<&str> {
    let Expr::Value(value) = unnested(expression) else {
        return None;
    };
    match &value.value {
        Value::SingleQuotedString(text) | Value::EscapedStringLiteral(text) => Some(text),
        Value::DollarQuotedString(quoted) => Some(&quoted.value),
        _ => None,
    }
}

/// The digits at the head of `pattern`, and the rest.
fn digits(pattern: &str) -> (&str, &str) {
    let end = pattern
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(pattern.len());
    pattern.split_at(end)
}

/// The zero-based positions among `format`'s value arguments that a `%s`
/// placeholder of `pattern` fills, following PostgreSQL's
/// `%[position][flags][width]type` grammar.
fn plain_positions(mut pattern: &str) -> Vec<usize> {
    let mut plain = Vec::new();
    let mut next = 0;
    while let Some(start) = pattern.find('%') {
        pattern = &pattern[start + 1..];
        if let Some(rest) = pattern.strip_prefix('%') {
            pattern = rest;
            continue;
        }
        let (number, rest) = digits(pattern);
        let mut position = None;
        if let (false, Some(rest)) = (number.is_empty(), rest.strip_prefix('$')) {
            position = number.parse::<usize>().ok();
            pattern = rest;
        }
        pattern = pattern.trim_start_matches('-');
        if let Some(rest) = pattern.strip_prefix('*') {
            let (number, after) = digits(rest);
            match after.strip_prefix('$') {
                Some(after) if !number.is_empty() => {
                    next = number.parse::<usize>().unwrap_or(next);
                    pattern = after;
                }
                _ => {
                    next += 1;
                    pattern = rest;
                }
            }
        } else {
            pattern = digits(pattern).1;
        }
        let mut characters = pattern.chars();
        let Some(kind) = characters.next() else { break };
        pattern = characters.as_str();
        let index = match position {
            Some(position) => position.checked_sub(1),
            None => Some(next),
        };
        if let Some(index) = index {
            next = index + 1;
            if kind == 's' {
                plain.push(index);
            }
        }
    }
    plain
}

/// The SQL a [`Splices`] walk is in: the command of a site, or the value a
/// definition reaching one of its variables assigns.
struct Frame<'f, 'scope, 'r, 'db, DB: DatabaseLike> {
    /// The context typing the SQL.
    context: &'f ExpressionContext<'scope, 'db, DB>,
    /// The variables the SQL reads, with the definitions reaching it.
    reads: &'f [VariableRead<'r, 'db, DB>],
}

/// Collects the string operands a command splices in without quoting.
struct Splices<'db, DB: DatabaseLike> {
    database: &'db DB,
    /// The definitions already followed, so a variable a loop builds from
    /// itself is read once.
    followed: Vec<DefinitionId>,
    found: Vec<String>,
}

impl<'db, DB: DatabaseLike> Splices<'db, DB> {
    /// Whether a value of type `operand` can carry a quote into SQL text.
    fn string(&self, operand: &OperandType<'_>) -> bool {
        let OperandType::Known { type_name, .. } = operand else {
            return false;
        };
        self.database
            .type_facts(type_name.clone())
            .is_some_and(|facts| facts.category() == TypeCategory::STRING)
    }

    /// Visits what `expression` contributes to the command text.
    fn visit(
        &mut self,
        expression: &Expr,
        frame: &Frame<'_, '_, '_, 'db, DB>,
    ) -> Result<(), LookupError> {
        let expression = unnested(expression);
        match expression {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::StringConcat,
                right,
            } => {
                self.visit(left, frame)?;
                return self.visit(right, frame);
            }
            Expr::Value(value) if !matches!(value.value, Value::Placeholder(_)) => {
                return Ok(());
            }
            Expr::TypedString(_) => return Ok(()),
            Expr::Cast { expr, .. } => {
                let target = frame.context.type_of(expression)?;
                return if self.string(&target) {
                    self.visit(expr, frame)
                } else {
                    Ok(())
                };
            }
            _ => {}
        }
        if let Some(call) = frame.context.call(expression)?
            && let CallResolution::Selected(selected) = call.resolution()
            && selected.function().target_name().schema() == Some("pg_catalog")
        {
            let arguments = call.arguments();
            match selected.function().name() {
                name if QUOTING.contains(&name) => return Ok(()),
                "format" => return self.formatted(arguments, frame),
                "concat" | "concat_ws" => {
                    for argument in arguments {
                        self.visit(argument, frame)?;
                    }
                    return Ok(());
                }
                _ => {}
            }
        }
        let operand = frame.context.type_of(expression)?;
        let string = if operand == OperandType::Unknown {
            // A trigger row field the trigger tables type differently.
            frame
                .context
                .row_field_types(expression)?
                .iter()
                .any(|(_, field)| self.string(field))
        } else {
            self.string(&operand)
        };
        if !string {
            return Ok(());
        }
        match read(expression, frame)?.map(VariableRead::reaching) {
            Some(Reaching::Unreachable) => Ok(()),
            Some(Reaching::Definitions(definitions)) => {
                for definition in definitions {
                    self.follow(definition, expression)?;
                }
                Ok(())
            }
            None => {
                self.spliced(expression);
                Ok(())
            }
        }
    }

    /// Visits the value `definition` assigns to the variable `operand`
    /// reads whole, or records `operand` when the definition leaves a value
    /// the body does not spell out, such as an argument or a query's output.
    fn follow(
        &mut self,
        definition: &Definition<'_, 'db, DB>,
        operand: &Expr,
    ) -> Result<(), LookupError> {
        if self.followed.contains(&definition.id()) {
            return Ok(());
        }
        self.followed.push(definition.id());
        match definition.source() {
            DefinitionSource::Null => Ok(()),
            DefinitionSource::Value(value)
                if definition.part().is_empty()
                    && let Some(scope) = definition.scope() =>
            {
                let scope = ExpressionScope::PlPgSql(&scope);
                let context = ExpressionContext::for_expression(
                    value,
                    &scope,
                    self.database,
                    IdentifierCase::Folded,
                )?;
                let reads = definition.reads(IdentifierCase::Folded)?;
                self.visit(
                    value,
                    &Frame {
                        context: &context,
                        reads: &reads,
                    },
                )
            }
            _ => {
                self.spliced(operand);
                Ok(())
            }
        }
    }

    /// Records `operand` as spliced in without quoting.
    fn spliced(&mut self, operand: &Expr) {
        let operand = operand.to_string();
        if !self.found.contains(&operand) {
            self.found.push(operand);
        }
    }

    /// Visits the values a `format` call fills into `%s` placeholders, and
    /// every value and the pattern itself when the pattern is not a constant.
    fn formatted(
        &mut self,
        arguments: &[&Expr],
        frame: &Frame<'_, '_, '_, 'db, DB>,
    ) -> Result<(), LookupError> {
        let Some((pattern, values)) = arguments.split_first() else {
            return Ok(());
        };
        let Some(text) = string_constant(pattern) else {
            self.visit(pattern, frame)?;
            for value in values {
                self.visit(value, frame)?;
            }
            return Ok(());
        };
        for position in plain_positions(text) {
            if let Some(value) = values.get(position) {
                self.visit(value, frame)?;
            }
        }
        Ok(())
    }
}

/// The read of the PL/pgSQL variable `expression` names whole, by name or
/// as `$n`, among the reads of `frame`.
fn read<'f, 'r, 'db, DB: DatabaseLike>(
    expression: &Expr,
    frame: &Frame<'f, '_, 'r, 'db, DB>,
) -> Result<Option<&'f VariableRead<'r, 'db, DB>>, LookupError> {
    if let Expr::Value(value) = expression
        && let Value::Placeholder(placeholder) = &value.value
    {
        let position = placeholder
            .strip_prefix('$')
            .and_then(|digits| digits.parse::<usize>().ok());
        return Ok(frame.reads.iter().find(|read| {
            matches!(read.variable().kind(), VariableKind::Parameter { position: parameter, .. } if Some(*parameter) == position)
        }));
    }
    let Some((ColumnDefinition::Variable(variable), _)) = frame.context.reference(expression)?
    else {
        return Ok(None);
    };
    Ok(frame
        .reads
        .iter()
        .find(|read| read.variable().id() == variable.id()))
}

impl<DB: DatabaseLike> FunctionRule for DynamicSqlInjection<DB> {
    type Database = DB;

    fn check_function(
        &self,
        database: &Self::Database,
        function: &<Self::Database as DatabaseLike>::Function,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if function.target_name().schema() == Some("pg_catalog") {
            return Ok(());
        }
        let body = match function.dynamic_execution_sites(database) {
            Ok(body) => body,
            Err(error) if unreadable_body(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let sites = match body.sites() {
            Ok(sites) => sites,
            Err(error) if unreadable_body(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for site in &sites {
            let context = site.context(IdentifierCase::Folded)?;
            let reads = site.reads(IdentifierCase::Folded)?;
            let mut splices = Splices {
                database,
                followed: Vec::new(),
                found: Vec::new(),
            };
            splices.visit(
                site.command(),
                &Frame {
                    context: &context,
                    reads: &reads,
                },
            )?;
            if splices.found.is_empty() {
                continue;
            }
            let signature = signature(function, database);
            let operands = splices
                .found
                .iter()
                .map(|operand| format!("'{operand}'"))
                .collect::<Vec<_>>()
                .join(", ");
            let resolution = match site.function() {
                None => {
                    "Pass the values with USING, or quote them with format's %L or %I placeholders, quote_literal or quote_ident."
                }
                Some(_) => {
                    "Quote the values with format's %L or %I placeholders, quote_literal or quote_ident."
                }
            };
            reporter.function(
                function,
                format!(
                    "Function '{signature}' builds the SQL it executes from {operands} without quoting, so a caller choosing that text can run SQL of their own."
                ),
                resolution.to_owned(),
            )?;
        }
        Ok(())
    }
}
