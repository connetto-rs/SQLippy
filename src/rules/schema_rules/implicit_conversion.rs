//! Submodule providing the `ImplicitConversion` rule.

use std::ops::ControlFlow;

use sql_traits::{
    errors::LookupError,
    structs::{
        ArraySource, CallResolution, CoercionStep, ExpressionContext, ExpressionScope,
        IdentifierCase, Operand, OperandEvidence, OperandType, OperatorResolution,
    },
    traits::DatabaseLike,
};
use sqlparser::ast::{Expr, Statement, UnaryOperator, Value, Visit, Visitor};

use crate::{
    engine::Engine,
    error::Interruption,
    lint::{Basis, LintGroup, Rule, RuleExample, RuleMetadata},
    rules::{
        typed_site_support::{TypedFinder, TypedFinding, check_typed_sites},
        walk_support::walk,
    },
    traits::{Constrainer, GenericConstrainer, QueryRule, Reporter, SchemaRule},
};

/// Struct defining a rule that reports an operand or a call argument whose
/// type PostgreSQL converts implicitly, and a comparison or computation over
/// two types of one family.
///
/// Types are judged as Rust judges them. Both operands of an operator and
/// every argument of a call must already have the type the operator or the
/// function takes, so `id + ratio` over `int4` and `float8`, `round(id, 2)`
/// and `label || id` are reported, and so are `id = big` over `int4` and
/// `int8` and `day < at` over `date` and `timestamp`, which PostgreSQL
/// compares across types without a conversion. An integer literal takes any
/// integer type and a decimal literal any of `numeric`, `real` and `double
/// precision`, so `big > 5` and `ratio * 2.5` pass while `amount * 2` over a
/// `numeric` is reported. A quoted string stands for text alone, so `atz >
/// '2026-01-01'` and `ident = '…'` are reported and a typed literal such as
/// `TIMESTAMPTZ '2026-01-01'` passes. `NULL` takes any type. A domain reads
/// as its base type, `varchar` and `text` count as one type, and a type
/// modifier is no type difference. A value whose type is unknown is not
/// judged. The rule reads views, materialized views, policies, table check
/// constraints, SQL and PL/pgSQL function bodies and, as a query rule,
/// statements. It does not run on SQLite.
///
/// # Example
///
/// ```rust
/// use sqlippy::prelude::*;
/// use sqlparser::dialect::PostgreSqlDialect;
///
/// let constrainer: GenericConstrainer<ParserDB> = ImplicitConversion::default().into();
/// let mixed = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (id INT4, big INT8); CREATE VIEW v AS SELECT id FROM t WHERE id = big;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&mixed).is_err());
/// let cast = ParserDB::parse::<PostgreSqlDialect>(
///     "CREATE TABLE t (id INT4, big INT8); CREATE VIEW v AS SELECT id FROM t WHERE id::INT8 = big;",
/// )
/// .unwrap();
/// assert!(constrainer.validate_schema(&cast).is_ok());
/// ```
pub struct ImplicitConversion<DB>(std::marker::PhantomData<DB>);

impl<DB> Default for ImplicitConversion<DB> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<DB: DatabaseLike + 'static> From<ImplicitConversion<DB>> for GenericConstrainer<DB> {
    fn from(rule: ImplicitConversion<DB>) -> Self {
        let mut constrainer = GenericConstrainer::default();
        constrainer.register_schema_rule(Box::new(rule));
        constrainer.register_query_rule(Box::new(ImplicitConversion::default()));
        constrainer
    }
}

impl<DB> Rule for ImplicitConversion<DB> {
    fn metadata(&self) -> &'static RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            name: rule_name!(ImplicitConversion),
            group: LintGroup::Suspicious,
            rationale: "An implicit conversion decides what an operation means without the SQL saying so, and the engines convert by different rules, so the same expression can compare or compute differently.",
            source: Some("https://www.postgresql.org/docs/current/typeconv.html"),
            basis: Basis::Declared,
            example: RuleExample {
                bad: "CREATE TABLE t (id INT4, big INT8);\n\
SELECT id FROM t WHERE id = big;",
                good: "CREATE TABLE t (id INT4, big INT8);\n\
SELECT id FROM t WHERE id::INT8 = big;",
            },
        };
        &METADATA
    }
}

const PROBLEM: &str = "so its meaning rests on an implicit conversion the SQL does not show";

/// The types of one family PostgreSQL compares or combines across without a
/// conversion, as `int4 = int8` and `date < timestamp` do.
const FAMILIES: [&[&str]; 5] = [
    &["int2", "int4", "int8"],
    &["float4", "float8"],
    &["date", "timestamp", "timestamptz"],
    &["time", "timetz"],
    &["text", "bpchar", "name"],
];

/// The literal a node writes, through parentheses and a sign.
enum Literal {
    /// An integer, such as `5` or `-5`.
    Integer,
    /// A number with a fraction or an exponent, such as `2.5`.
    Decimal,
    /// A quoted string.
    String,
    /// `NULL`.
    Null,
}

impl Literal {
    /// The literal `expression` writes, or `None` for any other node.
    fn of(mut expression: &Expr) -> Option<Self> {
        loop {
            match expression {
                Expr::Nested(inner)
                | Expr::UnaryOp {
                    op: UnaryOperator::Minus | UnaryOperator::Plus,
                    expr: inner,
                } => expression = inner,
                Expr::Value(value) => {
                    return match &value.value {
                        Value::Number(text, _) if text.contains(['.', 'e', 'E']) => {
                            Some(Self::Decimal)
                        }
                        Value::Number(..) => Some(Self::Integer),
                        Value::SingleQuotedString(_)
                        | Value::DollarQuotedString(_)
                        | Value::EscapedStringLiteral(_)
                        | Value::UnicodeStringLiteral(_) => Some(Self::String),
                        Value::Null => Some(Self::Null),
                        _ => None,
                    };
                }
                _ => return None,
            }
        }
    }

    /// Whether the literal stands for a value of the type named `target`
    /// without a conversion a reader would need to see.
    fn adapts_to(&self, target: &str) -> bool {
        match self {
            Self::Integer => matches!(target, "int2" | "int4" | "int8"),
            Self::Decimal => matches!(target, "numeric" | "float4" | "float8"),
            Self::String => is_textual(target),
            Self::Null => true,
        }
    }
}

/// Whether the type named `name` holds text, `varchar` and `text` alike.
fn is_textual(name: &str) -> bool {
    matches!(name, "text" | "varchar" | "bpchar" | "name")
}

/// The name a type is compared by, `varchar` read as `text` and an array
/// as its element.
fn identity(name: &str) -> &str {
    match name.strip_prefix('_').unwrap_or(name) {
        "varchar" => "text",
        other => other,
    }
}

/// The family of the type named `name`, if it belongs to one.
fn family(name: &str) -> Option<usize> {
    let name = identity(name);
    FAMILIES.iter().position(|members| members.contains(&name))
}

/// The name of a known type.
fn known_name<'t>(operand_type: &'t OperandType<'_>) -> Option<&'t str> {
    match operand_type {
        OperandType::Known { type_name, .. } => Some(type_name.name()),
        OperandType::UntypedLiteral | OperandType::Unknown => None,
    }
}

/// One implicit conversion, with the expression it sits in.
struct Conversion {
    /// The expression applying the operator or the call, rendered as SQL.
    expression: String,
    /// The finding, continuing a sentence after "uses".
    finding: TypedFinding,
}

/// Collects the implicit conversions of the expressions of one context.
struct Conversions<'c, 'q, 'db, DB: DatabaseLike> {
    context: &'c ExpressionContext<'q, 'db, DB>,
    found: Vec<Conversion>,
}

impl<'db, DB: DatabaseLike> Conversions<'_, '_, 'db, DB> {
    /// Records the findings of the operators and the call `expression`
    /// evaluates itself.
    fn inspect(&mut self, expression: &Expr) -> Result<(), LookupError> {
        if matches!(expression, Expr::Nested(_)) {
            return Ok(());
        }
        let mut findings = Vec::new();
        for application in self.context.operators(expression)?.unwrap_or_default() {
            let OperatorResolution::Selected(selected) = application.resolution() else {
                continue;
            };
            let right = selected.right();
            let left = application.left().zip(selected.left());
            match application.right() {
                Operand::Node(node)
                | Operand::Any(ArraySource::Node(node))
                | Operand::All(ArraySource::Node(node)) => {
                    if let Some((left, left_evidence)) = left
                        && let Some(finding) =
                            mixed_family(expression, left, left_evidence, node, right)
                    {
                        findings.push(finding);
                        continue;
                    }
                    let concatenation = application.name().name() == "||";
                    if let Some((left, left_evidence)) = left {
                        findings.extend(self.operand(
                            expression,
                            left,
                            left_evidence,
                            concatenation.then(|| right.target().name()),
                        )?);
                    }
                    findings.extend(
                        self.operand(
                            expression,
                            node,
                            right,
                            concatenation
                                .then(|| left.map(|(_, evidence)| evidence.target().name()))
                                .flatten(),
                        )?,
                    );
                }
                Operand::Any(ArraySource::Built(elements))
                | Operand::All(ArraySource::Built(elements)) => {
                    if let Some((left, left_evidence)) = left {
                        findings.extend(self.operand(expression, left, left_evidence, None)?);
                    }
                    let element = element_name(right.target().name());
                    for node in elements {
                        findings.extend(self.judge(expression, node, element, &[])?);
                    }
                }
                Operand::Call(_) => {
                    if let Some((left, left_evidence)) = left {
                        findings.extend(self.operand(expression, left, left_evidence, None)?);
                    }
                }
            }
        }
        if let Some(call) = self.context.call(expression)?
            && let CallResolution::Selected(selected) = call.resolution()
        {
            for (argument, evidence) in call.arguments().iter().zip(selected.arguments()) {
                let evidence = evidence.evidence();
                findings.extend(self.judge(
                    expression,
                    argument,
                    evidence.target().name(),
                    evidence.conversion(),
                )?);
            }
        }
        for finding in findings {
            if !self
                .found
                .iter()
                .any(|known| known.finding.found == finding.found)
            {
                self.found.push(Conversion {
                    expression: expression.to_string(),
                    finding,
                });
            }
        }
        Ok(())
    }

    /// The finding of the operand `node` of an operator, which `evidence`
    /// says what PostgreSQL makes of. For `||`, `other` names the type the
    /// other operand takes, and a value of another type that a polymorphic
    /// parameter takes beside text is reported as read as text.
    fn operand(
        &self,
        expression: &Expr,
        node: &Expr,
        evidence: &OperandEvidence<'db, DB>,
        other: Option<&str>,
    ) -> Result<Option<TypedFinding>, LookupError> {
        let target = evidence.target().name();
        if evidence.is_polymorphic_binding() && !is_textual(target) && other.is_some_and(is_textual)
        {
            return self.converted(expression, node, "text").map(Some);
        }
        self.judge(expression, node, target, evidence.conversion())
    }

    /// The finding of `operand`, which PostgreSQL carries to the type named
    /// `target` by `steps`, unless strict typing accepts every step.
    fn judge(
        &self,
        expression: &Expr,
        operand: &Expr,
        target: &str,
        steps: &[CoercionStep<'db, DB>],
    ) -> Result<Option<TypedFinding>, LookupError> {
        if let Some(literal) = Literal::of(operand) {
            if let Literal::String = literal {
                let read_as = literal_input(steps).unwrap_or(target);
                if !literal.adapts_to(read_as) {
                    return Ok(Some(TypedFinding {
                        found: format!(
                            "`{expression}`, which reads the string `{operand}` as `{read_as}`"
                        ),
                        resolution: format!("Write a typed literal, as `{operand}::{read_as}`."),
                    }));
                }
                return Ok(None);
            }
            let unconverted = steps.iter().all(|step| {
                matches!(
                    step,
                    CoercionStep::DomainCheck { .. } | CoercionStep::LengthCoercion { .. }
                )
            });
            if unconverted || literal.adapts_to(element_name(target)) {
                return Ok(None);
            }
            return self.converted(expression, operand, target).map(Some);
        }
        let source = self.context.type_of(operand)?;
        if accepted(known_name(&source), steps, target) {
            return Ok(None);
        }
        self.converted(expression, operand, target).map(Some)
    }

    /// The finding of `operand`, converted to the type named `target`.
    fn converted(
        &self,
        expression: &Expr,
        operand: &Expr,
        target: &str,
    ) -> Result<TypedFinding, LookupError> {
        let source = self.context.type_of(operand)?;
        let target = shown(target);
        Ok(TypedFinding {
            found: match known_name(&source) {
                Some(source) => format!(
                    "`{expression}`, which converts `{operand}` from `{}` to `{target}`",
                    shown(source)
                ),
                None => format!("`{expression}`, which converts `{operand}` to `{target}`"),
            },
            resolution: format!(
                "Convert `{operand}` explicitly, as `({operand})::{target}`, or declare both sides with the same type."
            ),
        })
    }
}

/// The finding of two operands an operator takes as two types of one
/// family without converting either, unless one is a literal that takes the
/// other's type.
fn mixed_family<DB: DatabaseLike>(
    expression: &Expr,
    left: &Expr,
    left_evidence: &OperandEvidence<'_, DB>,
    right: &Expr,
    right_evidence: &OperandEvidence<'_, DB>,
) -> Option<TypedFinding> {
    let left_type = left_evidence.target().name();
    let right_type = right_evidence.target().name();
    if identity(left_type) == identity(right_type)
        || family(left_type).is_none()
        || family(left_type) != family(right_type)
        || Literal::of(left).is_some_and(|literal| literal.adapts_to(right_type))
        || Literal::of(right).is_some_and(|literal| literal.adapts_to(left_type))
    {
        return None;
    }
    let (left_type, right_type) = (shown(left_type), shown(right_type));
    Some(TypedFinding {
        found: format!("`{expression}`, whose operands are `{left_type}` and `{right_type}`"),
        resolution: format!(
            "Cast one side so both have the same type, as `({left})::{right_type}`."
        ),
    })
}

/// The element type of the array type named `name`, or `name` itself.
fn element_name(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

/// The type named `name` as SQL writes it, an array type as its element
/// followed by `[]`.
fn shown(name: &str) -> String {
    match name.strip_prefix('_') {
        Some(element) => format!("{element}[]"),
        None => name.to_owned(),
    }
}

/// The type whose input function reads an untyped literal in `steps`, if
/// one does.
fn literal_input<'s, DB: DatabaseLike>(steps: &'s [CoercionStep<'_, DB>]) -> Option<&'s str> {
    steps.iter().find_map(|step| match step {
        CoercionStep::LiteralInput { type_name } => Some(type_name.name()),
        _ => None,
    })
}

/// Whether strict typing accepts `steps`, which carry a value of the type
/// named `source`, when known, to the type named `target`. A domain read as
/// its base, a modifier applied, a row read under another of its names and
/// a relabelling between `varchar` and `text` are accepted, and so is an
/// array whose elements take only such steps.
fn accepted<DB: DatabaseLike>(
    source: Option<&str>,
    steps: &[CoercionStep<'_, DB>],
    target: &str,
) -> bool {
    let mut current = source;
    for step in steps {
        match step {
            CoercionStep::DomainToBase { base } => current = Some(base.name()),
            CoercionStep::LengthCoercion { .. }
            | CoercionStep::RecordToComposite
            | CoercionStep::CompositeToRecord
            | CoercionStep::Inherited => {}
            CoercionStep::Relabel(_) => {
                if current.is_none_or(|current| identity(current) != identity(target)) {
                    return false;
                }
            }
            CoercionStep::Array { element } => {
                if !accepted(current.map(element_name), element, element_name(target)) {
                    return false;
                }
            }
            CoercionStep::LiteralInput { .. }
            | CoercionStep::Function(_)
            | CoercionStep::InOut(_)
            | CoercionStep::DomainCheck { .. } => return false,
        }
    }
    true
}

impl<DB: DatabaseLike> Visitor for Conversions<'_, '_, '_, DB> {
    type Break = LookupError;

    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<LookupError> {
        match self.inspect(expression) {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => ControlFlow::Break(error),
        }
    }
}

/// The implicit conversions of `node`, whose expressions `context` binds
/// and types.
fn conversions<DB: DatabaseLike, V: Visit + ?Sized>(
    context: &ExpressionContext<'_, '_, DB>,
    node: &V,
) -> Result<Vec<Conversion>, LookupError> {
    let mut conversions = Conversions {
        context,
        found: Vec::new(),
    };
    if let ControlFlow::Break(error) = walk(node, &mut conversions) {
        return Err(error);
    }
    Ok(conversions.found)
}

/// Finds and explains implicit conversions.
struct Finder;

impl TypedFinder for Finder {
    fn reads_checks(&self) -> bool {
        true
    }

    fn find<DB: DatabaseLike, V: Visit + ?Sized>(
        &self,
        _database: &DB,
        context: &ExpressionContext<'_, '_, DB>,
        node: &V,
        _clause: bool,
    ) -> Result<Vec<TypedFinding>, LookupError> {
        Ok(conversions(context, node)?
            .into_iter()
            .map(|conversion| conversion.finding)
            .collect())
    }

    fn problem(&self) -> &'static str {
        PROBLEM
    }
}

impl<DB: DatabaseLike> SchemaRule for ImplicitConversion<DB> {
    type Database = DB;

    fn check_schema(
        &self,
        database: &Self::Database,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if Engine::of(database) == Engine::Sqlite {
            return Ok(());
        }
        check_typed_sites(&Finder, database, reporter)
    }
}

impl<DB: DatabaseLike> QueryRule for ImplicitConversion<DB> {
    type Database = DB;

    fn check_statement(
        &self,
        database: &Self::Database,
        statement: &Statement,
        reporter: &mut Reporter<'_, Self::Database>,
    ) -> Result<(), Interruption> {
        if Engine::of(database) == Engine::Sqlite {
            return Ok(());
        }
        let context = ExpressionContext::for_statement(
            statement,
            &ExpressionScope::Empty,
            database,
            IdentifierCase::Folded,
        )?;
        for Conversion {
            expression,
            finding,
        } in conversions(&context, statement)?
        {
            reporter.statement(
                statement,
                expression,
                format!("The statement uses {}, {PROBLEM}.", finding.found),
                finding.resolution,
            )?;
        }
        Ok(())
    }
}
